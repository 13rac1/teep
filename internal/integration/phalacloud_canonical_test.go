package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/13rac1/teep/internal/provider/phalacloud"
	"github.com/13rac1/teep/internal/verify"
)

// TestVerifyRun_PhalaCloudCanonical_Fixture replays a live Phala Cloud
// capture of 2026-11-01 of the canonical ACI/1 report (/v1/aci/attestation),
// the attested sessions of the model, and the pinned E2EE test exchange
// through verify.Run with the production policy. The gateway evidence, the
// ACI/1 §3.2 statement binding of the client nonce, the key custody, the TLS
// key binding and the session audit pass and are enforced; the nonce
// factors (no echoed nonce) and the GPU factors of the report (no GPU
// evidence) fail and are allowed.
func TestVerifyRun_PhalaCloudCanonical_Fixture(t *testing.T) {
	env := loadFixture(t, "phalacloud_aci")
	if !strings.HasPrefix(env.entries[0].URL, "https://tee.redpill.ai"+aci.CanonicalPath+"?nonce=") {
		t.Fatalf("first request %q is not the canonical report", env.entries[0].URL)
	}
	cfg, cp := buildVerifyRunConfig(env.manifest.Provider, "https://tee.redpill.ai")
	report, err := verify.Run(context.Background(), &verify.Options{
		Config:           cfg,
		Provider:         cp,
		ProviderName:     env.manifest.Provider,
		ModelName:        env.manifest.Model,
		Client:           env.client,
		Nonce:            env.nonce,
		CapturedE2EE:     fixtureE2EEResult(env.manifest.E2EE),
		VerificationTime: fixtureVerificationTime(&env),
	})
	if err != nil {
		t.Fatalf("verify.Run: %v", err)
	}
	logReportScore(t, report)
	assertNoEnforcedFailures(t, report)
	assertMustPass(t, report, []string{
		"signing_key_present",
		"aci_key_custody",
		"gateway_tee_quote_present",
		"gateway_tee_quote_structure",
		"gateway_tee_cert_chain",
		"gateway_tee_quote_signature",
		"gateway_tee_debug_disabled",
		"gateway_tee_reportdata_binding",
		"gateway_compose_binding",
		"gateway_event_log_integrity",
		"tls_key_binding",
	})
	assertAllowedFail(t, report, []string{"gateway_tee_measurement"}, "the gateway deployment of 2026-11-12 has an MRTD that is not in the dstack base allowlist; the factor is allowed to fail by default")
	if f := findFactor(t, report, "tls_key_binding"); !f.Enforced {
		t.Error("tls_key_binding is not enforced")
	}
	// The fixture keyset lists this key for tee.redpill.ai, and the capture
	// recorded it as the peer key of the attestation connection.
	if report.TLSAuthority != "tee.redpill.ai" || report.TLSKeyFP != "dd7451eed78f36e8e230047e0e1e91955810f802fea052996fa83add370a00ce" {
		t.Errorf("transport identity %q %q, want the keyset TLS key of tee.redpill.ai", report.TLSAuthority, report.TLSKeyFP)
	}
	if f := findFactor(t, report, "gateway_tee_reportdata_binding"); !strings.Contains(f.Detail, "binds the keyset digest") || !f.Enforced {
		t.Errorf("gateway_tee_reportdata_binding = %q enforced=%v, want the §3.2 statement binding", f.Detail, f.Enforced)
	}
	for _, name := range []string{"nvidia_signature", "nvidia_nonce_client_bound", "tee_quote_present", "aci_backend_named", "nonce_match", "gateway_nonce_match"} {
		if f := findFactor(t, report, name); f.Status == attestation.Pass || f.Enforced {
			t.Errorf("%s: status=%s enforced=%v, want an allowed failure", name, f.Status, f.Enforced)
		}
	}
	if report.ACIKeysetDigest == "" {
		t.Error("report carries no verified keyset digest")
	}
	// The pinned path admits an authorization only with a transport identity
	// and an E2EE key that a passed REPORTDATA binding authenticates.
	if _, err := report.TransportIdentity(); err != nil || !report.ReportDataBindingPassed() {
		t.Errorf("authorization material: identity err=%v, key bound=%v", err, report.ReportDataBindingPassed())
	}
	assertPinnedSessions(t, &env, report)
}

// The capture's pinned sessions: one Phala model CVM session and the three
// Chutes sessions of the one Chutes bundle that the evidence limit allowed.
var fixtureSessionIDs = []string{
	"f82e2a6b603a3d0b1abe395f979440f0da44a425b238cfcb5354f20906f43cc7",
	"18aa6d5d8b108534e293deb250cb7b2f99b5790b10a500d4d5066647bee1dcf4",
	"429596d33189b26631b7c88daaac1dae4ed05c3eff005662b21573cdd86b3551",
	"68642a9de9504d777299fee0b759f5cc01a2080cce6a00d8fb63e8542f27031b",
}

// assertPinnedSessions requires the audit to pin exactly the sessions of the
// capture, and the captured E2EE test request to pin the same sessions. The
// gateway served that request through them (HTTP 200).
func assertPinnedSessions(t *testing.T, env *fixtureEnv, report *attestation.VerificationReport) {
	t.Helper()
	if f := findFactor(t, report, "aci_session_verified"); f.Status != attestation.Pass || !f.Enforced {
		t.Errorf("aci_session_verified: status %s, enforced %v; want an enforced pass", f.Status, f.Enforced)
	}
	if got, want := strings.Join(report.ACISessionIDs, ","), strings.Join(fixtureSessionIDs, ","); got != want {
		t.Errorf("pinned sessions %s, want %s", got, want)
	}
	var chat *capture.RecordedEntry
	for i := range env.entries {
		if strings.HasSuffix(env.entries[i].URL, "/v1/chat/completions") {
			chat = &env.entries[i]
		}
	}
	if chat == nil {
		t.Fatal("the capture has no E2EE test request")
	}
	if chat.Status != http.StatusOK {
		t.Errorf("E2EE test request status %d, want 200", chat.Status)
	}
	var body struct {
		Provider struct {
			ACISessionIDs []string `json:"aci_session_ids"`
		} `json:"provider"`
	}
	if err := json.Unmarshal(chat.ReqBody, &body); err != nil {
		t.Fatalf("E2EE test request body: %v", err)
	}
	if got, want := strings.Join(body.Provider.ACISessionIDs, ","), strings.Join(fixtureSessionIDs, ","); got != want {
		t.Errorf("request pinned %s, want %s", got, want)
	}
}

// A gateway identity outside the pins fails the key custody chain of the
// canonical report.
func TestPhalaCloudCanonical_PinsDecideCustody(t *testing.T) {
	env := loadFixture(t, "phalacloud_aci")
	raw, err := phalacloud.ParseAttestationResponse(context.Background(), env.entries[0].Body)
	if err != nil {
		t.Fatalf("parse fixture report: %v", err)
	}
	at := fixtureVerificationTime(&env)
	if r := aci.VerifyKeyset(raw, at, aci.GatewayPins()); r == nil || !r.CustodyChainValid {
		t.Fatalf("custody with the gateway pins: %+v", r)
	}
	pins := aci.GatewayPins()
	other := aci.Pins{KMSRoots: []string{"03" + strings.Repeat("11", 32)}, GatewayAppIDs: pins.GatewayAppIDs}
	if r := aci.VerifyKeyset(raw, at, other); r == nil || r.CustodyChainValid {
		t.Fatalf("custody with another KMS root passed: %+v", r)
	}
}
