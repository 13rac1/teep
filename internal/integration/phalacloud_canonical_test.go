package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/13rac1/teep/internal/provider/phalacloud"
	"github.com/13rac1/teep/internal/verify"
)

// TestVerifyRun_PhalaCloudCanonical_Fixture replays a live Phala Cloud
// capture of the canonical ACI/1 report (/v1/aci/attestation) through
// verify.Run with the production policy. The gateway evidence, the ACI/1
// §3.2 statement binding of the client nonce, the key custody and the TLS
// key binding pass and are enforced; the nonce factors (no echoed nonce) and the GPU factors (no
// GPU evidence) fail and are allowed.
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
		"gateway_tee_measurement",
		"gateway_tee_reportdata_binding",
		"gateway_compose_binding",
		"gateway_event_log_integrity",
		"tls_key_binding",
	})
	if f := findFactor(t, report, "tls_key_binding"); !f.Enforced {
		t.Error("tls_key_binding is not enforced")
	}
	// The fixture keyset lists this key for tee.redpill.ai, and the capture
	// recorded it as the peer key of the attestation connection.
	if report.TLSAuthority != "tee.redpill.ai" || report.TLSKeyFP != "951885459fbd27cad038c40a198e6a1fb63f4d18dd5d5a24d408d5d951488ffe" {
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
