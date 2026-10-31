package integration

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/provider/venice"
	"github.com/13rac1/teep/internal/verify"
)

// TestVerifyRun_VeniceACI_Fixture replays a captured Venice ACI/1
// attestation through the full verify.Run production code path (GH #113).
// ACI/1 attests the private-ai-gateway CVM, not the machine serving
// inference, so the report puts the quote in the gateway tier: the gateway
// chain, the key custody factor, and the gateway compose binding are
// enforced and must pass; the core tee_* factors fail and are waived by
// ACIDefaultAllowFail. The fixture is selected via the "venice_aci"
// prefix, which the bare "venice" (dstack) fixture lookup excludes — SEE:
// findFixtureDir.
func TestVerifyRun_VeniceACI_Fixture(t *testing.T) {
	env := loadFixture(t, "venice_aci")
	baseURL := extractBaseURL(t, env.entries)
	t.Logf("base URL: %s", baseURL)

	cfg, cp := buildVerifyRunConfig(env.manifest.Provider, baseURL)

	report, err := verify.Run(context.Background(), &verify.Options{
		Config:           cfg,
		Provider:         cp,
		ProviderName:     env.manifest.Provider,
		ModelName:        env.manifest.Model,
		Offline:          false,
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
		"nonce_match",
		"signing_key_present",
		"aci_key_custody",
		"nvidia_signature",
		"nvidia_nonce_client_bound",
		"gateway_nonce_match",
		"gateway_tee_quote_present",
		"gateway_tee_quote_structure",
		"gateway_tee_cert_chain",
		"gateway_tee_quote_signature",
		"gateway_tee_debug_disabled",
		"gateway_tee_measurement",
		"gateway_tee_reportdata_binding",
		"gateway_compose_binding",
		"gateway_event_log_integrity",
	})

	// E2EE authorization must read the gateway binding factor: the E2EE key
	// is the gateway's, and the core tee_reportdata_binding never passes.
	if report.E2EEBindingFactor != attestation.FactorGWReportData {
		t.Errorf("E2EEBindingFactor = %q, want %q", report.E2EEBindingFactor, attestation.FactorGWReportData)
	}

	// The core factors that describe the unattested inference host must
	// fail visibly (waived, never hidden as NotApplicable or passing).
	for _, name := range []string{"tee_quote_present", "tee_reportdata_binding", "compose_binding"} {
		f := findFactor(t, report, name)
		if f.Status != attestation.Fail || f.Enforced {
			t.Errorf("%s: status=%s enforced=%v, want a waived Fail — teep has no evidence about the inference host",
				name, f.Status, f.Enforced)
		}
	}

	// The report must not present the gateway's platform as the model
	// endpoint's.
	if hw, ok := report.Metadata["hardware"]; ok {
		t.Errorf("report claims Hardware %q for a gateway-only attestation", hw)
	}
	if _, ok := report.Metadata["gateway_downstream_tls"]; !ok {
		t.Error("gateway_downstream_tls metadata missing — the attested downstream pin must be reported")
	}
}

// TestVeniceACI_GatewayIdentityAcrossModels compares every captured ACI/1
// fixture pairwise: models with different upstream vendors must present the
// same gateway identity (keyset digest, signing key, downstream TLS pin)
// while their relayed GPU evidence differs. This is the observable proof
// that ACI/1 attests one shared gateway rather than per-model backends —
// the basis for reporting it in the gateway tier.
func TestVeniceACI_GatewayIdentityAcrossModels(t *testing.T) {
	raws := loadAllACIRaws(t)
	if len(raws) < 2 {
		t.Skipf("need at least 2 venice_aci fixtures for the cross-model comparison, have %d", len(raws))
	}
	first := raws[0]
	for _, other := range raws[1:] {
		if first.raw.ACIWorkloadKeysetDigest != other.raw.ACIWorkloadKeysetDigest {
			t.Errorf("workload_keyset_digest differs between %s and %s — gateway identity not shared",
				first.model, other.model)
		}
		if first.raw.SigningKey != other.raw.SigningKey {
			t.Errorf("signing key differs between %s and %s", first.model, other.model)
		}
		if first.raw.ACIDownstreamTLSDomain != other.raw.ACIDownstreamTLSDomain ||
			first.raw.ACIDownstreamTLSSPKI != other.raw.ACIDownstreamTLSSPKI {
			t.Errorf("downstream TLS binding differs between %s and %s", first.model, other.model)
		}
		if first.raw.GatewayAppCompose != other.raw.GatewayAppCompose {
			t.Errorf("gateway app_compose differs between %s and %s", first.model, other.model)
		}
		if first.raw.NvidiaPayload == other.raw.NvidiaPayload {
			t.Errorf("relayed GPU evidence is identical between %s and %s — expected per-backend GPUs",
				first.model, other.model)
		}
	}
}

type aciFixtureRaw struct {
	model string
	raw   *attestation.RawAttestation
}

// loadAllACIRaws parses the attestation response body of every venice_aci
// fixture in testdata.
func loadAllACIRaws(t *testing.T) []aciFixtureRaw {
	t.Helper()
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	var raws []aciFixtureRaw
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "venice_aci_") {
			continue
		}
		body, err := os.ReadFile(filepath.Join("testdata", e.Name(),
			"responses", "0001_api.venice.ai_api_v1_tee_attestation.body"))
		if err != nil {
			t.Fatalf("read fixture attestation body: %v", err)
		}
		raw, err := venice.ParseAttestationResponse(context.Background(), body)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		if raw.BackendFormat != attestation.FormatACI1 {
			t.Fatalf("%s parsed as %q, want aci/1", e.Name(), raw.BackendFormat)
		}
		raws = append(raws, aciFixtureRaw{model: raw.Model, raw: raw})
	}
	return raws
}

// trustServerFailure fails every request to one Proof of Cloud trust server
// at transport level and sends all other requests to the fixture replay. The
// error text carries the current time, as a TLS certificate error does.
type trustServerFailure struct {
	host string
	next http.RoundTripper
}

func (f trustServerFailure) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == f.host {
		return nil, errors.New("tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time " +
			time.Now().UTC().Format(time.RFC3339Nano) + " is after 2026-09-07T23:59:59Z")
	}
	return f.next.RoundTrip(req)
}

// A live transport error on an external check must replay as the same
// failure. One trust server fails during a captured Venice ACI/1
// verification; the capture self-check replays the saved capture and must
// produce the same report, so Run returns no error.
func TestVerifyRun_VeniceACI_CaptureRecordsTransportFailure(t *testing.T) {
	env := loadFixture(t, "venice_aci")
	baseURL := extractBaseURL(t, env.entries)
	cfg, cp := buildVerifyRunConfig(env.manifest.Provider, baseURL)
	const failingHost = "trust-server.scrtlabs.com"
	client := &http.Client{Transport: trustServerFailure{host: failingHost, next: env.client.Transport}}

	captureDir := t.TempDir()
	report, err := verify.Run(context.Background(), &verify.Options{
		Config:           cfg,
		Provider:         cp,
		ProviderName:     env.manifest.Provider,
		ModelName:        env.manifest.Model,
		Client:           client,
		Nonce:            env.nonce,
		CaptureDir:       captureDir,
		CapturedE2EE:     fixtureE2EEResult(env.manifest.E2EE),
		VerificationTime: fixtureVerificationTime(&env),
	})
	if err != nil {
		t.Fatalf("verify.Run with capture: %v", err)
	}
	assertNoEnforcedFailures(t, report)
	f := findFactor(t, report, "gateway_cpu_id_registry")
	if !strings.Contains(f.Detail, failingHost) || !strings.Contains(f.Detail, "certificate has expired") {
		t.Fatalf("gateway_cpu_id_registry detail = %q, want the trust server transport failure", f.Detail)
	}

	dirs, err := os.ReadDir(captureDir)
	if err != nil || len(dirs) != 1 {
		t.Fatalf("capture dir entries = %v (err %v), want one capture", dirs, err)
	}
	_, entries, err := capture.Load(filepath.Join(captureDir, dirs[0].Name()))
	if err != nil {
		t.Fatalf("load capture: %v", err)
	}
	var failed int
	for i := range entries {
		if entries[i].Err != "" {
			failed++
		}
	}
	if failed == 0 {
		t.Error("capture holds no failed exchange; the trust server failure was not recorded")
	}
}
