package verify

import (
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
)

// teep verify --offline sends no probe, also with an API key, so the
// receipt of a Phala Cloud canonical report is not checked, and
// aci_receipt_verified says why. The base URL is not a server: a request
// would fail the test with an error result.
func TestOfflineRunSendsNoProbeAndSaysSo(t *testing.T) {
	opts := &Options{ProviderName: "phalacloud", ModelName: "m", Offline: true,
		Provider: &config.Provider{BaseURL: "https://127.0.0.1:1", APIKey: "secret-api-key", E2EE: true}}
	raw := &attestation.RawAttestation{BackendFormat: attestation.FormatACI1, ACICanonicalReport: true, SigningKey: "04" + "ab"}
	got := evidenceE2EEOutcome(t.Context(), opts, raw)
	if got == nil || got.Attempted || got.Err != nil {
		t.Fatalf("offline outcome = %+v, want no probe", got)
	}
	if got.NoReceiptCheck != "not checked: teep verify --offline sends no probe" {
		t.Errorf("NoReceiptCheck = %q", got.NoReceiptCheck)
	}
	report := &attestation.VerificationReport{Factors: []attestation.FactorResult{
		{Name: attestation.FactorACIReceiptVerified, Status: attestation.Skip, Deferred: true, Enforced: true},
	}}
	report.MarkACIReceipt(got, "")
	if f := report.Factors[0]; f.Status != attestation.Skip || f.Detail != got.NoReceiptCheck {
		t.Errorf("aci_receipt_verified = %+v", f)
	}
}
