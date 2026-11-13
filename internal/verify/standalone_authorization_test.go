package verify

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
)

// A recorded inference success cannot authorize a key that the attestation
// does not bind. NEAR Cloud, and either NEAR provider with E2EE, needs a
// passed REPORTDATA binding; a TLS-only NEAR direct request does not use the
// model key. When the check fails, the recorded success becomes an enforced
// failure of the probe, and the report blocks.
func TestStandaloneAuthorizationRefusesUnboundKey(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	defer clear(private)
	key := hex.EncodeToString(private.Public().(ed25519.PublicKey))

	for _, tc := range []struct {
		name     string
		provider string
		e2ee     bool
		binding  attestation.Status
		wantErr  bool
	}{
		{"nearcloud TLS-only, binding failed", "nearcloud", false, attestation.Fail, true},
		{"nearcloud TLS-only, binding passed", "nearcloud", false, attestation.Pass, false},
		{"neardirect TLS-only, binding failed", "neardirect", false, attestation.Fail, false},
		{"neardirect E2EE, binding failed", "neardirect", true, attestation.Fail, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := &Options{ProviderName: tc.provider, Provider: &config.Provider{Name: tc.provider, E2EE: tc.e2ee}}
			report := &attestation.VerificationReport{Factors: []attestation.FactorResult{
				{Tier: attestation.TierCore, Name: attestation.FactorTEEReportData, Status: tc.binding},
			}}
			result := &verificationOutcome{
				report:       report,
				raw:          &attestation.RawAttestation{SigningKey: key},
				tlsInference: &attestation.TLSInferenceResult{Attempted: true, Detail: "recorded TLS-only success"},
			}
			err := validateStandaloneAuthorization(opts, result)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateStandaloneAuthorization: err = %v, want error %v", err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "does not authenticate the model key") {
				t.Fatalf("err = %v, want the unbound model key refused", err)
			}
			if !tc.wantErr || tc.e2ee {
				return
			}
			// The TLS-only probe outcome replaces the recorded success.
			if admitStandaloneAuthorization(opts, result) {
				t.Fatal("admitted an unbound model key")
			}
			var probe *attestation.FactorResult
			for i := range report.Factors {
				if report.Factors[i].Name == "tls_inference" {
					probe = &report.Factors[i]
				}
			}
			if probe == nil || probe.Status != attestation.Fail || !probe.Enforced || !report.Blocked() {
				t.Fatalf("tls_inference = %+v, blocked %v; want an enforced failure that blocks", probe, report.Blocked())
			}
		})
	}
}
