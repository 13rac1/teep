package proxy

import (
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
)

// publishReport, the Venice and NanoGPT path, refuses a passing ACI/1
// report whose keyset is not usable at publication: the leader request
// encrypts to it without a cache lookup. A blocked report authorizes
// nothing and is stored as before.
func TestPublishReportRefusesExpiredKeyset(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		name     string
		notAfter int64
		blocked  bool
		want     string
	}{
		{"passed", now.Unix(), false, "passed before publication"},
		{"no not_after", 0, false, "has no valid not_after"},
		{"blocked", now.Unix(), true, ""},
		{"usable", now.Unix() + 1, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, prov := newReportTestServer(t, newHeldReportAttester(nil))
			s.authorizations.now = func() time.Time { return now }
			key := providerModelKey{prov.Name, "model"}
			report := &attestation.VerificationReport{BackendFormat: attestation.FormatACI1, ACIKeysetNotAfter: tc.notAfter}
			if tc.blocked {
				report.Factors = []attestation.FactorResult{{Name: attestation.FactorTEEQuotePresent, Status: attestation.Fail, Enforced: true}}
			}
			_, err := s.publishReport(t.Context(), prov, "model", key, s.reportEpoch(key), attestation.AdmissionTime{}, report, &attestation.RawAttestation{})
			_, stored := s.cache.Get(key.provider, key.model)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("err = %v, want %q", err, tc.want)
				}
				if stored {
					t.Fatal("a report with an unusable keyset was published")
				}
				return
			}
			if err != nil {
				t.Fatalf("publishReport: %v", err)
			}
			if !tc.blocked && !stored {
				t.Fatal("a usable report was not published")
			}
		})
	}
}
