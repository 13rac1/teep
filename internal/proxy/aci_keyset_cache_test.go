package proxy

import (
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
)

// For a provider without TLS binding (Venice, NanoGPT), a cached ACI/1
// report and its signing key are usable before the keyset not_after and not
// from it on, so the next request verifies again. A report without a
// keyset is unaffected.
func TestCurrentSigningKeyEndsAtKeysetNotAfter(t *testing.T) {
	for _, tc := range []struct {
		name     string
		format   attestation.BackendFormat
		notAfter int64
		usable   bool
	}{
		{"ACI/1 before not_after", attestation.FormatACI1, time.Now().Add(time.Minute).Unix(), true},
		{"ACI/1 at not_after", attestation.FormatACI1, time.Now().Unix(), false},
		{"ACI/1 without not_after", attestation.FormatACI1, 0, false},
		{"dstack, no keyset", attestation.FormatDstack, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, prov := newReportTestServer(t, &mockAttester{})
			report := bindingReport()
			report.BackendFormat = tc.format
			report.ACIKeysetNotAfter = tc.notAfter
			key := providerModelKey{prov.Name, "model"}
			s.reportMu.Lock()
			s.storeReportLocked(key, report)
			s.reportMu.Unlock()
			s.signingKeyCache.Put(prov.Name, "model", "key")
			if _, ok := s.currentSigningKey(key); ok != tc.usable {
				t.Fatalf("currentSigningKey usable = %v, want %v", ok, tc.usable)
			}
		})
	}
}
