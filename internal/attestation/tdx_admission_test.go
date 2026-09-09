package attestation

import (
	"strings"
	"testing"
	"time"
)

func TestTDXAdmissionChecksCertificateTime(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   time.Time
		pass bool
	}{
		{"valid", time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC), true},
		{"expired", time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := VerifyTDXQuoteOffline(t.Context(), realTDXQuoteHex(), tc.at)
			if result.ParseErr != nil {
				t.Fatal(result.ParseErr)
			}
			if tc.pass {
				if result.CertChainErr != nil || result.SignatureErr != nil {
					t.Fatalf("valid quote rejected: chain=%v signature=%v", result.CertChainErr, result.SignatureErr)
				}
			} else if result.CertChainErr == nil || result.SignatureErr == nil || !strings.Contains(result.CertChainErr.Error(), "expired") {
				t.Fatalf("expired certificate did not fail admission: chain=%v signature=%v", result.CertChainErr, result.SignatureErr)
			}
		})
	}
}
