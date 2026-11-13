package verify

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee/aciv2test"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// With a canonical ACI/1 report, the E2EE test fails a response without
// X-ACI-Keyset-Digest, and a response of another digest: ACI/1 §5.2 lets the
// gateway finish it under the new keyset, but its receipt is signed under
// keys that teep has not verified.
func TestTestE2EE_ACIv2ServedKeysetDigest(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		const verified = "sha256:" + "ab"
		for _, tc := range []struct {
			name    string
			served  string
			wantErr string
		}{
			{"verified digest", verified, ""},
			{"other digest", "sha256:cd", "another keyset digest"},
			{"no digest", "", "carries no X-ACI-Keyset-Digest"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				gw := aciv2test.New(t)
				ts := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					body, err := io.ReadAll(req.Body)
					if err != nil {
						t.Error(err)
						return
					}
					r := gw.ReadRequest(req.Header, body)
					w.Header().Set("Content-Type", "text/event-stream")
					if tc.served != "" {
						w.Header().Set("X-Aci-Keyset-Digest", tc.served)
					}
					_, _ = io.WriteString(w, gw.Stream(r, "chatcmpl-1", []string{"Hi"}, true))
				}))
				defer ts.Close()
				raw := &attestation.RawAttestation{
					BackendFormat:           attestation.FormatACI1,
					SigningKey:              gw.PubKeyHex(),
					ACICanonicalReport:      true,
					ACIWorkloadKeysetDigest: verified,
				}
				got := testE2EE(context.Background(), raw, "phalacloud", &config.Provider{APIKey: "key", BaseURL: ts.URL}, "TEE/m", false)
				if got == nil || !got.Attempted {
					t.Fatalf("testE2EE = %+v", got)
				}
				if tc.wantErr == "" {
					if got.Err != nil {
						t.Fatalf("err = %v", got.Err)
					}
					return
				}
				if got.Err == nil || !strings.Contains(got.Err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", got.Err, tc.wantErr)
				}
			})
		}
	})
}
