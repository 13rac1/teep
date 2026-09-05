package neardirect_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestDirectAttestationTransportBinding(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, mode := range []string{"match", "mismatch", "missing", "malformed", "wrong_length", "redirect"} {
			t.Run(mode, func(t *testing.T) {
				var fingerprint string
				ts := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.ProtoMajor != 2 {
						t.Error("attestation did not negotiate HTTP/2")
					}
					if r.URL.Path != "/v1/attestation/report" {
						t.Error("redirect target received request")
					}
					if mode == "redirect" {
						w.Header().Set("Location", "/target")
						w.WriteHeader(http.StatusTemporaryRedirect)
						return
					}
					fp := fingerprint
					switch mode {
					case "mismatch":
						fp = strings.Repeat("ab", 32)
					case "missing":
						fp = ""
					case "malformed":
						fp = strings.Repeat("z", 64)
					case "wrong_length":
						fp = "ab"
					}
					_, _ = fmt.Fprintf(w, `{"model_name":"model","intel_quote":"quote","tls_cert_fingerprint":%q,"request_nonce":%q}`, fp, r.URL.Query().Get("nonce"))
				}))
				fingerprint = serverFingerprint(ts)
				client := tlsct.NewHTTPClientWithTransport(time.Second, tlsct.NewPooledTransport(), true)
				defer client.CloseIdleConnections()
				a := neardirect.NewAttester(ts.URL, "test-key")
				a.SetClient(client)
				raw, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
				if mode != "match" {
					if err == nil || raw != nil {
						t.Fatal("invalid TLS binding returned usable evidence")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				wantAuthority, err := tlsct.HTTPSOriginAuthority(ts.URL)
				if err != nil {
					t.Fatal(err)
				}
				if raw.TransportTLSAuthority != wantAuthority || !tlsct.SPKIFingerprintsEqual(raw.TransportTLSFingerprint, fingerprint) {
					t.Fatal("incorrect direct transport identity")
				}
			})
		}
	})
}
