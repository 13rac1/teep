package tinfoil_test

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/tinfoil"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/verify/testdata"
	"github.com/google/go-sev-guest/verify/trust"
)

func TestTinfoilKDS(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, mode := range []string{"valid", "report_signature", "certificate_signature", "unavailable", "redirect", "oversized", "tls12"} {
			t.Run(mode, func(t *testing.T) {
				raw, cert := append([]byte(nil), testdata.AttestationBytes...), append([]byte(nil), testdata.VcekBytes...)
				if mode == "report_signature" {
					raw[0x2a0] ^= 1
				}
				if mode == "certificate_signature" {
					cert[len(cert)-1] ^= 1
				}
				parsed, err := sevabi.ReportToProto(raw)
				if err != nil {
					t.Fatal(err)
				}
				target := kds.VCEKCertURL("Milan", parsed.GetChipId(), kds.TCBVersion(parsed.GetReportedTcb()))
				var calls atomic.Int32
				server := authority.NewTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.TLS.Version != tls.VersionTLS13 || r.ProtoMajor != 2 {
						t.Error("KDS requires TLS 1.3 and HTTP/2 negotiation")
					}
					if "https://kdsintf.amd.com"+r.URL.RequestURI() != target {
						t.Error("KDS changed the requested certificate")
					}
					switch mode {
					case "unavailable":
						w.WriteHeader(http.StatusServiceUnavailable)
					case "redirect":
						http.Redirect(w, r, "https://kdsintf.amd.com/", http.StatusFound)
					case "oversized":
						_, _ = w.Write([]byte(strings.Repeat("x", (256<<10)+1)))
					default:
						_, _ = w.Write(cert)
					}
				}), func(server *httptest.Server) {
					if mode == "tls12" {
						server.TLS.MinVersion = tls.VersionTLS12
						server.TLS.MaxVersion = tls.VersionTLS12
					}
				})
				client := tlsct.NewHTTPClient(30*time.Second, true)
				defer client.CloseIdleConnections()
				local, err := url.Parse(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				client.Transport = &kdsTestTransport{t: t, base: client.Transport, local: local}

				getter := tinfoil.NewSEVCertGetter(client)
				var wg sync.WaitGroup
				for range 8 {
					wg.Go(func() {
						result := attestation.VerifySEVReportOnline(t.Context(), raw, getter)
						if mode == "valid" {
							if !result.OnlineVerified || result.CertChainErr != nil || result.SignatureErr != nil {
								t.Errorf("verified=%v chain=%v signature=%v", result.OnlineVerified, result.CertChainErr, result.SignatureErr)
							}
						} else if result.OnlineVerified || (result.CertChainErr == nil && result.SignatureErr == nil) {
							t.Error("invalid evidence accepted")
						}
					})
				}
				wg.Wait()
				wantCalls := int32(8)
				if mode == "tls12" {
					wantCalls = 0
				}
				if calls.Load() != wantCalls {
					t.Errorf("certificate requests=%d; want %d with no chain download or source fallback", calls.Load(), wantCalls)
				}
			})
		}
	})
}

func TestTinfoilKDSEmbeddedChains(t *testing.T) {
	getter := tinfoil.NewSEVCertGetter(nil) // Embedded chains must not require a client.
	for _, product := range []string{"Milan", "Genoa", "Turin"} {
		target := "https://kdsintf.amd.com/vcek/v1/" + product + "/cert_chain"
		a, err := getter.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		b, err := getter.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		a[0] ^= 1
		if subtle.ConstantTimeCompare(a, b) == 1 {
			t.Fatal("embedded chain aliases returned storage")
		}
	}
	for _, target := range []string{
		"https://other.example/vcek/v1/Genoa/cert_chain",
		"https://user@kdsintf.amd.com/vcek/v1/Genoa/cert_chain",
		"https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain?unexpected=1",
		"https://kdsintf.amd.com/vcek/v1/Unknown/cert_chain",
		"https://kdsintf.amd.com/vlek/v1/Genoa/cert_chain",
		"https://kdsintf.amd.com/vcek/v1/Genoa/invalid",
	} {
		if _, err := getter.Get(target); err == nil {
			t.Errorf("accepted unsupported URL %s", target)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := trust.GetWith(ctx, getter, "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain"); err == nil {
		t.Error("ignored cancellation")
	}
}

// Only the network destination changes; TLS and certificate verification use
// the production client and the isolated local system trust root.
type kdsTestTransport struct {
	t     *testing.T
	base  http.RoundTripper
	local *url.URL
}

func (tr *kdsTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "kds-proxy.tinfoil.sh" {
		tr.t.Errorf("unexpected KDS destination %s", req.URL.Host)
	}
	clone := req.Clone(req.Context())
	clone.URL.Host = tr.local.Host
	return tr.base.RoundTrip(clone)
}
func (tr *kdsTestTransport) CloseIdleConnections() {
	if c, ok := tr.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
