package proxy

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/tlsct/testtls"
	sevtrust "github.com/google/go-sev-guest/verify/trust"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"
)

func collateralTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(&config.Config{Offline: true, Providers: map[string]*config.Provider{
		"nearcloud": {Name: "nearcloud", BaseURL: "https://cloud-api.near.ai", E2EE: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func fetchTestCollateral(ctx context.Context, client *http.Client, kind, origin string) ([]byte, error) {
	if kind == "SEV" {
		return sevtrust.GetWith(ctx, attestation.NewSEVCertGetter(client), origin)
	}
	_, body, err := tdxtrust.GetWith(ctx, attestation.NewCollateralGetter(client), origin)
	return body, err
}

func TestAuthorizationCollateralRetryPolicy(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, kind := range []string{"TDX", "SEV"} {
			for _, mode := range []string{"serve", "verify"} {
				t.Run(kind+"/"+mode, func(t *testing.T) {
					var calls atomic.Int32
					upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						if calls.Add(1) == 1 {
							w.WriteHeader(http.StatusServiceUnavailable)
							return
						}
						_, _ = w.Write([]byte("collateral"))
					}))
					var client *http.Client
					if mode == "serve" {
						client = collateralTestServer(t).attestClient
					} else {
						client = config.NewAttestationClient(true)
						t.Cleanup(client.CloseIdleConnections)
					}
					body, err := fetchTestCollateral(t.Context(), client, kind, upstream.URL)
					if err != nil || string(body) != "collateral" || calls.Load() != 2 {
						t.Fatalf("transient collateral failure: calls=%d err=%v", calls.Load(), err)
					}
				})
			}
		}
	})
}

type failedCollateralAttester struct {
	client *http.Client
	kind   string
	origin string
	calls  atomic.Int32
}

func (a *failedCollateralAttester) FetchAttestation(ctx context.Context, _ string, _ attestation.Nonce) (*attestation.RawAttestation, error) {
	a.calls.Add(1)
	_, err := fetchTestCollateral(ctx, a.client, a.kind, a.origin)
	if err == nil {
		err = errors.New("failure fixture unexpectedly returned collateral")
	}
	return nil, err
}

func TestAuthorizationNegativeCacheAfterCollateralRetries(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, kind := range []string{"TDX", "SEV"} {
			t.Run(kind, func(t *testing.T) {
				s := collateralTestServer(t)
				prov := s.providers["nearcloud"]
				route, key, err := resolveRequestRoute(t.Context(), prov, "model")
				if err != nil {
					t.Fatal(err)
				}
				var requests atomic.Int32
				upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					requests.Add(1)
					if _, blocked := s.negCache.ActiveInfo(prov.Name, key.EvidenceScope().SingleflightKey()); blocked {
						t.Error("negative cache published before collateral retries finished")
					}
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
				// This negative test stops at failed retrieval; it does not replace
				// cryptographic verification with a successful mock.
				fetch := &failedCollateralAttester{client: s.attestClient, kind: kind, origin: upstream.URL}
				prov.Attester = fetch
				var wg sync.WaitGroup
				for range 8 {
					wg.Go(func() {
						value, _, err := s.loadAuthorization(t.Context(), prov, route, key)
						if value != nil || err == nil {
							t.Error("failed collateral authorized inference")
						}
					})
				}
				wg.Wait()
				if requests.Load() != 3 || fetch.calls.Load() != 1 {
					t.Fatalf("collateral requests=%d attestation runs=%d; want 3 and 1", requests.Load(), fetch.calls.Load())
				}
				if _, blocked := s.negCache.ActiveInfo(prov.Name, key.EvidenceScope().SingleflightKey()); !blocked {
					t.Fatal("exhausted collateral failure was not negatively cached")
				}
			})
		}
	})
}
