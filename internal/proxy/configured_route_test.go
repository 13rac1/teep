package proxy

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/tlsct"
)

type unexpectedRouteIO struct{ calls atomic.Int32 }

func (r *unexpectedRouteIO) RoundTrip(req *http.Request) (*http.Response, error) {
	r.calls.Add(1)
	if req.Body != nil {
		req.Body.Close()
	}
	return nil, errors.New("fixed backend must not perform discovery")
}

func TestNearDirectConfiguredRouteParity(t *testing.T) {
	const origin = "https://selected.completions.near.ai:8443"
	server, err := New(&config.Config{Providers: map[string]*config.Provider{
		"neardirect": {Name: "neardirect", BaseURL: origin, APIKey: "test", E2EE: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	prov := server.providers["neardirect"]
	attester, ok := prov.Attester.(*neardirect.Attester)
	if !ok {
		t.Fatal("missing NEAR direct attester")
	}
	observed := &unexpectedRouteIO{}
	client := tlsct.NewHTTPClient(time.Second)
	client.Transport = observed
	attester.SetClient(client)
	var wg sync.WaitGroup
	for _, model := range []string{"one", "two"} {
		for range 8 {
			wg.Go(func() {
				route, key, err := resolveRequestRoute(t.Context(), prov, model)
				if err != nil {
					t.Error(err)
					return
				}
				standalone, err := attester.ResolveRoute(t.Context(), model)
				if err != nil {
					t.Error(err)
					return
				}
				if route != standalone || route.BaseURL() != origin || key.Model() != model || key.Authority() != route.Authority() {
					t.Error("serve and verify did not retain the configured backend and model")
				}
			})
		}
	}
	wg.Wait()
	// Resolving a fixed origin is local even if a caller has already canceled.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := resolveRequestRoute(ctx, prov, "uncatalogued"); err != nil {
		t.Error(err)
	}
	if observed.calls.Load() != 0 {
		t.Fatalf("discovery requests=%d, want zero", observed.calls.Load())
	}
	if prov.BaseURL != origin {
		t.Fatal("concurrent routing changed the configured origin")
	}
}
