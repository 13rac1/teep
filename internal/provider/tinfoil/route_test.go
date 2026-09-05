package tinfoil

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDirectRouteSnapshot(t *testing.T) {
	for _, promptKey := range []string{"", "sticky-key"} {
		r := NewDirectResolver("test-key")
		r.fetchedAt = time.Now()
		r.mapping["model"] = ModelMapping{Domain: "a1.tinfoil.sh", Domains: []string{"a1.tinfoil.sh", "a2.tinfoil.sh"}, Repo: "repo/a"}
		ctx := WithPromptCacheKey(context.Background(), promptKey)
		route, err := r.ResolveRoute(ctx, "model")
		if err != nil {
			t.Fatal(err)
		}
		oldKey, err := route.AuthorizationKey("tinfoil_v3_direct", "model")
		if err != nil {
			t.Fatal(err)
		}
		mapping, err := r.ResolveMapping(ctx, "model")
		if err != nil {
			t.Fatal(err)
		}
		mapping.Domains[0] = "changed.example.com"
		current, err := r.ResolveRoute(ctx, "model")
		if err != nil || current != route {
			t.Fatal("returned mapping changed cached route")
		}
		r.mu.Lock()
		updated := r.mapping["model"]
		updated.Repo = "repo/updated"
		r.mapping["model"] = updated
		r.mu.Unlock()
		current, err = r.ResolveRoute(ctx, "model")
		if err != nil {
			t.Fatal(err)
		}
		newKey, err := current.AuthorizationKey("tinfoil_v3_direct", "model")
		if err != nil {
			t.Fatal(err)
		}
		if newKey != oldKey || route.SupplyChainRepo() != "repo/a" {
			t.Fatal("repository change altered old authorization identity or snapshot")
		}
	}
}

func TestDirectConcurrentRouteSnapshots(t *testing.T) {
	r := NewDirectResolver("test-key")
	r.fetchedAt = time.Now()
	r.mapping["model"] = ModelMapping{Domain: "a.tinfoil.sh", Repo: "repo/a"}
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			for range 32 {
				label := "a"
				if i%2 != 0 {
					label = "b"
				}
				r.mu.Lock()
				r.mapping["model"] = ModelMapping{Domain: label + ".tinfoil.sh", Repo: "repo/" + label}
				r.mu.Unlock()
				route, err := r.ResolveRoute(context.Background(), "model")
				if err != nil {
					t.Error(err)
					return
				}
				if route.SupplyChainRepo() != "repo/"+strings.TrimSuffix(route.Authority(), ".tinfoil.sh") {
					t.Error("route mixed two discovery snapshots")
				}
			}
		})
	}
	wg.Wait()
}

func TestDirectAttesterUsesResolvedRoute(t *testing.T) {
	for _, repository := range []string{"repo/custom", ""} {
		t.Run(repository, func(t *testing.T) {
			body, nonce, cert := makeServedDocument(t)
			server := serveDocument(t, body, cert, func(r *http.Request) {
				if r.URL.Path != attestationPath {
					t.Error("unexpected attestation path")
				}
			})
			origin, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			resolver := NewDirectResolver("key", true)
			resolver.fetchedAt = time.Now()
			resolver.mapping["gemma4-31b"] = ModelMapping{Domain: origin.Host, Repo: repository}
			attester := NewDirectAttester(resolver, "key", true)
			attester.SetClient(server.Client())
			route, err := resolver.ResolveRoute(t.Context(), "gemma4-31b")
			if err != nil {
				t.Fatal(err)
			}
			raw, err := attester.FetchAttestation(t.Context(), "gemma4-31b", nonce)
			if err != nil {
				t.Fatal(err)
			}
			if raw.TinfoilRepo != route.SupplyChainRepo() || raw.TransportTLSAuthority != route.Authority() {
				t.Fatal("attester differs from resolved route")
			}
		})
	}
}
