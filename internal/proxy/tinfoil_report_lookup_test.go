package proxy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/proxy"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestTinfoilIntegrationReportLookup(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		const name, model = "tinfoil_v3_direct", "org/model"
		s, err := proxy.New(&config.Config{Providers: map[string]*config.Provider{name: {Name: name}}})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		// No inference is sent: this test isolates selection of cached reports.
		routes := make([]provider.ResolvedRoute, 0, 2)
		for _, origin := range []string{"https://default.example", "https://selected.example:8443"} {
			route, err := provider.NewResolvedRoute(origin, "")
			if err != nil {
				t.Fatal(err)
			}
			routes = append(routes, route)
			report := &attestation.VerificationReport{Provider: name, Model: model, TLSAuthority: route.Authority(), TLSKeyFP: strings.Repeat("ab", 32)}
			if err := s.PutAuthorizationForTest(t.Context(), name, model, route, report, ""); err != nil {
				t.Fatal(err)
			}
		}
		calls := 0
		s.ProviderByName(name).ResolveRoute = func(_ context.Context, requested string) (provider.ResolvedRoute, error) {
			calls++
			if requested != model {
				t.Error("report lookup changed the model identifier")
			}
			return routes[0], nil
		}
		server := authority.NewTLSServer(t, s)
		defer server.Close()
		assertTinfoilReportCached(t, server.URL, name, model, "")
		assertTinfoilReportCached(t, server.URL, name, model, routes[1].Authority())
		if calls != 1 {
			t.Fatalf("route resolutions=%d; explicit report lookup must not resolve", calls)
		}
	})
}
