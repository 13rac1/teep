package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestRouteFailuresLogDiscoveryDiagnostics(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, _ *testtls.Authority) {
		t.Helper()
		server, err := New(&config.Config{Providers: map[string]*config.Provider{
			"neardirect": {Name: "neardirect", BaseURL: "https://a.near.ai", APIKey: "test", E2EE: true},
		}})
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		const diagnostic = "endpoint discovery fields: unknown [unexpected_field], missing [endpoints]"
		server.providers["neardirect"].ResolveRoute = func(context.Context, string) (provider.ResolvedRoute, error) {
			return provider.ResolvedRoute{}, errors.New("endpoint discovery: " + diagnostic)
		}
		for _, request := range []*http.Request{
			httptest.NewRequest(http.MethodPost, "https://proxy.test/v1/chat/completions", strings.NewReader(`{"model":"neardirect:model","messages":[{"role":"user","content":"test"}]}`)),
		} {
			recorder := httptest.NewRecorder()
			logs := captureSlogWithLevel(t, slog.LevelWarn, func() { server.ServeHTTP(recorder, request) })
			if recorder.Code != http.StatusBadGateway {
				t.Fatalf("%s status=%d, want 502", request.URL.Path, recorder.Code)
			}
			for _, want := range []string{"level=WARN", "provider=neardirect", "model=model", diagnostic} {
				if !strings.Contains(logs, want) {
					t.Fatalf("%s log missing %q: %s", request.URL.Path, want, logs)
				}
			}
		}
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://proxy.test/v1/tee/report?provider=neardirect&model=model", http.NoBody)
		logs := captureSlogWithLevel(t, slog.LevelWarn, func() { server.ServeHTTP(recorder, request) })
		if recorder.Code != http.StatusNotFound || strings.Contains(logs, diagnostic) {
			t.Fatalf("report lookup performed discovery: status=%d", recorder.Code)
		}
	})
}
