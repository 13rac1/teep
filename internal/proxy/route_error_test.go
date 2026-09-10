package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearroute"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestRouteErrorResponsesPreserveAuthorization(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		var requests atomic.Int32
		upstream, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
		server, err := New(&config.Config{Providers: map[string]*config.Provider{
			"neardirect": {Name: "neardirect", BaseURL: upstream.URL, APIKey: "test", E2EE: true},
		}})
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		input := tlsAuthorizationInput(t, server, "neardirect", "model", upstream.URL, fp)
		initial, _ := server.authorizations.acquire(input.key)
		for _, tc := range []struct {
			kind           nearroute.ErrorKind
			cause          error
			status         int
			classification string
		}{
			{nearroute.Input, nil, 400, "invalid_model"},
			{nearroute.UnknownModel, nil, 400, "unknown_model"},
			{nearroute.Metadata, nil, 502, "metadata_failed"},
			{nearroute.Capacity, nil, 503, "route_capacity"},
			{nearroute.Delay, nil, 503, "metadata_delay"},
			{nearroute.Expired, nil, 503, "metadata_expired"},
			{nearroute.Configuration, nil, 502, "route_configuration_mismatch"},
			{nearroute.Metadata, fmt.Errorf("wrapped: %w", tlsct.ErrConnectionCapacity), 503, "metadata_socket_capacity"},
			{nearroute.Metadata, context.Canceled, 408, "route_canceled"},
			{nearroute.Metadata, context.DeadlineExceeded, 504, "route_deadline"},
		} {
			t.Run(tc.classification, func(t *testing.T) {
				var resolutions atomic.Int32
				server.providers["neardirect"].ResolveRoute = func(context.Context, string) (provider.ResolvedRoute, error) {
					resolutions.Add(1)
					return provider.ResolvedRoute{}, fmt.Errorf("route: %w", &nearroute.Error{Kind: tc.kind, Detail: "test metadata error", Cause: tc.cause})
				}
				var wg sync.WaitGroup
				for range 8 {
					for _, path := range []string{"/v1/chat/completions", "/explore/attest"} {
						wg.Go(func() {
							body := `{"model":"neardirect:model","messages":[{"role":"user","content":"test"}]}`
							if path == "/explore/attest" {
								body = `{"model":"neardirect:model"}`
							}
							req := httptest.NewRequest(http.MethodPost, "https://proxy.test"+path, strings.NewReader(body))
							recorder := httptest.NewRecorder()
							server.ServeHTTP(recorder, req)
							retryAfter := ""
							if tc.status == 503 {
								retryAfter = "1"
							}
							if recorder.Code != tc.status || strings.TrimSpace(recorder.Body.String()) != tc.classification || recorder.Header().Get("Retry-After") != retryAfter {
								t.Errorf("%s: status=%d body=%q retry=%q", path, recorder.Code, recorder.Body.String(), recorder.Header().Get("Retry-After"))
							}
						})
					}
				}
				wg.Wait()
				current, ok := server.authorizations.acquire(input.key)
				if !ok || current.generation != initial.generation || server.negCache.Len() != 0 {
					t.Fatal("route errors changed authorization or installed cooldown")
				}
				if resolutions.Load() != 16 || requests.Load() != 0 || server.stats.cacheMisses.Load() != 0 {
					t.Fatal("route errors retried, verified, or sent upstream requests")
				}
			})
		}
	})
}
