package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/config"
)

// GET /v1/tee/report before any report is published matches its route; the
// handler's own 404 response is not an unmatched route. A path with no route
// still logs the unmatched route warning.
func TestReportEndpointNotFoundIsNotUnmatchedRoute(t *testing.T) {
	server, err := New(&config.Config{Offline: true, Providers: map[string]*config.Provider{
		"venice": {Name: "venice", BaseURL: "https://venice.test", APIKey: "test-key"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	for _, tc := range []struct {
		name, path, body string
		unmatched        bool
	}{
		{"report before publication", "/v1/tee/report?provider=venice&model=model", "no cached report", false},
		{"unknown path", "/v1/no-such-endpoint", "404 page not found", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			logs := captureSlog(t, func() {
				server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, http.NoBody))
			})
			if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), tc.body) {
				t.Fatalf("response %d %q, want 404 with %q", rec.Code, rec.Body.String(), tc.body)
			}
			if got := strings.Contains(logs, "unmatched route"); got != tc.unmatched {
				t.Fatalf("unmatched route logged = %v, want %v:\n%s", got, tc.unmatched, logs)
			}
		})
	}
}
