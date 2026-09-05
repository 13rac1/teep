package proxy

import (
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestAuthorizedTLSOnlyKeyErrorsRetainAuthorization(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, tc := range []struct {
			name, contentType, body string
			status                  int
		}{
			{"tinfoil_v3_cloud", "application/problem+json", `{"type":"urn:ietf:params:ehbp:error:key-config"}`, 422},
			{"tinfoil_v3_direct", "application/problem+json", `{"type":"urn:ietf:params:ehbp:error:key-config"}`, 422},
			{"nearcloud", "application/json", `{"error":{"type":"invalid_request_error","message":"Decryption failed"}}`, 400},
			{"neardirect", "application/json", `{"error":{"type":"bad_request","message":"Decryption failed"}}`, 400},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var requests atomic.Int32
				upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.Header.Get("Ehbp-Encapsulated-Key") != "" || r.Header.Get("X-Client-Pub-Key") != "" {
						t.Error("TLS-only request sent an encryption key")
					}
					if _, err := io.Copy(io.Discard, r.Body); err != nil {
						t.Error(err)
						return
					}
					w.Header().Set("Content-Type", tc.contentType)
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, tc.body)
				}))
				server, input, first := authorizedFailureFixture(t, upstream, authorizedTestKey(t))
				server.authorizations.deleteGeneration(input.key, first.generation)
				input.provider.Name, input.provider.E2EE = tc.name, false
				key, err := input.route.AuthorizationKey(tc.name, input.key.Model())
				if err != nil {
					t.Fatal(err)
				}
				input.key = key
				report := first.report.Clone()
				report.Provider = tc.name
				candidate, err := newAuthorization(key, report, "", false, false, time.Time{}, false, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				value := loadTestAuthorization(t, server.authorizations, key, candidate)
				const clients = 8
				var wg sync.WaitGroup
				for range clients {
					wg.Go(func() {
						writer := newInferenceRecorder()
						out := server.handleAuthorizedEndpoint(t.Context(), writer, input)
						if writer.Code != tc.status || writer.Body.String() != tc.body || out.status != "upstream_failed" {
							t.Error("TLS-only error was not relayed as an ordinary upstream failure")
						}
					})
				}
				wg.Wait()
				current, ok := server.authorizations.acquire(key)
				if !ok || current.generation != value.generation {
					t.Fatal("TLS-only error invalidated authorization")
				}
				if requests.Load() != clients {
					t.Fatalf("upstream requests=%d, want %d without retry", requests.Load(), clients)
				}
			})
		}
	})
}
