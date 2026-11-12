package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// uncheckedPlaintext is the content an upstream sends in plaintext with a
// 2xx status other than 200. It must never reach the client of an E2EE
// request.
const uncheckedPlaintext = "PLAINTEXT-FROM-UPSTREAM"

// uncheckedSuccessUpstream answers every request with status and a plaintext
// body in the shape of a normal answer: an SSE stream when the request asks
// for one, otherwise a chat completion.
func uncheckedSuccessUpstream(status int, requests *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if strings.Contains(string(body), `"stream":true`) || strings.Contains(r.Header.Get("Accept"), "event-stream") {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":%q}}]}\n\ndata: [DONE]\n\n", uncheckedPlaintext)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}]}`, uncheckedPlaintext)
	})
}

// A TLS-binding provider with E2EE refuses a 2xx response other than 200
// before anything is relayed, ends the authorization generation, and does
// not send the request again.
func TestAuthorizedRefusesUncheckedSuccess(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, name := range []string{"tinfoil_v3_cloud", "nearcloud", "neardirect"} {
			for _, status := range []int{http.StatusCreated, http.StatusNonAuthoritativeInfo, http.StatusPartialContent} {
				for _, stream := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%d/stream=%v", name, status, stream), func(t *testing.T) {
						var requests atomic.Int32
						upstream, fp := newTLSBindingTestServerWithHandler(t, authority, uncheckedSuccessUpstream(status, &requests))
						var server *Server
						var input *authorizedRequest
						if name == "tinfoil_v3_cloud" {
							server, input, _ = authorizedFailureFixture(t, upstream, authorizedTestKey(t))
						} else {
							server, input, _ = nearCompletionAuthorization(t, name, upstream.URL, fp)
						}
						request := *input
						request.stream = stream
						rec := newInferenceRecorder()
						out := server.handleAuthorizedEndpoint(t.Context(), rec, &request)
						if strings.Contains(rec.Body.String(), uncheckedPlaintext) {
							t.Fatalf("plaintext reached the client: %q", rec.Body.String())
						}
						if rec.Code == status || out.status == "ok" {
							t.Errorf("client status=%d outcome=%q; want the request refused", rec.Code, out.status)
						}
						if _, ok := server.authorizations.acquire(input.key); ok {
							t.Error("the authorization generation was not ended")
						}
						if requests.Load() != 1 {
							t.Errorf("upstream requests=%d, want 1", requests.Load())
						}
					})
				}
			}
		}
	})
}

// Without E2EE no response is decrypted, and a 2xx response other than 200
// is relayed as before, as an upstream failure; the authorization stays.
func TestAuthorizedUncheckedSuccessWithoutE2EE(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		var requests atomic.Int32
		upstream, fp := newTLSBindingTestServerWithHandler(t, authority, uncheckedSuccessUpstream(http.StatusCreated, &requests))
		server, input, first := nearCompletionAuthorization(t, "neardirect", upstream.URL, fp)
		prov := *input.provider
		prov.E2EE = false
		input.provider = &prov
		rec := newInferenceRecorder()
		out := server.handleAuthorizedEndpoint(t.Context(), rec, input)
		if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), uncheckedPlaintext) || out.status == "ok" {
			t.Fatalf("client status=%d outcome=%q body=%q; want the response relayed as a failure", rec.Code, out.status, rec.Body.String())
		}
		if current, ok := server.authorizations.acquire(input.key); !ok || current.generation != first.generation {
			t.Error("the authorization changed")
		}
	})
}

// A report-cache provider with E2EE (Venice) refuses a 2xx response other
// than 200 before anything is relayed, and ends the publication as a
// decryption failure does: the report and the key are removed and the
// failure is recorded.
func TestRelayRefusesUncheckedSuccess(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, status := range []int{http.StatusCreated, http.StatusNonAuthoritativeInfo, http.StatusPartialContent} {
			for _, stream := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/stream=%v", status, stream), func(t *testing.T) {
					var requests atomic.Int32
					s, prov := newPublicationTestServer(t, authority, keyAttester{newVeniceSigningKey(t)}, uncheckedSuccessUpstream(status, &requests))
					bindTestEvidence(s, prov)
					key := providerModelKey{prov.Name, "model"}
					publishTestReport(s, key, bindingReport())
					body := strings.Replace(publicationTestBody, `"model":"model"`, `"model":"venice:model"`, 1)
					if !stream {
						body = strings.Replace(body, `"stream":true`, `"stream":false`, 1)
					}
					w := httptest.NewRecorder()
					req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
					req.Header.Set("Content-Type", "application/json")
					s.ServeHTTP(w, req)
					if strings.Contains(w.Body.String(), uncheckedPlaintext) {
						t.Fatalf("plaintext reached the client: %q", w.Body.String())
					}
					if w.Code != http.StatusBadGateway {
						t.Errorf("client status=%d, want 502", w.Code)
					}
					if _, ok := s.cache.Get(key.provider, key.model); ok {
						t.Error("the report is still cached")
					}
					if _, ok := s.signingKeyCache.Get(key.provider, key.model); ok {
						t.Error("the key is still cached")
					}
					if _, failed := s.e2eeFailed.Load(key); !failed {
						t.Error("the failure was not recorded")
					}
					if requests.Load() != 1 {
						t.Errorf("upstream requests=%d, want 1", requests.Load())
					}
				})
			}
		}
	})
}
