package proxy

import (
	"encoding/hex"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestAuthorizedDuplicateRejectionRetainsAuthorization(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		private := authorizedTestKey(t)
		var requests atomic.Int32
		upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			encap, err := hex.DecodeString(r.Header.Get("Ehbp-Encapsulated-Key"))
			if err != nil {
				t.Error(err)
				return
			}
			_ = decryptAuthorizedTestRequest(t, private, encap, io.LimitReader(r.Body, 1<<20))
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = io.WriteString(w, `{"type":"other","type":"urn:ietf:params:ehbp:error:key-config"}`)
		}))
		server, input, first := authorizedFailureFixture(t, upstream, private)
		const clients = 8
		var wg sync.WaitGroup
		for range clients {
			wg.Go(func() {
				writer := newInferenceRecorder()
				outcome := server.handleAuthorizedEndpoint(t.Context(), writer, input)
				if writer.Code != http.StatusBadGateway || outcome.status != "upstream_failed" {
					t.Error("ambiguous rejection did not fail the original attempt")
				}
			})
		}
		wg.Wait()
		if requests.Load() != clients {
			t.Fatalf("requests=%d; want %d without replay", requests.Load(), clients)
		}
		current, ok := server.authorizations.acquire(input.key)
		if !ok || current.generation != first.generation {
			t.Fatal("ambiguous rejection invalidated shared authorization")
		}
	})
}
