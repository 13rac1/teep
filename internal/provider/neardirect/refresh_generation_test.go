package neardirect

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestDiscoveryDelayedRefresh(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		var calls atomic.Int32
		upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			_, _ = w.Write([]byte(`{"endpoints":[{"domain":"a.near.ai","models":["known"]}]}`))
		}))
		defer upstream.Close()
		resolver := newEndpointResolverForTest(upstream.URL)
		defer resolver.client.CloseIdleConnections()
		if _, err := resolver.Resolve(t.Context(), "known"); err != nil {
			t.Fatal(err)
		}
		// Delayed metadata callers must reuse a still-fresh publication.
		// Include unknown-model callers: a completed refresh already answered them.
		var wg sync.WaitGroup
		for range 32 {
			wg.Go(func() {
				if _, err := resolver.Resolve(t.Context(), "known"); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if calls.Load() != 1 {
			t.Fatalf("redundant discovery requests: %d", calls.Load())
		}
		resolver.mu.Lock()
		resolver.endpoints.snapshot.fetchedAt = time.Now().Add(-10 * time.Minute)
		resolver.mu.Unlock()
		if _, err := resolver.Resolve(t.Context(), "known"); err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 2 {
			t.Fatal("stale replacement mapping was reused")
		}
	})
}
