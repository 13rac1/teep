package tinfoil

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
			_, _ = w.Write([]byte(proxyResponseJSON("known")))
		}))
		defer upstream.Close()
		resolver := newDirectResolverForTest(upstream.URL)
		defer resolver.client.CloseIdleConnections()
		observed := resolver.fetchedAt
		if _, err := resolver.Resolve(t.Context(), "known"); err != nil {
			t.Fatal(err)
		}
		// Reproduce callers delayed between their initial read and singleflight.
		// Include unknown-model callers: a completed refresh already answered them.
		var wg sync.WaitGroup
		for range 32 {
			wg.Go(func() {
				if err := resolver.refreshAfter(t.Context(), observed); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if calls.Load() != 1 {
			t.Fatalf("redundant discovery requests: %d", calls.Load())
		}
		resolver.mu.Lock()
		resolver.fetchedAt = time.Now().Add(-10 * time.Minute)
		resolver.mu.Unlock()
		if err := resolver.refreshAfter(t.Context(), observed); err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 2 {
			t.Fatal("stale replacement mapping was reused")
		}
	})
}
