package neardirect

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestAttesterDiscoveryUsesOwnedClient(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		closed := make(chan struct{})
		var closeOnce sync.Once
		var requests atomic.Int32
		upstream := authority.NewTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"endpoints":[{"domain":"model.completions.near.ai","models":["model"]}]}`))
		}), func(server *httptest.Server) {
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateClosed {
					closeOnce.Do(func() { close(closed) })
				}
			}
		})
		resolver := NewEndpointResolver()
		resolver.endpointsURL = upstream.URL
		attester := NewAttesterWithResolver("https://completions.near.ai", "test", resolver)
		client := tlsct.NewHTTPClient(5 * time.Second)
		defer client.CloseIdleConnections()
		var observed atomic.Int32
		client.Transport = tlsct.WrapCounting(client.Transport, func() { observed.Add(1) }, nil)
		// The injection used by standalone verification must also govern discovery.
		attester.SetClient(client)
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				route, err := attester.ResolveRoute(t.Context(), "model")
				if err != nil {
					t.Error(err)
					return
				}
				if route.Authority() != "model.completions.near.ai" {
					t.Error("unexpected discovered authority")
				}
			})
		}
		wg.Wait()
		if requests.Load() != 1 || observed.Load() != 1 {
			t.Fatalf("discovery requests=%d observed=%d, want one request through the injected client", requests.Load(), observed.Load())
		}
		// This is the cleanup performed by verify.Run for its owned client.
		client.CloseIdleConnections()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Fatal("owner cleanup did not close the discovery connection")
		}
	})
}
