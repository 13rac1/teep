package tlsct

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestReservedBudgetAcrossHTTPSProxyOrigins(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		originA := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 2 {
				t.Error("origin did not negotiate HTTP/2")
			}
			_, _ = io.WriteString(w, "ok")
		}))
		originB := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 2 {
				t.Error("origin did not negotiate HTTP/2")
			}
			_, _ = io.WriteString(w, "ok")
		}))
		var connects atomic.Int64
		handlers := map[string]http.Handler{
			originA.Listener.Addr().String(): connectProxyHandler(t, originA.Listener.Addr().String(), &connects),
			originB.Listener.Addr().String(): connectProxyHandler(t, originB.Listener.Addr().String(), &connects),
		}
		proxy := authority.NewTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler := handlers[r.Host]
			if handler == nil {
				t.Error("unexpected proxy destination")
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			handler.ServeHTTP(w, r)
		}), func(server *httptest.Server) {
			server.EnableHTTP2 = false
			server.TLS.NextProtos = []string{"http/1.1"}
		})
		budget := NewAttestationSocketBudget(2)
		clientFor := func(view *SocketBudget) *http.Client {
			transport := NewPooledTransportWithBudget(view)
			transport.Proxy = http.ProxyURL(proxyTestURL(t, proxy.URL))
			client := NewHTTPClientWithTransport(5*time.Second, transport, true)
			t.Cleanup(client.CloseIdleConnections)
			return client
		}
		pooled, other, fresh, excess := clientFor(budget), clientFor(budget), clientFor(budget.Fresh()), clientFor(budget.Fresh())
		request := func(client *http.Client, endpoint string) error {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint, http.NoBody)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			_, err = io.Copy(io.Discard, resp.Body)
			return err
		}
		if err := request(pooled, originA.URL); err != nil {
			t.Fatal(err)
		}
		if err := request(other, originB.URL); !errors.Is(err, ErrConnectionCapacity) {
			t.Fatalf("pooled origins did not share proxy-address limit: %v", err)
		}
		if err := request(fresh, originB.URL); err != nil {
			t.Fatalf("fresh proxy slot unavailable: %v", err)
		}
		if err := request(excess, originA.URL); !errors.Is(err, ErrConnectionCapacity) {
			t.Fatalf("fresh factory bypassed aggregate proxy limit: %v", err)
		}
		fresh.CloseIdleConnections()
		if err := request(pooled, originA.URL); err != nil {
			t.Fatal(err)
		}
		if connects.Load() != 2 {
			t.Fatal("fresh cleanup replaced another pool's tunnel")
		}
		if err := request(excess, originB.URL); err != nil {
			t.Fatalf("closed fresh tunnel retained permit: %v", err)
		}
	})
}
