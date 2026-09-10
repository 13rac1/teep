package tlsct

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestNestedAttestationTransportSharesSocketBudget(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		server := authority.NewTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }), func(server *httptest.Server) {
			server.TLS.MinVersion = tls.VersionTLS12
		})
		endpoint, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		budget := NewSocketBudget(1)
		ordinary := NewHTTPClientWithTransport(time.Second*5, NewPooledTransportWithBudget(budget), true)
		defer ordinary.CloseIdleConnections()
		nested := NewHTTPClientWithTransport(time.Second*5, NewPooledTransportWithBudget(budget), true)
		nested.Transport = NewTLS12FallbackTransportWithBudget(nested.Transport, budget, endpoint.Hostname())
		defer nested.CloseIdleConnections()
		request := func(client *http.Client) error {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			_, err = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return err
		}
		if err := request(ordinary); err != nil {
			t.Fatal(err)
		}
		if err := request(nested); !errors.Is(err, ErrConnectionCapacity) {
			t.Fatalf("nested transport bypassed shared allowance: %v", err)
		}
		ordinary.CloseIdleConnections()
		if err := request(nested); err != nil {
			t.Fatalf("nested transport failed after release: %v", err)
		}
		if err := request(ordinary); !errors.Is(err, ErrConnectionCapacity) {
			t.Fatalf("nested socket was not accounted: %v", err)
		}
		nested.CloseIdleConnections()
		if err := request(ordinary); err != nil {
			t.Fatalf("nested cleanup did not release permit: %v", err)
		}
	})
}
