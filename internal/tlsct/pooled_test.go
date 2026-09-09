package tlsct

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestPooledTransportHandshakeBudgets(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, tc := range []struct {
			name      string
			budget    time.Duration
			wantError bool
		}{
			{"stalled", 10 * time.Millisecond, true},
			{"slow_success", time.Second, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ts := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				}))
				handshakeConfig := ts.TLS.Clone()
				ts.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
					time.Sleep(50 * time.Millisecond)
					return handshakeConfig, nil
				}
				base := newPooledTransport(time.Second, tc.budget)
				base.MaxConnsPerHost = 1
				client := NewHTTPClientWithTransport(time.Second, base, true)
				defer base.CloseIdleConnections()
				for range 2 {
					resp, err := client.Get(ts.URL)
					if resp != nil {
						resp.Body.Close()
					}
					if (err != nil) != tc.wantError {
						t.Fatalf("handshake error = %v", err)
					}
					if errors.Is(err, context.DeadlineExceeded) {
						t.Fatal("handshake did not release its connection slot within its budget")
					}
				}
			})
		}
	})
}

func TestPooledTransportHTTP2(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		ts := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 2 {
				t.Error("HTTP/2 was not negotiated")
			}
			if r.Header.Get("Connection") != "" {
				t.Error("unexpected Connection header")
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		base := NewPooledTransport()
		if base.MaxConnsPerHost != 16 || base.TLSHandshakeTimeout != 5*time.Minute || base.DialContext == nil {
			t.Fatal("missing finite transport limits")
		}
		client := NewHTTPClientWithTransport(5*time.Second, base, true)
		defer base.CloseIdleConnections()
		resp, err := client.Get(ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	})
}

func TestPooledTransportConnectionWaitCancellation(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		entered := make(chan struct{})
		release := make(chan struct{})
		ts := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer close(release)
		base := NewPooledTransport()
		base.MaxConnsPerHost = 1
		base.ForceAttemptHTTP2 = false
		client := NewHTTPClientWithTransport(5*time.Second, base, true)
		defer base.CloseIdleConnections()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, http.NoBody)
			if err != nil {
				done <- err
				return
			}
			resp, err := client.Do(req)
			if resp != nil {
				resp.Body.Close()
			}
			done <- err
		}()
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		waitCtx, stop := context.WithTimeout(ctx, 25*time.Millisecond)
		defer stop()
		req, err := http.NewRequestWithContext(waitCtx, http.MethodGet, ts.URL, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("waiting request: %v", err)
		}
		cancel()
		<-done
	})
}

// ProxyFromEnvironment caches configuration, so test it in a fresh process.
func TestPooledTransportProxyEnvironment(t *testing.T) {
	if os.Getenv("TEEP_PROXY_ENV_TEST") != "1" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestPooledTransportProxyEnvironment$")
		for _, entry := range os.Environ() {
			name, _, _ := strings.Cut(entry, "=")
			if !strings.Contains(strings.ToUpper(name), "PROXY") {
				cmd.Env = append(cmd.Env, entry)
			}
		}
		cmd.Env = append(cmd.Env, "TEEP_PROXY_ENV_TEST=1", "HTTPS_PROXY=https://proxy.example:8443", "NO_PROXY=direct.example")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("proxy environment test: %v: %s", err, output)
		}
		return
	}
	transport := NewPooledTransport()
	if transport.Proxy == nil {
		t.Fatal("missing environment proxy selection")
	}
	for _, tc := range []struct{ host, want string }{{"upstream.example", "https://proxy.example:8443"}, {"direct.example", ""}} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+tc.host, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		proxy, err := transport.Proxy(req)
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if proxy != nil {
			got = proxy.String()
		}
		if got != tc.want {
			t.Errorf("%s proxy = %q, want %q", tc.host, got, tc.want)
		}
	}
}
