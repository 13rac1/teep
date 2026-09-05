package tlsct

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func connectProxyHandler(t *testing.T, target string, connects *atomic.Int64) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != target || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
			t.Error("unexpected CONNECT request or proxy TLS version")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		connects.Add(1)
		upstream, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", target)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer client.Close()
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			t.Error(err)
			return
		}
		if err := buffered.Flush(); err != nil {
			t.Error(err)
			return
		}
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(upstream, buffered)
			_ = upstream.Close()
			close(done)
		}()
		_, _ = io.Copy(client, upstream)
		_ = client.Close()
		<-done
	})
}

func proxyTestURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestPinnedHTTPSProxyConcurrentHTTP2(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		var requests, connects atomic.Int64
		arrived := make(chan struct{})
		origin := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 2 {
				t.Error("origin did not negotiate HTTP/2")
			}
			if n := requests.Add(1); n > 2 {
				if n == 6 {
					close(arrived)
				}
				select {
				case <-arrived:
				case <-r.Context().Done():
					return
				}
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		proxy := authority.NewTLSServer(t, connectProxyHandler(t, origin.Listener.Addr().String(), &connects))
		base := NewPooledTransport()
		base.Proxy = http.ProxyURL(proxyTestURL(t, proxy.URL))
		client, err := NewSPKIPinnedHTTPClientWithTransport(5*time.Second, base, pinnedTestIdentity(t, origin.URL, certificateSPKI(t, origin)))
		if err != nil {
			t.Fatal(err)
		}
		defer client.CloseIdleConnections()
		send := func() {
			resp, err := client.Get(origin.URL)
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Error("unexpected origin status")
			}
		}
		send()
		send()
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(send)
		}
		wg.Wait()
		if connects.Load() != 1 || requests.Load() != 6 {
			t.Fatalf("CONNECTs=%d requests=%d, want 1 and 6", connects.Load(), requests.Load())
		}
	})
}

func TestPinnedHTTPSProxyRejectsTrustFailures(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, failure := range []string{"origin_pin", "proxy_webpki", "proxy_ct", "proxy_tls12"} {
			t.Run(failure, func(t *testing.T) {
				var requests, connects atomic.Int64
				origin := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); w.WriteHeader(http.StatusNoContent) }))
				handler := connectProxyHandler(t, origin.Listener.Addr().String(), &connects)
				var proxy *httptest.Server
				switch failure {
				case "proxy_webpki":
					proxy = httptest.NewTLSServer(handler)
					t.Cleanup(proxy.Close)
				case "proxy_ct":
					proxy = authority.NewTLSServerForHost(t, handler, "proxy.example")
				case "proxy_tls12":
					proxy = authority.NewTLSServerWithConfig(t, handler, func(server *httptest.Server) {
						server.TLS.MinVersion = tls.VersionTLS12
						server.TLS.MaxVersion = tls.VersionTLS12
					})
				default:
					proxy = authority.NewTLSServer(t, handler)
				}
				base := NewPooledTransport()
				selected := proxyTestURL(t, proxy.URL)
				if failure == "proxy_ct" {
					selected.Host = "proxy.example"
					base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, network, proxy.Listener.Addr().String())
					}
				}
				base.Proxy = http.ProxyURL(selected)
				fingerprint := certificateSPKI(t, origin)
				if failure == "origin_pin" {
					fingerprint = hexFingerprint(sha256.Sum256([]byte("wrong pin")))
				}
				client, err := NewSPKIPinnedHTTPClientWithTransport(time.Second, base, pinnedTestIdentity(t, origin.URL, fingerprint))
				if err != nil {
					t.Fatal(err)
				}
				defer client.CloseIdleConnections()
				body := &countingReader{}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, origin.URL, io.NopCloser(body))
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if resp != nil {
					resp.Body.Close()
				}
				if err == nil || requests.Load() != 0 || body.reads.Load() != 0 {
					t.Fatal("trust failure did not prevent origin request transmission")
				}
				if failure == "origin_pin" {
					if !errors.Is(err, ErrSPKIMismatch) || connects.Load() != 1 {
						t.Fatalf("origin pin failure: %v, CONNECTs=%d", err, connects.Load())
					}
				} else if connects.Load() != 0 {
					t.Fatal("CONNECT sent before proxy authentication")
				}
			})
		}
	})
}

func TestPinnedHTTPSProxyHandshakeBudget(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		proxy := authority.NewTLSServerWithConfig(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("CONNECT sent after handshake timeout") }), func(server *httptest.Server) {
			config := server.TLS.Clone()
			server.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { time.Sleep(50 * time.Millisecond); return config, nil }
		})
		base := newPooledTransport(time.Second, 10*time.Millisecond)
		base.MaxConnsPerHost = 1
		base.Proxy = http.ProxyURL(proxyTestURL(t, proxy.URL))
		client, err := NewSPKIPinnedHTTPClientWithTransport(time.Second, base, pinnedTestIdentity(t, "https://origin.example", certificateSPKI(t, proxy)))
		if err != nil {
			t.Fatal(err)
		}
		defer client.CloseIdleConnections()
		for range 2 {
			start := time.Now()
			resp, err := client.Get("https://origin.example")
			if resp != nil {
				resp.Body.Close()
			}
			if err == nil || time.Since(start) >= 500*time.Millisecond {
				t.Fatalf("proxy handshake did not release its slot promptly: %v", err)
			}
		}
	})
}
