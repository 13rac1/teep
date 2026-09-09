package tlsct

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestPinnedHTTP1SequentialReuse(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		var connections atomic.Int32
		upstream := authority.NewTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 1 || r.TLS.Version != tls.VersionTLS13 || r.Header.Get("Connection") != "" {
				t.Error("unexpected HTTP/1.1 TLS request")
			}
			_, _ = io.WriteString(w, "ok")
		}), func(ts *httptest.Server) {
			ts.EnableHTTP2 = false
			ts.TLS.NextProtos = []string{"http/1.1"}
			ts.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context { connections.Add(1); return ctx }
		})
		defer upstream.Close()
		client, err := NewSPKIPinnedHTTPClientWithTransport(5*time.Second, NewPooledTransport(), pinnedTestIdentity(t, upstream.URL, certificateSPKI(t, upstream)), true)
		if err != nil {
			t.Fatal(err)
		}
		defer client.CloseIdleConnections()
		for range 3 {
			response, err := client.Get(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		if connections.Load() != 1 {
			t.Fatalf("connections=%d", connections.Load())
		}
	})
}

func TestHTTP2ClosingStreamPreservesOtherStream(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		closed := make(chan struct{})
		release := make(chan struct{})
		var connections atomic.Int32
		upstream := authority.NewTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 2 {
				t.Error("HTTP/2 not negotiated")
			}
			_, _ = io.WriteString(w, "start\n")
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Error(err)
				return
			}
			if r.URL.Path == "/cancel" {
				<-r.Context().Done()
				close(closed)
				return
			}
			select {
			case <-release:
				_, _ = io.WriteString(w, "finish\n")
			case <-r.Context().Done():
				t.Error("closing another stream canceled this request")
			}
		}), func(ts *httptest.Server) {
			ts.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context { connections.Add(1); return ctx }
		})
		defer upstream.Close()
		client, err := NewSPKIPinnedHTTPClientWithTransport(5*time.Second, NewPooledTransport(), pinnedTestIdentity(t, upstream.URL, certificateSPKI(t, upstream)), true)
		if err != nil {
			t.Fatal(err)
		}
		defer client.CloseIdleConnections()
		first, err := client.Get(upstream.URL + "/cancel")
		if err != nil {
			t.Fatal(err)
		}
		defer first.Body.Close()
		second, err := client.Get(upstream.URL + "/continue")
		if err != nil {
			t.Fatal(err)
		}
		defer second.Body.Close()
		first.Body.Close()
		select {
		case <-closed:
		case <-time.After(3 * time.Second):
			t.Fatal("closed stream did not cancel its handler")
		}
		close(release)
		body, err := io.ReadAll(io.LimitReader(second.Body, 1024))
		if err != nil || !strings.Contains(string(body), "finish") {
			t.Fatalf("remaining stream failed: %v", err)
		}
		if connections.Load() != 1 {
			t.Fatalf("streams used %d connections", connections.Load())
		}
	})
}
