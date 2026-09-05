package tlsct

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct/testtls"
	"golang.org/x/net/http2"
)

func TestHTTP2ConcurrentStreamConnectionBound(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		var connections, requests atomic.Int32
		held := make(chan struct{}, 4)
		release := make(chan struct{})
		server := authority.NewTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 2 {
				t.Error("HTTP/2 not negotiated")
			}
			if r.URL.Path == "/warm" {
				_, _ = io.WriteString(w, "ok")
				return
			}
			requests.Add(1)
			select {
			case held <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}), func(ts *httptest.Server) {
			ts.Config.TLSConfig = ts.TLS
			ts.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context { connections.Add(1); return ctx }
			if err := http2.ConfigureServer(ts.Config, &http2.Server{MaxConcurrentStreams: 2}); err != nil {
				t.Fatal(err)
			}
		})
		defer server.Close()
		fp := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
		transport := NewPooledTransport()
		transport.MaxConnsPerHost = 2
		client, err := NewSPKIPinnedHTTPClientWithTransport(0, transport, pinnedTestIdentity(t, server.URL, hex.EncodeToString(fp[:])), true)
		if err != nil {
			t.Fatal(err)
		}
		defer client.CloseIdleConnections()
		warm, err := client.Get(server.URL + "/warm")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, warm.Body)
		warm.Body.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		request := func(path string) error {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+path, http.NoBody)
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
		var wg sync.WaitGroup
		defer wg.Wait()
		defer cancel()
		for range 4 {
			wg.Go(func() {
				if err := request("/hold"); err != nil {
					t.Errorf("held request: %v", err)
				}
			})
			select {
			case <-held:
			case <-ctx.Done():
				t.Fatal("stream capacity did not fill")
			}
		}
		var excess sync.WaitGroup
		for range 12 {
			excess.Go(func() {
				if err := request("/excess"); !errors.Is(err, ErrConnectionCapacity) {
					t.Errorf("excess request: %v; want capacity error", err)
				}
			})
		}
		excess.Wait()
		if ctx.Err() != nil {
			t.Fatal("overload waited for the caller deadline")
		}
		close(release)
		wg.Wait()
		if err := request("/warm"); err != nil {
			t.Fatalf("pool did not recover: %v", err)
		}
		if connections.Load() != 2 || requests.Load() != 4 {
			t.Fatalf("connections=%d requests=%d; want 2 and 4", connections.Load(), requests.Load())
		}
	})
}
