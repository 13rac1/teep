package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
	"golang.org/x/net/http2"
)

func TestAuthorizedConnectionCapacityRetainsAuthorization(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		release := make(chan struct{})
		var inference atomic.Int32
		upstream := authority.NewTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/hold" {
				inference.Add(1)
				return
			}
			_, _ = io.WriteString(w, "held")
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Error(err)
				return
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}), func(ts *httptest.Server) {
			ts.Config.TLSConfig = ts.TLS
			if err := http2.ConfigureServer(ts.Config, &http2.Server{MaxConcurrentStreams: 1}); err != nil {
				t.Fatal(err)
			}
		})
		defer close(release)
		server, input, first := authorizedFailureFixture(t, upstream, authorizedTestKey(t))
		client, err := server.pinnedClientForIdentity(input.provider.Name, first.identity)
		if err != nil {
			t.Fatal(err)
		}
		entry := server.pinnedUpstreams.entries[pinnedUpstreamKey{provider: input.provider.Name, authority: input.route.Authority()}]
		entry.transport.MaxConnsPerHost = 1
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream.URL+"/hold", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		held, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Body.Close()
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				rec := newInferenceRecorder()
				server.handleAuthorizedEndpoint(ctx, rec, input)
				if rec.Header().Get("Retry-After") != "1" {
					t.Error("missing overload backoff advice")
				}
				if rec.Code != http.StatusServiceUnavailable {
					t.Errorf("status=%d; want 503", rec.Code)
				}
			})
		}
		wg.Wait()
		if ctx.Err() != nil {
			t.Fatal("capacity error waited for deadline")
		}
		value, ok := server.authorizations.acquire(input.key)
		if !ok || value.generation != first.generation {
			t.Fatal("overload changed authorization")
		}
		if inference.Load() != 0 {
			t.Fatal("overloaded requests reached upstream")
		}
	})
}

func TestLocalCapacityIsNotChutesFailover(t *testing.T) {
	if chutesRetryableError(tlsct.ErrConnectionCapacity, nil) {
		t.Fatal("local capacity permits instance failover")
	}
	_, code, _ := classifyUpstreamError(&httpError{http.StatusBadGateway, "upstream_failed", tlsct.ErrConnectionCapacity})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d; want 503", code)
	}
}
