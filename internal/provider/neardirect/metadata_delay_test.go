package neardirect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/provider/nearroute"
	"github.com/13rac1/teep/internal/tlsct"
)

func TestMetadataFailureDelayRecovery(t *testing.T) {
	for _, failure := range []string{"endpoints", "count", "zero_healthy"} {
		t.Run(failure, func(t *testing.T) { testMetadataFailureRecovery(t, failure) })
	}
}

func testMetadataFailureRecovery(t *testing.T, failure string) {
	t.Helper()
	var recovered atomic.Bool
	var lists, counts, elapsed atomic.Int64
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		isList := req.URL.Path == "/endpoints"
		if isList {
			lists.Add(1)
		} else {
			counts.Add(1)
		}
		failingStage := (failure == "endpoints") == isList
		if failingStage {
			if !recovered.Load() {
				if failure == "zero_healthy" {
					_, _ = fmt.Fprint(w, `{"domain":"model.completions.near.ai","requested_domain":"model.completions.near.ai","healthy":0,"total":2}`)
				} else {
					w.WriteHeader(http.StatusBadGateway)
				}
				return
			}
			close(entered)
			select {
			case <-release:
			case <-req.Context().Done():
				return
			}
		}
		if isList {
			_, _ = fmt.Fprint(w, `{"endpoints":[{"domain":"model.completions.near.ai","models":["model"]}]}`)
		} else {
			_, _ = fmt.Fprint(w, `{"domain":"model.completions.near.ai","requested_domain":"model.completions.near.ai","healthy":2,"total":2}`)
		}
	}))
	t.Cleanup(upstream.Close)
	r := NewEndpointResolver()
	r.SetClient(upstream.Client())
	r.endpointsURL, r.countURL = upstream.URL+"/endpoints", upstream.URL+"/count"
	start := time.Now()
	r.now = func() time.Time { return start.Add(time.Duration(elapsed.Load())) }
	t.Cleanup(func() { unblock(); r.Stop(); r.CloseIdleConnections() })
	_, err := r.ResolveRoute(t.Context(), "model")
	assertMetadataKind(t, err, nearroute.Metadata)
	beforeLists, beforeCounts := lists.Load(), counts.Load()
	for _, offset := range []time.Duration{0, time.Second / 4, time.Second / 2, time.Second - time.Nanosecond} {
		elapsed.Store(int64(offset))
		_, err := r.ResolveRoute(t.Context(), "model")
		assertMetadataKind(t, err, nearroute.Delay)
	}
	r.mu.Lock()
	record := &r.endpoints
	if failure != "endpoints" {
		record = r.counts["model.completions.near.ai"]
	}
	if !record.retryAfter.Equal(start.Add(time.Second)) || len(r.selections) != 0 {
		t.Error("delay extended or failed selection retained")
	}
	r.mu.Unlock()
	if lists.Load() != beforeLists || counts.Load() != beforeCounts {
		t.Fatal("failure delay repeated metadata requests")
	}
	recovered.Store(true)
	elapsed.Store(int64(time.Second))
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, err := r.ResolveRoute(t.Context(), "model"); err != nil {
				t.Errorf("recovery: %v", err)
			}
		})
	}
	<-entered
	unblock()
	wg.Wait()
	wantLists := int64(1)
	if failure == "endpoints" {
		wantLists = 2
	}
	wantCounts := int64(2)
	if failure == "endpoints" {
		wantCounts = 1
	}
	if lists.Load() != wantLists || counts.Load() != wantCounts {
		t.Fatalf("recovery did not share fetch: lists=%d counts=%d", lists.Load(), counts.Load())
	}
	r.mu.Lock()
	if record.failure != nil || !record.retryAfter.IsZero() {
		t.Error("success retained failure delay")
	}
	r.mu.Unlock()
	recovered.Store(false)
	elapsed.Store(int64(10 * time.Minute))
	if _, err := r.ResolveRoute(t.Context(), "model"); err != nil {
		t.Fatal(err)
	}
	if lists.Load() != wantLists || counts.Load() != wantCounts {
		t.Fatal("established route consulted expired metadata")
	}
}

func assertMetadataKind(t *testing.T, err error, kind nearroute.ErrorKind) {
	t.Helper()
	value, ok := errors.AsType[*nearroute.Error](err)
	if !ok || value.Kind != kind {
		t.Fatalf("expected metadata kind %d: %v", kind, err)
	}
}

type metadataFailureTransport struct {
	base    http.RoundTripper
	failure error
	calls   atomic.Int32
}

func (r *metadataFailureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if r.calls.Add(1) == 1 {
		return nil, r.failure
	}
	return r.base.RoundTrip(req)
}

func TestMetadataCanceledAndCapacityFetchesDoNotDelayRecovery(t *testing.T) {
	for _, failure := range []error{context.Canceled, context.DeadlineExceeded, tlsct.ErrConnectionCapacity} {
		t.Run(failure.Error(), func(t *testing.T) {
			r, _, _ := selectionFixture(t)
			transport := &metadataFailureTransport{base: r.client.Transport, failure: fmt.Errorf("metadata transport: %w", failure)}
			r.client.Transport = transport
			_, err := r.ResolveRoute(t.Context(), "a")
			if !errors.Is(err, failure) {
				t.Fatalf("lost cause: %v", err)
			}
			r.mu.Lock()
			if r.endpoints.failure != nil || !r.endpoints.retryAfter.IsZero() {
				t.Error("installed delay for canceled or rejected work")
			}
			r.mu.Unlock()
			if _, err := r.ResolveRoute(t.Context(), "a"); err != nil {
				t.Fatal(err)
			}
			if transport.calls.Load() != 3 {
				t.Fatal("recovery did not fetch endpoints and count")
			}
		})
	}
}

func TestMetadataOwnerCancellationDoesNotInstallDelay(t *testing.T) {
	entered := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		close(entered)
		<-req.Context().Done()
	}))
	defer upstream.Close()
	r := NewEndpointResolver()
	r.SetClient(upstream.Client())
	r.endpointsURL = upstream.URL
	defer r.CloseIdleConnections()
	caller, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { _, err := r.ResolveRoute(caller, "model"); result <- err }()
	<-entered
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	r.mu.Lock()
	if r.endpoints.operation == nil || r.endpoints.failure != nil {
		t.Error("waiter canceled shared metadata")
	}
	r.mu.Unlock()
	r.Stop()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.endpoints.failure != nil || !r.endpoints.retryAfter.IsZero() || r.endpoints.operation != nil || len(r.selections) != 0 {
		t.Fatal("shutdown retained failed work or delay")
	}
}

func (r *metadataFailureTransport) CloseIdleConnections() {
	if closer, ok := r.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
