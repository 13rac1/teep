package neardirect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/provider/nearroute"
)

func selectionFixture(t *testing.T) (resolver *EndpointResolver, listCalls, countCalls *atomic.Int32) {
	t.Helper()
	lists, counts := &atomic.Int32{}, &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/endpoints" {
			lists.Add(1)
			_, _ = fmt.Fprint(w, `{"endpoints":[{"domain":"model.completions.near.ai","models":["a","b"]}]}`)
			return
		}
		counts.Add(1)
		_, _ = fmt.Fprint(w, `{"domain":"model.completions.near.ai","requested_domain":"model.completions.near.ai","healthy":2,"total":2}`)
	}))
	t.Cleanup(server.Close)
	r := NewEndpointResolver()
	r.SetClient(server.Client())
	r.endpointsURL = server.URL + "/endpoints"
	r.countURL = server.URL + "/count"
	t.Cleanup(func() { r.Stop(); r.CloseIdleConnections() })
	return r, lists, counts
}

func TestEstablishedSelectionSurvivesMetadataExpiry(t *testing.T) {
	r, lists, counts := selectionFixture(t)
	var draws atomic.Int32
	var elapsed atomic.Int64
	start := time.Now()
	r.now = func() time.Time { return start.Add(time.Duration(elapsed.Load())) }
	r.selector = func(context.Context, uint64) (uint64, error) { draws.Add(1); return 1, nil }
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			route, err := r.ResolveRoute(t.Context(), "a")
			if err != nil || route.Authority() != "model-i1.completions.near.ai" {
				t.Errorf("route=%v err=%v", route, err)
			}
		})
	}
	wg.Wait()
	if lists.Load() != 1 || counts.Load() != 1 || draws.Load() != 1 {
		t.Fatalf("list=%d count=%d draws=%d", lists.Load(), counts.Load(), draws.Load())
	}
	elapsed.Store(int64(10 * time.Minute))
	if _, err := r.ResolveRoute(t.Context(), "a"); err != nil {
		t.Fatal(err)
	}
	if _, found := r.LookupSelection("a"); !found {
		t.Fatal("report lookup lost established selection")
	}
	if lists.Load() != 1 || counts.Load() != 1 || draws.Load() != 1 {
		t.Fatal("established route consulted expired metadata")
	}
	if _, err := r.ResolveRoute(t.Context(), "b"); err != nil {
		t.Fatal(err)
	}
	if lists.Load() != 2 || counts.Load() != 2 || draws.Load() != 2 {
		t.Fatal("new model did not refresh metadata")
	}
}

func TestSelectionWaiterCancellationAndShutdown(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(strconv.FormatBool(shutdown), func(t *testing.T) {
			r, _, _ := selectionFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			r.selector = func(ctx context.Context, _ uint64) (uint64, error) {
				close(entered)
				select {
				case <-release:
					return 0, nil
				case <-ctx.Done():
					return 0, ctx.Err()
				}
			}
			caller, cancel := context.WithCancel(t.Context())
			result := make(chan error, 1)
			go func() { _, err := r.ResolveRoute(caller, "a"); result <- err }()
			<-entered
			cancel()
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Fatalf("waiter cancellation: %v", err)
			}
			if shutdown {
				r.Stop()
				close(release)
				if _, ok := r.LookupSelection("a"); ok {
					t.Fatal("published route after shutdown")
				}
				return
			}
			close(release)
			if _, err := r.ResolveRoute(t.Context(), "a"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSelectionSnapshotExpiresBeforePublication(t *testing.T) {
	r, _, _ := selectionFixture(t)
	var elapsed atomic.Int64
	start := time.Now()
	r.now = func() time.Time { return start.Add(time.Duration(elapsed.Load())) }
	r.selector = func(context.Context, uint64) (uint64, error) { elapsed.Store(int64(6 * time.Minute)); return 0, nil }
	_, err := r.ResolveRoute(t.Context(), "a")
	var failure *nearroute.Error
	if !errors.As(err, &failure) || failure.Kind != nearroute.Expired {
		t.Fatalf("expired snapshot: %v", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.selections) != 0 || r.endpoints.failure != nil {
		t.Fatal("expired publication retained reservation or metadata failure")
	}
}

func TestSelectionRejectsInvalidModelsBeforeAdmission(t *testing.T) {
	r, lists, counts := selectionFixture(t)
	for _, model := range []string{"", "a\n", "a\x7f", string(make([]byte, 257))} {
		_, err := r.ResolveRoute(t.Context(), model)
		var failure *nearroute.Error
		if !errors.As(err, &failure) || failure.Kind != nearroute.Input {
			t.Fatalf("invalid input classification: %v", err)
		}
	}
	if lists.Load() != 0 || counts.Load() != 0 || len(r.selections) != 0 {
		t.Fatal("invalid model started metadata or retained state")
	}
}

func TestConfiguredSelectionMetadataRequirements(t *testing.T) {
	for _, tt := range []struct {
		origin, authority string
		lists, counts     int32
		invalid           bool
	}{
		{"https://api.near.ai:443", "model-i0.completions.near.ai", 1, 1, false},
		{"https://model.completions.near.ai", "model-i0.completions.near.ai", 1, 1, false},
		{"https://model-i18446744073709551615.completions.near.ai", "model-i18446744073709551615.completions.near.ai", 1, 0, false},
		{"https://model.completions.near.ai:8443", "model.completions.near.ai:8443", 0, 0, false},
		{"https://example.com", "example.com", 0, 0, false},
		{"https://other.completions.near.ai", "", 1, 0, true},
		{"https://other-i0.completions.near.ai", "", 1, 0, true},
	} {
		t.Run(tt.origin, func(t *testing.T) {
			r, lists, counts := selectionFixture(t)
			r.selector = func(context.Context, uint64) (uint64, error) { return 0, nil }
			origin, err := nearroute.ParseOrigin(tt.origin)
			if err != nil {
				t.Fatal(err)
			}
			route, err := r.ResolveConfigured(t.Context(), "a", origin)
			if tt.invalid {
				if err == nil {
					t.Fatal("accepted configured model mismatch")
				}
			} else if err != nil || route.Authority() != tt.authority {
				t.Fatalf("authority=%s err=%v", route.Authority(), err)
			}
			if lists.Load() != tt.lists || counts.Load() != tt.counts {
				t.Fatalf("list=%d count=%d", lists.Load(), counts.Load())
			}
		})
	}
}

func TestSelectionFailureReleasesReservation(t *testing.T) {
	r, lists, counts := selectionFixture(t)
	entropyErr := errors.New("entropy unavailable")
	var draws atomic.Int32
	r.selector = func(context.Context, uint64) (uint64, error) {
		if draws.Add(1) == 1 {
			return 0, entropyErr
		}
		return 1, nil
	}
	if _, err := r.ResolveRoute(t.Context(), "a"); !errors.Is(err, entropyErr) {
		t.Fatalf("entropy failure: %v", err)
	}
	if _, ok := r.LookupSelection("a"); ok {
		t.Fatal("entropy failure established route")
	}
	if _, err := r.ResolveRoute(t.Context(), "a"); err != nil {
		t.Fatal(err)
	}
	if draws.Load() != 2 || lists.Load() != 1 || counts.Load() != 1 {
		t.Fatal("failed selection retried internally or discarded valid metadata")
	}
}

func TestSelectionCapacityRetainsEstablishedRoutes(t *testing.T) {
	r, lists, counts := selectionFixture(t)
	established, err := r.ResolveRoute(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	for i := 1; i < maxDiscoveryMappings; i++ {
		r.selections[fmt.Sprintf("pending%d", i)] = &selectionOperation{done: make(chan struct{})}
	}
	r.mu.Unlock()
	if _, err := r.ResolveRoute(t.Context(), "b"); err == nil {
		t.Fatal("exceeded retained selection capacity")
	} else if failure, ok := errors.AsType[*nearroute.Error](err); !ok || failure.Kind != nearroute.Capacity {
		t.Fatalf("capacity classification: %v", err)
	}
	again, err := r.ResolveRoute(t.Context(), "a")
	if err != nil || again != established {
		t.Fatal("capacity pressure changed established route")
	}
	if lists.Load() != 1 || counts.Load() != 1 {
		t.Fatal("capacity pressure started metadata work")
	}
}
