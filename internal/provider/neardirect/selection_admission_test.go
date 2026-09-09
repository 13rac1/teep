package neardirect

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/provider/nearroute"
)

type selectionWaitContext struct {
	context.Context //nolint:containedctx // Test context observes wait entry while retaining caller cancellation.
	onWait          func()
}

func (c selectionWaitContext) Done() <-chan struct{} {
	c.onWait()
	return c.Context.Done()
}

func TestUnknownModelsDoNotReserveSelections(t *testing.T) {
	for _, state := range []string{"cold", "fresh", "expired"} {
		t.Run(state, func(t *testing.T) { testUnknownSelectionAdmission(t, state) })
	}
}

func testUnknownSelectionAdmission(t *testing.T, state string) {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var lists, counts atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/endpoints" {
			lists.Add(1)
			select {
			case <-release:
			case <-req.Context().Done():
				return
			}
			_, _ = fmt.Fprint(w, `{"endpoints":[{"domain":"valid.completions.near.ai","models":["valid"]}]}`)
			return
		}
		counts.Add(1)
		_, _ = fmt.Fprint(w, `{"domain":"valid.completions.near.ai","requested_domain":"valid.completions.near.ai","healthy":1,"total":1}`)
	}))
	r := NewEndpointResolver()
	r.SetClient(upstream.Client())
	r.endpointsURL, r.countURL = upstream.URL+"/endpoints", upstream.URL+"/count"
	t.Cleanup(func() { unblock(); r.Stop(); r.CloseIdleConnections(); upstream.Close() })
	if state != "cold" {
		r.endpoints.snapshot = metadataSnapshot{mapping: map[string]string{"valid": "valid.completions.near.ai"}, fetchedAt: time.Now()}
		if state == "expired" {
			r.endpoints.snapshot.fetchedAt = time.Now().Add(-2 * endpointsTTL)
		}
	}
	const callers = 64
	var ready sync.WaitGroup
	ready.Add(callers)
	results := make(chan error, callers)
	for i := range callers {
		go func() {
			var signaled sync.Once
			mark := func() { signaled.Do(ready.Done) }
			defer mark()
			_, err := r.ResolveRoute(selectionWaitContext{Context: t.Context(), onWait: mark}, fmt.Sprintf("unknown-%d", i))
			results <- err
		}()
	}
	// Every caller has either returned or reached the metadata/selection wait.
	ready.Wait()
	r.mu.Lock()
	if len(r.selections) != 0 {
		t.Error("unknown models reserved route slots")
	}
	r.mu.Unlock()
	valid := make(chan error, 1)
	go func() { _, err := r.ResolveRoute(t.Context(), "valid"); valid <- err }()
	unblock()
	for range callers {
		assertMetadataKind(t, <-results, nearroute.UnknownModel)
	}
	if err := <-valid; err != nil {
		t.Fatal(err)
	}
	wantLists := int32(1)
	if state == "fresh" {
		wantLists = 0
	}
	if lists.Load() != wantLists || counts.Load() != 1 {
		t.Fatal("unknown models repeated discovery or backend counts")
	}
}

func TestRandomIndexBounds(t *testing.T) {
	for _, healthy := range []uint64{0, 1, ^uint64(0)} {
		index, err := randomIndex(t.Context(), healthy)
		if healthy == 0 {
			if err == nil {
				t.Fatal("empty healthy set did not fail")
			}
		} else if err != nil || index >= healthy {
			t.Fatalf("healthy=%d index=%d: %v", healthy, index, err)
		}
	}
}
