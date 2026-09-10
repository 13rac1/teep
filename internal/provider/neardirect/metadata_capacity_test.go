package neardirect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/provider/nearroute"
)

func TestCountAdmissionBoundsAndCancellation(t *testing.T) {
	entered := make(chan struct{}, maxCountFetches)
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-req.Context().Done():
			return
		}
		domain := req.URL.Query().Get("domain")
		_, _ = fmt.Fprintf(w, `{"domain":%q,"requested_domain":%q,"healthy":1,"total":1}`, domain, domain)
	}))
	defer server.Close()
	r := NewEndpointResolver()
	r.SetClient(server.Client())
	r.countURL = server.URL
	defer r.Stop()
	caller, cancel := context.WithCancel(t.Context())
	defer cancel()
	var wg sync.WaitGroup
	for i := range maxCountFetches {
		wg.Go(func() { _, _ = r.metadata(caller, fmt.Sprintf("model%d.completions.near.ai", i)) })
	}
	for range maxCountFetches {
		<-entered
	}
	cancel()
	wg.Wait()
	_, err := r.metadata(t.Context(), "excess.completions.near.ai")
	failure, ok := errors.AsType[*nearroute.Error](err)
	if !ok || failure.Kind != nearroute.Capacity {
		t.Fatalf("admission: %v", err)
	}
	r.mu.Lock()
	if r.activeCounts != maxCountFetches || len(r.counts) != maxCountFetches {
		t.Error("canceled waiters released active owner or excess name retained")
	}
	r.mu.Unlock()
	close(release)
	// Joining the operation after all prior waiters cancel must still succeed.
	if _, err := r.metadata(t.Context(), "model0.completions.near.ai"); err != nil {
		t.Fatal(err)
	}
}

func TestCountRecordEvictionProtectsPendingAndFailureDelay(t *testing.T) {
	r := NewEndpointResolver()
	defer r.Stop()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.initializeLocked()
	now := time.Now()
	for i := range maxDiscoveryMappings {
		r.counts[strconv.Itoa(i)] = &metadataRecord{retryAfter: now.Add(time.Hour), lastUsed: now}
	}
	if _, err := r.metadataRecordLocked("new"); err == nil {
		t.Fatal("evicted protected failure delay")
	}
	candidate := r.counts["0"]
	candidate.retryAfter = time.Time{}
	candidate.operation = &metadataOperation{done: make(chan struct{})}
	if _, err := r.metadataRecordLocked("new"); err == nil {
		t.Fatal("evicted pending fetch")
	}
	candidate.operation = nil
	if _, err := r.metadataRecordLocked("new"); err != nil {
		t.Fatal(err)
	}
	if len(r.counts) != maxDiscoveryMappings || r.counts["0"] != nil {
		t.Fatal("did not evict eligible completed record")
	}
}

func TestUnknownModelsDoNotRetainFailureState(t *testing.T) {
	r, lists, counts := selectionFixture(t)
	for i := range 100 {
		_, err := r.ResolveRoute(t.Context(), fmt.Sprintf("missing%d", i))
		failure, ok := errors.AsType[*nearroute.Error](err)
		if !ok || failure.Kind != nearroute.UnknownModel {
			t.Fatalf("unknown model: %v", err)
		}
	}
	if lists.Load() != 1 || counts.Load() != 0 || len(r.selections) != 0 || len(r.counts) != 0 {
		t.Fatal("unknown model requests refreshed metadata or retained names")
	}
}
