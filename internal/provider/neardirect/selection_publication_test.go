package neardirect

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSelectionAcquiredSnapshotsSurviveReplacement(t *testing.T) {
	for _, change := range []string{"removed", "replaced", "restored"} {
		t.Run(change, func(t *testing.T) { testSelectionSnapshotReplacement(t, change) })
	}
}

func testSelectionSnapshotReplacement(t *testing.T, change string) {
	t.Helper()
	var revision, lists, counts, draws atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/endpoints" {
			lists.Add(1)
			selected := `{"domain":"first.completions.near.ai","models":["selected"]},`
			if revision.Load() == 1 {
				if change == "removed" {
					selected = ""
				} else {
					selected = `{"domain":"replacement.completions.near.ai","models":["selected"]},`
				}
			}
			_, _ = fmt.Fprintf(w, `{"endpoints":[%s{"domain":"other.completions.near.ai","models":["established","new"]}]}`, selected)
			return
		}
		counts.Add(1)
		domain := req.URL.Query().Get("domain")
		healthy := 2 + revision.Load()
		_, _ = fmt.Fprintf(w, `{"domain":%q,"requested_domain":%q,"healthy":%d,"total":%d}`, domain, domain, healthy, healthy)
	}))
	defer server.Close()
	r := NewEndpointResolver()
	r.SetClient(server.Client())
	r.endpointsURL, r.countURL = server.URL+"/endpoints", server.URL+"/count"
	defer r.Stop()
	entered, release := make(chan struct{}), make(chan struct{})
	r.selector = func(ctx context.Context, healthy uint64) (uint64, error) {
		if draws.Add(1) == 2 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return 0, ctx.Err()
			}
			if healthy != 2 {
				t.Error("acquired count changed")
			}
		}
		return 1, nil
	}
	established, err := r.ResolveRoute(t.Context(), "established")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		route, err := r.ResolveRoute(t.Context(), "selected")
		if err == nil && route.Authority() != "first-i1.completions.near.ai" {
			err = fmt.Errorf("published replacement mapping: %s", route.Authority())
		}
		done <- err
	}()
	<-entered
	// Expire only the retained cache records to start controlled replacements.
	// Acquired snapshots are copies and remain fresh at publication.
	refresh := func(version int32) {
		revision.Store(version)
		r.mu.Lock()
		r.endpoints.snapshot.fetchedAt = time.Time{}
		r.counts["first.completions.near.ai"].snapshot.fetchedAt = time.Time{}
		r.mu.Unlock()
		if _, err := r.Resolve(t.Context(), "new"); err != nil {
			t.Fatal(err)
		}
		if _, err := r.metadata(t.Context(), "first.completions.near.ai"); err != nil {
			t.Fatal(err)
		}
	}
	refresh(1)
	if change == "restored" {
		refresh(2)
	}
	if again, err := r.ResolveRoute(t.Context(), "established"); err != nil || again != established {
		t.Fatal("blocked selector prevented established route use")
	}
	if _, err := r.ResolveRoute(t.Context(), "new"); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	beforeLists, beforeCounts, beforeDraws := lists.Load(), counts.Load(), draws.Load()
	if _, err := r.ResolveRoute(t.Context(), "selected"); err != nil {
		t.Fatal(err)
	}
	if lists.Load() != beforeLists || counts.Load() != beforeCounts || draws.Load() != beforeDraws {
		t.Fatal("published route repeated selection or discovery")
	}
}
