package neardirect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEndpointResolver_Resolve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"endpoints": [
				{"domain": "a.completions.near.ai", "models": ["model-a", "model-b"]},
				{"domain": "b.completions.near.ai", "models": ["model-c"]}
			]
		}`))
	}))
	defer srv.Close()

	r := newEndpointResolverForTest(srv.URL)

	domain, err := r.Resolve(context.Background(), "model-b")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if domain != "a.completions.near.ai" {
		t.Errorf("domain = %q, want %q", domain, "a.completions.near.ai")
	}

	domain, err = r.Resolve(context.Background(), "model-c")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if domain != "b.completions.near.ai" {
		t.Errorf("domain = %q, want %q", domain, "b.completions.near.ai")
	}
}

func TestEndpointResolver_UnknownModel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"endpoints": [{"domain": "a.near.ai", "models": ["known"]}]}`))
	}))
	defer srv.Close()

	r := newEndpointResolverForTest(srv.URL)

	_, err := r.Resolve(context.Background(), "unknown-model")
	if err == nil {
		t.Fatal("expected error for unknown model")
	}
}

func TestEndpointResolver_RefreshOnStale(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			_, _ = w.Write([]byte(`{"endpoints": [{"domain": "old.near.ai", "models": ["m"]}]}`))
		} else {
			_, _ = w.Write([]byte(`{"endpoints": [{"domain": "new.near.ai", "models": ["m"]}]}`))
		}
	}))
	defer srv.Close()

	r := newEndpointResolverForTest(srv.URL)

	// First call loads the mapping.
	domain, err := r.Resolve(context.Background(), "m")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if domain != "old.near.ai" {
		t.Errorf("domain = %q, want %q", domain, "old.near.ai")
	}

	// Force staleness by backdating fetchedAt.
	r.mu.Lock()
	r.fetchedAt = time.Now().Add(-10 * time.Minute)
	r.mu.Unlock()

	// Second call triggers refresh.
	domain, err = r.Resolve(context.Background(), "m")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if domain != "new.near.ai" {
		t.Errorf("domain = %q, want %q", domain, "new.near.ai")
	}

	if calls != 2 {
		t.Errorf("expected 2 fetches, got %d", calls)
	}
}

func TestEndpointResolver_HTTP500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error": "oops"}`))
	}))
	defer srv.Close()

	r := newEndpointResolverForTest(srv.URL)

	_, err := r.Resolve(context.Background(), "model")
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestEndpointResolver_InvalidDomain(t *testing.T) {
	// Domains that fail isValidDomain should be silently skipped.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"endpoints": [
				{"domain": "", "models": ["m-empty"]},
				{"domain": "has spaces", "models": ["m-spaces"]},
				{"domain": "has\tspace.near.ai", "models": ["m-tab"]},
				{"domain": "line\nfeed.near.ai", "models": ["m-lf"]},
				{"domain": "carriage\rreturn.near.ai", "models": ["m-cr"]},
				{"domain": "http://evil.com", "models": ["m-scheme"]},
				{"domain": "nodot", "models": ["m-nodot"]},
				{"domain": "path/slash", "models": ["m-slash"]},
				{"domain": "attacker.example.com", "models": ["m-wrong-suffix"]},
				{"domain": "xn--near-8oa.ai", "models": ["m-punycode"]},
				{"domain": "valid.near.ai", "models": ["m-good"]}
			]
		}`))
	}))
	defer srv.Close()

	r := newEndpointResolverForTest(srv.URL)
	r.restrictToNearAI = true

	// The only valid domain should resolve.
	domain, err := r.Resolve(context.Background(), "m-good")
	if err != nil {
		t.Fatalf("Resolve m-good: %v", err)
	}
	if domain != "valid.near.ai" {
		t.Errorf("domain = %q, want %q", domain, "valid.near.ai")
	}

	// All invalid-domain models should fail.
	for _, model := range []string{"m-empty", "m-spaces", "m-tab", "m-lf", "m-cr", "m-scheme", "m-nodot", "m-slash", "m-wrong-suffix", "m-punycode"} {
		_, err := r.Resolve(context.Background(), model)
		if err == nil {
			t.Errorf("Resolve(%q) should fail (invalid domain), but got nil error", model)
		}
	}
}

func TestEndpointResolver_FailClosedOnRefreshError(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"endpoints": [{"domain": "old.near.ai", "models": ["m"]}]}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"temporary outage"}`))
	}))
	defer srv.Close()

	r := newEndpointResolverForTest(srv.URL)

	domain, err := r.Resolve(context.Background(), "m")
	if err != nil {
		t.Fatalf("initial Resolve: %v", err)
	}
	if domain != "old.near.ai" {
		t.Fatalf("domain = %q, want %q", domain, "old.near.ai")
	}

	// Force staleness.
	r.mu.Lock()
	r.fetchedAt = time.Now().Add(-10 * time.Minute)
	r.mu.Unlock()

	// Refresh fails — must return error, not stale data.
	_, err = r.Resolve(context.Background(), "m")
	if err == nil {
		t.Fatal("expected error when refresh fails (fail-closed), got nil")
	}
}

func TestEndpointResolver_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	r := newEndpointResolverForTest(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := r.Resolve(ctx, "model")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestEndpointResolver_Models(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		_, _ = w.Write([]byte(`{
			"endpoints": [
				{"domain": "a.completions.near.ai", "models": ["model-a", "model-b"]},
				{"domain": "b.completions.near.ai", "models": ["model-c"]}
			]
		}`))
	}))
	defer srv.Close()

	r := newEndpointResolverForTest(srv.URL)

	models, err := r.Models(context.Background())
	if err != nil {
		t.Fatalf("Models: %v", err)
	}
	if len(models) != 3 {
		t.Fatalf("len(models) = %d, want 3", len(models))
	}
	want := []string{"model-a", "model-b", "model-c"}
	for _, name := range want {
		if _, ok := models[name]; !ok {
			t.Errorf("models missing %q", name)
		}
	}
}

func TestEndpointResolver_Models_ReusesCache(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"endpoints": [{"domain": "x.near.ai", "models": ["m"]}]}`))
	}))
	defer srv.Close()

	r := newEndpointResolverForTest(srv.URL)

	// First call fetches.
	if _, err := r.Models(context.Background()); err != nil {
		t.Fatalf("first Models: %v", err)
	}
	// Second call should reuse the cache (no second fetch).
	if _, err := r.Models(context.Background()); err != nil {
		t.Fatalf("second Models: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 fetch, got %d", calls)
	}
}

func TestEndpointResolver_Models_StaleOnRefreshError(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"endpoints": [{"domain": "x.near.ai", "models": ["m"]}]}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"oops"}`))
	}))
	defer srv.Close()

	r := newEndpointResolverForTest(srv.URL)

	if _, err := r.Models(context.Background()); err != nil {
		t.Fatalf("initial Models: %v", err)
	}

	r.mu.Lock()
	r.fetchedAt = time.Now().Add(-10 * time.Minute)
	r.mu.Unlock()

	// Should return stale data, not an error.
	models, err := r.Models(context.Background())
	if err != nil {
		t.Fatalf("stale Models: %v", err)
	}
	if len(models) != 1 {
		t.Errorf("len(models) = %d, want 1", len(models))
	}
}

func TestEndpointResolver_Models_ErrorWhenEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"oops"}`))
	}))
	defer srv.Close()

	r := newEndpointResolverForTest(srv.URL)

	_, err := r.Models(context.Background())
	if err == nil {
		t.Fatal("expected error when discovery fails and cache is empty")
	}
}
