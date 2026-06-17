package tinfoil

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
)

// newDirectResolverForTest returns a resolver pointing at a custom URL
// with a short HTTP timeout. Domain validation is still active — test
// model IDs must produce valid *.inference.tinfoil.sh domains.
func newDirectResolverForTest(url string) *DirectResolver {
	return &DirectResolver{
		modelsURL: url,
		apiKey:    "test-key",
		client:    tlsct.NewHTTPClient(1 * time.Second),
		mapping:   make(map[string]string),
	}
}

func TestSlugToDomain(t *testing.T) {
	tests := []struct {
		slug string
		want string
	}{
		{"meta-llama/Llama-4-Scout-17B-16E-Instruct", "meta-llama--Llama-4-Scout-17B-16E-Instruct.inference.tinfoil.sh"},
		{"simple-model", "simple-model.inference.tinfoil.sh"},
		{"org/sub/deep", "org--sub--deep.inference.tinfoil.sh"},
	}
	for _, tt := range tests {
		got := slugToDomain(tt.slug)
		if got != tt.want {
			t.Errorf("slugToDomain(%q) = %q, want %q", tt.slug, got, tt.want)
		}
	}
}

func TestIsValidTinfoilDomain(t *testing.T) {
	tests := []struct {
		domain string
		valid  bool
	}{
		{"foo.inference.tinfoil.sh", true},
		{"org--model.inference.tinfoil.sh", true},
		{"UPPER.INFERENCE.TINFOIL.SH", true},
		{"foo.example.com", false},
		{"inference.tinfoil.sh", false},          // not a subdomain
		{"evil.foo.inference.tinfoil.sh", false}, // multi-level subdomain
		{"a.b.c.inference.tinfoil.sh", false},    // deep nesting
		{".inference.tinfoil.sh", false},         // empty label
		{"", false},
		// Invalid hostname characters must be rejected (models API is
		// untrusted input).
		{"foo bar.inference.tinfoil.sh", false}, // space
		{"foo_bar.inference.tinfoil.sh", false}, // underscore
		{"foo;bar.inference.tinfoil.sh", false}, // semicolon
		{"foo/bar.inference.tinfoil.sh", false}, // slash
		{"foo\x00.inference.tinfoil.sh", false}, // null byte
		{"foo!@#.inference.tinfoil.sh", false},  // special chars
		{"foo:bar.inference.tinfoil.sh", false}, // colon
	}
	for _, tt := range tests {
		got := isValidTinfoilDomain(tt.domain)
		if got != tt.valid {
			t.Errorf("isValidTinfoilDomain(%q) = %v, want %v", tt.domain, got, tt.valid)
		}
	}
}

func TestDirectResolver_ParseModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":[{"id":"meta-llama/Llama-4-Scout-17B-16E-Instruct"},{"id":"simple-model"}]}`)
	}))
	defer srv.Close()

	resolver := newDirectResolverForTest(srv.URL)

	domain, err := resolver.Resolve(context.Background(), "meta-llama/Llama-4-Scout-17B-16E-Instruct")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if domain != "meta-llama--Llama-4-Scout-17B-16E-Instruct.inference.tinfoil.sh" {
		t.Errorf("domain = %q, want meta-llama--Llama-4-Scout-17B-16E-Instruct.inference.tinfoil.sh", domain)
	}

	domain, err = resolver.Resolve(context.Background(), "simple-model")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if domain != "simple-model.inference.tinfoil.sh" {
		t.Errorf("domain = %q, want simple-model.inference.tinfoil.sh", domain)
	}
}

func TestDirectResolver_UnknownModel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":[{"id":"known-model"}]}`)
	}))
	defer srv.Close()

	resolver := newDirectResolverForTest(srv.URL)

	_, err := resolver.Resolve(context.Background(), "unknown-model")
	if err == nil {
		t.Fatal("expected error for unknown model")
	}
}

func TestDirectResolver_CacheTTL(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":[{"id":"model-a"}]}`)
	}))
	defer srv.Close()

	resolver := newDirectResolverForTest(srv.URL)

	// First resolve triggers fetch.
	_, err := resolver.Resolve(context.Background(), "model-a")
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	if callCount.Load() != 1 {
		t.Errorf("expected 1 fetch call, got %d", callCount.Load())
	}

	// Second resolve within TTL should not fetch again.
	_, err = resolver.Resolve(context.Background(), "model-a")
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if callCount.Load() != 1 {
		t.Errorf("expected 1 fetch call (cached), got %d", callCount.Load())
	}

	// Expire the cache.
	resolver.mu.Lock()
	resolver.fetchedAt = time.Now().Add(-resolverTTL - time.Second)
	resolver.mu.Unlock()

	// Third resolve should trigger a new fetch.
	_, err = resolver.Resolve(context.Background(), "model-a")
	if err != nil {
		t.Fatalf("third Resolve: %v", err)
	}
	if callCount.Load() != 2 {
		t.Errorf("expected 2 fetch calls after TTL expiry, got %d", callCount.Load())
	}
}

func TestDirectResolver_OfflineReturnsError(t *testing.T) {
	// Start server that will be shut down to simulate offline.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":[{"id":"cached-model"}]}`)
	}))

	resolver := newDirectResolverForTest(srv.URL)

	// Populate cache.
	_, err := resolver.Resolve(context.Background(), "cached-model")
	if err != nil {
		t.Fatalf("initial Resolve: %v", err)
	}

	// Shut down server and expire cache.
	srv.Close()
	resolver.mu.Lock()
	resolver.fetchedAt = time.Now().Add(-resolverTTL - time.Second)
	resolver.mu.Unlock()

	// Should return error even with stale cache (matches neardirect behavior).
	_, err = resolver.Resolve(context.Background(), "cached-model")
	if err == nil {
		t.Fatal("expected error when refresh fails with stale cache")
	}
}

func TestDirectResolver_OfflineNoCacheFails(t *testing.T) {
	// Server that immediately fails.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	resolver := newDirectResolverForTest(srv.URL)

	_, err := resolver.Resolve(context.Background(), "no-cache-model")
	if err == nil {
		t.Fatal("expected error when offline with no cache")
	}
}

func TestDirectResolver_SingleflightCollapse(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		time.Sleep(50 * time.Millisecond) // slow enough for concurrent callers
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":[{"id":"model-x"}]}`)
	}))
	defer srv.Close()

	resolver := newDirectResolverForTest(srv.URL)

	const concurrency = 10
	var wg sync.WaitGroup
	errs := make([]error, concurrency)

	for i := range concurrency {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = resolver.Resolve(context.Background(), "model-x")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}

	// Singleflight should collapse all concurrent calls into one HTTP request.
	if callCount.Load() != 1 {
		t.Errorf("expected 1 HTTP call (singleflight), got %d", callCount.Load())
	}
}

func TestDirectResolver_SkipsEmptyID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":[{"id":""},{"id":"valid-model"}]}`)
	}))
	defer srv.Close()

	resolver := newDirectResolverForTest(srv.URL)

	// Empty ID should be skipped, valid-model should resolve.
	domain, err := resolver.Resolve(context.Background(), "valid-model")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if domain != "valid-model.inference.tinfoil.sh" {
		t.Errorf("domain = %q, want valid-model.inference.tinfoil.sh", domain)
	}

	// Empty string model should not be found.
	_, err = resolver.Resolve(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty model")
	}
}

// TestDirectResolver_SetClient_Concurrent verifies that SetClient is safe for
// concurrent use with Resolve. Previously SetClient wrote r.client without
// synchronization, racing with refresh's read of r.client under -race.
func TestDirectResolver_SetClient_Concurrent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":[{"id":"model-a"}]}`)
	}))
	defer srv.Close()

	resolver := newDirectResolverForTest(srv.URL)

	// Expire the cache so Resolve triggers refresh (which reads r.client).
	resolver.mu.Lock()
	resolver.fetchedAt = time.Now().Add(-resolverTTL - time.Second)
	resolver.mu.Unlock()

	var wg sync.WaitGroup

	// Writer goroutine: repeatedly swap the client a bounded number of times.
	wg.Go(func() {
		for range 100 {
			resolver.SetClient(srv.Client())
		}
	})

	// Reader goroutines: repeatedly Resolve (triggers refresh → reads client).
	for range 4 {
		wg.Go(func() {
			for range 5 {
				_, _ = resolver.Resolve(context.Background(), "model-a")
			}
		})
	}

	wg.Wait()
}
