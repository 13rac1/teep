package tinfoil

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
)

// newDirectResolverForTest returns a resolver pointing at a custom URL
// with a short HTTP timeout. The test server should serve the
// /.well-known/tinfoil-proxy response format.
func newDirectResolverForTest(url string) *DirectResolver {
	return &DirectResolver{
		proxyURL: url,
		apiKey:   "test-key",
		client:   tlsct.NewHTTPClient(1 * time.Second),
		mapping:  make(map[string]ModelMapping),
	}
}

// proxyResponseJSON builds a minimal tinfoil-proxy JSON response for testing.
func proxyResponseJSON(models ...string) string {
	var sb strings.Builder
	sb.WriteString(`{"models":{`)
	for i, m := range models {
		if i > 0 {
			sb.WriteString(",")
		}
		domain := m + ".inf10.tinfoil.sh"
		fmt.Fprintf(&sb, `%q:{"enclaves":{%q:{"hpke_key":"abc","predicate":"https://tinfoil.sh/predicate/tdx-guest/v2","tls_key_fp":"def"}}}`, m, domain)
	}
	sb.WriteString(`}}`)
	return sb.String()
}

func TestIsValidBackendDomain(t *testing.T) {
	tests := []struct {
		domain string
		valid  bool
	}{
		// Real backend enclave domains.
		{"gemma4-31b-1.inf10.tinfoil.sh", true},
		{"gemma4-31b-inf6.tinfoil.containers.tinfoil.dev", true},
		{"llama3-3-70b.tinfoil.containers.tinfoil.dev", true},
		{"nomic.inf10.tinfoil.sh", true},
		// Router wildcard subdomains are NOT valid direct backends.
		{"gemma4-31b.inference.tinfoil.sh", true}, // still a valid tinfoil.sh domain
		// Invalid domains.
		{"foo.example.com", false},
		{"", false},
		{"foo bar.tinfoil.sh", false}, // space
		{"foo_bar.tinfoil.sh", false}, // underscore
		{"foo;bar.tinfoil.sh", false}, // semicolon
		{"foo\x00.tinfoil.sh", false}, // null byte
	}
	for _, tt := range tests {
		got := isValidBackendDomain(tt.domain)
		if got != tt.valid {
			t.Errorf("isValidBackendDomain(%q) = %v, want %v", tt.domain, got, tt.valid)
		}
	}
}

func TestDirectResolver_ParseProxy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, proxyResponseJSON("gemma4-31b", "llama3-3-70b"))
	}))
	defer srv.Close()

	resolver := newDirectResolverForTest(srv.URL)

	domain, err := resolver.Resolve(context.Background(), "gemma4-31b")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if domain != "gemma4-31b.inf10.tinfoil.sh" {
		t.Errorf("domain = %q, want gemma4-31b.inf10.tinfoil.sh", domain)
	}

	domain, err = resolver.Resolve(context.Background(), "llama3-3-70b")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if domain != "llama3-3-70b.inf10.tinfoil.sh" {
		t.Errorf("domain = %q, want llama3-3-70b.inf10.tinfoil.sh", domain)
	}
}

func TestDirectResolver_UnknownModel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, proxyResponseJSON("known-model"))
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
		fmt.Fprint(w, proxyResponseJSON("model-a"))
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
		fmt.Fprint(w, proxyResponseJSON("cached-model"))
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
		fmt.Fprint(w, proxyResponseJSON("model-x"))
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

func TestDirectResolver_SkipsModelWithNoEnclaves(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"models":{"valid-model":{"enclaves":{"valid-model.inf10.tinfoil.sh":{"hpke_key":"abc","predicate":"x","tls_key_fp":"def"}}},"empty-model":{"enclaves":{}}}}`)
	}))
	defer srv.Close()

	resolver := newDirectResolverForTest(srv.URL)

	// Empty enclaves should be skipped, valid-model should resolve.
	domain, err := resolver.Resolve(context.Background(), "valid-model")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if domain != "valid-model.inf10.tinfoil.sh" {
		t.Errorf("domain = %q, want valid-model.inf10.tinfoil.sh", domain)
	}

	// Model with no enclaves should not be found.
	_, err = resolver.Resolve(context.Background(), "empty-model")
	if err == nil {
		t.Fatal("expected error for model with no enclaves")
	}
}

// TestDirectResolver_SetClient_Concurrent verifies that SetClient is safe for
// concurrent use with Resolve. Previously SetClient wrote r.client without
// synchronization, racing with refresh's read of r.client under -race.
func TestDirectResolver_SetClient_Concurrent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, proxyResponseJSON("model-a"))
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

// proxyResponseMultiEnclaveJSON builds a tinfoil-proxy JSON response with
// multiple enclaves for a single model, for testing cache-aware selection.
func proxyResponseMultiEnclaveJSON(model string, domains ...string) string {
	var sb strings.Builder
	sb.WriteString(`{"models":{`)
	fmt.Fprintf(&sb, `%q:{"enclaves":{`, model)
	for i, d := range domains {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `%q:{"hpke_key":"abc","predicate":"https://tinfoil.sh/predicate/tdx-guest/v2","tls_key_fp":"def"}`, d)
	}
	sb.WriteString(`}}}}`)
	return sb.String()
}

func TestSelectDomain_NoPromptCacheKey(t *testing.T) {
	m := ModelMapping{
		Domain:  "b.tinfoil.sh",
		Domains: []string{"a.tinfoil.sh", "b.tinfoil.sh", "c.tinfoil.sh"},
	}
	// Without prompt_cache_key, should return lexicographically smallest.
	got := m.SelectDomain("")
	if got != "a.tinfoil.sh" {
		t.Errorf("SelectDomain(\"\") = %q, want a.tinfoil.sh", got)
	}
}

func TestSelectDomain_WithPromptCacheKey(t *testing.T) {
	m := ModelMapping{
		Domain:  "a.tinfoil.sh",
		Domains: []string{"a.tinfoil.sh", "b.tinfoil.sh", "c.tinfoil.sh"},
	}
	// Same prompt_cache_key should always select the same domain.
	key := "my-cache-key"
	first := m.SelectDomain(key)
	if first == "" {
		t.Fatal("SelectDomain returned empty string")
	}
	for range 10 {
		got := m.SelectDomain(key)
		if got != first {
			t.Errorf("SelectDomain not deterministic: got %q, want %q", got, first)
		}
	}
}

func TestSelectDomain_DifferentKeysDifferentDomains(t *testing.T) {
	m := ModelMapping{
		Domain:  "a.tinfoil.sh",
		Domains: []string{"a.tinfoil.sh", "b.tinfoil.sh", "c.tinfoil.sh", "d.tinfoil.sh"},
	}
	// Different keys should distribute across domains (at least 2 distinct).
	seen := make(map[string]bool)
	for i := range 100 {
		key := fmt.Sprintf("key-%d", i)
		seen[m.SelectDomain(key)] = true
	}
	if len(seen) < 2 {
		t.Errorf("expected at least 2 distinct domains, got %d", len(seen))
	}
}

func TestSelectDomain_EmptyDomains(t *testing.T) {
	m := ModelMapping{
		Domain:  "fallback.tinfoil.sh",
		Domains: nil,
	}
	got := m.SelectDomain("some-key")
	if got != "fallback.tinfoil.sh" {
		t.Errorf("SelectDomain with nil Domains = %q, want fallback.tinfoil.sh", got)
	}
}

func TestResolve_WithPromptCacheKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, proxyResponseMultiEnclaveJSON("gemma4-31b",
			"gemma4-31b-1.inf10.tinfoil.sh",
			"gemma4-31b-2.inf10.tinfoil.sh",
			"gemma4-31b-3.inf10.tinfoil.sh",
		))
	}))
	defer srv.Close()

	resolver := newDirectResolverForTest(srv.URL)

	// Without prompt_cache_key: lexicographically smallest.
	ctx := context.Background()
	domain, err := resolver.Resolve(ctx, "gemma4-31b")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if domain != "gemma4-31b-1.inf10.tinfoil.sh" {
		t.Errorf("domain without key = %q, want gemma4-31b-1.inf10.tinfoil.sh", domain)
	}

	// With prompt_cache_key: should be deterministic and may differ.
	ctx = WithPromptCacheKey(context.Background(), "test-cache-key")
	domainWithKey, err := resolver.Resolve(ctx, "gemma4-31b")
	if err != nil {
		t.Fatalf("Resolve with key: %v", err)
	}
	if domainWithKey == "" {
		t.Fatal("domain with key is empty")
	}

	// Same key should always produce the same domain.
	domainAgain, err := resolver.Resolve(ctx, "gemma4-31b")
	if err != nil {
		t.Fatalf("Resolve with key (2nd): %v", err)
	}
	if domainAgain != domainWithKey {
		t.Errorf("domain not deterministic: %q vs %q", domainWithKey, domainAgain)
	}
}

func TestPromptCacheKeyFromContext(t *testing.T) {
	// Empty context returns empty string.
	if got := PromptCacheKeyFromContext(context.Background()); got != "" {
		t.Errorf("empty context: got %q, want empty", got)
	}

	// Set and get.
	ctx := WithPromptCacheKey(context.Background(), "my-key")
	if got := PromptCacheKeyFromContext(ctx); got != "my-key" {
		t.Errorf("set context: got %q, want my-key", got)
	}
}
