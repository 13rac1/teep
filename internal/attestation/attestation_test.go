package attestation

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestNewNonce verifies the nonce is 32 bytes and non-zero.
func TestNewNonce(t *testing.T) {
	n := NewNonce()

	allZero := true
	for _, b := range n {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("NewNonce returned all-zero nonce; crypto/rand may be broken")
	}

	hex := n.Hex()
	if len(hex) != 64 {
		t.Errorf("Nonce.Hex() length: got %d, want 64", len(hex))
	}
}

// TestNewNonceUniqueness verifies two nonces are statistically distinct.
func TestNewNonceUniqueness(t *testing.T) {
	a := NewNonce()
	b := NewNonce()
	if a == b {
		t.Error("two NewNonce calls returned the same value; crypto/rand may be broken")
	}
}

// TestParseNonce tests all ParseNonce paths.
func TestParseNonce(t *testing.T) {
	original := NewNonce()
	hex := original.Hex()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid 64-char hex",
			input:   hex,
			wantErr: false,
		},
		{
			name:    "all zeros",
			input:   "0000000000000000000000000000000000000000000000000000000000000000",
			wantErr: false,
		},
		{
			name:    "not hex",
			input:   "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
			wantErr: true,
		},
		{
			name:    "too short (62 chars)",
			input:   hex[:62],
			wantErr: true,
		},
		{
			name:    "too long (66 chars)",
			input:   hex + "ff",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseNonce(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ParseNonce(%q): expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseNonce(%q): unexpected error: %v", tc.input, err)
				return
			}
			// Round-trip: parsed nonce must hex-encode back to the same string.
			if got.Hex() != tc.input {
				t.Errorf("ParseNonce round-trip: got %q, want %q", got.Hex(), tc.input)
			}
		})
	}

	// Verify the original nonce survives a round-trip.
	parsed, err := ParseNonce(hex)
	if err != nil {
		t.Fatalf("round-trip ParseNonce: %v", err)
	}
	if parsed != original {
		t.Error("round-trip nonce mismatch")
	}
}

// TestCacheGetPutMiss tests the happy path and cache miss.
func TestCacheGetPutMiss(t *testing.T) {
	c := NewCache(time.Minute)
	report := &VerificationReport{Provider: "venice", Model: "test-model"}

	// Miss on empty cache.
	if _, ok := c.Get("venice", "test-model"); ok {
		t.Error("Get on empty cache returned ok=true")
	}

	c.Put("venice", "test-model", report)

	// Hit after put.
	got, ok := c.Get("venice", "test-model")
	if !ok {
		t.Fatal("Get after Put returned ok=false")
	}
	if got != report {
		t.Error("Get returned wrong report pointer")
	}

	// Different model key must miss.
	if _, ok := c.Get("venice", "other-model"); ok {
		t.Error("Get for different model returned ok=true")
	}

	// Different provider key must miss.
	if _, ok := c.Get("neardirect", "test-model"); ok {
		t.Error("Get for different provider returned ok=true")
	}
}

// TestCacheTTLExpiry verifies expired entries are not returned.
func TestCacheTTLExpiry(t *testing.T) {
	c := NewCache(time.Nanosecond)
	report := &VerificationReport{}
	c.Put("p", "m", report)

	// Any measurable time > 1ns passes between Put and Get.
	if _, ok := c.Get("p", "m"); ok {
		t.Error("Get after TTL expiry returned ok=true")
	}
}

// TestNegativeCacheBasic tests the negative cache record and block flow.
func TestNegativeCacheBasic(t *testing.T) {
	c := NewNegativeCache(time.Minute)

	if c.IsBlocked("venice", "test-model") {
		t.Error("IsBlocked on empty cache returned true")
	}

	c.Record("venice", "test-model")

	if !c.IsBlocked("venice", "test-model") {
		t.Error("IsBlocked after Record returned false")
	}

	// Different key must not be blocked.
	if c.IsBlocked("venice", "other-model") {
		t.Error("IsBlocked for different model returned true")
	}
}

// TestNegativeCacheTTLExpiry verifies failure records expire.
func TestNegativeCacheTTLExpiry(t *testing.T) {
	c := NewNegativeCache(time.Nanosecond)
	c.Record("p", "m")

	// Any measurable time > 1ns passes between Record and IsBlocked.
	if c.IsBlocked("p", "m") {
		t.Error("IsBlocked after TTL expiry returned true")
	}
}

// TestNegativeCacheOverwrite verifies that re-recording refreshes the timestamp.
func TestNegativeCacheOverwrite(t *testing.T) {
	c := NewNegativeCache(time.Minute)
	c.Record("p", "m")

	if !c.IsBlocked("p", "m") {
		t.Error("IsBlocked after Record returned false")
	}

	// Record again — should still be blocked (fresh timestamp).
	c.Record("p", "m")
	if !c.IsBlocked("p", "m") {
		t.Error("IsBlocked after re-Record returned false")
	}
}

// --------------------------------------------------------------------------
// Cache.Len / Cache.Models / NegativeCache.Len tests
// --------------------------------------------------------------------------

func TestCacheLen(t *testing.T) {
	c := NewCache(time.Minute)
	t.Logf("empty cache Len = %d", c.Len())
	if c.Len() != 0 {
		t.Errorf("empty cache Len = %d, want 0", c.Len())
	}

	c.Put("venice", "model-a", &VerificationReport{})
	t.Logf("after 1 Put, Len = %d", c.Len())
	if c.Len() != 1 {
		t.Errorf("Len after 1 Put = %d, want 1", c.Len())
	}

	c.Put("neardirect", "model-b", &VerificationReport{})
	t.Logf("after 2 Puts, Len = %d", c.Len())
	if c.Len() != 2 {
		t.Errorf("Len after 2 Puts = %d, want 2", c.Len())
	}

	// Overwrite same key — should not increase Len.
	c.Put("venice", "model-a", &VerificationReport{})
	t.Logf("after overwrite, Len = %d", c.Len())
	if c.Len() != 2 {
		t.Errorf("Len after overwrite = %d, want 2", c.Len())
	}
}

func TestCacheModels(t *testing.T) {
	c := NewCache(time.Minute)

	// Empty cache returns empty slice.
	models := c.Models()
	t.Logf("empty cache Models = %v", models)
	if len(models) != 0 {
		t.Errorf("empty cache Models len = %d, want 0", len(models))
	}

	c.Put("venice", "qwen3", &VerificationReport{})
	c.Put("neardirect", "llama", &VerificationReport{})

	models = c.Models()
	t.Logf("after 2 Puts, Models = %v", models)
	if len(models) != 2 {
		t.Errorf("Models len = %d, want 2", len(models))
	}

	// Check that both entries are present (order not guaranteed).
	found := map[string]bool{}
	for _, m := range models {
		found[m.Provider+"/"+m.Model] = true
		t.Logf("  %s/%s fetched at %v", m.Provider, m.Model, m.FetchedAt)
		if m.FetchedAt.IsZero() {
			t.Errorf("FetchedAt is zero for %s/%s", m.Provider, m.Model)
		}
	}
	if !found["venice/qwen3"] {
		t.Error("venice/qwen3 not in Models()")
	}
	if !found["neardirect/llama"] {
		t.Error("neardirect/llama not in Models()")
	}
}

func TestCacheModels_ExcludesExpired(t *testing.T) {
	c := NewCache(time.Nanosecond)
	c.Put("p", "m", &VerificationReport{})

	// Entry expires immediately (TTL = 1ns).
	models := c.Models()
	t.Logf("expired cache Models len = %d", len(models))
	if len(models) != 0 {
		t.Errorf("expired entry should not appear in Models; got %d", len(models))
	}
}

func TestNegativeCacheLen(t *testing.T) {
	c := NewNegativeCache(time.Minute)
	t.Logf("empty negative cache Len = %d", c.Len())
	if c.Len() != 0 {
		t.Errorf("empty Len = %d, want 0", c.Len())
	}

	c.Record("venice", "model-a")
	t.Logf("after 1 Record, Len = %d", c.Len())
	if c.Len() != 1 {
		t.Errorf("Len after 1 Record = %d, want 1", c.Len())
	}

	c.Record("neardirect", "model-b")
	t.Logf("after 2 Records, Len = %d", c.Len())
	if c.Len() != 2 {
		t.Errorf("Len after 2 Records = %d, want 2", c.Len())
	}
}

// --------------------------------------------------------------------------
// Cache eviction tests
// --------------------------------------------------------------------------

func TestCachePutEviction(t *testing.T) {
	c := NewCache(time.Nanosecond) // Everything expires instantly.
	for i := range 1001 {
		c.Put("p", fmt.Sprintf("m-%d", i), &VerificationReport{})
	}
	t.Logf("cache Len before eviction trigger = %d", c.Len())

	// Next Put triggers eviction of all expired entries.
	c.Put("p", "final", &VerificationReport{})
	t.Logf("cache Len after eviction = %d", c.Len())

	// After eviction, only "final" (and maybe a few not-yet-expired) should remain.
	if c.Len() > 5 {
		t.Errorf("expected most entries evicted, got Len = %d", c.Len())
	}
}

func TestNegativeCacheRecordEviction(t *testing.T) {
	c := NewNegativeCache(time.Nanosecond) // Everything expires instantly.
	for i := range 1001 {
		c.Record("p", fmt.Sprintf("m-%d", i))
	}
	t.Logf("negative cache Len before eviction trigger = %d", c.Len())

	// Next Record triggers eviction of all expired entries.
	c.Record("p", "final")
	t.Logf("negative cache Len after eviction = %d", c.Len())

	if c.Len() > 5 {
		t.Errorf("expected most entries evicted, got Len = %d", c.Len())
	}
}

// --------------------------------------------------------------------------
// SigningKeyCache tests
// --------------------------------------------------------------------------

func TestSigningKeyCacheGetPutMiss(t *testing.T) {
	c := NewSigningKeyCache(time.Minute)

	// Miss on empty cache.
	if _, ok := c.Get("venice", "test-model"); ok {
		t.Error("Get on empty cache returned ok=true")
	}

	c.Put("venice", "test-model", "04abcdef...")
	t.Logf("put signing key for venice/test-model")

	// Hit after put.
	got, ok := c.Get("venice", "test-model")
	if !ok {
		t.Fatal("Get after Put returned ok=false")
	}
	t.Logf("got signing key: %s", got)
	if got != "04abcdef..." {
		t.Errorf("Get returned %q, want %q", got, "04abcdef...")
	}

	// Different model must miss.
	if _, ok := c.Get("venice", "other-model"); ok {
		t.Error("Get for different model returned ok=true")
	}

	// Different provider must miss.
	if _, ok := c.Get("neardirect", "test-model"); ok {
		t.Error("Get for different provider returned ok=true")
	}
}

func TestSigningKeyCacheTTLExpiry(t *testing.T) {
	c := NewSigningKeyCache(time.Nanosecond)
	c.Put("p", "m", "04abcdef...")

	// Any measurable time > 1ns passes between Put and Get.
	if _, ok := c.Get("p", "m"); ok {
		t.Error("Get after TTL expiry returned ok=true")
	}
	t.Log("signing key expired as expected")
}

func TestSigningKeyCachePutEviction(t *testing.T) {
	c := NewSigningKeyCache(time.Nanosecond) // Everything expires instantly.
	for i := range 1001 {
		c.Put("p", fmt.Sprintf("m-%d", i), "key")
	}
	t.Logf("signing key cache Len before eviction trigger = %d", c.Len())

	// Next Put triggers eviction of all expired entries.
	c.Put("p", "final", "key")
	t.Logf("signing key cache Len after eviction = %d", c.Len())

	if c.Len() > 5 {
		t.Errorf("expected most entries evicted, got Len = %d", c.Len())
	}
}

// --------------------------------------------------------------------------
// Eviction with all non-expired entries (I-1 regression tests)
// --------------------------------------------------------------------------

// TestCachePutEviction_AllNonExpired verifies that when all entries are within
// TTL (none expired), the cache still enforces a hard upper bound by evicting
// the oldest entry.
func TestCachePutEviction_AllNonExpired(t *testing.T) {
	c := NewCache(time.Hour) // Long TTL — nothing expires.
	for i := range maxCacheEntries + 2 {
		c.Put("p", fmt.Sprintf("m-%d", i), &VerificationReport{})
	}
	if c.Len() > maxCacheEntries {
		t.Errorf("cache should enforce hard cap; got Len = %d, want <= %d", c.Len(), maxCacheEntries)
	}
}

// TestNegativeCacheRecordEviction_AllNonExpired verifies that when all entries
// are within TTL, the negative cache still enforces a hard upper bound.
func TestNegativeCacheRecordEviction_AllNonExpired(t *testing.T) {
	c := NewNegativeCache(time.Hour) // Long TTL — nothing expires.
	for i := range maxCacheEntries + 2 {
		c.Record("p", fmt.Sprintf("m-%d", i))
	}
	if c.Len() > maxCacheEntries {
		t.Errorf("negative cache should enforce hard cap; got Len = %d, want <= %d", c.Len(), maxCacheEntries)
	}
}

// TestSigningKeyCachePutEviction_AllNonExpired verifies that when all entries
// are within TTL, the signing key cache still enforces a hard upper bound.
func TestSigningKeyCachePutEviction_AllNonExpired(t *testing.T) {
	c := NewSigningKeyCache(time.Hour) // Long TTL — nothing expires.
	for i := range maxCacheEntries + 2 {
		c.Put("p", fmt.Sprintf("m-%d", i), "key")
	}
	if c.Len() > maxCacheEntries {
		t.Errorf("signing key cache should enforce hard cap; got Len = %d, want <= %d", c.Len(), maxCacheEntries)
	}
}

// --------------------------------------------------------------------------
// Update-at-capacity tests (I-2 regression tests)
// --------------------------------------------------------------------------
// Updating an existing key at capacity must not evict unrelated entries.

func TestCachePut_UpdateAtCapacity(t *testing.T) {
	c := NewCache(time.Hour)
	for i := range maxCacheEntries {
		c.Put("p", fmt.Sprintf("m-%d", i), &VerificationReport{})
	}
	if c.Len() != maxCacheEntries {
		t.Fatalf("setup: Len = %d, want %d", c.Len(), maxCacheEntries)
	}
	// Update an existing key — should not evict anything.
	c.Put("p", "m-0", &VerificationReport{})
	if c.Len() != maxCacheEntries {
		t.Errorf("update evicted entries: Len = %d, want %d", c.Len(), maxCacheEntries)
	}
}

func TestNegativeCacheRecord_UpdateAtCapacity(t *testing.T) {
	c := NewNegativeCache(time.Hour)
	for i := range maxCacheEntries {
		c.Record("p", fmt.Sprintf("m-%d", i))
	}
	if c.Len() != maxCacheEntries {
		t.Fatalf("setup: Len = %d, want %d", c.Len(), maxCacheEntries)
	}
	// Update an existing key — should not evict anything.
	c.Record("p", "m-0")
	if c.Len() != maxCacheEntries {
		t.Errorf("update evicted entries: Len = %d, want %d", c.Len(), maxCacheEntries)
	}
}

func TestSigningKeyCachePut_UpdateAtCapacity(t *testing.T) {
	c := NewSigningKeyCache(time.Hour)
	for i := range maxCacheEntries {
		c.Put("p", fmt.Sprintf("m-%d", i), "key")
	}
	if c.Len() != maxCacheEntries {
		t.Fatalf("setup: Len = %d, want %d", c.Len(), maxCacheEntries)
	}
	// Update an existing key — should not evict anything.
	c.Put("p", "m-0", "new-key")
	if c.Len() != maxCacheEntries {
		t.Errorf("update evicted entries: Len = %d, want %d", c.Len(), maxCacheEntries)
	}
}

// --------------------------------------------------------------------------
// Concurrent access tests
// --------------------------------------------------------------------------

func TestCacheConcurrentAccess(t *testing.T) {
	c := NewCache(time.Minute)
	var wg sync.WaitGroup

	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.Put("p", fmt.Sprintf("m-%d", i), &VerificationReport{})
		}(i)
	}
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.Get("p", fmt.Sprintf("m-%d", i))
		}(i)
	}
	wg.Wait()
}

func TestNegativeCacheConcurrentAccess(t *testing.T) {
	c := NewNegativeCache(time.Minute)
	var wg sync.WaitGroup

	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.Record("p", fmt.Sprintf("m-%d", i))
		}(i)
	}
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.IsBlocked("p", fmt.Sprintf("m-%d", i))
		}(i)
	}
	wg.Wait()
}

func TestSigningKeyCacheConcurrentAccess(t *testing.T) {
	c := NewSigningKeyCache(time.Minute)
	var wg sync.WaitGroup

	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.Put("p", fmt.Sprintf("m-%d", i), "key")
		}(i)
	}
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.Get("p", fmt.Sprintf("m-%d", i))
		}(i)
	}
	wg.Wait()
}
