package attestation

import (
	"fmt"
	"sync"
	"testing"
	"time"

	pb "github.com/google/go-sev-guest/proto/sevsnp"
)

func TestSEVCacheKey(t *testing.T) {
	k1 := sevCacheKey([]byte{0xab, 0xcd}, 0x0102030405060708)
	k2 := sevCacheKey([]byte{0xab, 0xcd}, 0x0102030405060708)
	if k1 != k2 {
		t.Fatalf("sevCacheKey not deterministic: %q != %q", k1, k2)
	}
	// Distinct chip ID or TCB must produce distinct keys.
	if sevCacheKey([]byte{0xab, 0xce}, 0x0102030405060708) == k1 {
		t.Error("distinct chip ID should produce distinct key")
	}
	if sevCacheKey([]byte{0xab, 0xcd}, 0x0102030405060709) == k1 {
		t.Error("distinct reportedTcb should produce distinct key (no downgrade risk)")
	}
}

func TestSEVCertCache_PutGet(t *testing.T) {
	c := NewSEVCertCache()
	key := sevCacheKey([]byte{1, 2, 3}, 42)

	if _, ok := c.Get(key); ok {
		t.Fatal("empty cache should not contain anything")
	}

	chain := &pb.CertificateChain{VcekCert: []byte("vcek"), AskCert: []byte("ask"), ArkCert: []byte("ark")}
	c.Put(key, chain)

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("expected cache hit after Put")
	}
	if string(got.GetVcekCert()) != "vcek" {
		t.Errorf("VcekCert = %q, want %q", got.GetVcekCert(), "vcek")
	}
	if string(got.GetAskCert()) != "ask" || string(got.GetArkCert()) != "ark" {
		t.Errorf("AskCert/ArkCert not preserved: %+v", got)
	}

	// A different key must miss.
	if _, ok := c.Get(sevCacheKey([]byte{9, 9, 9}, 1)); ok {
		t.Error("different key should not hit")
	}
}

// TestSEVCertCache_CloneIsolation verifies that neither Put nor Get exposes
// the caller to mutation of the cached proto (or vice versa) — a cache hit
// must supply certificate bytes only, never a reference the caller could
// corrupt for a later reader.
func TestSEVCertCache_CloneIsolation(t *testing.T) {
	c := NewSEVCertCache()
	key := "k"
	chain := &pb.CertificateChain{VcekCert: []byte("original")}
	c.Put(key, chain)

	// Mutating the input after Put must not affect the cached copy.
	chain.VcekCert = []byte("mutated-input")

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if string(got.GetVcekCert()) != "original" {
		t.Errorf("Put did not clone its input: got %q", got.GetVcekCert())
	}

	// Mutating a Get result must not affect a subsequent Get.
	got.VcekCert = []byte("mutated-output")
	got2, ok := c.Get(key)
	if !ok {
		t.Fatal("expected second cache hit")
	}
	if string(got2.GetVcekCert()) != "original" {
		t.Errorf("Get did not clone its output: got %q", got2.GetVcekCert())
	}
}

func TestSEVCertCache_Expiry(t *testing.T) {
	c := NewSEVCertCacheWithTTL(time.Hour)
	key := "k"
	c.Put(key, &pb.CertificateChain{VcekCert: []byte("v")})

	if _, ok := c.Get(key); !ok {
		t.Fatal("expected hit immediately after Put")
	}

	// Backdate the entry beyond the TTL.
	c.mu.Lock()
	e := c.entries[key]
	e.addedAt = time.Now().Add(-2 * time.Hour)
	c.entries[key] = e
	c.mu.Unlock()

	if _, ok := c.Get(key); ok {
		t.Fatal("expired entry should not be found by Get")
	}
}

// TestSEVCertCache_ExpiredPrunedOnPut verifies that Put prunes expired
// entries rather than accumulating them forever.
func TestSEVCertCache_ExpiredPrunedOnPut(t *testing.T) {
	c := NewSEVCertCacheWithTTL(time.Hour)
	c.Put("old", &pb.CertificateChain{VcekCert: []byte("old")})

	c.mu.Lock()
	e := c.entries["old"]
	e.addedAt = time.Now().Add(-2 * time.Hour)
	c.entries["old"] = e
	c.mu.Unlock()

	c.Put("new", &pb.CertificateChain{VcekCert: []byte("new")})

	if got := c.Len(); got != 1 {
		t.Errorf("Len = %d, want 1 (expired entry pruned)", got)
	}
	if _, ok := c.Get("old"); ok {
		t.Error("expired entry should have been pruned on Put")
	}
	if _, ok := c.Get("new"); !ok {
		t.Error("new entry should be present")
	}
}

// TestSEVCertCache_EvictOldest verifies that once the cache is at capacity,
// adding a new entry evicts the oldest rather than growing unboundedly.
func TestSEVCertCache_EvictOldest(t *testing.T) {
	c := NewSEVCertCacheWithTTL(time.Hour)

	for i := range maxSEVCertEntries + 1 {
		key := fmt.Sprintf("chip-%d", i)
		c.Put(key, &pb.CertificateChain{VcekCert: []byte(key)})
	}

	if got := c.Len(); got != maxSEVCertEntries {
		t.Errorf("Len = %d, want %d (oldest evicted)", got, maxSEVCertEntries)
	}
	if _, ok := c.Get("chip-0"); ok {
		t.Error("oldest entry should have been evicted")
	}
	if _, ok := c.Get(fmt.Sprintf("chip-%d", maxSEVCertEntries)); !ok {
		t.Error("newest entry should still be present")
	}
}

// TestSEVCertCache_NilReceiver verifies every method is safe to call on a
// nil *SEVCertCache: Get always misses, Put is a no-op, Len is 0. A cache
// miss can only trigger a real re-fetch, never unattested pass-through.
func TestSEVCertCache_NilReceiver(t *testing.T) {
	var c *SEVCertCache

	if _, ok := c.Get("k"); ok {
		t.Error("nil cache Get should always miss")
	}
	if got := c.Len(); got != 0 {
		t.Errorf("nil cache Len = %d, want 0", got)
	}

	// Must not panic.
	c.Put("k", &pb.CertificateChain{VcekCert: []byte("v")})

	if _, ok := c.Get("k"); ok {
		t.Error("nil cache Put should be a no-op; Get should still miss")
	}
}

// TestSEVCertCache_ConcurrentAccess exercises concurrent Get/Put from many
// goroutines. Run with -race to catch data races on the shared map.
func TestSEVCertCache_ConcurrentAccess(t *testing.T) {
	c := NewSEVCertCache()
	var wg sync.WaitGroup

	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("chip-%d", i%10)
			c.Put(key, &pb.CertificateChain{VcekCert: fmt.Appendf(nil, "v%d", i)})
		}(i)
	}
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("chip-%d", i%10)
			c.Get(key) // must not panic or race
		}(i)
	}

	wg.Wait()
}
