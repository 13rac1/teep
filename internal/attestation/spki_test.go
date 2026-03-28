package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"
)

// selfSignedCertDER generates a self-signed certificate and returns its DER bytes.
func selfSignedCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func TestComputeSPKIHash(t *testing.T) {
	der := selfSignedCertDER(t)

	hash, err := ComputeSPKIHash(der)
	if err != nil {
		t.Fatalf("ComputeSPKIHash: %v", err)
	}

	// Verify by computing independently.
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	expected := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	expectedHex := hex.EncodeToString(expected[:])

	if hash != expectedHex {
		t.Errorf("ComputeSPKIHash = %q, want %q", hash, expectedHex)
	}

	// 64 hex chars = 32 bytes SHA-256.
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}
}

func TestComputeSPKIHash_InvalidDER(t *testing.T) {
	_, err := ComputeSPKIHash([]byte("not a cert"))
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}
}

func TestSPKICache_ContainsAdd(t *testing.T) {
	c := NewSPKICache()

	if c.Contains("example.com", "aabbccdd") {
		t.Fatal("empty cache should not contain anything")
	}

	c.Add("example.com", "aabbccdd")

	if !c.Contains("example.com", "aabbccdd") {
		t.Fatal("cache should contain added entry")
	}

	// Different domain should not match.
	if c.Contains("other.com", "aabbccdd") {
		t.Fatal("different domain should not match")
	}

	// Different hash should not match.
	if c.Contains("example.com", "11223344") {
		t.Fatal("different hash should not match")
	}

	// Multiple hashes per domain.
	c.Add("example.com", "11223344")
	if !c.Contains("example.com", "aabbccdd") {
		t.Fatal("first hash should still be present")
	}
	if !c.Contains("example.com", "11223344") {
		t.Fatal("second hash should be present")
	}
}

func TestSPKICache_Expiry(t *testing.T) {
	c := NewSPKICache()

	c.Add("example.com", "aabbccdd")
	if !c.Contains("example.com", "aabbccdd") {
		t.Fatal("entry should be present immediately after Add")
	}

	// Backdate the entry beyond the TTL.
	c.mu.Lock()
	c.domains["example.com"]["aabbccdd"] = spkiEntry{
		addedAt: time.Now().Add(-2 * defaultSPKITTL),
	}
	c.mu.Unlock()

	if c.Contains("example.com", "aabbccdd") {
		t.Fatal("expired entry should not be found by Contains")
	}

	// Adding a new entry should prune the expired one.
	c.Add("example.com", "11223344")
	c.mu.RLock()
	_, stalePresent := c.domains["example.com"]["aabbccdd"]
	c.mu.RUnlock()
	if stalePresent {
		t.Fatal("expired entry should be pruned on Add")
	}
}

func TestSPKICache_ConcurrentAccess(t *testing.T) {
	c := NewSPKICache()
	var wg sync.WaitGroup

	// Concurrent writers.
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hash := hex.EncodeToString([]byte{byte(i)})
			c.Add("domain.com", hash)
		}(i)
	}

	// Concurrent readers.
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hash := hex.EncodeToString([]byte{byte(i)})
			c.Contains("domain.com", hash) // must not panic
		}(i)
	}

	wg.Wait()
}

// TestSPKICache_MaxSPKIsPerDomain verifies that adding more than 16 SPKIs
// for a single domain evicts the oldest entry and keeps the latest 16.
func TestSPKICache_MaxSPKIsPerDomain(t *testing.T) {
	c := NewSPKICacheWithTTL(time.Hour)

	// Add 17 SPKIs with staggered timestamps.
	for i := range 17 {
		hash := fmt.Sprintf("%064x", i)
		c.Add("example.com", hash)
	}

	// Should have 16 entries (oldest evicted).
	if got := c.Len(); got != 16 {
		t.Errorf("Len = %d, want 16", got)
	}

	// The first (oldest) SPKI should be evicted.
	first := fmt.Sprintf("%064x", 0)
	if c.Contains("example.com", first) {
		t.Error("oldest SPKI should have been evicted")
	}

	// The last 16 should all be present.
	for i := 1; i <= 16; i++ {
		hash := fmt.Sprintf("%064x", i)
		if !c.Contains("example.com", hash) {
			t.Errorf("SPKI %d should be present", i)
		}
	}
}

// TestSPKICache_MaxDomains verifies that adding more than 1024 domains
// evicts the domain with the globally oldest SPKI entry.
func TestSPKICache_MaxDomains(t *testing.T) {
	c := NewSPKICacheWithTTL(time.Hour)

	// Add entries for 1025 domains.
	for i := range 1025 {
		domain := fmt.Sprintf("d%d.example.com", i)
		c.Add(domain, "aabbccdd")
	}

	// Should have 1024 domains (oldest evicted).
	if got := c.DomainCount(); got != 1024 {
		t.Errorf("DomainCount = %d, want 1024", got)
	}

	// The first domain inserted should be the one evicted.
	if c.Contains("d0.example.com", "aabbccdd") {
		t.Error("oldest domain should have been evicted")
	}

	// A later domain should still be present.
	if !c.Contains("d1024.example.com", "aabbccdd") {
		t.Error("newest domain should be present")
	}
}

// TestSPKICache_ExpiredPrunedBeforeEviction verifies that expired entries
// are pruned before evicting any non-expired entry.
func TestSPKICache_ExpiredPrunedBeforeEviction(t *testing.T) {
	c := NewSPKICacheWithTTL(time.Hour)

	// Add 16 SPKIs — filling the per-domain limit.
	for i := range 16 {
		hash := fmt.Sprintf("%064x", i)
		c.Add("example.com", hash)
	}

	// Backdate half the entries to make them expired.
	c.mu.Lock()
	for i := range 8 {
		hash := fmt.Sprintf("%064x", i)
		c.domains["example.com"][hash] = spkiEntry{
			addedAt: time.Now().Add(-2 * time.Hour),
		}
	}
	c.mu.Unlock()

	// Add a new entry — should prune the 8 expired ones, not evict non-expired.
	c.Add("example.com", fmt.Sprintf("%064x", 99))

	// 8 non-expired originals + 1 new = 9 entries.
	if got := c.Len(); got != 9 {
		t.Errorf("Len = %d, want 9 (8 non-expired + 1 new)", got)
	}

	// Non-expired entries 8–15 should still be present.
	for i := 8; i < 16; i++ {
		hash := fmt.Sprintf("%064x", i)
		if !c.Contains("example.com", hash) {
			t.Errorf("non-expired SPKI %d should still be present", i)
		}
	}
}

// TestSPKICache_ContainsExpiredEntry verifies Contains returns false for
// entries past TTL even though the map still holds the key.
func TestSPKICache_ContainsExpiredEntry(t *testing.T) {
	c := NewSPKICacheWithTTL(time.Nanosecond)
	c.Add("example.com", "aabbccdd")

	// Deterministically backdate the entry so it is past TTL, without relying
	// on any actual time passing between Add and Contains.
	c.mu.Lock()
	entry := c.domains["example.com"]["aabbccdd"]
	entry.addedAt = time.Now().Add(-time.Hour)
	c.domains["example.com"]["aabbccdd"] = entry
	c.mu.Unlock()
	if c.Contains("example.com", "aabbccdd") {
		t.Error("expired entry should not be found by Contains")
	}
}

// TestSPKICache_AddIdempotent verifies that adding the same domain+spki
// twice results in one entry with a refreshed timestamp.
func TestSPKICache_AddIdempotent(t *testing.T) {
	c := NewSPKICacheWithTTL(time.Hour)

	c.Add("example.com", "aabbccdd")
	if got := c.Len(); got != 1 {
		t.Fatalf("Len after first Add = %d, want 1", got)
	}

	// Record the timestamp.
	c.mu.RLock()
	first := c.domains["example.com"]["aabbccdd"].addedAt
	c.mu.RUnlock()

	// Re-add the same entry.
	c.Add("example.com", "aabbccdd")
	if got := c.Len(); got != 1 {
		t.Errorf("Len after second Add = %d, want 1", got)
	}

	c.mu.RLock()
	second := c.domains["example.com"]["aabbccdd"].addedAt
	c.mu.RUnlock()

	if !second.After(first) && second != first {
		t.Error("timestamp should be refreshed (or equal) on re-add")
	}
}

// TestSPKICache_LenAndDomainCount verifies the Len and DomainCount methods.
func TestSPKICache_LenAndDomainCount(t *testing.T) {
	c := NewSPKICacheWithTTL(time.Hour)

	if c.Len() != 0 || c.DomainCount() != 0 {
		t.Fatal("empty cache should have Len=0 and DomainCount=0")
	}

	c.Add("a.com", "hash1")
	c.Add("a.com", "hash2")
	c.Add("b.com", "hash3")

	if got := c.Len(); got != 3 {
		t.Errorf("Len = %d, want 3", got)
	}
	if got := c.DomainCount(); got != 2 {
		t.Errorf("DomainCount = %d, want 2", got)
	}
}
