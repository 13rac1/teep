package attestation

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ComputeSPKIHash returns the lowercase hex SHA-256 of a DER-encoded
// certificate's SubjectPublicKeyInfo. This matches the SPKI fingerprinting
// scheme used by NEAR AI's proxy.py.
func ComputeSPKIHash(certDER []byte) (string, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:]), nil
}

const (
	// maxSPKIsPerDomain limits the number of SPKI hashes stored per domain.
	// When exceeded, the oldest entry is evicted.
	maxSPKIsPerDomain = 16

	// maxDomains caps the total number of distinct domains in the cache,
	// preventing unbounded memory growth under a stream of unique domains.
	// When exceeded, the domain with the oldest SPKI entry is evicted first.
	maxDomains = 1024

	// defaultSPKITTL is how long a cached SPKI hash is trusted before
	// re-attestation is required. This limits the window during which a
	// stale pin is accepted after a key rotation.
	defaultSPKITTL = PinnedCacheTTL
)

// spkiEntry stores a verified SPKI hash with its insertion time.
type spkiEntry struct {
	addedAt time.Time
}

// SPKICache stores verified TLS certificate SPKI hashes per domain.
// After attestation verifies that a given SPKI hash belongs to a TEE backend,
// subsequent connections presenting the same certificate skip attestation.
// Entries expire after the configured TTL, forcing re-attestation.
//
// Thread-safe for concurrent reads and writes.
type SPKICache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	domains map[string]map[string]spkiEntry // domain → spkiHex → entry
}

// NewSPKICache returns an empty SPKI cache with a 1-hour TTL.
func NewSPKICache() *SPKICache {
	return NewSPKICacheWithTTL(defaultSPKITTL)
}

// NewSPKICacheWithTTL returns an empty SPKI cache with the specified TTL.
func NewSPKICacheWithTTL(ttl time.Duration) *SPKICache {
	return &SPKICache{
		ttl:     ttl,
		domains: make(map[string]map[string]spkiEntry),
	}
}

// Len returns the total number of SPKI entries across all domains
// (including expired ones).
func (c *SPKICache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	n := 0
	for _, hashes := range c.domains {
		n += len(hashes)
	}
	return n
}

// DomainCount returns the number of distinct domains in the cache.
func (c *SPKICache) DomainCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.domains)
}

// Contains reports whether the given SPKI hash has been verified for domain
// and has not expired.
//
// The SPKI hex comparison is performed with subtle.ConstantTimeCompare to
// eliminate timing side-channels on cache membership (F-20).
func (c *SPKICache) Contains(domain, spkiHex string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	hashes, ok := c.domains[domain]
	if !ok {
		return false
	}
	spkiBytes := []byte(spkiHex)
	now := time.Now()
	for k, e := range hashes {
		if subtle.ConstantTimeCompare([]byte(k), spkiBytes) == 1 {
			return now.Sub(e.addedAt) <= c.ttl
		}
	}
	return false
}

// Add records a verified SPKI hash for domain. Expired entries for the domain
// are pruned first. If the per-domain limit is still exceeded after pruning,
// the oldest entry is evicted. If the total domain count exceeds maxDomains,
// the domain with the globally oldest SPKI entry is evicted first (F-21).
func (c *SPKICache) Add(domain, spkiHex string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.domains[domain] == nil {
		// Enforce the overall domain cap before allocating a new bucket.
		if len(c.domains) >= maxDomains {
			c.evictOldestDomain()
		}
		c.domains[domain] = make(map[string]spkiEntry)
	}
	// Prune expired entries.
	for k, e := range c.domains[domain] {
		if time.Since(e.addedAt) > c.ttl {
			delete(c.domains[domain], k)
		}
	}
	if len(c.domains[domain]) >= maxSPKIsPerDomain {
		var oldestKey string
		var oldestAt time.Time
		for k, e := range c.domains[domain] {
			if oldestKey == "" || e.addedAt.Before(oldestAt) {
				oldestKey = k
				oldestAt = e.addedAt
			}
		}
		if oldestKey != "" {
			delete(c.domains[domain], oldestKey)
		}
	}
	c.domains[domain][spkiHex] = spkiEntry{addedAt: time.Now()}
}

// DeleteDomain removes all SPKI entries for the given domain. This forces
// re-attestation on the next connection to that domain. Used when the
// attestation report cache expires while SPKI entries are still live.
func (c *SPKICache) DeleteDomain(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.domains, domain)
}

// evictOldestDomain removes the domain whose oldest SPKI entry was
// added earliest. Called under the write lock.
func (c *SPKICache) evictOldestDomain() {
	var victim string
	var victimOldest time.Time
	for d, hashes := range c.domains {
		for _, e := range hashes {
			if victim == "" || e.addedAt.Before(victimOldest) {
				victim = d
				victimOldest = e.addedAt
			}
		}
	}
	if victim != "" {
		delete(c.domains, victim)
	}
}
