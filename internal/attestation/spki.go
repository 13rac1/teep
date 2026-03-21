package attestation

import (
	"crypto/sha256"
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
	// When exceeded, one arbitrary entry is evicted.
	maxSPKIsPerDomain = 16

	// defaultSPKITTL is how long a cached SPKI hash is trusted before
	// re-attestation is required. This limits the window during which a
	// stale pin is accepted after a key rotation.
	defaultSPKITTL = 1 * time.Hour
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
	return &SPKICache{
		ttl:     defaultSPKITTL,
		domains: make(map[string]map[string]spkiEntry),
	}
}

// Contains reports whether the given SPKI hash has been verified for domain
// and has not expired.
func (c *SPKICache) Contains(domain, spkiHex string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	hashes, ok := c.domains[domain]
	if !ok {
		return false
	}
	entry, found := hashes[spkiHex]
	if !found {
		return false
	}
	return time.Since(entry.addedAt) <= c.ttl
}

// Add records a verified SPKI hash for domain. Expired entries for the domain
// are pruned first. If the per-domain limit is still exceeded after pruning,
// one arbitrary entry is evicted.
func (c *SPKICache) Add(domain, spkiHex string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.domains[domain] == nil {
		c.domains[domain] = make(map[string]spkiEntry)
	}
	// Prune expired entries.
	for k, e := range c.domains[domain] {
		if time.Since(e.addedAt) > c.ttl {
			delete(c.domains[domain], k)
		}
	}
	if len(c.domains[domain]) >= maxSPKIsPerDomain {
		for k := range c.domains[domain] {
			delete(c.domains[domain], k)
			break
		}
	}
	c.domains[domain][spkiHex] = spkiEntry{addedAt: time.Now()}
}
