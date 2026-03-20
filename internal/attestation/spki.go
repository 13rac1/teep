package attestation

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"
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

// SPKICache stores verified TLS certificate SPKI hashes per domain.
// After attestation verifies that a given SPKI hash belongs to a TEE backend,
// subsequent connections presenting the same certificate skip attestation.
//
// Thread-safe for concurrent reads and writes.
type SPKICache struct {
	mu      sync.RWMutex
	domains map[string]map[string]struct{} // domain → set of SPKI hex hashes
}

// NewSPKICache returns an empty SPKI cache.
func NewSPKICache() *SPKICache {
	return &SPKICache{
		domains: make(map[string]map[string]struct{}),
	}
}

// Contains reports whether the given SPKI hash has been verified for domain.
func (c *SPKICache) Contains(domain, spkiHex string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	hashes, ok := c.domains[domain]
	if !ok {
		return false
	}
	_, found := hashes[spkiHex]
	return found
}

// Add records a verified SPKI hash for domain.
func (c *SPKICache) Add(domain, spkiHex string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.domains[domain] == nil {
		c.domains[domain] = make(map[string]struct{})
	}
	c.domains[domain][spkiHex] = struct{}{}
}
