package attestation

import (
	"encoding/hex"
	"strconv"
	"sync"
	"time"

	pb "github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/proto"
)

const (
	// sevCertCacheTTL is how long a fetched VCEK certificate chain is
	// trusted before a fresh AMD KDS fetch is required. The VCEK is
	// per-chip/per-TCB and long-lived; reportedTcb is part of the cache
	// key (see sevCacheKey), so a TCB change is always a distinct cache
	// entry rather than a stale-downgrade risk.
	sevCertCacheTTL = 24 * time.Hour

	// maxSEVCertEntries caps the number of distinct chip/TCB chains held in
	// memory, preventing unbounded growth. When exceeded, the oldest entry
	// is evicted.
	maxSEVCertEntries = 1024
)

// sevCertEntry stores a cached VCEK certificate chain with its insertion time.
type sevCertEntry struct {
	chain   *pb.CertificateChain
	addedAt time.Time
}

// SEVCertCache caches VCEK certificate chains fetched from AMD KDS, keyed by
// chip ID and reported TCB version. A cache hit supplies certificate bytes
// only — it never supplies a verdict. The caller must re-run the
// cryptographic signature/chain verification on every request; the cache
// exists solely so that a KDS outage does not force a fetch failure once a
// chain has been fetched and verified successfully at least once.
//
// Thread-safe for concurrent reads and writes. All methods are safe to call
// on a nil *SEVCertCache (no-op / cache miss), so callers never need a nil
// check before use.
type SEVCertCache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[string]sevCertEntry
}

// NewSEVCertCache returns an empty VCEK cert cache with a 24-hour TTL.
func NewSEVCertCache() *SEVCertCache {
	return NewSEVCertCacheWithTTL(sevCertCacheTTL)
}

// NewSEVCertCacheWithTTL returns an empty VCEK cert cache with the specified TTL.
func NewSEVCertCacheWithTTL(ttl time.Duration) *SEVCertCache {
	return &SEVCertCache{
		ttl:     ttl,
		entries: make(map[string]sevCertEntry),
	}
}

// sevCacheKey builds the cache key from the report's chip ID and reported
// TCB version, so a TCB change (or a distinct chip) is always a distinct
// cache entry.
func sevCacheKey(chipID []byte, reportedTCB uint64) string {
	return hex.EncodeToString(chipID) + "|" + strconv.FormatUint(reportedTCB, 16)
}

// Get returns a deep copy of the cached certificate chain for key, if
// present and not expired. The clone protects the cache from mutation by
// callers holding the returned proto. Nil-receiver-safe: a nil cache always
// misses.
func (c *SEVCertCache) Get(key string) (*pb.CertificateChain, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if time.Since(e.addedAt) > c.ttl {
		return nil, false
	}
	return cloneCertChain(e.chain), true
}

// Put stores a deep copy of chain under key. Expired entries are pruned
// first; if the cache is still at capacity, the oldest entry is evicted.
// Nil-receiver-safe: a Put on a nil cache is a no-op (the caller re-fetches
// next time, which is always safe — a cache miss can only trigger a real
// fetch, never a pass-through).
func (c *SEVCertCache) Put(key string, chain *pb.CertificateChain) {
	if c == nil || chain == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if time.Since(e.addedAt) > c.ttl {
			delete(c.entries, k)
		}
	}
	if len(c.entries) >= maxSEVCertEntries {
		c.evictOldestLocked()
	}
	c.entries[key] = sevCertEntry{
		chain:   cloneCertChain(chain),
		addedAt: time.Now(),
	}
}

// Len returns the number of entries currently in the cache (including
// expired ones). Nil-receiver-safe. Intended for tests.
func (c *SEVCertCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// evictOldestLocked removes the entry with the earliest addedAt. Called
// under the write lock.
func (c *SEVCertCache) evictOldestLocked() {
	var victim string
	var victimAt time.Time
	first := true
	for k, e := range c.entries {
		if first || e.addedAt.Before(victimAt) {
			victim = k
			victimAt = e.addedAt
			first = false
		}
	}
	if victim != "" {
		delete(c.entries, victim)
	}
}

// cloneCertChain returns a deep copy of chain via proto.Clone, checking the
// type assertion rather than trusting proto.Clone's concrete return type.
func cloneCertChain(chain *pb.CertificateChain) *pb.CertificateChain {
	cloned, ok := proto.Clone(chain).(*pb.CertificateChain)
	if !ok {
		// Unreachable: proto.Clone always returns the same concrete type as
		// its input. Fail loudly rather than silently return a wrong type.
		panic("proto.Clone did not return *sevsnp.CertificateChain")
	}
	return cloned
}
