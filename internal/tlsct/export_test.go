package tlsct

import (
	"context"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

// Expose pure functions for external tests.
var IsPrivateHost = isPrivateHost
var ToCTChain = toCTChain
var CtEnabledFromOpt = ctEnabledFromOpt

// AddCacheEntry exposes addCacheEntry for eviction tests.
var AddCacheEntry = (*Checker).addCacheEntry

// SetLogListHTTP replaces the HTTP client used to fetch the CT log list.
func (c *Checker) SetLogListHTTP(client *http.Client) {
	c.logListHTTP = client
}

// InjectLogList pre-populates the cached log list, bypassing HTTP fetch.
func (c *Checker) InjectLogList(ll *loglist3.LogList) {
	c.logListMu.Lock()
	c.logList = ll
	c.logListAt = time.Now()
	c.logListMu.Unlock()
}

// CacheLen returns the number of entries in the cert cache.
func (c *Checker) CacheLen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// InjectCacheEntry adds a cache entry with a specific timestamp.
func (c *Checker) InjectCacheEntry(key string, checkedAt time.Time) {
	c.mu.Lock()
	c.entries[key] = certCacheEntry{checkedAt: checkedAt}
	c.mu.Unlock()
}

// LoadLogList exposes loadLogList for external tests.
func LoadLogList(ctx context.Context, c *Checker) (*loglist3.LogList, error) {
	return c.loadLogList(ctx)
}

// CertCacheKey computes the cache key for a host+cert pair, matching the
// format used internally by CheckTLSState.
func CertCacheKey(host string, cert *x509.Certificate) string {
	return certCacheKey(host, cert)
}
