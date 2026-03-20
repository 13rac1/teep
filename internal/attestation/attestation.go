package attestation

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Nonce is a 32-byte cryptographic nonce for attestation replay protection.
// The zero value is not valid; use NewNonce or ParseNonce.
type Nonce [32]byte

// NewNonce generates a fresh random 32-byte nonce.
// Panics if crypto/rand fails — a broken random source is unrecoverable.
func NewNonce() Nonce {
	var n Nonce
	if _, err := rand.Read(n[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return n
}

// Hex returns the nonce as a 64-character lowercase hex string.
func (n Nonce) Hex() string { return hex.EncodeToString(n[:]) }

// ParseNonce decodes a 64-character hex string into a Nonce.
func ParseNonce(s string) (Nonce, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return Nonce{}, fmt.Errorf("invalid nonce hex: %w", err)
	}
	if len(b) != 32 {
		return Nonce{}, fmt.Errorf("nonce must be 32 bytes, got %d", len(b))
	}
	var n Nonce
	copy(n[:], b)
	return n, nil
}

// RawAttestation holds the parsed fields from a TEE provider's attestation
// endpoint response (Venice /tee/attestation, NEAR /attestation/report, etc.).
// All fields are raw strings exactly as returned by the provider; higher layers
// are responsible for validation.
type RawAttestation struct {
	// Verified is the server-side verification result. This is a convenience
	// flag from the provider — clients must perform their own client-side checks.
	Verified bool

	// Nonce is the hex nonce echoed back by the provider.
	Nonce string

	// Model is the attested model identifier.
	Model string

	// TEEProvider identifies the TEE type (e.g. "TDX", "TDX+NVIDIA").
	TEEProvider string

	// SigningKey is the uncompressed secp256k1 public key in hex (130 chars,
	// starts with "04"). Used for E2EE key exchange.
	SigningKey string

	// SigningAddress is the keccak256-derived address of SigningKey.
	// Present for Venice; may be empty for other providers.
	SigningAddress string

	// IntelQuote is the raw Intel TDX quote, hex or base64-encoded.
	IntelQuote string

	// NvidiaPayload is the NVIDIA GPU attestation JWT or raw payload.
	NvidiaPayload string

	// TLSFingerprint is the hex SHA-256 of the backend's TLS certificate SPKI.
	// Set by providers that perform connection-level attestation (NEAR AI).
	// Empty for E2EE providers (Venice).
	TLSFingerprint string

	// TEE environment metadata from the provider's attestation response.
	TEEHardware        string          // e.g. "intel-tdx"
	SigningAlgo        string          // e.g. "ecdsa"
	UpstreamModel      string          // HuggingFace model ID
	AppName            string          // dstack app name
	ComposeHash        string          // docker-compose hash
	AppCompose         string          // raw app_compose JSON from info.tcb_info
	OSImageHash        string          // OS image hash
	DeviceID           string          // TDX device ID
	EventLogCount      int             // number of event log entries
	NonceSource        string          // "client" or "server"
	CandidatesAvail    int             // node pool size
	CandidatesEval     int             // nodes evaluated
	ServerVerification json.RawMessage // provider's own verification result (opaque)

	// RawBody is the unmodified HTTP response body from the provider.
	// Used by --save-dir to write the original JSON as-is.
	RawBody []byte `json:"-"`
}

// cacheKey identifies a provider/model pair for cache lookups.
// Using a struct avoids delimiter-based key collisions.
type cacheKey struct {
	provider string
	model    string
}

// cacheEntry stores a verified report and the time it was populated.
type cacheEntry struct {
	report    *VerificationReport
	fetchedAt time.Time
}

// Cache stores expensive attestation verification results keyed by
// provider+model. The signing key is intentionally NOT cached — each E2EE
// session fetches a fresh signing key to prevent TOCTOU with key rotation.
type Cache struct {
	mu      sync.RWMutex
	entries map[cacheKey]*cacheEntry
	ttl     time.Duration
}

// NewCache returns a Cache with the specified TTL.
func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		entries: make(map[cacheKey]*cacheEntry),
		ttl:     ttl,
	}
}

// Get returns the cached VerificationReport for the given provider and model,
// or (nil, false) if absent or expired.
func (c *Cache) Get(provider, model string) (*VerificationReport, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[cacheKey{provider, model}]
	if !ok || time.Since(e.fetchedAt) > c.ttl {
		return nil, false
	}
	return e.report, true
}

// maxCacheEntries is the threshold above which expired entries are evicted
// during Put/Record to prevent unbounded memory growth.
const maxCacheEntries = 1000

// Put stores a VerificationReport for the given provider and model.
func (c *Cache) Put(provider, model string, report *VerificationReport) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) > maxCacheEntries {
		now := time.Now()
		for k, e := range c.entries {
			if now.Sub(e.fetchedAt) > c.ttl {
				delete(c.entries, k)
			}
		}
	}
	c.entries[cacheKey{provider, model}] = &cacheEntry{
		report:    report,
		fetchedAt: time.Now(),
	}
}

// NegativeCache records attestation failures to prevent repeated upstream
// hammering when attestation has recently failed. Entries expire after TTL.
type NegativeCache struct {
	mu      sync.RWMutex
	entries map[cacheKey]time.Time
	ttl     time.Duration
}

// NewNegativeCache returns a NegativeCache with the specified TTL.
func NewNegativeCache(ttl time.Duration) *NegativeCache {
	return &NegativeCache{
		entries: make(map[cacheKey]time.Time),
		ttl:     ttl,
	}
}

// IsBlocked returns true if a recent failure for the given provider and model
// is still within the TTL window.
func (c *NegativeCache) IsBlocked(provider, model string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	t, ok := c.entries[cacheKey{provider, model}]
	return ok && time.Since(t) < c.ttl
}

// Record records an attestation failure for the given provider and model.
func (c *NegativeCache) Record(provider, model string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) > maxCacheEntries {
		now := time.Now()
		for k, t := range c.entries {
			if now.Sub(t) > c.ttl {
				delete(c.entries, k)
			}
		}
	}
	c.entries[cacheKey{provider, model}] = time.Now()
}
