package attestation

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
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

// HexPrefix returns the first 8 hex characters of the nonce for safe logging.
func (n Nonce) HexPrefix() string { return hex.EncodeToString(n[:4]) }

// NoncePrefix returns the first 8 characters of a hex-encoded nonce string.
// Used for safe logging of nonce values from untrusted sources.
func NoncePrefix(hexNonce string) string {
	if len(hexNonce) > 8 {
		return hexNonce[:8]
	}
	return hexNonce
}

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

// BackendFormat identifies which backend attestation format a response uses.
// Set by Attesters during ParseAttestationResponse. Gateway providers use this
// to dispatch to the correct ReportDataVerifier via multi.Verifier.
type BackendFormat string

// BackendFormat constants for known attestation backends.
const (
	FormatDstack  BackendFormat = "dstack"
	FormatChutes  BackendFormat = "chutes"
	FormatTinfoil BackendFormat = "tinfoil"
	FormatGateway BackendFormat = "gateway"
	FormatNear    BackendFormat = "near"
)

// GPUEvidence is a single GPU's NVIDIA attestation entry: an X.509 certificate
// chain and SPDM 1.1 measurement signature. Used by chutes-format providers
// that return per-GPU evidence instead of a single EAT envelope.
type GPUEvidence struct {
	Certificate string `json:"certificate"` // base64-encoded PEM certificate chain
	Evidence    string `json:"evidence"`    // base64-encoded SPDM measurement blob
	Arch        string `json:"arch"`        // GPU architecture (e.g. "HOPPER")
}

// EventLogEntry is one entry in the TDX event log — a RTMR extend event.
// The JSON tags match both Venice and NEAR AI attestation response formats.
type EventLogEntry struct {
	IMR          int    `json:"imr"`
	Digest       string `json:"digest"` // 96 hex chars (SHA-384)
	EventType    int    `json:"event_type"`
	Event        string `json:"event"`
	EventPayload string `json:"event_payload"`
}

// RawAttestation holds the parsed fields from a TEE provider's attestation
// endpoint response (Venice /tee/attestation, NEAR /attestation/report, etc.).
// All fields are raw strings exactly as returned by the provider; higher layers
// are responsible for validation.
type RawAttestation struct {
	// BackendFormat identifies which backend attestation format this response
	// uses. Set by Attesters during ParseAttestationResponse. Gateway providers
	// use this to dispatch to the correct ReportDataVerifier.
	BackendFormat BackendFormat

	// Verified is the server-side verification result. This is a convenience
	// flag from the provider — clients must perform their own client-side checks.
	Verified bool

	// Nonce is the hex nonce echoed back by the provider.
	Nonce string

	// Model is the attested model identifier.
	Model string

	// TEEProvider identifies the TEE type (e.g. "TDX", "TDX+NVIDIA").
	TEEProvider string

	// SigningKey is the enclave's ECDH public key in hex, used for E2EE key
	// exchange. For v1 (ECDSA/Venice): uncompressed secp256k1 (130 chars,
	// starts with "04"). For v2 (Ed25519/nearcloud): Ed25519 public key
	// (64 chars).
	SigningKey string

	// SigningAddress is the keccak256-derived address of SigningKey.
	// Present for Venice; may be empty for other providers.
	SigningAddress string

	// IntelQuote is the raw Intel TDX quote, hex or base64-encoded.
	IntelQuote string

	// NvidiaPayload is the NVIDIA GPU attestation JWT or raw payload.
	// Used by dstack-based providers that return a single EAT envelope.
	NvidiaPayload string

	// GPUEvidence is per-GPU NVIDIA attestation evidence (certificate chain +
	// SPDM measurement signature). Used by chutes-format providers that return
	// individual GPU evidence entries instead of a single EAT envelope.
	GPUEvidence []GPUEvidence

	// TLSFingerprint is the hex SHA-256 of the backend's TLS certificate SPKI.
	// Set by providers that perform connection-level attestation (NEAR AI).
	// Empty for E2EE providers (Venice).
	TLSFingerprint string

	// TEE environment metadata from the provider's attestation response.
	TEEHardware     string          // e.g. "intel-tdx"
	SigningAlgo     string          // e.g. "ecdsa"
	UpstreamModel   string          // HuggingFace model ID
	AppName         string          // dstack app name
	ComposeHash     string          // docker-compose hash
	AppCompose      string          // raw app_compose JSON from info.tcb_info
	OSImageHash     string          // OS image hash
	DeviceID        string          // TDX device ID
	EventLog        []EventLogEntry // TDX RTMR extend events
	EventLogCount   int             // number of event log entries
	NonceSource     string          // "client" or "server"
	CandidatesAvail int             // node pool size
	CandidatesEval  int             // nodes evaluated

	// Gateway fields — populated by providers with TEE-attested API gateways.
	// Empty for providers without a gateway (e.g. Venice, NEAR AI direct).
	GatewayIntelQuote     string          `json:"-"`
	GatewayNonceHex       string          `json:"-"`
	GatewayAppCompose     string          `json:"-"`
	GatewayEventLog       []EventLogEntry `json:"-"`
	GatewayTLSFingerprint string          `json:"-"`

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

// evictWarnInterval throttles eviction warnings so that sustained cache
// pressure does not flood the log.
const evictWarnInterval = 10 * time.Second

// Cache stores expensive attestation verification results keyed by
// provider+model. The signing key is cached separately in SigningKeyCache
// with a shorter TTL to avoid re-fetching attestation on every E2EE request.
type Cache struct {
	mu            sync.RWMutex
	entries       map[cacheKey]*cacheEntry
	ttl           time.Duration
	lastEvictWarn time.Time
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
	key := cacheKey{provider, model}
	// Only evict when inserting a new key that would exceed the cap.
	// Updates to existing keys don't grow the map.
	if _, exists := c.entries[key]; !exists && len(c.entries) >= maxCacheEntries {
		now := time.Now()
		sizeBefore := len(c.entries)
		for k, e := range c.entries {
			if now.Sub(e.fetchedAt) > c.ttl {
				delete(c.entries, k)
			}
		}
		// If still at capacity after pruning expired entries,
		// evict the oldest entry to enforce the hard cap.
		if len(c.entries) >= maxCacheEntries {
			var oldestKey cacheKey
			var oldestTime time.Time
			for k, e := range c.entries {
				if oldestTime.IsZero() || e.fetchedAt.Before(oldestTime) {
					oldestKey = k
					oldestTime = e.fetchedAt
				}
			}
			if !oldestTime.IsZero() {
				delete(c.entries, oldestKey)
			}
		}
		if len(c.entries) < sizeBefore && now.Sub(c.lastEvictWarn) > evictWarnInterval {
			slog.Warn("attestation cache at capacity, evicting entries",
				"cache", "attestation",
				"size", len(c.entries),
				"max", maxCacheEntries,
			)
			c.lastEvictWarn = now
		}
	}
	c.entries[key] = &cacheEntry{
		report:    report,
		fetchedAt: time.Now(),
	}
}

// Len returns the number of entries in the cache (including expired ones).
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// CacheInfo describes a single cached attestation entry for status reporting.
type CacheInfo struct {
	Provider  string
	Model     string
	FetchedAt time.Time
}

// Models returns (provider, model, fetchedAt) for all non-expired entries.
func (c *Cache) Models() []CacheInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := time.Now()
	var out []CacheInfo
	for k, e := range c.entries {
		if now.Sub(e.fetchedAt) <= c.ttl {
			out = append(out, CacheInfo{
				Provider:  k.provider,
				Model:     k.model,
				FetchedAt: e.fetchedAt,
			})
		}
	}
	return out
}

// NegativeCache records attestation failures to prevent repeated upstream
// hammering when attestation has recently failed. Entries expire after TTL.
type NegativeCache struct {
	mu            sync.RWMutex
	entries       map[cacheKey]time.Time
	ttl           time.Duration
	lastEvictWarn time.Time
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
	key := cacheKey{provider, model}
	// Only evict when inserting a new key that would exceed the cap.
	// Updates to existing keys don't grow the map.
	if _, exists := c.entries[key]; !exists && len(c.entries) >= maxCacheEntries {
		now := time.Now()
		sizeBefore := len(c.entries)
		for k, t := range c.entries {
			if now.Sub(t) > c.ttl {
				delete(c.entries, k)
			}
		}
		// If still at capacity after pruning expired entries,
		// evict the oldest entry to enforce the hard cap.
		if len(c.entries) >= maxCacheEntries {
			var oldestKey cacheKey
			var oldestTime time.Time
			for k, t := range c.entries {
				if oldestTime.IsZero() || t.Before(oldestTime) {
					oldestKey = k
					oldestTime = t
				}
			}
			if !oldestTime.IsZero() {
				delete(c.entries, oldestKey)
			}
		}
		if len(c.entries) < sizeBefore && now.Sub(c.lastEvictWarn) > evictWarnInterval {
			slog.Warn("attestation cache at capacity, evicting entries",
				"cache", "negative",
				"size", len(c.entries),
				"max", maxCacheEntries,
			)
			c.lastEvictWarn = now
		}
	}
	c.entries[key] = time.Now()
}

// Len returns the number of entries in the negative cache (including expired ones).
func (c *NegativeCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// signingKeyEntry stores a REPORTDATA-verified signing key and fetch time.
type signingKeyEntry struct {
	signingKey string
	fetchedAt  time.Time
}

// SigningKeyCache caches REPORTDATA-verified signing keys by provider+model.
// The signing key is bound to the TDX quote via REPORTDATA; it only changes
// on VM restart (new TDX quote). The TTL must be ≥ the SPKI cache TTL to
// prevent "no signing key available" errors on pinned connections where an
// SPKI cache hit skips attestation.
type SigningKeyCache struct {
	mu            sync.RWMutex
	entries       map[cacheKey]*signingKeyEntry
	ttl           time.Duration
	lastEvictWarn time.Time
}

// NewSigningKeyCache returns a SigningKeyCache with the specified TTL.
func NewSigningKeyCache(ttl time.Duration) *SigningKeyCache {
	return &SigningKeyCache{
		entries: make(map[cacheKey]*signingKeyEntry),
		ttl:     ttl,
	}
}

// Get returns the cached signing key for the given provider and model,
// or ("", false) if absent or expired.
func (c *SigningKeyCache) Get(provider, model string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[cacheKey{provider, model}]
	if !ok || time.Since(e.fetchedAt) > c.ttl {
		return "", false
	}
	return e.signingKey, true
}

// Put stores a signing key for the given provider and model.
func (c *SigningKeyCache) Put(provider, model, signingKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := cacheKey{provider, model}
	// Only evict when inserting a new key that would exceed the cap.
	// Updates to existing keys don't grow the map.
	if _, exists := c.entries[key]; !exists && len(c.entries) >= maxCacheEntries {
		now := time.Now()
		sizeBefore := len(c.entries)
		for k, e := range c.entries {
			if now.Sub(e.fetchedAt) > c.ttl {
				delete(c.entries, k)
			}
		}
		// If still at capacity after pruning expired entries,
		// evict the oldest entry to enforce the hard cap.
		if len(c.entries) >= maxCacheEntries {
			var oldestKey cacheKey
			var oldestTime time.Time
			for k, e := range c.entries {
				if oldestTime.IsZero() || e.fetchedAt.Before(oldestTime) {
					oldestKey = k
					oldestTime = e.fetchedAt
				}
			}
			if !oldestTime.IsZero() {
				delete(c.entries, oldestKey)
			}
		}
		if len(c.entries) < sizeBefore && now.Sub(c.lastEvictWarn) > evictWarnInterval {
			slog.Warn("attestation cache at capacity, evicting entries",
				"cache", "signing_key",
				"size", len(c.entries),
				"max", maxCacheEntries,
			)
			c.lastEvictWarn = now
		}
	}
	c.entries[key] = &signingKeyEntry{
		signingKey: signingKey,
		fetchedAt:  time.Now(),
	}
}

// Len returns the number of entries in the signing key cache (including expired).
func (c *SigningKeyCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
