package tinfoil

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
	"golang.org/x/sync/singleflight"
)

const (
	// DefaultBaseURL is the Tinfoil router base URL, shared between cloud
	// provider construction and direct provider model discovery.
	DefaultBaseURL = "https://inference.tinfoil.sh"

	// defaultProxyURL is the Tinfoil router's proxy discovery endpoint,
	// which maps model names to their actual backend inference enclave
	// domains. This is the authoritative source for direct provider
	// model-to-domain resolution.
	defaultProxyURL = DefaultBaseURL + "/.well-known/tinfoil-proxy"

	// resolverTTL is how long model mappings are cached before refresh.
	resolverTTL = 5 * time.Minute

	// refreshTimeout bounds how long a singleflight refresh can take.
	refreshTimeout = 30 * time.Second
)

// promptCacheKeyCtxKey is the context key for the OpenAI prompt_cache_key
// field. When set, the resolver uses it for cache-aware backend selection
// to maximize vLLM Automatic Prefix Cache (APC) hit rates.
type promptCacheKeyCtxKey struct{}

// WithPromptCacheKey returns a new context with the given prompt_cache_key
// value. The resolver uses this to select a backend enclave domain via
// hash-based sticky routing.
func WithPromptCacheKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, promptCacheKeyCtxKey{}, key)
}

// PromptCacheKeyFromContext extracts the prompt_cache_key from the context,
// or returns empty string if not set.
func PromptCacheKeyFromContext(ctx context.Context) string {
	v, _ := ctx.Value(promptCacheKeyCtxKey{}).(string)
	return v
}

// proxyResponse is the JSON response from /.well-known/tinfoil-proxy.
type proxyResponse struct {
	Attempted string                `json:"attempted"`
	Errors    any                   `json:"errors"`
	Models    map[string]proxyModel `json:"models"`
	Updated   string                `json:"updated"`
	Version   string                `json:"version"`
}

// proxyModel is a single model entry in the proxy response.
type proxyModel struct {
	Repo        string                  `json:"repo"`
	Tag         string                  `json:"tag"`
	Measurement any                     `json:"measurement"`
	Enclaves    map[string]proxyEnclave `json:"enclaves"`
	Overload    any                     `json:"overload"`
}

// proxyEnclave is a single backend enclave for a model.
type proxyEnclave struct {
	HPKEKey   string `json:"hpke_key"`
	Predicate string `json:"predicate"`
	TLSKeyFP  string `json:"tls_key_fp"`
}

// ModelMapping holds the resolved backend enclave domain and Sigstore
// repo for a model, as returned by the proxy discovery endpoint.
type ModelMapping struct {
	Domain  string   // selected backend enclave domain (e.g. "gemma4-31b-1.inf10.tinfoil.sh")
	Repo    string   // Sigstore GitHub repo (e.g. "tinfoilsh/confidential-gemma4-31b")
	Domains []string // all available enclave domains, sorted lexicographically
}

// DirectResolver maps model names to backend inference enclave domains via
// the Tinfoil router's proxy discovery endpoint
// (/.well-known/tinfoil-proxy). The proxy endpoint returns the actual
// backend enclave domains (e.g. "gemma4-31b-1.inf10.tinfoil.sh"), not the
// router's wildcard subdomains (*.inference.tinfoil.sh). Results are cached
// with a 5-minute TTL and refreshed lazily on the next Resolve call after
// expiry.
//
// Thread-safe for concurrent use.
type DirectResolver struct {
	proxyURL string
	apiKey   string
	client   *http.Client

	mu        sync.RWMutex
	mapping   map[string]ModelMapping // model → mapping
	fetchedAt time.Time

	sf singleflight.Group
}

// NewDirectResolver returns a resolver that discovers backend enclave
// domains from the Tinfoil router's proxy discovery endpoint.
func NewDirectResolver(apiKey string, offline ...bool) *DirectResolver {
	ctEnabled := len(offline) == 0 || !offline[0]
	return &DirectResolver{
		proxyURL: defaultProxyURL,
		apiKey:   apiKey,
		client:   tlsct.NewHTTPClient(30*time.Second, ctEnabled),
		mapping:  make(map[string]ModelMapping),
	}
}

// SetClient replaces the HTTP client used for model discovery. Safe for
// concurrent use with Resolve/refresh: the client pointer is read under the
// same mutex that protects the cached mapping.
func (r *DirectResolver) SetClient(c *http.Client) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.client = c
}

// Resolve returns the backend enclave domain for the given model. If the
// cached mapping is stale (older than 5 minutes), it refreshes from the
// proxy discovery endpoint first. Returns an error if the model is not
// found after refresh.
//
// When a prompt_cache_key is present in the context (set via
// WithPromptCacheKey), the resolver uses hash-based sticky routing to
// select a backend enclave domain, maximizing vLLM APC cache hit rates.
func (r *DirectResolver) Resolve(ctx context.Context, model string) (string, error) {
	m, err := r.ResolveMapping(ctx, model)
	if err != nil {
		return "", err
	}
	promptCacheKey := PromptCacheKeyFromContext(ctx)
	return m.SelectDomain(promptCacheKey), nil
}

// ResolveMapping returns the full model mapping (domain + repo) for the
// given model. If the cached mapping is stale (older than 5 minutes), it
// refreshes from the proxy discovery endpoint first.
func (r *DirectResolver) ResolveMapping(ctx context.Context, model string) (ModelMapping, error) {
	r.mu.RLock()
	m, ok := r.mapping[model]
	stale := time.Since(r.fetchedAt) > resolverTTL
	r.mu.RUnlock()

	if ok && !stale {
		return m, nil
	}

	// Collapse concurrent refreshes into a single HTTP call.
	ch := r.sf.DoChan("refresh", func() (any, error) {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
		defer cancel()
		return nil, r.refresh(rctx)
	})

	var err error
	select {
	case <-ctx.Done():
		return ModelMapping{}, fmt.Errorf("tinfoil model discovery: %w", ctx.Err())
	case res := <-ch:
		err = res.Err
	}
	if err != nil {
		if ok {
			slog.WarnContext(ctx, "tinfoil model discovery refresh failed",
				"model", model,
				"stale_domain", m.Domain,
				"err", err,
			)
		}
		return ModelMapping{}, fmt.Errorf("tinfoil model discovery: %w", err)
	}

	r.mu.RLock()
	m, ok = r.mapping[model]
	r.mu.RUnlock()

	if !ok {
		return ModelMapping{}, fmt.Errorf("unknown model %q (not in tinfoil proxy discovery)", model)
	}
	return m, nil
}

// SelectDomain selects the best backend enclave domain from the mapping
// using the prompt_cache_key for cache-aware routing. When promptCacheKey
// is non-empty, it hashes the key with each domain and picks the lowest
// lexicographic hash. This provides sticky routing so that requests with
// the same prompt_cache_key consistently hit the same backend enclave,
// maximizing vLLM Automatic Prefix Cache (APC) hit rates.
//
// When promptCacheKey is empty, it falls back to the lexicographically
// smallest domain for deterministic selection (capture/replay consistency).
func (m ModelMapping) SelectDomain(promptCacheKey string) string {
	if len(m.Domains) == 0 {
		return m.Domain
	}
	if promptCacheKey == "" {
		return m.Domains[0]
	}

	// Hash prompt_cache_key with each domain and pick the lowest hash.
	// This ensures that the same prompt_cache_key always routes to the
	// same backend, as long as the set of available domains doesn't change.
	bestDomain := ""
	bestHash := ""
	for _, domain := range m.Domains {
		h := sha256.Sum256([]byte(promptCacheKey + ":" + domain))
		hashHex := hex.EncodeToString(h[:])
		if bestHash == "" || hashHex < bestHash {
			bestHash = hashHex
			bestDomain = domain
		}
	}
	return bestDomain
}

// refresh fetches the model-to-enclave mapping from the proxy discovery
// endpoint and rebuilds the cached mapping. Holds the write lock only for
// the swap.
func (r *DirectResolver) refresh(ctx context.Context) error {
	// Snapshot the client under the lock to avoid racing with SetClient.
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.proxyURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if r.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+r.apiKey)
	}
	provider.SetUserAgent(req)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", r.proxyURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, provider.Truncate(string(body), 256))
	}

	var pr proxyResponse
	if unknown, err := jsonstrict.Unmarshal(body, &pr); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	} else if len(unknown) > 0 {
		slog.Warn("unexpected JSON fields", "fields", unknown, "context", "tinfoil proxy discovery")
	}

	mapping := make(map[string]ModelMapping, len(pr.Models))
	for model, pm := range pr.Models {
		if model == "" {
			continue
		}
		// Collect all valid enclave domains for this model. The proxy
		// endpoint may list multiple enclaves for load balancing.
		// Domains are sorted lexicographically for deterministic
		// selection. The attestation verification will confirm the
		// enclave's identity regardless of which backend is selected.
		//
		// TODO: Add chutes-style instance pool handling with a skip set
		// for failing/skipped enclaves. The Tinfoil router uses a similar
		// pattern (NextEnclave with a skip map) to avoid overloaded or
		// circuit-broken backends. Teep could maintain a per-model skip
		// set populated by attestation failures or TLS binding mismatches,
		// and exclude those domains from selection until they recover.
		domains := sortedEnclaveDomains(pm.Enclaves)
		if len(domains) == 0 {
			slog.WarnContext(ctx, "tinfoil: proxy discovery: model has no enclaves",
				"model", model)
			continue
		}
		valid := make([]string, 0, len(domains))
		for _, domain := range domains {
			if !isValidBackendDomain(domain) {
				slog.WarnContext(ctx, "tinfoil: proxy discovery: skipping invalid enclave domain",
					"model", model, "domain", domain)
				continue
			}
			valid = append(valid, domain)
		}
		if len(valid) == 0 {
			continue
		}
		mapping[model] = ModelMapping{
			Domain:  valid[0],
			Repo:    pm.Repo,
			Domains: valid,
		}
	}

	r.mu.Lock()
	r.mapping = mapping
	r.fetchedAt = time.Now()
	r.mu.Unlock()

	return nil
}

// sortedEnclaveDomains returns all enclave domains from the map, sorted
// lexicographically. Deterministic ordering ensures capture/replay
// consistency: the same proxy response always resolves to the same set
// of backend enclaves in the same order. The attestation verification
// will confirm the enclave's identity regardless of which backend is
// selected.
func sortedEnclaveDomains(enclaves map[string]proxyEnclave) []string {
	if len(enclaves) == 0 {
		return nil
	}
	domains := make([]string, 0, len(enclaves))
	for domain := range enclaves {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains
}

// isValidBackendDomain validates that a backend enclave domain is a
// legitimate Tinfoil infrastructure domain. Backend enclaves are hosted on
// domains like:
//   - *.inf10.tinfoil.sh (TDX enclaves)
//   - *.inf6.tinfoil.sh (SEV-SNP enclaves)
//   - *.tinfoil.containers.tinfoil.dev
//
// The domain must be a valid DNS hostname and end with a known Tinfoil
// suffix. This prevents the proxy endpoint from directing clients to
// arbitrary hosts.
func isValidBackendDomain(d string) bool {
	lower := strings.ToLower(d)
	if lower == "" {
		return false
	}

	// Must end with a known Tinfoil infrastructure suffix.
	allowedSuffixes := []string{
		".tinfoil.sh",
		".tinfoil.containers.tinfoil.dev",
	}
	matched := false
	for _, suffix := range allowedSuffixes {
		if strings.HasSuffix(lower, suffix) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}

	// Must be a valid DNS hostname: letters, digits, hyphens, dots.
	for _, c := range d {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-', c == '.':
		default:
			return false
		}
	}

	return true
}
