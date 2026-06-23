package tinfoil

import (
	"context"
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
	Domain string // backend enclave domain (e.g. "gemma4-31b-1.inf10.tinfoil.sh")
	Repo   string // Sigstore GitHub repo (e.g. "tinfoilsh/confidential-gemma4-31b")
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
func (r *DirectResolver) Resolve(ctx context.Context, model string) (string, error) {
	m, err := r.ResolveMapping(ctx, model)
	if err != nil {
		return "", err
	}
	return m.Domain, nil
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
		// Pick the first available enclave for this model. The proxy
		// endpoint may list multiple enclaves for load balancing; we
		// select the first one deterministically. The attestation
		// verification will confirm the enclave's identity regardless
		// of which backend is selected.
		domain := firstEnclaveDomain(pm.Enclaves)
		if domain == "" {
			slog.WarnContext(ctx, "tinfoil: proxy discovery: model has no enclaves",
				"model", model)
			continue
		}
		if !isValidBackendDomain(domain) {
			slog.WarnContext(ctx, "tinfoil: proxy discovery: skipping invalid enclave domain",
				"model", model, "domain", domain)
			continue
		}
		mapping[model] = ModelMapping{
			Domain: domain,
			Repo:   pm.Repo,
		}
	}

	r.mu.Lock()
	r.mapping = mapping
	r.fetchedAt = time.Now()
	r.mu.Unlock()

	return nil
}

// firstEnclaveDomain returns the lexicographically smallest enclave domain
// from the map, or empty string if none. Deterministic selection ensures
// capture/replay consistency: the same proxy response always resolves to
// the same backend enclave. The attestation verification will confirm the
// enclave's identity regardless of which backend is selected.
func firstEnclaveDomain(enclaves map[string]proxyEnclave) string {
	if len(enclaves) == 0 {
		return ""
	}
	domains := make([]string, 0, len(enclaves))
	for domain := range enclaves {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains[0]
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
