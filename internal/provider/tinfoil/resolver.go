package tinfoil

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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

	// defaultModelsURL is the Tinfoil model discovery URL.
	defaultModelsURL = DefaultBaseURL + "/v1/models"

	// resolverTTL is how long model mappings are cached before refresh.
	resolverTTL = 5 * time.Minute

	// refreshTimeout bounds how long a singleflight refresh can take.
	refreshTimeout = 30 * time.Second

	// tinfoilDomainSuffix is the required domain suffix for Tinfoil backends.
	tinfoilDomainSuffix = ".inference.tinfoil.sh"
)

// modelsResponse is the OpenAI-compatible JSON response from /v1/models.
type modelsResponse struct {
	Data []modelEntry `json:"data"`
}

// modelEntry is one element of the models data array.
type modelEntry struct {
	ID string `json:"id"`
}

// DirectResolver maps model names to backend domains via the Tinfoil
// model discovery API. Model slug "foo/bar" maps to domain
// "foo--bar.inference.tinfoil.sh". Results are cached with a 5-minute TTL
// and refreshed lazily on the next Resolve call after expiry.
//
// Thread-safe for concurrent use.
type DirectResolver struct {
	modelsURL string
	apiKey    string
	client    *http.Client

	mu        sync.RWMutex
	mapping   map[string]string // model → domain
	fetchedAt time.Time

	sf singleflight.Group
}

// NewDirectResolver returns a resolver that discovers models from the
// default Tinfoil URL (https://inference.tinfoil.sh/v1/models).
func NewDirectResolver(apiKey string, offline ...bool) *DirectResolver {
	ctEnabled := len(offline) == 0 || !offline[0]
	return &DirectResolver{
		modelsURL: defaultModelsURL,
		apiKey:    apiKey,
		client:    tlsct.NewHTTPClient(30*time.Second, ctEnabled),
		mapping:   make(map[string]string),
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

// Resolve returns the backend domain for the given model. If the cached
// mapping is stale (older than 5 minutes), it refreshes from the models
// API first. Returns an error if the model is not found after refresh.
func (r *DirectResolver) Resolve(ctx context.Context, model string) (string, error) {
	r.mu.RLock()
	domain, ok := r.mapping[model]
	stale := time.Since(r.fetchedAt) > resolverTTL
	r.mu.RUnlock()

	if ok && !stale {
		return domain, nil
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
		return "", fmt.Errorf("tinfoil model discovery: %w", ctx.Err())
	case res := <-ch:
		err = res.Err
	}
	if err != nil {
		if ok {
			slog.WarnContext(ctx, "tinfoil model discovery refresh failed",
				"model", model,
				"stale_domain", domain,
				"err", err,
			)
		}
		return "", fmt.Errorf("tinfoil model discovery: %w", err)
	}

	r.mu.RLock()
	domain, ok = r.mapping[model]
	r.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("unknown model %q (not in tinfoil model discovery)", model)
	}
	return domain, nil
}

// refresh fetches the model list from the discovery URL and rebuilds
// the cached mapping. Holds the write lock only for the swap.
func (r *DirectResolver) refresh(ctx context.Context) error {
	// Snapshot the client under the lock to avoid racing with SetClient.
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.modelsURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if r.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+r.apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", r.modelsURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, provider.Truncate(string(body), 256))
	}

	var mr modelsResponse
	if unknown, err := jsonstrict.Unmarshal(body, &mr); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	} else if len(unknown) > 0 {
		slog.Warn("unexpected JSON fields", "fields", unknown, "context", "tinfoil model discovery")
	}

	mapping := make(map[string]string, len(mr.Data))
	for _, m := range mr.Data {
		if m.ID == "" {
			continue
		}
		domain := slugToDomain(m.ID)
		if !isValidTinfoilDomain(domain) {
			slog.WarnContext(ctx, "tinfoil: model discovery: skipping invalid domain",
				"model", m.ID, "domain", domain)
			continue
		}
		mapping[m.ID] = domain
	}

	r.mu.Lock()
	r.mapping = mapping
	r.fetchedAt = time.Now()
	r.mu.Unlock()

	return nil
}

// slugToDomain converts a model slug like "org/model-name" to a domain
// like "org--model-name.inference.tinfoil.sh".
func slugToDomain(slug string) string {
	// Replace "/" with "--" per Tinfoil convention.
	domain := strings.ReplaceAll(slug, "/", "--")
	return domain + tinfoilDomainSuffix
}

// isValidTinfoilDomain checks that a domain is exactly one label under
// .inference.tinfoil.sh (e.g., "foo.inference.tinfoil.sh" but not
// "evil.foo.inference.tinfoil.sh" or bare "inference.tinfoil.sh"). The label
// must also contain only valid DNS hostname characters (letters, digits,
// hyphens) since the models API is untrusted input.
func isValidTinfoilDomain(d string) bool {
	lower := strings.ToLower(d)
	if !strings.HasSuffix(lower, tinfoilDomainSuffix) {
		return false
	}
	// Extract the subdomain label before the suffix.
	label := strings.TrimSuffix(lower, tinfoilDomainSuffix)
	if label == "" || strings.Contains(label, ".") {
		return false
	}
	// Reject labels with invalid DNS hostname characters. The models API is
	// untrusted input; allowing spaces, underscores, etc. could produce
	// confusing downstream failures or unsafe hostnames.
	for _, c := range label {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return true
}
