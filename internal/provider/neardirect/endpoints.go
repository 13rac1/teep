package neardirect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	maxDiscoveryBody        = 1 << 20
	maxDiscoveryMappings    = 4096
	maxDiscoveryModelLength = 256
	// defaultEndpointsURL is the NEAR AI endpoint discovery URL.
	defaultEndpointsURL = "https://completions.near.ai/endpoints"

	// endpointsTTL is how long endpoint mappings are cached before refresh.
	endpointsTTL = 5 * time.Minute

	// refreshTimeout bounds how long a singleflight refresh can take.
	// The refresh context is detached from caller cancellation (via
	// WithoutCancel) so one caller's cancel doesn't abort the shared
	// refresh, but any deadline on the parent context may still shorten
	// the effective timeout.
	refreshTimeout = 30 * time.Second
)

// endpointsResponse is the JSON shape returned by the endpoints URL.
type endpointsResponse struct {
	Endpoints []endpointEntry `json:"endpoints"`
}

// endpointEntry is one element of the endpoints array.
type endpointEntry struct {
	Domain string   `json:"domain"`
	Models []string `json:"models"`
}

// EndpointResolver maps model names to backend domains via the NEAR AI
// endpoint discovery API. Results are cached with a 5-minute TTL and
// refreshed lazily on the next Resolve call after expiry.
//
// Thread-safe for concurrent use.
type EndpointResolver struct {
	endpointsURL     string
	client           *http.Client
	restrictToNearAI bool

	mu        sync.RWMutex
	mapping   map[string]string // model → domain
	fetchedAt time.Time

	sf singleflight.Group
}

// NewEndpointResolver returns a resolver that discovers endpoints from
// the default NEAR AI URL (https://completions.near.ai/endpoints).
func NewEndpointResolver(offline ...bool) *EndpointResolver {
	ctEnabled := len(offline) == 0 || !offline[0]
	return &EndpointResolver{
		endpointsURL:     defaultEndpointsURL,
		client:           tlsct.NewHTTPClient(30*time.Second, ctEnabled),
		restrictToNearAI: true,
		mapping:          make(map[string]string),
	}
}

// newEndpointResolverForTest returns a resolver pointing at a custom URL.
func newEndpointResolverForTest(url string) *EndpointResolver {
	return &EndpointResolver{
		endpointsURL:     url,
		client:           tlsct.NewHTTPClient(1 * time.Second),
		restrictToNearAI: false,
		mapping:          make(map[string]string),
	}
}

// Resolve returns the backend domain for the given model. If the cached
// mapping is stale (older than 5 minutes), it refreshes from the endpoints
// API first. Returns an error if the model is not found after refresh.
func (r *EndpointResolver) Resolve(ctx context.Context, model string) (string, error) {
	r.mu.RLock()
	domain, ok := r.mapping[model]
	observed := r.fetchedAt
	stale := time.Since(observed) > endpointsTTL
	r.mu.RUnlock()

	if ok && !stale {
		return domain, nil
	}

	// Collapse concurrent refreshes into a single HTTP call.
	// Use a detached context with a fixed timeout so one caller's
	// cancellation doesn't fail the refresh for all collapsed callers,
	// while still bounding how long the refresh can block.
	// DoChan lets cancelled callers return immediately while the
	// shared refresh continues in the background.
	ch := r.sf.DoChan("refresh", func() (any, error) {
		return nil, r.refreshAfter(ctx, observed)
	})

	var err error
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("endpoint discovery: %w", ctx.Err())
	case res := <-ch:
		err = res.Err
	}
	if err != nil {
		if ok {
			slog.WarnContext(ctx, "nearai endpoint discovery refresh failed",
				"model", model,
				"stale_domain", domain,
				"err", err,
			)
		}
		return "", fmt.Errorf("endpoint discovery: %w", err)
	}

	r.mu.RLock()
	domain, ok = r.mapping[model]
	r.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("unknown model %q (not in endpoint discovery)", model)
	}
	return domain, nil
}

// ResolveRoute fixes the selected authority before authorization access.
func (r *EndpointResolver) ResolveRoute(ctx context.Context, model string) (provider.ResolvedRoute, error) {
	domain, err := r.Resolve(ctx, model)
	if err != nil {
		return provider.ResolvedRoute{}, err
	}
	return provider.NewResolvedRoute("https://"+domain, "")
}

// refresh fetches the endpoint mapping from the discovery URL and replaces
// the cached mapping. Holds the write lock only for the swap.
func (r *EndpointResolver) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.endpointsURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	provider.SetUserAgent(req)

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", r.endpointsURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBody+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if len(body) > maxDiscoveryBody {
		return fmt.Errorf("endpoint discovery body exceeds %d bytes", maxDiscoveryBody)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, provider.Truncate(string(body), 256))
	}

	mapping, err := parseEndpointMapping(body, r.restrictToNearAI)
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.mapping = mapping
	r.fetchedAt = time.Now()
	r.mu.Unlock()

	return nil
}

func canonicalDiscoveryAuthority(domain string, restrictToNearAI bool) (string, error) {
	authority, err := tlsct.HTTPSOriginAuthority("https://" + domain)
	if err != nil {
		return "", err
	}
	host := authority
	if strings.Contains(authority, ":") {
		host, _, err = net.SplitHostPort(authority)
		if err != nil {
			return "", errors.New("invalid discovery authority")
		}
	}
	if net.ParseIP(host) != nil || strings.HasPrefix(host, "xn--") || strings.Contains(host, ".xn--") {
		return "", errors.New("discovery requires a DNS hostname without punycode")
	}
	if restrictToNearAI && host != "near.ai" && !strings.HasSuffix(host, ".near.ai") {
		return "", errors.New("discovery authority is not owned by NEAR AI")
	}
	return authority, nil
}

func parseEndpointMapping(body []byte, restrictToNearAI bool) (map[string]string, error) {
	var response endpointsResponse
	unknown, missing, err := jsonstrict.UnmarshalWarn(body, &response, "nearai endpoint discovery")
	if err != nil {
		return nil, fmt.Errorf("decode endpoint discovery: %w", err)
	}
	if len(unknown) != 0 || len(missing) != 0 {
		return nil, fmt.Errorf("endpoint discovery fields: unknown %v, missing %v", unknown, missing)
	}
	if len(response.Endpoints) == 0 {
		return nil, errors.New("endpoint discovery has no endpoints")
	}
	mapping := make(map[string]string)
	for _, endpoint := range response.Endpoints {
		authority, err := canonicalDiscoveryAuthority(endpoint.Domain, restrictToNearAI)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint authority: %w", err)
		}
		if len(endpoint.Models) == 0 {
			return nil, errors.New("endpoint has no models")
		}
		for _, model := range endpoint.Models {
			if model == "" || len(model) > maxDiscoveryModelLength || strings.ContainsFunc(model, func(c rune) bool { return c < 32 || c == 127 }) {
				return nil, errors.New("endpoint has an invalid model identifier")
			}
			if _, exists := mapping[model]; exists {
				return nil, errors.New("duplicate model in endpoint discovery")
			}
			if len(mapping) >= maxDiscoveryMappings {
				return nil, fmt.Errorf("endpoint discovery exceeds %d mappings", maxDiscoveryMappings)
			}
			mapping[model] = authority
		}
	}
	return mapping, nil
}

// refreshAfter runs inside the singleflight callback. A caller can arrive here
// after another refresh has completed since it inspected the mapping.
func (r *EndpointResolver) refreshAfter(ctx context.Context, observed time.Time) error {
	r.mu.RLock()
	refreshed := !r.fetchedAt.Equal(observed) && time.Since(r.fetchedAt) <= endpointsTTL
	r.mu.RUnlock()
	if refreshed {
		return nil
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
	defer cancel()
	return r.refresh(rctx)
}
