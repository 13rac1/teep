package neardirect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
	"golang.org/x/sync/singleflight"
)

const (
	// defaultEndpointsURL is the NEAR AI endpoint discovery URL.
	defaultEndpointsURL = "https://completions.near.ai/endpoints"

	// endpointsTTL is how long endpoint mappings are cached before refresh.
	endpointsTTL = 5 * time.Minute

	// refreshTimeout bounds how long a singleflight refresh can take,
	// independent of the caller's context. This prevents a detached
	// refresh from blocking longer than the HTTP handler's deadline.
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
	stale := time.Since(r.fetchedAt) > endpointsTTL
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
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
		defer cancel()
		return nil, r.refresh(rctx)
	})

	var err error
	select {
	case <-ctx.Done():
		if ok {
			slog.WarnContext(ctx, "nearai endpoint discovery: caller cancelled, using stale mapping",
				"model", model,
				"domain", domain,
			)
			return domain, nil
		}
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

// ListModels implements provider.ModelLister by returning all models from the
// endpoint discovery cache. The /endpoints URL is public and requires no API
// key, so this never sends an Authorization header upstream.
func (r *EndpointResolver) ListModels(ctx context.Context) ([]json.RawMessage, error) {
	r.mu.RLock()
	stale := time.Since(r.fetchedAt) > endpointsTTL
	size := len(r.mapping)
	r.mu.RUnlock()

	if stale || size == 0 {
		ch := r.sf.DoChan("refresh", func() (any, error) {
			rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
			defer cancel()
			return nil, r.refresh(rctx)
		})

		var err error
		select {
		case <-ctx.Done():
			r.mu.RLock()
			size = len(r.mapping)
			r.mu.RUnlock()
			if size == 0 {
				return nil, fmt.Errorf("endpoint discovery: %w", ctx.Err())
			}
			slog.WarnContext(ctx, "nearai: endpoint discovery: caller cancelled for ListModels, using stale mapping")
		case res := <-ch:
			err = res.Err
			if err != nil {
				r.mu.RLock()
				size = len(r.mapping)
				r.mu.RUnlock()
				if size == 0 {
					return nil, fmt.Errorf("endpoint discovery: %w", err)
				}
				slog.WarnContext(ctx, "nearai: endpoint discovery refresh failed for ListModels, using stale mapping", "err", err)
			}
		}
	}

	r.mu.RLock()
	models := make([]string, 0, len(r.mapping))
	for m := range r.mapping {
		models = append(models, m)
	}
	r.mu.RUnlock()

	sort.Strings(models)

	out := make([]json.RawMessage, 0, len(models))
	now := time.Now().Unix()
	for _, m := range models {
		b, err := json.Marshal(struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			Created int64  `json:"created"`
			OwnedBy string `json:"owned_by"`
		}{ID: m, Object: "model", Created: now, OwnedBy: "near-ai"})
		if err != nil {
			return nil, fmt.Errorf("models: marshal %q: %w", m, err)
		}
		out = append(out, json.RawMessage(b))
	}
	return out, nil
}

// refresh fetches the endpoint mapping from the discovery URL and replaces
// the cached mapping. Holds the write lock only for the swap.
func (r *EndpointResolver) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.endpointsURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", r.endpointsURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, provider.Truncate(string(body), 256))
	}

	var er endpointsResponse
	if unknown, err := jsonstrict.Unmarshal(body, &er); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	} else if len(unknown) > 0 {
		slog.Warn("unexpected JSON fields", "fields", unknown, "context", "nearai endpoint discovery")
	}

	mapping := make(map[string]string)
	for _, ep := range er.Endpoints {
		if !isValidDomain(ep.Domain, r.restrictToNearAI) {
			slog.WarnContext(ctx, "nearai: endpoint discovery: skipping invalid domain", "domain", ep.Domain)
			continue
		}
		for _, m := range ep.Models {
			if prior, exists := mapping[m]; exists && prior != ep.Domain {
				slog.WarnContext(ctx, "nearai: endpoint discovery: duplicate model mapping; last value wins",
					"model", m,
					"first_domain", prior,
					"second_domain", ep.Domain,
				)
			}
			mapping[m] = ep.Domain
		}
	}

	r.mu.Lock()
	r.mapping = mapping
	r.fetchedAt = time.Now()
	r.mu.Unlock()

	return nil
}

// isValidDomain rejects domain strings that are empty, contain schemes,
// spaces, path separators, punycode labels, or do not belong to near.ai.
// Accepts host:port but only for near.ai hosts.
func isValidDomain(d string, restrictToNearAI bool) bool {
	if d == "" {
		return false
	}

	for _, r := range d {
		if unicode.IsSpace(r) || r < 0x20 || r == 0x7f {
			return false
		}
		if r > unicode.MaxASCII {
			return false
		}
	}
	if strings.ContainsAny(d, "/\\") || strings.Contains(d, "://") {
		return false
	}

	host := d
	if strings.Count(d, ":") > 0 {
		h, p, err := net.SplitHostPort(d)
		if err != nil {
			return false
		}
		port, err := strconv.Atoi(p)
		if err != nil || port <= 0 || port > 65535 {
			return false
		}
		host = h
	}

	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || strings.Contains(host, "..") {
		return false
	}
	if strings.HasPrefix(host, "xn--") || strings.Contains(host, ".xn--") {
		return false
	}

	if !restrictToNearAI {
		return true
	}
	return host == "near.ai" || strings.HasSuffix(host, ".near.ai")
}
