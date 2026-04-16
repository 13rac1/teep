package chutes

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
	"golang.org/x/sync/singleflight"
)

// modelResolver abstracts model name → chute UUID resolution for testing.
type modelResolver interface {
	Resolve(ctx context.Context, model string) (string, error)
}

// NoncePool caches the /e2e/instances/ response and serves nonces from
// the pool without re-fetching. When all nonces are consumed or expired,
// a fresh batch is fetched automatically.
//
// This mirrors the nonce caching strategy in chutesai/e2ee-proxy's
// e2ee_discovery.lua and eliminates the per-request /e2e/instances +
// /chutes/{id}/evidence roundtrips that made E2EE requests slow.
type NoncePool struct {
	baseURL  string
	apiKey   string
	client   *http.Client
	resolver modelResolver

	mu       sync.Mutex
	refresh  singleflight.Group        // per-chute refresh dedup
	pools    map[string]*chutePool     // keyed by chute UUID
	failures map[string]map[string]int // chute UUID → instance ID → failure count
}

// chutePool holds cached instances and their remaining nonces for one chute.
type chutePool struct {
	instances []poolInstance
	expiresAt time.Time
}

// poolInstance is one instance with remaining nonces.
type poolInstance struct {
	instanceID string
	e2ePubKey  string
	nonces     []string
}

// NewNoncePool creates a NoncePool that fetches from the given base URL.
// Panics if resolver or client is nil (programmer error caught at startup).
func NewNoncePool(baseURL, apiKey string, resolver modelResolver, client *http.Client) *NoncePool {
	if resolver == nil {
		panic("noncepool: resolver must not be nil")
	}
	if client == nil {
		panic("noncepool: client must not be nil")
	}
	return &NoncePool{
		baseURL:  baseURL,
		apiKey:   apiKey,
		client:   client,
		resolver: resolver,
		pools:    make(map[string]*chutePool),
		failures: make(map[string]map[string]int),
	}
}

// Take returns E2EE material for one request: a live instance with its
// ML-KEM pubkey and a single-use nonce. The nonce is consumed (removed
// from the pool) atomically. If the pool is empty or expired, a fresh
// batch is fetched from /e2e/instances/{chute}.
func (p *NoncePool) Take(ctx context.Context, model string) (*provider.E2EEMaterial, error) {
	chuteID, err := p.resolver.Resolve(ctx, model)
	if err != nil {
		return nil, fmt.Errorf("nonce pool: resolve model: %w", err)
	}

	// Fast path: try to take from cache.
	if m := p.take(ctx, chuteID); m != nil {
		return m, nil
	}

	// Slow path: use singleflight keyed by chuteID so unrelated chutes
	// can refresh in parallel while preventing thundering herd per chute.
	_, err, _ = p.refresh.Do(chuteID, func() (any, error) {
		return nil, p.doRefresh(ctx, chuteID)
	})
	if err != nil {
		return nil, err
	}

	if m := p.take(ctx, chuteID); m != nil {
		return m, nil
	}
	return nil, fmt.Errorf("nonce pool: no nonces available for chute %s after refresh", chuteID)
}

// MarkFailed records that an instance failed, so future Take calls prefer
// other instances. Does not remove the instance — it may recover.
func (p *NoncePool) MarkFailed(chuteID, instanceID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failures[chuteID] == nil {
		p.failures[chuteID] = make(map[string]int)
	}
	p.failures[chuteID][instanceID]++
}

// Invalidate discards cached nonces for a chute, forcing a refresh on next Take.
func (p *NoncePool) Invalidate(chuteID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pools, chuteID)
	delete(p.failures, chuteID)
}

// FetchE2EEMaterial implements provider.E2EEMaterialFetcher.
func (p *NoncePool) FetchE2EEMaterial(ctx context.Context, model string) (*provider.E2EEMaterial, error) {
	return p.Take(ctx, model)
}

// take attempts to consume one nonce from the pool. Returns nil if no nonces
// are available or the pool is expired. Prefers instances with fewer failures.
func (p *NoncePool) take(ctx context.Context, chuteID string) *provider.E2EEMaterial {
	p.mu.Lock()
	defer p.mu.Unlock()

	pool, ok := p.pools[chuteID]
	if !ok || time.Now().After(pool.expiresAt) {
		delete(p.pools, chuteID)
		return nil
	}

	// Find the instance with the fewest failures that has nonces.
	chuteFailures := p.failures[chuteID]
	bestIdx := -1
	bestFailures := 0
	for i := range pool.instances {
		if len(pool.instances[i].nonces) == 0 {
			continue
		}
		f := chuteFailures[pool.instances[i].instanceID]
		if bestIdx == -1 || f < bestFailures {
			bestIdx = i
			bestFailures = f
		}
	}
	if bestIdx == -1 {
		// All nonces consumed.
		delete(p.pools, chuteID)
		return nil
	}

	inst := &pool.instances[bestIdx]
	nonce := inst.nonces[0]
	inst.nonces = inst.nonces[1:]

	slog.DebugContext(ctx, "nonce pool: took nonce",
		"chute_id", chuteID,
		"instance_id", inst.instanceID,
		"remaining", len(inst.nonces),
		"failures", bestFailures,
	)

	return &provider.E2EEMaterial{
		InstanceID: inst.instanceID,
		E2EPubKey:  inst.e2ePubKey,
		E2ENonce:   nonce,
		ChuteID:    chuteID,
	}
}

// doRefresh fetches /e2e/instances/{chute} and populates the pool.
func (p *NoncePool) doRefresh(ctx context.Context, chuteID string) error {
	instancesURL, err := url.Parse(p.baseURL + instancesPath + url.PathEscape(chuteID))
	if err != nil {
		return fmt.Errorf("nonce pool: parse instances URL: %w", err)
	}

	slog.DebugContext(ctx, "nonce pool: fetching fresh instances", "chute_id", chuteID)
	body, err := provider.FetchAttestationJSON(ctx, p.client, instancesURL.String(), p.apiKey, maxBodySize)
	if err != nil {
		// Do not propagate the underlying error because it may include a
		// truncated HTTP response body containing single-use nonce material.
		return fmt.Errorf("nonce pool: fetch instances for chute %s failed", chuteID)
	}

	var resp e2eInstancesResponse
	if unknown, err := jsonstrict.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("nonce pool: unmarshal instances: %w", err)
	} else if len(unknown) > 0 {
		slog.Warn("unexpected JSON fields", "fields", unknown, "context", "chutes nonce pool")
	}
	if len(resp.Instances) == 0 {
		return fmt.Errorf("nonce pool: no instances available for chute %s", chuteID)
	}
	if len(resp.Instances) > maxInstances {
		return fmt.Errorf("nonce pool: too many instances (%d, max %d)", len(resp.Instances), maxInstances)
	}

	const (
		defaultTTLSeconds = 55   // default from Chutes reference proxy
		maxTTLSeconds     = 300  // clamp provider TTL to 5 minutes
		rejectTTLSeconds  = 3600 // reject absurd provider TTLs
		safetyMargin      = 5
	)

	ttl := resp.NonceExpIn
	switch {
	case ttl <= 0:
		ttl = defaultTTLSeconds
	case ttl > rejectTTLSeconds:
		return fmt.Errorf("nonce pool: provider TTL too large (%d > %d seconds)", ttl, rejectTTLSeconds)
	case ttl > maxTTLSeconds:
		ttl = maxTTLSeconds
	}
	// Subtract a safety margin to avoid using near-expired nonces.
	if ttl > safetyMargin*2 {
		ttl -= safetyMargin
	}

	pool := &chutePool{
		expiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}

	totalNonces := 0
	for _, inst := range resp.Instances {
		if inst.E2EPubKey == "" || len(inst.Nonces) == 0 {
			continue
		}
		pi := poolInstance{
			instanceID: inst.InstanceID,
			e2ePubKey:  inst.E2EPubKey,
			nonces:     inst.Nonces,
		}
		pool.instances = append(pool.instances, pi)
		totalNonces += len(inst.Nonces)
	}

	if len(pool.instances) == 0 {
		return fmt.Errorf("nonce pool: no E2EE-capable instances for chute %s", chuteID)
	}

	slog.InfoContext(ctx, "nonce pool: refreshed",
		"chute_id", chuteID,
		"instances", len(pool.instances),
		"nonces", totalNonces,
		"ttl_seconds", ttl,
	)

	p.mu.Lock()
	p.pools[chuteID] = pool
	p.mu.Unlock()

	return nil
}
