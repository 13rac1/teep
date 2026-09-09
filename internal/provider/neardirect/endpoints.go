package neardirect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearparse"
	"github.com/13rac1/teep/internal/provider/nearroute"
	"github.com/13rac1/teep/internal/tlsct"
)

const (
	maxDiscoveryBody        = 1 << 20
	maxDiscoveryMappings    = 4096
	maxDiscoveryModelLength = 256
	defaultEndpointsURL     = "https://completions.near.ai/endpoints"
	defaultCountURL         = "https://completions.near.ai/backends/count"
	endpointsTTL            = 5 * time.Minute
	refreshTimeout          = 30 * time.Second
	selectionTimeout        = 60 * time.Second
	maxCountFetches         = 16
	metadataFailureDelay    = time.Second
)

type endpointsResponse struct {
	Endpoints []endpointEntry `json:"endpoints"`
}
type endpointEntry struct {
	Domain  string   `json:"domain"`
	Models  []string `json:"models"`
	unknown []string
}

// EndpointResolver owns bounded metadata operations and immutable model routes.
// Caller cancellation ends only its wait; Stop cancels and joins owned work.
type EndpointResolver struct {
	endpointsURL     string
	countURL         string
	client           *http.Client
	restrictToNearAI bool
	selector         func(context.Context, uint64) (uint64, error)
	now              func() time.Time
	mu               sync.Mutex
	owner            context.Context //nolint:containedctx // Resolver lifecycle owns shared work.
	cancel           context.CancelFunc
	closed           bool
	workers          sync.WaitGroup
	endpoints        metadataRecord
	counts           map[string]*metadataRecord
	activeCounts     int
	selections       map[string]*selectionOperation
	selectionOrigin  string
}

// NewEndpointResolver owns initial metadata and lifetime model selections.
func NewEndpointResolver(offline ...bool) *EndpointResolver {
	return &EndpointResolver{endpointsURL: defaultEndpointsURL, countURL: defaultCountURL,
		client: config.NewAttestationClient(len(offline) > 0 && offline[0]), restrictToNearAI: true, selector: randomIndex, now: time.Now}
}

// SetClient configures the metadata client before concurrent use.
func (r *EndpointResolver) SetClient(client *http.Client) { r.client = client }

// Resolve acquires canonical metadata for an initial selection. Established
// route users must use ResolveConfigured, which does not refresh metadata.
func (r *EndpointResolver) Resolve(ctx context.Context, model string) (string, error) {
	snapshot, err := r.mappingForModel(ctx, model)
	return snapshot.authority, err
}

// ResolveRoute selects a route for the default NEAR origin.
func (r *EndpointResolver) ResolveRoute(ctx context.Context, model string) (provider.ResolvedRoute, error) {
	return r.ResolveConfigured(ctx, model, nearroute.Origin{Authority: "completions.near.ai"})
}

// Stop stops admission, cancels shared operations, and waits for cleanup.
func (r *EndpointResolver) Stop() {
	r.mu.Lock()
	r.closed = true
	if r.cancel != nil {
		r.cancel()
	}
	r.mu.Unlock()
	r.workers.Wait()
}

// CloseIdleConnections releases idle metadata sockets without ending selection ownership.
func (r *EndpointResolver) CloseIdleConnections() { r.client.CloseIdleConnections() }

func (r *EndpointResolver) initializeLocked() {
	if r.owner == nil {
		r.owner, r.cancel = context.WithCancel(context.Background())
	}
	if r.counts == nil {
		r.counts = make(map[string]*metadataRecord)
	}
	if r.selections == nil {
		r.selections = make(map[string]*selectionOperation)
	}
}

func (r *EndpointResolver) mappingForModel(ctx context.Context, model string) (mappingSnapshot, error) {
	if err := nearroute.ValidateModel(model); err != nil {
		return mappingSnapshot{}, err
	}
	snapshot, err := r.metadata(ctx, "")
	if err != nil {
		return mappingSnapshot{}, err
	}
	authority, ok := snapshot.mapping[model]
	if !ok {
		return mappingSnapshot{}, resolutionError(nearroute.UnknownModel, "model absent from endpoint discovery", nil)
	}
	return mappingSnapshot{authority: authority, fetchedAt: snapshot.fetchedAt}, nil
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
	if len(body) > maxDiscoveryBody {
		return nil, errors.New("endpoint discovery exceeds size limit")
	}
	if err := jsonstrict.ValidateUniqueFields(body); err != nil {
		return nil, err
	}
	var response endpointsResponse
	unknown, missing, err := jsonstrict.Unmarshal(body, &response)
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
		if len(endpoint.unknown) > 0 {
			return nil, fmt.Errorf("unknown endpoint fields: %v", endpoint.unknown)
		}
		authority, err := canonicalDiscoveryAuthority(endpoint.Domain, restrictToNearAI)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint authority: %w", err)
		}
		if len(endpoint.Models) == 0 {
			return nil, errors.New("endpoint has no models")
		}
		for _, model := range endpoint.Models {
			if nearroute.ValidateModel(model) != nil {
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

func (e *endpointEntry) UnmarshalJSON(data []byte) error {
	type fields endpointEntry
	var out fields
	unknown, err := nearparse.Object(data, &out, "endpoint")
	if err != nil {
		return err
	}
	out.unknown = unknown
	*e = endpointEntry(out)
	return nil
}
