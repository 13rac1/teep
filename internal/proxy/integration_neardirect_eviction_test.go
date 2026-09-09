package proxy

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

func TestIntegration_NearDirectAuthorizationEviction(t *testing.T) {
	if testing.Short() || os.Getenv("NEARAI_API_KEY") == "" {
		t.Skip("live eviction requires NEAR credentials")
	}
	s, err := New(&config.Config{Providers: map[string]*config.Provider{"neardirect": {Name: "neardirect", BaseURL: "https://completions.near.ai", APIKey: os.Getenv("NEARAI_API_KEY"), E2EE: true}}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.authorizations.close()
	s.authorizations = newAuthorizationStore(1, 2, 2*time.Minute)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	prov := s.providers["neardirect"]
	direct := prov.Attester.(*neardirect.Attester)
	metadata := config.NewAttestationClient(false)
	countedMetadata := &evictionMetadataTransport{base: metadata.Transport}
	metadata.Transport = countedMetadata
	direct.SetMetadataClient(metadata)
	counted := &recoveryAttester{Attester: direct}
	prov.Attester = &recoveryRouteAttester{recoveryAttester: counted, routed: direct}
	// The wrapper owns cleanup, including resolver shutdown.
	defer direct.StopResolution()
	models := concurrentLiveModels(ctx, t, prov)
	var first *authorization
	var route provider.ResolvedRoute
	var key provider.AuthorizationKey
	for i, model := range models {
		selected, selectedKey, err := resolveRequestRoute(ctx, prov, model)
		if err != nil {
			t.Fatal(err)
		}
		value, blocked, err := s.loadAuthorization(ctx, prov, selected, selectedKey)
		if err != nil || blocked != nil {
			t.Fatal("live eviction admission failed")
		}
		if i == 0 {
			first, route, key = value, selected, selectedKey
		}
	}
	if _, ok := s.authorizations.acquire(key); ok {
		t.Fatal("capacity did not evict first authorization")
	}
	before := countedMetadata.calls.Load()
	// All callers retain the initial index and join one complete online verification.
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			selected, selectedKey, err := resolveRequestRoute(ctx, prov, models[0])
			if err != nil || selected != route || selectedKey != key {
				t.Error("eviction changed selected route")
				return
			}
			value, blocked, err := s.loadAuthorization(ctx, prov, selected, selectedKey)
			if err != nil || blocked != nil || value == nil {
				t.Error("concurrent online re-acquisition failed")
				return
			}
			if value.generation == first.generation {
				t.Error("evicted generation reacquired")
			}
		})
	}
	wg.Wait()
	current, ok := s.authorizations.acquire(key)
	if !ok || counted.calls.Load() != 3 || countedMetadata.calls.Load() != before {
		t.Fatal("eviction repeated discovery or failed to share full verification")
	}
	if s.authorizations.deleteGeneration(key, first.generation) {
		t.Fatal("old acquired attempt deleted replacement")
	}
	input := &authorizedRequest{provider: prov, route: route, key: key, path: prov.ChatPath, endpoint: e2ee.EndpointChat, contentType: "application/json"}
	if err := runLiveNearInference(ctx, s, input, true); err != nil {
		t.Fatal(err)
	}
	after, ok := s.authorizations.acquire(key)
	if !ok || after.generation != current.generation || counted.calls.Load() != 3 || countedMetadata.calls.Load() != before {
		t.Fatal("warm inference repeated discovery or attestation")
	}
}

type evictionMetadataTransport struct {
	base  http.RoundTripper
	calls atomic.Int32
}

func (r *evictionMetadataTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path != "/endpoints" && req.URL.Path != "/backends/count" {
		return nil, errors.New("unexpected route metadata path")
	}
	r.calls.Add(1)
	return r.base.RoundTrip(req)
}
func (r *evictionMetadataTransport) CloseIdleConnections() {
	if closer, ok := r.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
