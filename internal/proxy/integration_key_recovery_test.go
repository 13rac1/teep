package proxy

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
)

func TestIntegration_NearDirectKeyRecovery(t *testing.T) { testLiveKeyRecovery(t, "neardirect") }
func TestIntegration_NearCloudKeyRecovery(t *testing.T)  { testLiveKeyRecovery(t, "nearcloud") }
func TestIntegration_TinfoilKeyRecovery(t *testing.T)    { testLiveKeyRecovery(t, "tinfoil_v3_cloud") }

// Only the pre-inference rejection is injected. Both authorizations run the
// complete online verification pipeline, and retries use live encrypted I/O.
func testLiveKeyRecovery(t *testing.T, name string) {
	t.Helper()
	env, origin := "NEARAI_API_KEY", "https://completions.near.ai"
	if name == "nearcloud" {
		origin = "https://cloud-api.near.ai"
	}
	if name == "tinfoil_v3_cloud" {
		env, origin = "TINFOIL_API_KEY", "https://inference.tinfoil.sh"
	}
	if testing.Short() || os.Getenv(env) == "" {
		t.Skip("live key recovery requires provider credentials")
	}
	s, err := New(&config.Config{Providers: map[string]*config.Provider{name: {Name: name, BaseURL: origin, APIKey: os.Getenv(env), E2EE: true}}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	prov := s.providers[name]
	model := "gemma4-31b"
	if name != "tinfoil_v3_cloud" {
		model = liveNearTextModel(ctx, t, prov)
	} else if configured := os.Getenv("TINFOIL_CHAT_MODEL"); configured != "" {
		model = strings.TrimPrefix(configured, name+":")
	}
	counted := &recoveryAttester{Attester: prov.Attester}
	if routed, ok := prov.Attester.(provider.RouteAttester); ok {
		prov.Attester = &recoveryRouteAttester{recoveryAttester: counted, routed: routed}
	} else {
		prov.Attester = counted
	}
	route, key, err := resolveRequestRoute(ctx, prov, model)
	if err != nil {
		t.Fatal(err)
	}
	initial, blocked, err := s.loadAuthorization(ctx, prov, route, key)
	if err != nil || blocked != nil {
		t.Fatal("live attestation did not authorize recovery test")
	}
	if name == "tinfoil_v3_cloud" {
		checkLiveRouterModelReuse(ctx, t, s, prov, route, model, initial.generation, counted)
	}
	client, err := s.pinnedClientForIdentity(name, initial.identity)
	if err != nil {
		t.Fatal(err)
	}
	transport := &recoveryTransport{base: client.Transport, name: name, arrived: make(chan struct{}), replacement: make(chan struct{})}
	client.Transport = transport
	input := &authorizedRequest{provider: prov, route: route, key: key, path: prov.ChatPath, endpoint: e2ee.EndpointChat, contentType: "application/json"}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if err := runLiveNearInference(ctx, s, input, true); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	current, ok := s.authorizations.acquire(key)
	if !ok || current.generation == initial.generation {
		t.Fatal("recovery did not publish replacement authorization")
	}
	if counted.calls.Load() != 2 {
		t.Errorf("attestation fetches=%d; want initial plus one shared refresh", counted.calls.Load())
	}
	if name == "tinfoil_v3_cloud" {
		checkLiveRouterModelReuse(ctx, t, s, prov, route, model, current.generation, counted)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.calls != 8 {
		t.Errorf("inference attempts=%d; want two per client", transport.calls)
	}
}

type recoveryAttester struct {
	provider.Attester
	calls       atomic.Int32
	beforeFetch func(context.Context) error
}

func (a *recoveryAttester) FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	if err := a.beginFetch(ctx); err != nil {
		return nil, err
	}
	return a.Attester.FetchAttestation(ctx, model, nonce)
}

func (a *recoveryAttester) CloseIdleConnections() {
	if owner, ok := a.Attester.(interface{ CloseIdleConnections() }); ok {
		owner.CloseIdleConnections()
	}
}

func (a *recoveryAttester) beginFetch(ctx context.Context) error {
	a.calls.Add(1)
	if a.beforeFetch != nil {
		return a.beforeFetch(ctx)
	}
	return nil
}

type recoveryRouteAttester struct {
	*recoveryAttester
	routed provider.RouteAttester
}

func (a *recoveryRouteAttester) FetchAttestationForRoute(ctx context.Context, route provider.ResolvedRoute, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	if err := a.beginFetch(ctx); err != nil {
		return nil, err
	}
	return a.routed.FetchAttestationForRoute(ctx, route, model, nonce)
}

type recoveryTransport struct {
	base                 http.RoundTripper
	name                 string
	mu                   sync.Mutex
	calls                int
	sessions             []string
	arrived, replacement chan struct{}
	once                 sync.Once
}

func (t *recoveryTransport) CloseIdleConnections() {
	if owner, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		owner.CloseIdleConnections()
	}
}
func (t *recoveryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	session := req.Header.Get("X-Client-Pub-Key")
	if t.name == "tinfoil_v3_cloud" {
		session = req.Header.Get("Ehbp-Encapsulated-Key")
	}
	t.mu.Lock()
	for _, old := range t.sessions {
		if subtle.ConstantTimeCompare([]byte(old), []byte(session)) == 1 {
			t.mu.Unlock()
			req.Body.Close()
			return nil, errors.New("recovery reused an encryption session")
		}
	}
	t.sessions = append(t.sessions, session)
	t.calls++
	attempt := t.calls
	if attempt == 4 {
		close(t.arrived)
	}
	t.mu.Unlock()
	if attempt > 4 {
		resp, err := t.base.RoundTrip(req)
		if err == nil {
			t.once.Do(func() { close(t.replacement) })
		}
		return resp, err
	}
	defer req.Body.Close()
	select {
	case <-t.arrived:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	// Delay one old rejection until a retry has acquired the replacement.
	if attempt == 4 {
		select {
		case <-t.replacement:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	status, media, body := http.StatusBadRequest, "application/json", `{"error":{"type":"bad_request","message":"Decryption failed"}}`
	if t.name == "nearcloud" {
		status, body = http.StatusMisdirectedRequest, cloudStaleKeyBody
	}
	if t.name == "tinfoil_v3_cloud" {
		status, media, body = http.StatusUnprocessableEntity, "application/problem+json", `{"type":"urn:ietf:params:ehbp:error:key-config"}`
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {media}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
}

func checkLiveRouterModelReuse(ctx context.Context, t *testing.T, s *Server, prov *provider.Provider, route provider.ResolvedRoute, model string, generation authorizationGeneration, counted *recoveryAttester) {
	t.Helper()
	models, err := prov.ModelLister.ListModels(ctx)
	if err != nil {
		t.Fatal("router model discovery failed")
	}
	for _, raw := range models {
		var entry struct {
			ID string `json:"id"`
		}
		if _, _, err := jsonstrict.Unmarshal(raw, &entry); err != nil {
			t.Fatal("invalid model catalog")
		}
		if entry.ID == "" || entry.ID == model {
			continue
		}
		key, err := route.AuthorizationKey(prov.Name, entry.ID)
		if err != nil {
			t.Fatal(err)
		}
		before := counted.calls.Load()
		value, blocked, err := s.loadAuthorization(ctx, prov, route, key)
		if err != nil || blocked != nil {
			t.Fatal("router model authorization failed")
		}
		if value.generation != generation || value.report.Model != entry.ID || counted.calls.Load() != before {
			t.Fatal("another model repeated router attestation or received wrong report")
		}
		for _, factor := range value.report.Factors {
			if factor.Name == attestation.FactorE2EEUsable && factor.Status == attestation.Pass {
				t.Fatal("another model inherited E2EE outcome")
			}
		}
		return
	}
	t.Fatal("router model catalog has no second model")
}
