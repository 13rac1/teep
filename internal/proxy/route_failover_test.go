package proxy

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
)

// failoverCandidateA and failoverCandidateB are synthetic enclave authorities;
// no network traffic reaches them because every fetch is a mock.
const (
	failoverCandidateA = "a.enclave.test"
	failoverCandidateB = "b.enclave.test"
	failoverTestModel  = "model"
)

// failoverRouteAttester records which candidate authorities were fetched and
// reported. A candidate with no entry in errFor returns an evidence-free
// attestation, which the verifier blocks. errFor is fixed at construction.
type failoverRouteAttester struct {
	mu       sync.Mutex
	fetches  []string
	reported []string
	errFor   map[string]error
}

func (a *failoverRouteAttester) FetchAttestation(context.Context, string, attestation.Nonce) (*attestation.RawAttestation, error) {
	return nil, errors.New("failoverRouteAttester: FetchAttestation called outside the route-attester path")
}

func (a *failoverRouteAttester) FetchAttestationForRoute(_ context.Context, route provider.ResolvedRoute, _ string, _ attestation.Nonce) (*attestation.RawAttestation, error) {
	a.mu.Lock()
	a.fetches = append(a.fetches, route.Authority())
	a.mu.Unlock()
	if err := a.errFor[route.Authority()]; err != nil {
		return nil, err
	}
	return &attestation.RawAttestation{}, nil
}

func (a *failoverRouteAttester) RecordCandidateFailure(_ context.Context, _, authority string) {
	a.mu.Lock()
	a.reported = append(a.reported, authority)
	a.mu.Unlock()
}

func (a *failoverRouteAttester) hasReported(authority string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Contains(a.reported, authority)
}

func (a *failoverRouteAttester) state() (fetches, reported []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.fetches), slices.Clone(a.reported)
}

// failoverHarness builds a server and a request whose provider resolves
// candidates through resolve. It returns the resolution call count; the
// initial request construction consumes the first call.
func failoverHarness(t *testing.T, routeAttester provider.Attester, record provider.CandidateFailureRecorder, resolve func() provider.ResolvedRoute) (*Server, *authorizedRequest, *atomic.Int32) {
	t.Helper()
	server := newTLSBindingTestServerHandle()
	server.authorizations = newAuthorizationStore(10, 2, time.Second)
	t.Cleanup(server.Close)
	return failoverHarnessOn(t, server, routeAttester, record, resolve)
}

// failoverHarnessOn attaches the mock provider to an existing server. A nil
// record leaves candidate failover inert.
func failoverHarnessOn(t *testing.T, server *Server, routeAttester provider.Attester, record provider.CandidateFailureRecorder, resolve func() provider.ResolvedRoute) (*Server, *authorizedRequest, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	prov := &provider.Provider{
		Name:           "tinfoil_v3_direct",
		UsesTLSBinding: true,
		Attester:       routeAttester,
		// The blocked-report path reaches supply-chain verification with an
		// evidence-free raw attestation; the sentinel marks that factor
		// inapplicable instead of panicking on a nil policy.
		SupplyChainPolicy: attestation.NoSupplyChainPolicy(),
		ResolveRoute: func(context.Context, string) (provider.ResolvedRoute, error) {
			calls.Add(1)
			return resolve(), nil
		},
		RecordCandidateFailure: record,
	}
	route, key, err := resolveRequestRoute(t.Context(), prov, failoverTestModel)
	if err != nil {
		t.Fatal(err)
	}
	input := &authorizedRequest{provider: prov, route: route, key: key, body: []byte(`{"model":"model"}`), path: "/v1/chat/completions", contentType: "application/json", endpoint: e2ee.EndpointChat}
	return server, input, &calls
}

func failoverRoutes(t *testing.T) (routeA, routeB provider.ResolvedRoute) {
	t.Helper()
	routeA, err := provider.NewResolvedRoute("https://"+failoverCandidateA, "")
	if err != nil {
		t.Fatal(err)
	}
	routeB, err = provider.NewResolvedRoute("https://"+failoverCandidateB, "")
	if err != nil {
		t.Fatal(err)
	}
	return routeA, routeB
}

func TestLoadAuthorizationFailoverTriesNextCandidate(t *testing.T) {
	routeA, routeB := failoverRoutes(t)
	attester := &failoverRouteAttester{errFor: map[string]error{
		failoverCandidateA: errors.New("dial tcp: connection refused"),
		failoverCandidateB: errors.New("candidate B fetch failed"),
	}}
	server, input, resolveCalls := failoverHarness(t, attester, attester.RecordCandidateFailure, func() provider.ResolvedRoute {
		if attester.hasReported(failoverCandidateA) {
			return routeB
		}
		return routeA
	})

	_, _, final, err := server.loadAuthorizationWithFailover(t.Context(), input)
	if err == nil || !strings.Contains(err.Error(), "candidate B fetch failed") {
		t.Fatalf("err = %v, want candidate B's error returned unchanged", err)
	}
	fetches, reported := attester.state()
	if !slices.Equal(fetches, []string{failoverCandidateA, failoverCandidateB}) {
		t.Errorf("fetches = %v, want [%s %s]", fetches, failoverCandidateA, failoverCandidateB)
	}
	// We also record candidate B. We stop when the resolver returns B again.
	if !slices.Equal(reported, []string{failoverCandidateA, failoverCandidateB}) {
		t.Errorf("reported = %v, want [%s %s]", reported, failoverCandidateA, failoverCandidateB)
	}
	if calls := resolveCalls.Load(); calls != 3 {
		t.Errorf("resolution calls = %d, want 3 (initial plus two re-resolutions)", calls)
	}
	if final == input {
		t.Fatal("final request aliases the caller's input")
	}
	if final.route.Authority() != failoverCandidateB || final.key.Authority() != failoverCandidateB || final.key.Model() != failoverTestModel {
		t.Errorf("final request carries route %q key %q, want candidate B", final.route.Authority(), final.key.Authority())
	}
	if input.route.Authority() != failoverCandidateA {
		t.Errorf("caller input mutated: route = %q, want candidate A", input.route.Authority())
	}
}

// We stop on an error that no call site marks as a candidate failure, and we
// do not record the candidate. A route and key mismatch is a local error. If
// we recorded it, we would skip every healthy candidate.
func TestLoadAuthorizationFailoverStopsOnUnclassifiedError(t *testing.T) {
	routeA, routeB := failoverRoutes(t)
	attester := &failoverRouteAttester{}
	server, input, resolveCalls := failoverHarness(t, attester, attester.RecordCandidateFailure, func() provider.ResolvedRoute {
		if attester.hasReported(failoverCandidateA) {
			return routeB
		}
		return routeA
	})
	keyB, err := routeB.AuthorizationKey(input.provider.Name, failoverTestModel)
	if err != nil {
		t.Fatal(err)
	}
	input.key = keyB

	_, _, _, err = server.loadAuthorizationWithFailover(t.Context(), input)
	if err == nil || err.Error() != "authorization route and key differ" {
		t.Fatalf("err = %v, want the route and key mismatch", err)
	}
	fetches, reported := attester.state()
	if len(fetches) != 0 || len(reported) != 0 {
		t.Errorf("fetches = %v, reported = %v, want neither", fetches, reported)
	}
	if calls := resolveCalls.Load(); calls != 1 {
		t.Errorf("resolution calls = %d, want 1 (failover stops on unclassified error)", calls)
	}
}

// When an enforced factor fails, we try the next candidate. The client gets
// the last blocked report, so the request fails closed.
func TestLoadAuthorizationFailoverTriesNextOnFailedFactor(t *testing.T) {
	server, err := New(&config.Config{Offline: true, Providers: map[string]*config.Provider{
		"tinfoil_v3_direct": {Name: "tinfoil_v3_direct", BaseURL: "https://inference.tinfoil.sh", APIKey: "test"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)

	routeA, routeB := failoverRoutes(t)
	attester := &failoverRouteAttester{}
	_, input, resolveCalls := failoverHarnessOn(t, server, attester, attester.RecordCandidateFailure, func() provider.ResolvedRoute {
		if attester.hasReported(failoverCandidateA) {
			return routeB
		}
		return routeA
	})

	value, blocked, final, err := server.loadAuthorizationWithFailover(t.Context(), input)
	if err != nil {
		t.Fatalf("loadAuthorizationWithFailover: %v", err)
	}
	if value != nil {
		t.Errorf("value = %v, want nil for blocked acquisition", value)
	}
	if blocked == nil {
		t.Fatal("blocked report is nil, want the last candidate's blocked report")
	}
	fetches, reported := attester.state()
	if !slices.Equal(fetches, []string{failoverCandidateA, failoverCandidateB}) {
		t.Errorf("fetches = %v, want [%s %s]", fetches, failoverCandidateA, failoverCandidateB)
	}
	if !slices.Equal(reported, []string{failoverCandidateA, failoverCandidateB}) {
		t.Errorf("reported = %v, want [%s %s]", reported, failoverCandidateA, failoverCandidateB)
	}
	if calls := resolveCalls.Load(); calls != 3 {
		t.Errorf("resolution calls = %d, want 3 (initial plus two re-resolutions)", calls)
	}
	if final.route.Authority() != failoverCandidateB {
		t.Errorf("final route = %q, want candidate B", final.route.Authority())
	}
	if blocked.Model != failoverTestModel {
		t.Errorf("blocked report model = %q, want %q", blocked.Model, failoverTestModel)
	}
}
