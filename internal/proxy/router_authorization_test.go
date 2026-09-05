package proxy

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
)

func routerCandidate(t *testing.T, model string) *authorization {
	t.Helper()
	route, err := provider.NewResolvedRoute("https://inference.tinfoil.sh", "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := route.AuthorizationKey("tinfoil_v3_cloud", model)
	if err != nil {
		t.Fatal(err)
	}
	report := &attestation.VerificationReport{Provider: key.ProviderName(), Model: model, TLSAuthority: route.Authority(), TLSKeyFP: strings.Repeat("ab", 32), Factors: []attestation.FactorResult{{Name: attestation.FactorE2EEUsable, Status: attestation.Skip}}}
	candidate, err := newAuthorization(key, report, "", false, false, time.Time{}, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func TestAuthorizationRouterSharesVerificationAcrossModels(t *testing.T) {
	store := newAuthorizationStore(10, 2, time.Second)
	defer store.close()
	var calls atomic.Int32
	var wg sync.WaitGroup
	for _, model := range []string{"one", "two", "three"} {
		candidate := routerCandidate(t, model)
		for range 8 {
			wg.Go(func() {
				value, _, err := store.load(t.Context(), candidate.key, nil, nil, func(context.Context) (authorizationVerification, error) {
					calls.Add(1)
					return authorizationVerification{candidate: candidate}, nil
				})
				if err != nil {
					t.Error(err)
					return
				}
				if value.key != candidate.key || value.report.Model != model {
					t.Error("router report has another model")
				}
			})
		}
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("verifications=%d", calls.Load())
	}
	one, two := routerCandidate(t, "one").key, routerCandidate(t, "two").key
	first, _ := store.acquire(one)
	store.promote(one, first.generation, "model one succeeded")
	a, _ := store.acquire(one)
	b, _ := store.acquire(two)
	if a.report.Factors[0].Status != attestation.Pass || b.report.Factors[0].Status != attestation.Skip {
		t.Fatal("model outcomes were shared")
	}
	if a.generation != b.generation {
		t.Fatal("models have distinct router generations")
	}
	if !store.deleteGeneration(two, b.generation) {
		t.Fatal("model rejection did not invalidate router")
	}
	if _, ok := store.acquire(one); ok {
		t.Fatal("invalidated router remained available to another model")
	}
	replacement := routerCandidate(t, "two")
	current := loadTestAuthorization(t, store, two, replacement)
	if store.deleteGeneration(one, first.generation) || store.promote(one, first.generation, "stale") {
		t.Fatal("old model outcome changed replacement router")
	}
	if current.generation == first.generation {
		t.Fatal("router generation was reused")
	}
}

func TestAuthorizationRouterModelViewsBounded(t *testing.T) {
	store := newAuthorizationStore(2, 1, time.Second)
	defer store.close()
	candidate := routerCandidate(t, "one")
	loadTestAuthorization(t, store, candidate.key, candidate)
	for _, model := range []string{"two", "three", "four"} {
		if _, ok := store.acquire(routerCandidate(t, model).key); !ok {
			t.Fatal("model missed router authorization")
		}
	}
	if len(store.snapshots()) != 2 {
		t.Fatal("router model reports exceeded capacity")
	}
	entries, keys := store.counts()
	if entries != 1 || keys != 0 {
		t.Fatal("router duplicated authorization material")
	}
}
