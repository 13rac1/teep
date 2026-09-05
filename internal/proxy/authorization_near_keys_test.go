package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
)

func nearKeyCandidate(t *testing.T, name, model string) *authorization {
	t.Helper()
	route, err := provider.NewResolvedRoute("https://a.near.ai", "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := route.AuthorizationKey(name, model)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	report := &attestation.VerificationReport{Provider: name, Model: model, TLSAuthority: route.Authority(), TLSKeyFP: strings.Repeat("ab", 32), Factors: []attestation.FactorResult{{Name: attestation.FactorTEEReportData, Status: attestation.Pass}}}
	candidate, err := newAuthorization(key, report, hex.EncodeToString(public), true, false, time.Time{}, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

// This test isolates publication and request outcomes across providers, models,
// and generations. The HTTP/2 tests exercise the corresponding encrypted I/O.
func TestAuthorizationConcurrentNearModelKeys(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	store := newAuthorizationStore(10, 4, time.Second)
	defer store.close()
	candidates := make([]*authorization, 0, 4)
	for _, name := range []string{"nearcloud", "neardirect"} {
		for _, model := range []string{"one", "two"} {
			candidates = append(candidates, nearKeyCandidate(t, name, model))
		}
	}
	started := make(chan struct{}, len(candidates))
	release := make(chan struct{})
	retired := make(chan struct{})
	acquired := make(chan *authorization, 8*len(candidates))
	var calls atomic.Int32
	var wg sync.WaitGroup
	t.Cleanup(func() { cancel(); wg.Wait() })
	for _, candidate := range candidates {
		for range 8 {
			wg.Go(func() {
				value, _, err := store.load(ctx, candidate.key, nil, nil, func(verifyCtx context.Context) (authorizationVerification, error) {
					calls.Add(1)
					started <- struct{}{}
					select {
					case <-release:
						return authorizationVerification{candidate: candidate}, nil
					case <-verifyCtx.Done():
						return authorizationVerification{}, verifyCtx.Err()
					}
				})
				if err != nil {
					t.Error(err)
					return
				}
				if value.key != candidate.key || subtle.ConstantTimeCompare([]byte(value.signingKey), []byte(candidate.signingKey)) != 1 {
					t.Error("authorization contains another provider or model key")
				}
				acquired <- value
				select {
				case <-retired:
					if store.deleteGeneration(value.key, value.generation) || store.promote(value.key, value.generation, "old request") {
						t.Error("old request changed replacement authorization")
					}
				case <-ctx.Done():
				}
			})
		}
	}
	for range candidates {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("concurrent verification did not start")
		}
	}
	close(release)
	for range 8 * len(candidates) {
		select {
		case <-acquired:
		case <-ctx.Done():
			t.Fatal("callers did not acquire authorization")
		}
	}
	if calls.Load() != int32(len(candidates)) {
		t.Fatal("same-key verification was not collapsed")
	}
	replacements := make([]*authorization, 0, len(candidates))
	for _, candidate := range candidates {
		store.invalidate(candidate.key)
		replacement := nearKeyCandidate(t, candidate.key.ProviderName(), candidate.key.Model())
		replacements = append(replacements, loadTestAuthorization(t, store, replacement.key, replacement))
	}
	close(retired)
	wg.Wait()
	for _, replacement := range replacements {
		value, ok := store.acquire(replacement.key)
		if !ok || value.generation != replacement.generation || subtle.ConstantTimeCompare([]byte(value.signingKey), []byte(replacement.signingKey)) != 1 {
			t.Fatal("replacement key was lost after old requests completed")
		}
	}
}
