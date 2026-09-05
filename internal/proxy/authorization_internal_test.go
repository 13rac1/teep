package proxy

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
)

func testAuthorizationCandidate(t *testing.T, model string, expires time.Time, hasExpiry bool) (provider.AuthorizationKey, *authorization) {
	t.Helper()
	route, err := provider.NewResolvedRoute("https://a.near.ai", "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := route.AuthorizationKey("neardirect", model)
	if err != nil {
		t.Fatal(err)
	}
	report := &attestation.VerificationReport{Provider: "neardirect", Model: model, TLSAuthority: route.Authority(), TLSKeyFP: strings.Repeat("ab", 32), Metadata: map[string]string{"model": model}}
	value, err := newAuthorization(key, report, "", false, false, expires, hasExpiry, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return key, value
}

func loadTestAuthorization(t *testing.T, store *authorizationStore, key provider.AuthorizationKey, candidate *authorization) *authorization {
	t.Helper()
	value, blocked, err := store.load(context.Background(), key, nil, func(context.Context) (authorizationVerification, error) {
		return authorizationVerification{candidate: candidate}, nil
	})
	if err != nil || blocked != nil || value == nil {
		t.Fatalf("load authorization: %v", err)
	}
	return value
}

func TestAuthorizationSameKeySingleflight(t *testing.T) {
	store := newAuthorizationStore(maxAuthorizations, maxAuthorizationVerifications, authorizationVerificationTimeout)
	defer store.close()
	key, candidate := testAuthorizationCandidate(t, "model", time.Time{}, false)
	var calls atomic.Int32
	var wg sync.WaitGroup
	results := make(chan *authorization, 32)
	for range 32 {
		wg.Go(func() {
			value, _, err := store.load(context.Background(), key, nil, func(context.Context) (authorizationVerification, error) {
				calls.Add(1)
				return authorizationVerification{candidate: candidate}, nil
			})
			if err != nil {
				t.Error(err)
				return
			}
			results <- value
		})
	}
	wg.Wait()
	close(results)
	var generation authorizationGeneration
	for value := range results {
		if generation == 0 {
			generation = value.generation
		}
		if value.generation != generation {
			t.Error("joiners received different authorization generations")
		}
		value.report.Metadata["model"] = "caller mutation"
	}
	if calls.Load() != 1 {
		t.Fatalf("verification calls = %d", calls.Load())
	}
	value, ok := store.acquire(key)
	if !ok || value.report.Metadata["model"] != "model" {
		t.Fatal("caller mutated cached report")
	}
}

func TestAuthorizationStaleGenerationCannotChangeReplacement(t *testing.T) {
	store := newAuthorizationStore(2, 1, time.Second)
	defer store.close()
	key, candidate := testAuthorizationCandidate(t, "model", time.Time{}, false)
	a := loadTestAuthorization(t, store, key, candidate)
	store.invalidate(key)
	b := loadTestAuthorization(t, store, key, candidate)
	if a.generation == b.generation {
		t.Fatal("replacement reused generation")
	}
	if store.deleteGeneration(key, a.generation) || store.promote(key, a.generation, "late result") {
		t.Fatal("old result changed replacement authorization")
	}
	if !store.promote(key, b.generation, "E2EE succeeded") {
		t.Fatal("current result was not promoted")
	}
	current, ok := store.acquire(key)
	if !ok || current.generation != b.generation || current.hasExpiry {
		t.Fatal("promotion changed authorization lifetime or generation")
	}
}

func TestAuthorizationLifetimeAndAcquisition(t *testing.T) {
	store := newAuthorizationStore(2, 1, time.Second)
	defer store.close()
	key, candidate := testAuthorizationCandidate(t, "model", time.Time{}, false)
	a := loadTestAuthorization(t, store, key, candidate)
	store.now = func() time.Time { return time.Now().Add(24 * time.Hour) }
	if _, ok := store.acquire(key); !ok {
		t.Fatal("invented local authorization TTL")
	}
	ctx, cancel := a.attemptContext(context.Background())
	defer cancel()
	store.deleteGeneration(key, a.generation)
	if _, ok := store.acquire(key); ok {
		t.Fatal("acquired deleted generation")
	}
	if ctx.Err() != nil {
		t.Fatal("deletion canceled an already acquired attempt")
	}
	store.now = time.Now
	expiry := time.Now().Add(time.Hour)
	key, candidate = testAuthorizationCandidate(t, "model", expiry, true)
	a = loadTestAuthorization(t, store, key, candidate)
	ctx2, cancel2 := a.attemptContext(context.Background())
	defer cancel2()
	deadline, ok := ctx2.Deadline()
	if !ok || !deadline.Equal(expiry) {
		t.Fatal("attempt is not bounded by authenticated expiry")
	}
	store.now = func() time.Time { return expiry }
	if _, ok := store.acquire(key); ok {
		t.Fatal("acquired authorization at its expiration boundary")
	}
}

func TestAuthorizationInvalidationPreventsLatePublication(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		store := newAuthorizationStore(2, 1, time.Second)
		key, candidate := testAuthorizationCandidate(t, "model", time.Time{}, false)
		started := make(chan struct{})
		release := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			_, _, err := store.load(context.Background(), key, nil, func(context.Context) (authorizationVerification, error) {
				close(started)
				<-release // Simulate verification that completes after cancellation.
				return authorizationVerification{candidate: candidate}, nil
			})
			done <- err
		}()
		<-started
		if shutdown {
			store.close()
		} else {
			store.invalidate(key)
		}
		close(release)
		if err := <-done; err == nil {
			t.Fatal("invalidated verification published authorization")
		}
		if _, ok := store.acquire(key); ok {
			t.Fatal("late publication survived invalidation")
		}
		store.close()
	}
}

func TestAuthorizationVerificationAdmissionAndCancellation(t *testing.T) {
	store := newAuthorizationStore(2, 1, time.Second)
	defer store.close()
	key, candidate := testAuthorizationCandidate(t, "model", time.Time{}, false)
	other, _ := testAuthorizationCandidate(t, "other", time.Time{}, false)
	started := make(chan struct{})
	release := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var calls atomic.Int32
	verify := func(verifyCtx context.Context) (authorizationVerification, error) {
		calls.Add(1)
		close(started)
		<-release
		return authorizationVerification{candidate: candidate}, verifyCtx.Err()
	}
	go func() { _, _, err := store.load(ctx, key, nil, verify); done <- err }()
	<-started
	_, _, err := store.load(context.Background(), other, nil, verify)
	if _, ok := errors.AsType[*verificationOverloadError](err); !ok {
		t.Fatalf("distinct key did not fail fast: %v", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation: %v", err)
	}
	joined := make(chan error, 1)
	go func() { _, _, err := store.load(context.Background(), key, nil, verify); joined <- err }()
	close(release)
	if err := <-joined; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("cancellation restarted shared verification")
	}
}

func TestAuthorizationExpiryDuringVerificationAndEviction(t *testing.T) {
	store := newAuthorizationStore(1, 1, time.Second)
	defer store.close()
	expiry := time.Now().Add(time.Hour)
	key, candidate := testAuthorizationCandidate(t, "model", expiry, true)
	_, _, err := store.load(context.Background(), key, nil, func(context.Context) (authorizationVerification, error) {
		store.now = func() time.Time { return expiry }
		return authorizationVerification{candidate: candidate}, nil
	})
	if err == nil {
		t.Fatal("published evidence that expired during verification")
	}
	store.now = time.Now
	a := loadTestAuthorization(t, store, key, candidate)
	other, replacement := testAuthorizationCandidate(t, "other", time.Time{}, false)
	loadTestAuthorization(t, store, other, replacement)
	if _, ok := store.acquire(key); ok {
		t.Fatal("capacity eviction did not prevent acquisition")
	}
	if a.identity.Authority() != key.Authority() {
		t.Fatal("eviction changed an acquired snapshot")
	}
}

func TestAuthorizationBlockedReportNotCached(t *testing.T) {
	store := newAuthorizationStore(1, 1, time.Second)
	defer store.close()
	key, _ := testAuthorizationCandidate(t, "model", time.Time{}, false)
	blocked := &attestation.VerificationReport{Factors: []attestation.FactorResult{{Status: attestation.Fail, Enforced: true}}}
	value, report, err := store.load(context.Background(), key, nil, func(context.Context) (authorizationVerification, error) {
		return authorizationVerification{blocked: blocked}, nil
	})
	if err != nil || value != nil || report == nil || !report.Blocked() {
		t.Fatal("blocked report was not returned for diagnostics")
	}
	if _, ok := store.acquire(key); ok {
		t.Fatal("blocked report became authorization")
	}
}

func TestAuthorizationNegativeRecheck(t *testing.T) {
	store := newAuthorizationStore(1, 1, time.Second)
	defer store.close()
	key, _ := testAuthorizationCandidate(t, "model", time.Time{}, false)
	failure := errors.New("recent attestation failure")
	var checks atomic.Int32
	negative := func() error {
		if checks.Add(1) > 1 {
			return failure
		}
		return nil
	}
	_, _, err := store.load(context.Background(), key, negative, func(context.Context) (authorizationVerification, error) {
		t.Error("verification started despite negative cache")
		return authorizationVerification{}, errors.New("unexpected verification")
	})
	if !errors.Is(err, failure) {
		t.Fatalf("negative recheck: %v", err)
	}
}
