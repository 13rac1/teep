package proxy

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// An authorization ends at its ACI/1 keyset not_after: until then a request
// acquires it without verification; from not_after on, no request acquires
// it, and concurrent requests share one new verification.
func TestAuthorizationEndsAtKeysetNotAfter(t *testing.T) {
	store := newAuthorizationStore(4, 2, time.Second)
	defer store.close()
	now := time.Unix(1_800_000_000, 0)
	var mu sync.Mutex
	store.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	setNow := func(at time.Time) {
		mu.Lock()
		defer mu.Unlock()
		now = at
	}
	notAfter := now.Add(time.Hour).Unix()
	key, candidate := testAuthorizationCandidate(t, "valid")
	candidate.report.ACIKeysetNotAfter = notAfter
	first := loadTestAuthorization(t, store, key, candidate)

	setNow(time.Unix(notAfter-1, 0))
	if value, ok := store.acquire(key); !ok || value.generation != first.generation {
		t.Fatal("the authorization ended before its keyset not_after")
	}

	setNow(time.Unix(notAfter, 0))
	_, renewed := testAuthorizationCandidate(t, "valid")
	renewed.report.ACIKeysetNotAfter = notAfter + 3600
	var verifications atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			value, _, err := store.load(t.Context(), key, nil, nil, func(context.Context) (authorizationVerification, error) {
				verifications.Add(1)
				return authorizationVerification{candidate: renewed}, nil
			})
			if err != nil {
				t.Error(err)
				return
			}
			if value.generation == first.generation {
				t.Error("a request acquired the authorization at its keyset not_after")
			}
		})
	}
	wg.Wait()
	if n := verifications.Load(); n != 1 {
		t.Fatalf("verifications = %d, want one shared verification", n)
	}
}

// A verification whose keyset not_after has passed at publication publishes
// nothing and fails the load.
func TestAuthorizationRefusesExpiredKeysetAtPublication(t *testing.T) {
	store := newAuthorizationStore(4, 2, time.Second)
	defer store.close()
	now := time.Unix(1_800_000_000, 0)
	store.now = func() time.Time { return now }
	key, candidate := testAuthorizationCandidate(t, "valid")
	candidate.report.ACIKeysetNotAfter = now.Unix()
	_, _, err := store.load(t.Context(), key, nil, nil, func(context.Context) (authorizationVerification, error) {
		return authorizationVerification{candidate: candidate}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "not_after") {
		t.Fatalf("load error = %v, want the keyset not_after refusal", err)
	}
	if store.has(key) {
		t.Fatal("an authorization with an expired keyset was published")
	}
}
