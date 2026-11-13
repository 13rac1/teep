package proxy

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
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
	candidate.report.BackendFormat = attestation.FormatACI1
	candidate.report.ACIKeysetNotAfter = notAfter
	first := loadTestAuthorization(t, store, key, candidate)

	setNow(time.Unix(notAfter-1, 0))
	if value, ok := store.acquire(key); !ok || value.generation != first.generation {
		t.Fatal("the authorization ended before its keyset not_after")
	}

	setNow(time.Unix(notAfter, 0))
	_, renewed := testAuthorizationCandidate(t, "valid")
	renewed.report.BackendFormat = attestation.FormatACI1
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

// A verification whose keyset not_after has passed at publication, or that
// has no valid not_after, publishes nothing and fails the load with a
// message for its case.
func TestAuthorizationRefusesExpiredKeysetAtPublication(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		name     string
		notAfter int64
		want     string
	}{
		{"passed", now.Unix(), "passed before publication"},
		{"zero", 0, "has no valid not_after"},
		{"negative", -1, "has no valid not_after"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newAuthorizationStore(4, 2, time.Second)
			defer store.close()
			store.now = func() time.Time { return now }
			key, candidate := testAuthorizationCandidate(t, "valid")
			candidate.report.BackendFormat = attestation.FormatACI1
			candidate.report.ACIKeysetNotAfter = tc.notAfter
			_, _, err := store.load(t.Context(), key, nil, nil, func(context.Context) (authorizationVerification, error) {
				return authorizationVerification{candidate: candidate}, nil
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("load error = %v, want %q", err, tc.want)
			}
			if store.has(key) {
				t.Fatal("an authorization with an expired keyset was published")
			}
		})
	}
}

// The diagnostic snapshots leave out an authorization past its keyset
// not_after, and do not remove it from the store.
func TestSnapshotsLeaveOutExpiredKeyset(t *testing.T) {
	store := newAuthorizationStore(4, 2, time.Second)
	defer store.close()
	now := time.Unix(1_800_000_000, 0)
	var mu sync.Mutex
	store.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	notAfter := now.Add(time.Hour).Unix()
	key, candidate := testAuthorizationCandidate(t, "valid")
	candidate.report.BackendFormat = attestation.FormatACI1
	candidate.report.ACIKeysetNotAfter = notAfter
	loadTestAuthorization(t, store, key, candidate)

	mu.Lock()
	now = time.Unix(notAfter-1, 0)
	mu.Unlock()
	if len(store.snapshots()) != 1 {
		t.Fatal("snapshots leave out a valid authorization")
	}
	if _, ok := store.reportSnapshot(key); !ok {
		t.Fatal("reportSnapshot leaves out a valid authorization")
	}

	mu.Lock()
	now = time.Unix(notAfter, 0)
	mu.Unlock()
	if n := len(store.snapshots()); n != 0 {
		t.Errorf("snapshots = %d at the keyset not_after, want none", n)
	}
	if _, ok := store.reportSnapshot(key); ok {
		t.Error("reportSnapshot shows an authorization at its keyset not_after")
	}
	store.mu.Lock()
	n := len(store.entries)
	store.mu.Unlock()
	if n != 1 {
		t.Errorf("entries = %d after the snapshots, want the store unchanged", n)
	}
}
