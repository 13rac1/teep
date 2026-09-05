package proxy

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthorizationEvictionPrefersExpiredEntries(t *testing.T) {
	store := newAuthorizationStore(3, 2, time.Second)
	defer store.close()
	now := time.Now()
	store.now = func() time.Time { return now }
	key, candidate := testAuthorizationCandidate(t, "valid", time.Time{}, false)
	first := loadTestAuthorization(t, store, key, candidate)
	now = now.Add(time.Minute)
	expiry := now.Add(time.Hour)
	for _, model := range []string{"expired-one", "expired-two"} {
		expiredKey, expired := testAuthorizationCandidate(t, model, expiry, true)
		loadTestAuthorization(t, store, expiredKey, expired)
	}
	// Both newer entries expire exactly at the insertion boundary. Neither
	// has been looked up since expiry, so eviction must discover them itself.
	now = expiry
	newKey, fresh := testAuthorizationCandidate(t, "new", time.Time{}, false)
	loadTestAuthorization(t, store, newKey, fresh)

	var verifications atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			value, _, err := store.load(t.Context(), key, nil, nil, func(context.Context) (authorizationVerification, error) {
				verifications.Add(1)
				return authorizationVerification{}, errors.New("valid authorization should have been retained")
			})
			if err != nil {
				t.Error(err)
				return
			}
			if value.generation != first.generation {
				t.Error("capacity pressure replaced valid authorization")
			}
		})
	}
	wg.Wait()
	if verifications.Load() != 0 {
		t.Fatal("capacity pressure repeated verification despite expired entries")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.entries) != 2 {
		t.Fatal("expired entries still occupy authorization capacity")
	}
}
