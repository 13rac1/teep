package proxy

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthorizationEvictionUsesRecency(t *testing.T) {
	store := newAuthorizationStore(3, 2, time.Second)
	defer store.close()
	now := time.Now()
	store.now = func() time.Time { return now }
	key, candidate := testAuthorizationCandidate(t, "valid")
	first := loadTestAuthorization(t, store, key, candidate)
	now = now.Add(time.Minute)
	later := now.Add(time.Hour)
	for _, model := range []string{"second", "third"} {
		entryKey, entry := testAuthorizationCandidate(t, model)
		loadTestAuthorization(t, store, entryKey, entry)
	}
	// Age alone does not evict entries. Touch the first entry before insertion
	// so the least recently used entry is the second one.
	now = later
	store.acquire(key)
	newKey, fresh := testAuthorizationCandidate(t, "new")
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
		t.Fatal("capacity pressure repeated verification despite recent use")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.entries) != 3 {
		t.Fatal("unexpected authorization capacity")
	}
}
