package proxy

import (
	"sync"
	"testing"
	"time"
)

func TestResponseFailureCooldownGeneration(t *testing.T) {
	server := newTLSBindingTestServerHandle()
	server.authorizations = newAuthorizationStore(10, 2, time.Second)
	defer server.Close()
	key, candidate := testAuthorizationCandidate(t, "model")
	old := loadTestAuthorization(t, server.authorizations, key, candidate)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() { server.rejectResponseAuthorization(key, old.generation) })
	}
	wg.Wait()
	info, ok := server.negCache.ActiveInfo(key.ProviderName(), key.EvidenceScope().SingleflightKey())
	if !ok {
		t.Fatal("missing failure cooldown")
	}
	if _, ok := server.authorizations.acquire(key); ok {
		t.Fatal("failed generation remains available")
	}
	// Publishing through the store models recovery after the cooldown. A late
	// failure must neither remove the replacement nor refresh the old cooldown.
	replacement := loadTestAuthorization(t, server.authorizations, key, candidate)
	for range 32 {
		wg.Go(func() { server.rejectResponseAuthorization(key, old.generation) })
	}
	wg.Wait()
	after, _ := server.negCache.ActiveInfo(key.ProviderName(), key.EvidenceScope().SingleflightKey())
	if !after.RecordedAt.Equal(info.RecordedAt) {
		t.Fatal("old failure extended cooldown")
	}
	current, ok := server.authorizations.acquire(key)
	if !ok || current.generation != replacement.generation {
		t.Fatal("old failure affected replacement")
	}
	otherKey, otherCandidate := testAuthorizationCandidate(t, "other")
	other := loadTestAuthorization(t, server.authorizations, otherKey, otherCandidate)
	if _, blocked := server.negCache.ActiveInfo(otherKey.ProviderName(), otherKey.EvidenceScope().SingleflightKey()); blocked {
		t.Fatal("failure blocked another model")
	}
	if other == nil {
		t.Fatal("other model unavailable")
	}
}
