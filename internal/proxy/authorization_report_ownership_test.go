package proxy

import (
	"sync"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
)

func TestAuthorizationConcurrentReportOwnership(t *testing.T) {
	store := newAuthorizationStore(10, 2, time.Second)
	defer store.close()
	key, candidate := testAuthorizationCandidate(t, "model", time.Time{}, false)
	candidate.report.Factors = []attestation.FactorResult{{Name: attestation.FactorE2EEUsable, Status: attestation.Skip}}
	first := loadTestAuthorization(t, store, key, candidate)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 20 {
				value, ok := store.acquire(key)
				if !ok {
					t.Error("authorization disappeared")
					return
				}
				store.promote(key, value.generation, "authenticated response")
				value.report.Metadata["model"] = "caller mutation"
				value.report.Factors[0].Status = attestation.Fail
			}
		})
	}
	wg.Wait()
	value, ok := store.acquire(key)
	if !ok || value.report.Metadata["model"] != "model" || value.report.Factors[0].Status != attestation.Pass {
		t.Fatal("caller mutation changed the published report")
	}
	if first.report.Factors[0].Status != attestation.Skip {
		t.Fatal("promotion mutated an acquired report")
	}
	if value.generation != first.generation {
		t.Fatal("promotion changed generation")
	}
}
