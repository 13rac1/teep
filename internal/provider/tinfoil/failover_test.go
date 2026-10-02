package tinfoil

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"
)

// failoverModel is the model name used by the failover tests.
const failoverModel = "gemma4-31b"

// failoverSnapshot returns a fixed six-candidate discovery snapshot. Seeded
// domains are used in slice order when no prompt_cache_key is set, so tests
// that need a specific first candidate order the slice accordingly.
func failoverSnapshot() []string {
	return []string{
		"gemma4-31b-1.inf10.tinfoil.sh",
		"gemma4-31b-2.inf10.tinfoil.sh",
		"gemma4-31b-3.inf10.tinfoil.sh",
		"gemma4-31b-4.inf10.tinfoil.sh",
		"gemma4-31b-5.inf10.tinfoil.sh",
		"gemma4-31b-6.inf10.tinfoil.sh",
	}
}

// seedFailoverResolver returns a resolver with a fresh mapping for the model,
// so Resolve skips discovery and reads the seeded snapshot.
func seedFailoverResolver(m ModelMapping) *DirectResolver {
	r := NewDirectResolver("key", true)
	r.fetchedAt = time.Now()
	r.mapping[failoverModel] = m
	return r
}

func TestFailoverDeterministicSelection(t *testing.T) {
	const promptKey = "prompt-cache-key-fixed"
	want := rankedDomains(failoverSnapshot(), promptKey)
	for range 100 {
		got := rankedDomains(failoverSnapshot(), promptKey)
		if !slices.Equal(got, want) {
			t.Fatalf("rankedDomains not deterministic: got %v, want %v", got, want)
		}
	}

	resolver := seedFailoverResolver(ModelMapping{
		Domain:  failoverSnapshot()[0],
		Repo:    "repo/test",
		Domains: failoverSnapshot(),
	})
	resolver.RecordCandidateFailure(context.Background(), failoverModel, want[0])
	m := resolver.mapping[failoverModel]
	for range 100 {
		if got := resolver.selectDomain(failoverModel, m, promptKey); got != want[1] {
			t.Fatalf("selectDomain with skip = %q, want %q", got, want[1])
		}
	}
}

func TestFailoverStickyFirstChoicePreserved(t *testing.T) {
	m := ModelMapping{Domain: failoverSnapshot()[0], Repo: "repo/test", Domains: failoverSnapshot()}
	resolver := seedFailoverResolver(m)

	keys := make([]string, 0, 51)
	for i := range 50 {
		keys = append(keys, fmt.Sprintf("prompt-cache-key-%d", i))
	}
	keys = append(keys, "")
	for _, key := range keys {
		if got, want := resolver.selectDomain(failoverModel, m, key), m.SelectDomain(key); got != want {
			t.Errorf("selectDomain(%q) = %q, SelectDomain = %q", key, got, want)
		}
	}
}

func TestSkipSetExpiryAndRecovery(t *testing.T) {
	const a, b = "a.inf10.tinfoil.sh", "b.inf10.tinfoil.sh"
	resolver := seedFailoverResolver(ModelMapping{
		Domain:  a,
		Repo:    "repo/test",
		Domains: []string{a, b},
	})
	m := resolver.mapping[failoverModel]

	resolver.RecordCandidateFailure(context.Background(), failoverModel, a)
	if got := resolver.selectDomain(failoverModel, m, ""); got != b {
		t.Errorf("selectDomain after skip = %q, want %q", got, b)
	}

	// Backdate the skip entry to simulate cooldown expiry.
	resolver.mu.Lock()
	resolver.skip[failoverModel][a] = time.Now().Add(-time.Minute)
	resolver.mu.Unlock()
	if got := resolver.selectDomain(failoverModel, m, ""); got != a {
		t.Errorf("selectDomain after expiry = %q, want %q", got, a)
	}

	// A single-candidate model stays selectable: all-skipped selection falls
	// back to the full candidate order.
	const singleModel = "single-candidate-model"
	resolver.mu.Lock()
	resolver.mapping[singleModel] = ModelMapping{Domain: a, Repo: "repo/test", Domains: []string{a}}
	resolver.mu.Unlock()
	resolver.RecordCandidateFailure(context.Background(), singleModel, a)
	if got := resolver.selectDomain(singleModel, resolver.mapping[singleModel], ""); got != a {
		t.Errorf("single-candidate selectDomain = %q, want %q", got, a)
	}
	route, err := resolver.ResolveRoute(context.Background(), singleModel)
	if err != nil {
		t.Fatalf("ResolveRoute single candidate: %v", err)
	}
	if route.Authority() != a {
		t.Errorf("ResolveRoute authority = %q, want %q", route.Authority(), a)
	}
}

func TestRecordCandidateFailureConcurrent(t *testing.T) {
	resolver := seedFailoverResolver(ModelMapping{
		Domain:  failoverSnapshot()[0],
		Repo:    "repo/test",
		Domains: failoverSnapshot(),
	})

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			d := failoverSnapshot()[i%len(failoverSnapshot())]
			resolver.RecordCandidateFailure(context.Background(), failoverModel, d)
			if _, err := resolver.ResolveRoute(context.Background(), failoverModel); err != nil {
				t.Errorf("ResolveRoute: %v", err)
			}
			resolver.mu.RLock()
			m := resolver.mapping[failoverModel]
			resolver.mu.RUnlock()
			_ = resolver.selectDomain(failoverModel, m, "prompt-cache-key")
		})
	}
	wg.Wait()
}
