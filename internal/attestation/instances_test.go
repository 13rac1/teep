package attestation

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// rekorIndexServer answers every Rekor index search with no entries and
// counts the searches by digest.
func rekorIndexServer(t *testing.T) (rc *RekorClient, hits map[string]int) {
	t.Helper()
	var mu sync.Mutex
	hits = make(map[string]int)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Hash string `json:"hash"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode search: %v", err)
		}
		mu.Lock()
		hits[strings.TrimPrefix(body.Hash, "sha256:")]++
		mu.Unlock()
		_, _ = w.Write([]byte("[]"))
	}))
	t.Cleanup(srv.Close)
	return NewRekorClientWithBase(srv.URL, srv.Client()), hits
}

// The instances of one model share their image digests: the memo searches
// Rekor once for each digest and returns the results in the order asked.
func TestSupplyChainMemoSigstoreOncePerDigest(t *testing.T) {
	rc, hits := rekorIndexServer(t)
	memo := NewSupplyChainMemo()
	first := memo.CheckSigstoreDigests(t.Context(), rc, []string{"aa", "bb"})
	second := memo.CheckSigstoreDigests(t.Context(), rc, []string{"bb", "cc", "aa", "cc"})
	for d, n := range map[string]int{"aa": 1, "bb": 1, "cc": 1} {
		if hits[d] != n {
			t.Errorf("searches for %s = %d, want %d", d, hits[d], n)
		}
	}
	got := make([]string, 0, len(first)+len(second))
	for _, r := range append(first, second...) {
		if r.OK || r.Status != http.StatusNotFound {
			t.Errorf("digest %s: ok=%v status=%d, want absent", r.Digest, r.OK, r.Status)
		}
		got = append(got, r.Digest)
	}
	if strings.Join(got, ",") != "aa,bb,bb,cc,aa,cc" {
		t.Errorf("result order = %v", got)
	}
}

// Provenance is looked up once for each digest and repository pair; the
// same digest under another repository is a different lookup.
func TestSupplyChainMemoRekorOncePerDigestAndRepo(t *testing.T) {
	rc, hits := rekorIndexServer(t)
	memo := NewSupplyChainMemo()
	repos := map[string]string{"aa": "org/a", "bb": "org/b"}
	memo.FetchRekorProvenancesForPolicy(t.Context(), rc, []string{"aa", "bb"}, repos, nil)
	got := memo.FetchRekorProvenancesForPolicy(t.Context(), rc, []string{"bb", "aa"}, repos, nil)
	if hits["aa"] != 1 || hits["bb"] != 1 {
		t.Errorf("searches = %v, want one for each digest", hits)
	}
	if len(got) != 2 || got[0].Digest != "bb" || got[1].Digest != "aa" || got[0].Err == nil {
		t.Errorf("results = %+v", got)
	}
	memo.FetchRekorProvenancesForPolicy(t.Context(), rc, []string{"aa"}, map[string]string{"aa": "org/other"}, nil)
	if hits["aa"] != 2 {
		t.Errorf("searches for aa under another repository = %d, want 2", hits["aa"])
	}
}

// A nil memo sends every lookup.
func TestSupplyChainMemoNil(t *testing.T) {
	rc, hits := rekorIndexServer(t)
	var memo *SupplyChainMemo
	memo.CheckSigstoreDigests(t.Context(), rc, []string{"aa"})
	memo.CheckSigstoreDigests(t.Context(), rc, []string{"aa"})
	if hits["aa"] != 2 {
		t.Errorf("searches = %d, want 2", hits["aa"])
	}
}

// The gateway checks run once for gateway evidence that every instance
// shares, and again when the evidence differs.
func TestGatewayMemo(t *testing.T) {
	var memo GatewayMemo[int]
	calls := 0
	verify := func() int { calls++; return calls }
	raw := &RawAttestation{GatewayIntelQuote: "q", GatewayAppCompose: "c", GatewayNonceHex: "n"}
	same := *raw
	if a, b := memo.Get(raw, verify), memo.Get(&same, verify); a != 1 || b != 1 || calls != 1 {
		t.Fatalf("same evidence: results %d, %d after %d calls", a, b, calls)
	}
	for _, change := range []func(*RawAttestation){
		func(r *RawAttestation) { r.GatewayIntelQuote = "q2" },
		func(r *RawAttestation) { r.GatewayAppCompose = "c2" },
		func(r *RawAttestation) { r.GatewayNonceHex = "n2" },
		func(r *RawAttestation) { r.GatewaySigningAddress = "s2" },
		func(r *RawAttestation) { r.GatewayTLSFingerprint = "f2" },
	} {
		other := *raw
		change(&other)
		before := calls
		memo.Get(&other, verify)
		if calls != before+1 {
			t.Errorf("changed gateway evidence reused the stored result")
		}
		memo.Get(raw, verify)
	}
}
