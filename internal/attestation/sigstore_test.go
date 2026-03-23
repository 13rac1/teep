package attestation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// makeRekorMock returns a test server that acts as the Rekor search API.
// When found=true, it returns a UUID list for all retrieve requests;
// when found=false, it returns an empty list.
func makeRekorMock(t *testing.T, found bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Rekor mock: %s %s", r.Method, r.URL.Path)
		if r.URL.Path != "/api/v1/index/retrieve" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if found {
			json.NewEncoder(w).Encode([]string{"test-uuid-1234"})
		} else {
			json.NewEncoder(w).Encode([]string{})
		}
	}))
}

func TestCheckSigstoreDigests_AllOK(t *testing.T) {
	ts := makeRekorMock(t, true)
	defer ts.Close()

	origBase := RekorAPIBase
	defer func() { RekorAPIBase = origBase }()
	RekorAPIBase = ts.URL

	digests := []string{
		"abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
		"0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
	}

	results := CheckSigstoreDigests(context.Background(), digests, ts.Client())
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		if !r.OK {
			t.Errorf("result[%d] not OK: status=%d, err=%v", i, r.Status, r.Err)
		}
		if r.Status != http.StatusOK {
			t.Errorf("result[%d] status: got %d, want %d", i, r.Status, http.StatusOK)
		}
		t.Logf("result[%d]: digest=%s ok=%v status=%d", i, r.Digest[:16], r.OK, r.Status)
	}
}

func TestCheckSigstoreDigests_NotFound(t *testing.T) {
	ts := makeRekorMock(t, false)
	defer ts.Close()

	origBase := RekorAPIBase
	defer func() { RekorAPIBase = origBase }()
	RekorAPIBase = ts.URL

	digests := []string{"abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"}
	results := CheckSigstoreDigests(context.Background(), digests, ts.Client())

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].OK {
		t.Error("expected not OK for empty UUID list")
	}
	if results[0].Status != http.StatusNotFound {
		t.Errorf("status: got %d, want %d", results[0].Status, http.StatusNotFound)
	}
}

func TestCheckSigstoreDigests_RekorError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	origBase := RekorAPIBase
	defer func() { RekorAPIBase = origBase }()
	RekorAPIBase = ts.URL

	digests := []string{"abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"}
	results := CheckSigstoreDigests(context.Background(), digests, ts.Client())

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].OK {
		t.Error("expected not OK for server error")
	}
	if results[0].Err == nil {
		t.Error("expected non-nil Err for server error")
	}
}

func TestCheckSigstoreDigests_Empty(t *testing.T) {
	results := CheckSigstoreDigests(context.Background(), nil, http.DefaultClient)
	if len(results) != 0 {
		t.Fatalf("expected 0 results for nil digests, got %d", len(results))
	}
}
