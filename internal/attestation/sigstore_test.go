package attestation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckSigstoreDigests_AllOK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Sigstore mock: %s %s", r.Method, r.URL.String())
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Override the search base for testing.
	origBase := sigstoreSearchBase
	defer func() { restoreSigstoreBase(origBase) }()
	overrideSigstoreBase(ts.URL + "/?hash=")

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
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Sigstore mock: %s %s → 404", r.Method, r.URL.String())
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	origBase := sigstoreSearchBase
	defer func() { restoreSigstoreBase(origBase) }()
	overrideSigstoreBase(ts.URL + "/?hash=")

	digests := []string{"abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"}
	results := CheckSigstoreDigests(context.Background(), digests, ts.Client())

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].OK {
		t.Error("expected not OK for 404")
	}
	if results[0].Status != http.StatusNotFound {
		t.Errorf("status: got %d, want %d", results[0].Status, http.StatusNotFound)
	}
}

func TestCheckSigstoreDigests_HEADFallbackToGET(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Sigstore mock: %s %s", r.Method, r.URL.String())
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	origBase := sigstoreSearchBase
	defer func() { restoreSigstoreBase(origBase) }()
	overrideSigstoreBase(ts.URL + "/?hash=")

	digests := []string{"abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"}
	results := CheckSigstoreDigests(context.Background(), digests, ts.Client())

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].OK {
		t.Errorf("expected OK after GET fallback, got status=%d err=%v", results[0].Status, results[0].Err)
	}
}

func TestCheckSigstoreDigests_Empty(t *testing.T) {
	results := CheckSigstoreDigests(context.Background(), nil, http.DefaultClient)
	if len(results) != 0 {
		t.Fatalf("expected 0 results for nil digests, got %d", len(results))
	}
}
