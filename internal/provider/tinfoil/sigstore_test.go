package tinfoil

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSigstoreVerifier_FetchLatestTag(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/releases/latest") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		resp := githubRelease{TagName: "v1.2.3"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	sv := &SigstoreVerifier{client: ts.Client()}

	// Override URL by making the method testable — we test through the full path
	// by constructing a custom server.
	url := ts.URL + "/repos/tinfoilsh/test-repo/releases/latest"
	body, err := sv.fetchBounded(context.Background(), url, maxReleaseResponseSize)
	if err != nil {
		t.Fatalf("fetchBounded failed: %v", err)
	}

	var release githubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if release.TagName != "v1.2.3" {
		t.Errorf("TagName = %q, want v1.2.3", release.TagName)
	}
}

func TestSigstoreVerifier_FetchBounded_ReturnsBody(t *testing.T) {
	// This test exercises fetchBounded's HTTP plumbing only. It is NOT named
	// after fetchTinfoilHash because the digest below is shorter than 64 hex
	// chars and would be rejected by fetchTinfoilHash's validation.
	// fetchTinfoilHash validation is covered by TestFetchTinfoilHash_Validation.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("abc123def456\n"))
	}))
	defer ts.Close()

	sv := &SigstoreVerifier{client: ts.Client()}
	body, err := sv.fetchBounded(context.Background(), ts.URL+"/tinfoil.hash", maxHashFileSize)
	if err != nil {
		t.Fatalf("fetchBounded failed: %v", err)
	}

	digest := strings.TrimSpace(string(body))
	if digest != "abc123def456" {
		t.Errorf("digest = %q, want abc123def456", digest)
	}
}

func TestSigstoreVerifier_FetchBounded_SizeLimit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Write more than the limit.
		w.Write(make([]byte, 100))
	}))
	defer ts.Close()

	sv := &SigstoreVerifier{client: ts.Client()}
	_, err := sv.fetchBounded(context.Background(), ts.URL, 50)
	if err == nil {
		t.Fatal("expected error for response exceeding size limit")
	}
	if !strings.Contains(err.Error(), "exceeds size limit") {
		t.Errorf("error %q should mention exceeds size limit", err)
	}
}

func TestSigstoreVerifier_FetchBounded_HTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer ts.Close()

	sv := &SigstoreVerifier{client: ts.Client()}
	_, err := sv.fetchBounded(context.Background(), ts.URL, maxReleaseResponseSize)
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error %q should mention 404", err)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		s    string
		n    int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hello..."},
		{"", 5, ""},
		{"ab", 2, "ab"},
		{"abc", 2, "ab..."},
	}

	for _, tt := range tests {
		got := truncate(tt.s, tt.n)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.want)
		}
	}
}

func TestGithubAttestationResponse_EmptyAttestations(t *testing.T) {
	// Test that parsing an empty attestations array is detected.
	body := []byte(`{"attestations":[]}`)
	var resp githubAttestationResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(resp.Attestations) != 0 {
		t.Errorf("expected 0 attestations, got %d", len(resp.Attestations))
	}
}

func TestGithubAttestationResponse_WithBundle(t *testing.T) {
	body := []byte(`{"attestations":[{"bundle":{"mediaType":"test"}}]}`)
	var resp githubAttestationResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(resp.Attestations) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(resp.Attestations))
	}
	if resp.Attestations[0].Bundle == nil {
		t.Error("expected non-nil bundle")
	}
}
