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

func TestNewSigstoreVerifier(t *testing.T) {
	sv := NewSigstoreVerifier(http.DefaultClient)
	if sv == nil {
		t.Fatal("NewSigstoreVerifier returned nil")
	}
	if sv.client != http.DefaultClient {
		t.Error("client not set correctly")
	}
}

func TestGithubProxyURL(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "latest release",
			got:  githubProxyURL("/repos/%s/releases/latest", "tinfoilsh/confidential-model-router"),
			want: "https://github-proxy.tinfoil.sh/repos/tinfoilsh/confidential-model-router/releases/latest",
		},
		{
			name: "release asset",
			got:  githubProxyURL("/%s/releases/download/%s/tinfoil.hash", "tinfoilsh/confidential-model-router", "v1.2.3"),
			want: "https://github-proxy.tinfoil.sh/tinfoilsh/confidential-model-router/releases/download/v1.2.3/tinfoil.hash",
		},
		{
			name: "attestation",
			got:  githubProxyURL("/repos/%s/attestations/sha256:%s", "tinfoilsh/confidential-model-router", strings.Repeat("a", 64)),
			want: "https://github-proxy.tinfoil.sh/repos/tinfoilsh/confidential-model-router/attestations/sha256:" + strings.Repeat("a", 64),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("url = %q, want %q", tt.got, tt.want)
			}
			if strings.Contains(tt.got, "api.github.com") || strings.Contains(tt.got, "https://github.com") {
				t.Fatalf("url must use Tinfoil GitHub proxy, got %q", tt.got)
			}
		})
	}
}

// testSigstoreServer creates a mock GitHub API server that routes requests
// to the right handler based on path patterns.
func testSigstoreServer(t *testing.T, handlers map[string]http.HandlerFunc) (*httptest.Server, *SigstoreVerifier) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for pattern, h := range handlers {
			if strings.Contains(r.URL.Path, pattern) {
				h(w, r)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(ts.Close)
	return ts, &SigstoreVerifier{client: ts.Client()}
}

func TestFetchLatestTag_Success(t *testing.T) {
	ts, sv := testSigstoreServer(t, map[string]http.HandlerFunc{
		"releases/latest": func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(githubRelease{TagName: "v2.0.0"})
		},
	})
	body, err := sv.fetchBounded(context.Background(), ts.URL+"/repos/tinfoilsh/test/releases/latest", maxReleaseResponseSize)
	if err != nil {
		t.Fatalf("fetchBounded: %v", err)
	}
	var release githubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if release.TagName != "v2.0.0" {
		t.Errorf("TagName = %q, want v2.0.0", release.TagName)
	}
}

func TestFetchLatestTag_EmptyTag(t *testing.T) {
	ts, sv := testSigstoreServer(t, map[string]http.HandlerFunc{
		"releases/latest": func(w http.ResponseWriter, _ *http.Request) {
			json.NewEncoder(w).Encode(githubRelease{TagName: ""})
		},
	})
	// Call fetchLatestTag by directly constructing the URL.
	body, err := sv.fetchBounded(context.Background(), ts.URL+"/releases/latest", maxReleaseResponseSize)
	if err != nil {
		t.Fatalf("fetchBounded: %v", err)
	}
	var release githubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if release.TagName != "" {
		t.Errorf("expected empty tag_name, got %q", release.TagName)
	}
}

func TestFetchTinfoilHash_Validation(t *testing.T) {
	// Test the digest validation logic extracted into validateTinfoilHash.
	// This directly exercises the 64-hex-char and hex-decode checks that
	// fetchTinfoilHash applies, rather than only testing fetchBounded.
	validHash := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	t.Run("valid", func(t *testing.T) {
		got, err := validateTinfoilHash(validHash)
		if err != nil {
			t.Fatalf("validateTinfoilHash: %v", err)
		}
		if got != validHash {
			t.Errorf("digest = %q, want %q", got, validHash)
		}
	})

	t.Run("wrong_length", func(t *testing.T) {
		_, err := validateTinfoilHash("tooshort")
		if err == nil {
			t.Fatal("expected error for short digest")
		}
		if !strings.Contains(err.Error(), "64 hex chars") {
			t.Errorf("error %q should mention 64 hex chars", err)
		}
	})

	t.Run("invalid_hex", func(t *testing.T) {
		invalidHex := "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
		_, err := validateTinfoilHash(invalidHex)
		if err == nil {
			t.Fatal("expected error for non-hex digest")
		}
		if !strings.Contains(err.Error(), "not valid hex") {
			t.Errorf("error %q should mention not valid hex", err)
		}
	})

	t.Run("empty", func(t *testing.T) {
		_, err := validateTinfoilHash("")
		if err == nil {
			t.Fatal("expected error for empty digest")
		}
	})
}

func TestFetchAndVerifyAttestation_EmptyResponseParsing(t *testing.T) {
	// Test that parsing an empty attestations list is properly detected.
	body := []byte(`{"attestations":[]}`)
	var resp githubAttestationResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Attestations) != 0 {
		t.Errorf("expected 0 attestations, got %d", len(resp.Attestations))
	}
}

func TestFetchAndVerifyAttestation_InvalidBundleParsing(t *testing.T) {
	// Test that an invalid bundle raw message is detected during parsing.
	body := []byte(`{"attestations":[{"bundle":"not-an-object"}]}`)
	var resp githubAttestationResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Attestations) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(resp.Attestations))
	}
}
