package tinfoil

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
)

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
	body, err := sv.fetchBounded(context.Background(), ts.URL+"/tinfoil.hash", maxAttestationResponseSize)
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
	_, err := sv.fetchBounded(context.Background(), ts.URL, maxAttestationResponseSize)
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

// witnessPredicate is a freshness witness predicate endorsing repo@tag.
func witnessPredicate(repo, tag, digest string) []byte {
	return []byte(`{"format":"` + PredicateFreshnessWitness + `","endorses":{"repo":"` + repo +
		`","tag":"` + tag + `","commit":"005539a0","subject":{"name":"tinfoil-deployment.json","digest":"sha256:` + digest + `"}}}`)
}

func TestCheckWitness(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	rel := attestation.TinfoilRelease{Repo: "tinfoilsh/confidential-x", Tag: "v0.0.10+b300", Digest: digest}
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	ok := witnessPredicate(rel.Repo, rel.Tag, digest)

	if err := checkWitness(ok, rel, now.Add(-6*24*time.Hour), now); err != nil {
		t.Errorf("a six-day-old witness of this release: %v", err)
	}
	for name, tc := range map[string]struct {
		pred     []byte
		signedAt time.Time
		want     string
	}{
		"stale":        {ok, now.Add(-FreshnessWindow - time.Minute), "outside"},
		"future":       {ok, now.Add(2 * time.Hour), "outside"},
		"other tag":    {witnessPredicate(rel.Repo, "v0.0.9+b300", digest), now, "not this release"},
		"other repo":   {witnessPredicate("tinfoilsh/confidential-y", rel.Tag, digest), now, "not this release"},
		"other digest": {witnessPredicate(rel.Repo, rel.Tag, strings.Repeat("cd", 32)), now, "not this release"},
		"not json":     {[]byte("x"), now, "unmarshal"},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkWitness(tc.pred, rel, tc.signedAt, now)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("checkWitness err = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// An enclave that serves no witness for its release fails before any fetch.
func TestCheckFreshness_NoWitness(t *testing.T) {
	err := (&SigstoreVerifier{}).checkFreshness(context.Background(), attestation.TinfoilRelease{Repo: "tinfoilsh/x", Tag: "v1.0.0"}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "no freshness witness") {
		t.Errorf("checkFreshness err = %v", err)
	}
}

// The release an enclave names must be in the repo teep expects, and an
// enclave that names none fails. Both return before any fetch.
func TestVerifyNamedRelease_Rejects(t *testing.T) {
	sv := &SigstoreVerifier{}
	digest := strings.Repeat("ab", 32)
	for name, tc := range map[string]struct {
		rel  attestation.TinfoilRelease
		want string
	}{
		"absent":     {attestation.TinfoilRelease{}, "names no code release"},
		"other repo": {attestation.TinfoilRelease{Repo: "tinfoilsh/confidential-other", Tag: "v1.0.0", Digest: digest}, "want tinfoilsh/confidential-x"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := verifyNamedRelease(context.Background(), sv, tc.rel, "code", "tinfoilsh/confidential-x", time.Now())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("verifyNamedRelease err = %v, want one containing %q", err, tc.want)
			}
		})
	}
}
