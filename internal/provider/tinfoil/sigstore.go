package tinfoil

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/13rac1/teep/internal/provider"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

// GitHub API response size limits.
const (
	maxReleaseResponseSize     = 1 << 20 // 1 MiB
	maxHashFileSize            = 1 << 16 // 64 KiB
	maxAttestationResponseSize = 4 << 20 // 4 MiB
)

const githubProxyBaseURL = "https://github-proxy.tinfoil.sh"

// sigstoreOIDCIssuer is the expected OIDC issuer for GitHub Actions.
const sigstoreOIDCIssuer = "https://token.actions.githubusercontent.com"

// githubRelease is the minimal JSON structure from the GitHub releases API.
type githubRelease struct {
	TagName string `json:"tag_name"`
}

// githubAttestationResponse is the JSON response from the GitHub attestations API.
type githubAttestationResponse struct {
	Attestations []githubAttestation `json:"attestations"`
}

type githubAttestation struct {
	Bundle json.RawMessage `json:"bundle"`
}

// SigstoreVerifier fetches and verifies Sigstore attestations from GitHub.
type SigstoreVerifier struct {
	client *http.Client
}

// NewSigstoreVerifier returns a SigstoreVerifier using the given HTTP client.
func NewSigstoreVerifier(client *http.Client) *SigstoreVerifier {
	return &SigstoreVerifier{client: client}
}

// FetchAndVerify fetches the latest release of the given repo, retrieves the
// tinfoil.hash digest, fetches the Sigstore attestation for that digest, and
// verifies the DSSE bundle. Returns the verified in-toto predicate bytes.
func (sv *SigstoreVerifier) FetchAndVerify(ctx context.Context, repo string) (predicateBytes []byte, predicateType string, err error) {
	// Step 1: Fetch latest release tag.
	tag, err := sv.fetchLatestTag(ctx, repo)
	if err != nil {
		return nil, "", fmt.Errorf("fetch latest release tag: %w", err)
	}

	// Step 2: Fetch tinfoil.hash from the release.
	digest, err := sv.fetchTinfoilHash(ctx, repo, tag)
	if err != nil {
		return nil, "", fmt.Errorf("fetch tinfoil.hash: %w", err)
	}

	// Step 3: Fetch and verify Sigstore attestation.
	return sv.fetchAndVerifyAttestation(ctx, repo, digest)
}

func (sv *SigstoreVerifier) fetchLatestTag(ctx context.Context, repo string) (string, error) {
	url := githubProxyURL("/repos/%s/releases/latest", repo)
	body, err := sv.fetchBounded(ctx, url, maxReleaseResponseSize)
	if err != nil {
		return "", err
	}

	var release githubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return "", fmt.Errorf("unmarshal release response: %w", err)
	}
	if release.TagName == "" {
		return "", errors.New("release has empty tag_name")
	}
	return release.TagName, nil
}

func (sv *SigstoreVerifier) fetchTinfoilHash(ctx context.Context, repo, tag string) (string, error) {
	url := githubProxyURL("/%s/releases/download/%s/tinfoil.hash", repo, tag)
	body, err := sv.fetchBounded(ctx, url, maxHashFileSize)
	if err != nil {
		return "", err
	}

	digest := strings.TrimSpace(string(body))
	return validateTinfoilHash(digest)
}

// validateTinfoilHash validates that a tinfoil.hash digest is exactly 64 hex
// characters.
func validateTinfoilHash(digest string) (string, error) {
	if len(digest) != 64 {
		return "", fmt.Errorf("tinfoil.hash must be 64 hex chars, got %d", len(digest))
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", fmt.Errorf("tinfoil.hash is not valid hex: %w", err)
	}
	return digest, nil
}

func (sv *SigstoreVerifier) fetchAndVerifyAttestation(ctx context.Context, repo, digest string) (predicateBytes []byte, predicateType string, err error) {
	url := githubProxyURL("/repos/%s/attestations/sha256:%s", repo, digest)
	body, err := sv.fetchBounded(ctx, url, maxAttestationResponseSize)
	if err != nil {
		return nil, "", fmt.Errorf("fetch attestation: %w", err)
	}

	var resp githubAttestationResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, "", fmt.Errorf("unmarshal attestation response: %w", err)
	}
	if len(resp.Attestations) == 0 {
		return nil, "", fmt.Errorf("no attestations found for sha256:%s", digest)
	}

	// Parse the DSSE bundle from raw JSON bytes.
	var b bundle.Bundle
	if err := b.UnmarshalJSON(resp.Attestations[0].Bundle); err != nil {
		return nil, "", fmt.Errorf("parse DSSE bundle: %w", err)
	}

	// Get trusted root from Sigstore TUF.
	trustedRoot, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, "", fmt.Errorf("fetch Sigstore trusted root: %w", err)
	}

	// Build verification policy.
	workflowPattern := fmt.Sprintf("^https://github.com/%s/\\.github/workflows/[^@]+@refs/tags/[^/]+$",
		regexp.QuoteMeta(repo))

	certID, err := verify.NewShortCertificateIdentity(
		sigstoreOIDCIssuer,
		"", // issuerRegex
		"", // sanValue
		workflowPattern,
	)
	if err != nil {
		return nil, "", fmt.Errorf("build cert identity: %w", err)
	}

	// Decode hex digest to bytes for WithArtifactDigest.
	digestBytes, err := hex.DecodeString(digest)
	if err != nil {
		return nil, "", fmt.Errorf("decode digest hex: %w", err)
	}

	// Configure verifier with SCT, transparency log, and observer timestamps.
	sigVerifier, err := verify.NewVerifier(
		trustedRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, "", fmt.Errorf("create signed entity verifier: %w", err)
	}

	// Verify the bundle.
	result, err := sigVerifier.Verify(&b, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digestBytes),
		verify.WithCertificateIdentity(certID),
	))
	if err != nil {
		return nil, "", fmt.Errorf("DSSE bundle verification failed: %w", err)
	}

	// Extract the verified statement.
	statement := result.Statement
	if statement == nil {
		return nil, "", errors.New("verified bundle has no in-toto statement")
	}

	if statement.GetPredicate() == nil {
		return nil, "", errors.New("verified statement has nil predicate")
	}

	// Marshal the protobuf Struct predicate to JSON bytes.
	predicateJSON, err := protojson.Marshal(statement.GetPredicate())
	if err != nil {
		return nil, "", fmt.Errorf("marshal predicate to JSON: %w", err)
	}

	return predicateJSON, statement.GetPredicateType(), nil
}

func githubProxyURL(pathFormat string, args ...any) string {
	return githubProxyBaseURL + fmt.Sprintf(pathFormat, args...)
}

func (sv *SigstoreVerifier) fetchBounded(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", url, err)
	}
	// GitHub REST API requires a User-Agent header; without it requests
	// may be rejected with 403/blocked responses.
	// Ref: https://docs.github.com/en/rest/using-the-rest-api/getting-started-with-the-rest-api?apiVersion=2026-03-10#user-agent
	provider.SetUserAgent(req)

	resp, err := sv.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("GET %s returned HTTP %d: %s", url, resp.StatusCode, truncate(string(errBody), 256))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", url, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response from %s exceeds size limit %d", url, limit)
	}

	return body, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
