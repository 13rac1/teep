package tinfoil

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"google.golang.org/protobuf/encoding/protojson"
)

// GitHub API response size limits.
const (
	maxAttestationResponseSize = 4 << 20 // 4 MiB
)

const githubProxyBaseURL = "https://github-proxy.tinfoil.sh"

// SignerIdentity holds the verified Fulcio signer's OIDC issuer and Subject
// Alternative Name (GitHub Actions workflow identity), extracted from a
// verified Sigstore DSSE bundle. Both are non-secret, public attestation
// values. Callers copy this to attestation.TinfoilComponentResult for the
// report-layer identity-vs-policy comparison.
type SignerIdentity struct {
	OIDCIssuer string
	SAN        string
}

// WorkflowPattern returns the Fulcio SAN identity regex for a Tinfoil
// GitHub Actions release of repo. The regex is independent of the release
// tag: Tinfoil creates a new release tag for every deploy, so the trust
// anchor is the repo + OIDC issuer, not a tag. Shared between
// FetchAndVerify's Sigstore certificate-identity check and the supply chain
// policy's independent re-check (policy.go).
func WorkflowPattern(repo string) string {
	return attestation.GitHubReleaseWorkflowPattern(repo)
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

// FreshnessWitnessSAN is the Fulcio identity of Tinfoil's freshness witness,
// the workflow that re-signs every release Tinfoil still serves.
const FreshnessWitnessSAN = "https://github.com/tinfoilsh/freshness-witness/.github/workflows/freshness.yml@refs/heads/main"

// PredicateFreshnessWitness is the predicate type of a freshness witness.
const PredicateFreshnessWitness = "https://tinfoil.sh/predicate/freshness-witness/v1"

// FreshnessWindow is how long a freshness witness counts. Tinfoil's verifier
// accepts a witness for up to seven days.
const FreshnessWindow = 7 * 24 * time.Hour

// freshnessPredicate is the predicate of a freshness witness.
type freshnessPredicate struct {
	Format   string `json:"format"`
	Endorses struct {
		Repo    string `json:"repo"`
		Tag     string `json:"tag"`
		Subject struct {
			Digest string `json:"digest"`
		} `json:"subject"`
	} `json:"endorses"`
}

// VerifyRelease verifies the release an enclave names and returns the
// verified in-toto predicate and the Fulcio signer identity.
//
// rel is an unauthenticated hint from the enclave's collateral; the caller
// checks rel.Repo against its own expectation. teep fetches the bundle for
// rel.Digest from GitHub itself and verifies it with the repo's release
// workflow identity, so the digest is signed by that repo. The certificate's
// SAN names the git ref the workflow ran for, which must be rel.Tag: that
// binds the digest to the tag.
//
// Last, the release must be current. rel.Freshness is the freshness witness
// the enclave serves: a bundle signed by Tinfoil's freshness-witness
// workflow (FreshnessWitnessSAN) that endorses this repo, tag and digest. It
// must verify and be signed within FreshnessWindow of now, so an enclave
// cannot name a release Tinfoil stopped witnessing more than a window ago.
func (sv *SigstoreVerifier) VerifyRelease(ctx context.Context, rel attestation.TinfoilRelease, now time.Time) (predicateBytes []byte, predicateType string, signer SignerIdentity, err error) {
	predicateBytes, predicateType, signer, err = sv.fetchAndVerifyAttestation(ctx, rel.Repo, rel.Digest)
	if err != nil {
		return nil, "", SignerIdentity{}, err
	}
	if !strings.HasSuffix(signer.SAN, "@refs/tags/"+rel.Tag) {
		return nil, "", SignerIdentity{}, fmt.Errorf("release %s@%s: digest %s was signed by %q, not for that tag",
			rel.Repo, rel.Tag, rel.Digest, signer.SAN)
	}
	if err := checkFreshness(ctx, rel, now); err != nil {
		return nil, "", SignerIdentity{}, fmt.Errorf("release %s@%s: %w", rel.Repo, rel.Tag, err)
	}
	return predicateBytes, predicateType, signer, nil
}

// checkFreshness verifies the freshness witness of rel.
func checkFreshness(ctx context.Context, rel attestation.TinfoilRelease, now time.Time) error {
	if len(rel.Freshness) == 0 {
		return errors.New("the enclave serves no freshness witness")
	}
	predicateBytes, predicateType, _, signedAt, err := verifyBundle(ctx, rel.Freshness, rel.Digest,
		"^"+regexp.QuoteMeta(FreshnessWitnessSAN)+"$")
	if err != nil {
		return fmt.Errorf("freshness witness: %w", err)
	}
	if predicateType != PredicateFreshnessWitness {
		return fmt.Errorf("freshness witness predicate type %q, want %q", predicateType, PredicateFreshnessWitness)
	}
	return checkWitness(predicateBytes, rel, signedAt, now)
}

// checkWitness checks a verified freshness witness's predicate and age.
func checkWitness(predicateBytes []byte, rel attestation.TinfoilRelease, signedAt, now time.Time) error {
	var pred freshnessPredicate
	if err := json.Unmarshal(predicateBytes, &pred); err != nil {
		return fmt.Errorf("unmarshal freshness witness: %w", err)
	}
	e := pred.Endorses
	if pred.Format != PredicateFreshnessWitness || e.Repo != rel.Repo || e.Tag != rel.Tag || e.Subject.Digest != "sha256:"+rel.Digest {
		return fmt.Errorf("freshness witness endorses %s@%s (%s), not this release", e.Repo, e.Tag, e.Subject.Digest)
	}
	if age := now.Sub(signedAt); age > FreshnessWindow || age < -time.Hour {
		return fmt.Errorf("freshness witness signed %s, outside %s of %s",
			signedAt.UTC().Format(time.RFC3339), FreshnessWindow, now.UTC().Format(time.RFC3339))
	}
	return nil
}

func (sv *SigstoreVerifier) fetchAndVerifyAttestation(ctx context.Context, repo, digest string) (predicateBytes []byte, predicateType string, signer SignerIdentity, err error) {
	url := githubProxyURL("/repos/%s/attestations/sha256:%s", repo, digest)
	body, err := sv.fetchBounded(ctx, url, maxAttestationResponseSize)
	if err != nil {
		return nil, "", SignerIdentity{}, fmt.Errorf("fetch attestation: %w", err)
	}

	var resp githubAttestationResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, "", SignerIdentity{}, fmt.Errorf("unmarshal attestation response: %w", err)
	}
	if len(resp.Attestations) == 0 {
		return nil, "", SignerIdentity{}, fmt.Errorf("no attestations found for sha256:%s", digest)
	}

	predicateBytes, predicateType, signer, _, err = verifyBundle(ctx, resp.Attestations[0].Bundle, digest, WorkflowPattern(repo))
	return predicateBytes, predicateType, signer, err
}

// verifyBundle verifies a Sigstore DSSE bundle over the artifact digest, signed
// by a GitHub Actions Fulcio certificate whose SAN matches sanPattern. It
// returns the in-toto predicate, the signer, and the earliest verified
// signing timestamp.
func verifyBundle(ctx context.Context, bundleJSON []byte, digest, sanPattern string) (predicateBytes []byte, predicateType string, signer SignerIdentity, signedAt time.Time, err error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, "", SignerIdentity{}, time.Time{}, fmt.Errorf("parse DSSE bundle: %w", err)
	}

	// Get trusted root from Sigstore TUF.
	rootClient := tlsct.NewHTTPClient(30 * time.Second)
	defer rootClient.CloseIdleConnections()
	rootFetcher := newTrustedRootFetcher(ctx, rootClient)
	trustedRoot, err := root.FetchTrustedRootWithOptions(tuf.DefaultOptions().WithFetcher(rootFetcher))
	if err != nil {
		return nil, "", SignerIdentity{}, time.Time{}, fmt.Errorf("fetch Sigstore trusted root: %w", err)
	}

	// Build verification policy.
	certID, err := verify.NewShortCertificateIdentity(
		GithubActionsOIDCIssuer,
		"", // issuerRegex
		"", // sanValue
		sanPattern,
	)
	if err != nil {
		return nil, "", SignerIdentity{}, time.Time{}, fmt.Errorf("build cert identity: %w", err)
	}

	// Decode hex digest to bytes for WithArtifactDigest.
	digestBytes, err := hex.DecodeString(digest)
	if err != nil {
		return nil, "", SignerIdentity{}, time.Time{}, fmt.Errorf("decode digest hex: %w", err)
	}

	// Configure verifier with SCT, transparency log, and observer timestamps.
	sigVerifier, err := verify.NewVerifier(
		trustedRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, "", SignerIdentity{}, time.Time{}, fmt.Errorf("create signed entity verifier: %w", err)
	}

	// Verify the bundle.
	result, err := sigVerifier.Verify(&b, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digestBytes),
		verify.WithCertificateIdentity(certID),
	))
	if err != nil {
		return nil, "", SignerIdentity{}, time.Time{}, fmt.Errorf("DSSE bundle verification failed: %w", err)
	}

	// verify.WithCertificateIdentity requires a Fulcio cert to succeed, so
	// a nil certificate on a verified result is a library invariant
	// violation, not a legitimate raw-key signature: fail closed.
	if result.Signature == nil || result.Signature.Certificate == nil {
		return nil, "", SignerIdentity{}, time.Time{}, errors.New("verified bundle has no certificate identity")
	}
	signer = SignerIdentity{
		OIDCIssuer: result.Signature.Certificate.Issuer,
		SAN:        result.Signature.Certificate.SubjectAlternativeName,
	}
	slog.DebugContext(ctx, "Fulcio signer identity verified",
		"oidc_issuer", signer.OIDCIssuer,
		"san", signer.SAN,
		"san_pattern", sanPattern,
	)

	// Extract the verified statement.
	statement := result.Statement
	if statement == nil {
		return nil, "", SignerIdentity{}, time.Time{}, errors.New("verified bundle has no in-toto statement")
	}

	if statement.GetPredicate() == nil {
		return nil, "", SignerIdentity{}, time.Time{}, errors.New("verified statement has nil predicate")
	}

	// Marshal the protobuf Struct predicate to JSON bytes.
	predicateJSON, err := protojson.Marshal(statement.GetPredicate())
	if err != nil {
		return nil, "", SignerIdentity{}, time.Time{}, fmt.Errorf("marshal predicate to JSON: %w", err)
	}

	if len(result.VerifiedTimestamps) == 0 {
		return nil, "", SignerIdentity{}, time.Time{}, errors.New("verified bundle has no verified timestamp")
	}
	signedAt = result.VerifiedTimestamps[0].Timestamp
	for _, ts := range result.VerifiedTimestamps[1:] {
		if ts.Timestamp.Before(signedAt) {
			signedAt = ts.Timestamp
		}
	}
	return predicateJSON, statement.GetPredicateType(), signer, signedAt, nil
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

// newTrustedRootFetcher retains the dependency's one-attempt download policy.
func newTrustedRootFetcher(ctx context.Context, client *http.Client) *fetcher.DefaultFetcher {
	f := fetcher.NewDefaultFetcher()
	f.SetHTTPClient(trustedRootDo(func(req *http.Request) (*http.Response, error) {
		return client.Do(req.WithContext(ctx))
	}))
	return f
}

// trustedRootDo attaches the verification context before http.Client applies
// its download timeout, including while the fetcher reads the response body.
type trustedRootDo func(*http.Request) (*http.Response, error)

func (do trustedRootDo) Do(req *http.Request) (*http.Response, error) { return do(req) }
