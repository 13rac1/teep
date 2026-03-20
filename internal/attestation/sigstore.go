package attestation

import (
	"context"
	"fmt"
	"net/http"
)

// sigstoreSearchBase is the base URL for Sigstore transparency log searches.
var sigstoreSearchBase = "https://search.sigstore.dev/?hash="

// SigstoreResult records the outcome of checking one container image digest
// against the Sigstore transparency log.
type SigstoreResult struct {
	Digest string
	OK     bool
	Status int
	Err    error
}

// CheckSigstoreDigests verifies each sha256 digest against search.sigstore.dev.
// A digest is considered OK if the HTTP response status is < 400.
// HEAD is tried first; if the server returns 405, a GET fallback is used.
func CheckSigstoreDigests(ctx context.Context, digests []string, client *http.Client) []SigstoreResult {
	results := make([]SigstoreResult, len(digests))
	for i, digest := range digests {
		results[i] = checkOneDigest(ctx, digest, client)
	}
	return results
}

func checkOneDigest(ctx context.Context, digest string, client *http.Client) SigstoreResult {
	url := fmt.Sprintf("%ssha256:%s", sigstoreSearchBase, digest)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, http.NoBody)
	if err != nil {
		return SigstoreResult{Digest: digest, Err: fmt.Errorf("build HEAD request: %w", err)}
	}

	resp, err := client.Do(req)
	if err != nil {
		return SigstoreResult{Digest: digest, Err: fmt.Errorf("HEAD %s: %w", url, err)}
	}
	resp.Body.Close()

	// Some endpoints disallow HEAD; retry with GET.
	if resp.StatusCode == http.StatusMethodNotAllowed {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			return SigstoreResult{Digest: digest, Status: resp.StatusCode, Err: fmt.Errorf("build GET request: %w", err)}
		}
		resp, err = client.Do(req)
		if err != nil {
			return SigstoreResult{Digest: digest, Err: fmt.Errorf("GET %s: %w", url, err)}
		}
		resp.Body.Close()
	}

	return SigstoreResult{
		Digest: digest,
		OK:     resp.StatusCode < 400,
		Status: resp.StatusCode,
	}
}
