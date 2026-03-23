package attestation

import (
	"context"
	"fmt"
	"net/http"
)

// SigstoreResult records the outcome of checking one container image digest
// against the Sigstore transparency log.
type SigstoreResult struct {
	Digest string
	OK     bool
	Status int
	Err    error
}

// CheckSigstoreDigests verifies that each sha256 digest is present in the
// Sigstore/Rekor transparency log using the Rekor search API
// (POST /api/v1/index/retrieve). A digest is considered OK when at least one
// log entry is returned; an empty result means the digest is absent.
//
// Using the Rekor API instead of the search.sigstore.dev HTML endpoint (F-22)
// provides access to actual log entry UUIDs rather than relying solely on an
// HTTP status code from a non-machine-readable endpoint (F-24).
//
// NOTE: This check confirms the digest is recorded in the transparency log.
// It does not verify the cosign bundle signature on each entry. Full bundle
// signature verification would additionally confirm the signing identity.
func CheckSigstoreDigests(ctx context.Context, digests []string, client *http.Client) []SigstoreResult {
	results := make([]SigstoreResult, len(digests))
	for i, digest := range digests {
		results[i] = checkDigestViaRekor(ctx, digest, client)
	}
	return results
}

func checkDigestViaRekor(ctx context.Context, digest string, client *http.Client) SigstoreResult {
	uuids, err := fetchRekorUUIDs(ctx, digest, client)
	if err != nil {
		return SigstoreResult{Digest: digest, Err: fmt.Errorf("rekor transparency log search: %w", err)}
	}
	if len(uuids) == 0 {
		return SigstoreResult{Digest: digest, OK: false, Status: http.StatusNotFound}
	}
	return SigstoreResult{Digest: digest, OK: true, Status: http.StatusOK}
}
