package nanogpt

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/chutes"
)

// maxChutesEvidenceInstances bounds the number of instances in the Chutes
// evidence that NanoGPT relays. On 2026-11-12 the most was 43 instances,
// for TEE/gemma4-31b:thinking.
const maxChutesEvidenceInstances = 64

// isChutesEvidence reports whether body, which formatdetect detects as a
// Chutes format, is the evidence response of Chutes (a top-level evidence
// list) and not the attestation_type form.
func isChutesEvidence(body []byte) bool {
	var p struct {
		AttestationType string `json:"attestation_type"`
	}
	return json.Unmarshal(body, &p) == nil && p.AttestationType == ""
}

// parseChutesEvidence parses the Chutes evidence response that NanoGPT
// relays for a model that Chutes serves: one entry for each instance of the
// model, with no instance list and no E2EE public key. The result is the
// attestation of the first entry, with no signing key: no quote in the
// response can be shown to bind nonce, and nothing names the instance that
// serves the request (SEE: chutes.ParseEvidence).
func parseChutesEvidence(ctx context.Context, body []byte, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	raw, err := chutes.ParseEvidence(ctx, body, nonce)
	if err != nil {
		return nil, fmt.Errorf("nanogpt: %w", err)
	}
	if raw.CandidatesAvail > maxChutesEvidenceInstances {
		return nil, fmt.Errorf("nanogpt: chutes evidence has %d instances, max %d",
			raw.CandidatesAvail, maxChutesEvidenceInstances)
	}
	return raw, nil
}
