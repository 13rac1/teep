package chutes_test

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/chutes"
)

func FuzzParseAttestationResponse(f *testing.F) {
	// Matching instance+evidence pair.
	f.Add(
		[]byte(`{"instances":[{"instance_id":"i1","e2e_pubkey":"pk1","nonces":["n1"]}],"nonce_expires_in":300}`),
		[]byte(`{"evidence":[{"quote":"dGVzdA==","gpu_evidence":[],"instance_id":"i1","certificate":""}]}`),
	)

	// Multiple instances.
	f.Add(
		[]byte(`{"instances":[{"instance_id":"i1","e2e_pubkey":"pk1","nonces":["n1"]},{"instance_id":"i2","e2e_pubkey":"pk2","nonces":["n2"]}]}`),
		[]byte(`{"evidence":[{"quote":"dGVzdA==","gpu_evidence":[],"instance_id":"i2","certificate":""}]}`),
	)

	// No matching instance.
	f.Add(
		[]byte(`{"instances":[{"instance_id":"i1","e2e_pubkey":"pk1","nonces":["n1"]}]}`),
		[]byte(`{"evidence":[{"quote":"dGVzdA==","gpu_evidence":[],"instance_id":"unknown","certificate":""}]}`),
	)

	// Empty arrays.
	f.Add(
		[]byte(`{"instances":[]}`),
		[]byte(`{"evidence":[]}`),
	)

	// Invalid JSON.
	f.Add([]byte(`not json`), []byte(`{"evidence":[]}`))
	f.Add([]byte(`{"instances":[]}`), []byte(`not json`))
	f.Add([]byte(``), []byte(``))

	// Instance with empty e2e_pubkey (should be skipped).
	f.Add(
		[]byte(`{"instances":[{"instance_id":"i1","e2e_pubkey":"","nonces":["n1"]}]}`),
		[]byte(`{"evidence":[{"quote":"dGVzdA==","gpu_evidence":[],"instance_id":"i1"}]}`),
	)

	f.Fuzz(func(t *testing.T, instancesBody, evidenceBody []byte) {
		// Use zero nonce for determinism (NewNonce() reads crypto/rand).
		var nonce attestation.Nonce
		result, err := chutes.ParseAttestationResponse(context.Background(), instancesBody, evidenceBody, nonce)
		if err == nil && result == nil {
			t.Error("ParseAttestationResponse returned nil, nil")
		}
	})
}
