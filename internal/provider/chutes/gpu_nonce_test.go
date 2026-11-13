package chutes_test

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/chutes"
	"github.com/13rac1/teep/internal/provider/chutes/chutestest"
)

// The GPU evidence of every direct Chutes capture answers
// SHA256(client_nonce_hex + e2e_pubkey) and verifies against it; the client
// nonce itself is not the SPDM requester nonce.
func TestGPURequesterNonce(t *testing.T) {
	for _, c := range chutestest.Captures(t, "../../integration/testdata") {
		t.Run(c.Name, func(t *testing.T) {
			requester, err := chutes.GPURequesterNonce(c.Nonce, c.Raw.SigningKey)
			if err != nil {
				t.Fatal(err)
			}
			derived := attestation.VerifyNVIDIAGPUDirect(context.Background(), c.Raw.GPUEvidence, c.Nonce, requester)
			if derived.SignatureErr != nil {
				t.Errorf("derived requester nonce: SignatureErr = %v, want nil", derived.SignatureErr)
			}
			if got, want := derived.Nonce, c.Nonce.Hex(); got != want {
				t.Errorf("reported nonce = %s, want %s", got, want)
			}
			plain := attestation.VerifyNVIDIAGPUDirect(context.Background(), c.Raw.GPUEvidence, c.Nonce, c.Nonce)
			if plain.SignatureErr == nil {
				t.Error("GPU evidence verified against the client nonce itself")
			}
		})
	}
}

func TestGPURequesterNonceRefusesEmptyKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
	}{
		{"empty key", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := chutes.GPURequesterNonce(attestation.NewNonce(), tc.key); err == nil {
				t.Error("GPURequesterNonce: err = nil, want an error")
			}
		})
	}
}
