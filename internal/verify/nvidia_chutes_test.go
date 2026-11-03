package verify

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/chutes/chutestest"
)

// teep verify checks the GPU evidence of each Chutes capture against the
// requester nonce derived from the client nonce, and reports the
// attestation nonce.
func TestVerifyNVIDIAChutesGPUEvidence(t *testing.T) {
	for _, c := range chutestest.Captures(t, "../integration/testdata") {
		t.Run(c.Name, func(t *testing.T) {
			eat, nras := verifyNVIDIA(context.Background(), c.Raw, c.Nonce, nil, true, attestation.DefaultNVIDIAVerifier())
			if eat == nil {
				t.Fatal("verifyNVIDIA returned no GPU result")
			}
			if eat.SignatureErr != nil {
				t.Errorf("SignatureErr = %v, want nil", eat.SignatureErr)
			}
			if got, want := eat.Nonce, c.Raw.Nonce; got != want {
				t.Errorf("reported nonce = %s, want %s", got, want)
			}
			if nras != nil {
				t.Error("offline verification sent NRAS")
			}
		})
	}
}
