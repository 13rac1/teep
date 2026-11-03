package proxy

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/provider/chutes/chutestest"
)

// teep serve checks the GPU evidence of each Chutes capture against the
// requester nonce derived from the client nonce, and reports the
// attestation nonce.
func TestVerifyNVIDIAChutesGPUEvidence(t *testing.T) {
	for _, c := range chutestest.Captures(t, "../integration/testdata") {
		t.Run(c.Name, func(t *testing.T) {
			result, _ := verifyNVIDIA(context.Background(), c.Raw, c.Nonce, "chutes")
			if result == nil {
				t.Fatal("verifyNVIDIA returned no GPU result")
			}
			if result.SignatureErr != nil {
				t.Errorf("SignatureErr = %v, want nil", result.SignatureErr)
			}
			if got, want := result.Nonce, c.Raw.Nonce; got != want {
				t.Errorf("reported nonce = %s, want %s", got, want)
			}
		})
	}
}
