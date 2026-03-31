package nearcloud

import (
	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
)

// E2EE implements provider.RequestEncryptor for NearCloud E2EE
// (Ed25519/X25519 + XChaCha20-Poly1305).
type E2EE struct{}

// NewE2EE returns a NearCloud RequestEncryptor.
func NewE2EE() *E2EE { return &E2EE{} }

// EncryptRequest encrypts each message content with NearCloud E2EE and forces
// stream=true. The raw.SigningKey must be a 64-char hex Ed25519 public key.
func (n *E2EE) EncryptRequest(body []byte, raw *attestation.RawAttestation) ([]byte, e2ee.Decryptor, *e2ee.ChutesE2EE, error) {
	encBody, session, err := e2ee.EncryptChatMessagesNearCloud(body, raw.SigningKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return encBody, session, nil, nil
}
