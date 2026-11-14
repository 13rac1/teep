package tinfoil

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
)

// E2EE implements provider.RequestEncryptor for Tinfoil EHBP
// (HPKE X25519 + AES-256-GCM full-body encryption).
type E2EE struct{}

// NewE2EE returns a Tinfoil RequestEncryptor.
func NewE2EE() *E2EE { return &E2EE{} }

// EncryptRequest encrypts the request body for Tinfoil EHBP
// (HPKE X25519 + AES-256-GCM full-body encryption).
// The raw.SigningKey must be a 64 hex char (32 byte) X25519 public key.
// The endpoint parameter is not used; EHBP uses full-body encryption for all endpoints.
func (t *E2EE) EncryptRequest(body []byte, raw *attestation.RawAttestation, _ e2ee.EndpointType) (e2ee.EncryptResult, error) {
	if raw.SigningKey == "" {
		return e2ee.EncryptResult{}, errors.New("tinfoil E2EE: missing HPKE public key in attestation")
	}

	pubKeyBytes, err := hex.DecodeString(raw.SigningKey)
	if err != nil {
		return e2ee.EncryptResult{}, fmt.Errorf("tinfoil E2EE: decode HPKE key: %w", err)
	}

	session, err := e2ee.NewEHBPSession(pubKeyBytes)
	if err != nil {
		return e2ee.EncryptResult{}, fmt.Errorf("tinfoil E2EE: %w", err)
	}

	reader := session.EncryptRequest(bytes.NewReader(body))
	return e2ee.EncryptResult{BodyReader: reader, EHBP: session}, nil
}

// CoversE2EE reports whether this E2EE covers endpoint. EHBP encrypts the whole body of chat, embeddings, responses and speech requests; teep sends no multipart audio body with EHBP.
func (t *E2EE) CoversE2EE(endpoint e2ee.EndpointType) bool {
	switch endpoint {
	case e2ee.EndpointChat, e2ee.EndpointEmbeddings, e2ee.EndpointResponses, e2ee.EndpointSpeech:
		return true
	default:
		return false
	}
}
