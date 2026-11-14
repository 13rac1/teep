package chutes

import (
	"errors"
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
)

// E2EE implements provider.RequestEncryptor for Chutes E2EE
// (ML-KEM-768 + ChaCha20-Poly1305).
type E2EE struct{}

// NewE2EE returns a Chutes RequestEncryptor.
func NewE2EE() *E2EE {
	return &E2EE{}
}

// EncryptRequest encrypts the request body for Chutes E2EE
// (ML-KEM-768 + ChaCha20-Poly1305).
// Returns ChutesE2EE for the Preparer to inject headers.
// Requires raw.InstanceID, raw.E2ENonce, and raw.ChuteID from attestation.
// An endpoint outside CoversE2EE fails with e2ee.ErrEndpointNotCovered.
func (c *E2EE) EncryptRequest(body []byte, raw *attestation.RawAttestation, endpoint e2ee.EndpointType) (e2ee.EncryptResult, error) {
	if !c.CoversE2EE(endpoint) {
		return e2ee.EncryptResult{}, fmt.Errorf("chutes E2EE: endpoint %q: %w", endpoint, e2ee.ErrEndpointNotCovered)
	}
	encPayload, session, err := e2ee.EncryptChatRequestChutes(body, raw.SigningKey)
	if err != nil {
		return e2ee.EncryptResult{}, err
	}

	if raw.InstanceID == "" || raw.E2ENonce == "" {
		session.Zero()
		return e2ee.EncryptResult{}, errors.New("chutes E2EE requires instance_id and e2e_nonce from attestation")
	}

	if raw.ChuteID == "" {
		session.Zero()
		return e2ee.EncryptResult{}, errors.New("chutes E2EE requires resolved chute_id from attestation")
	}

	meta := &e2ee.ChutesE2EE{
		ChuteID:    raw.ChuteID,
		InstanceID: raw.InstanceID,
		E2ENonce:   raw.E2ENonce,
		Session:    session,
	}
	return e2ee.EncryptResult{Body: encPayload, Chutes: meta}, nil
}

// CoversE2EE reports whether this E2EE covers endpoint. Chutes E2EE
// encrypts the whole body of chat and embeddings requests.
func (c *E2EE) CoversE2EE(endpoint e2ee.EndpointType) bool {
	switch endpoint {
	case e2ee.EndpointChat, e2ee.EndpointEmbeddings:
		return true
	default:
		return false
	}
}
