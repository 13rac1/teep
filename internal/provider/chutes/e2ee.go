package chutes

import (
	"encoding/json"
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

// EncryptRequest encrypts the entire JSON body as a binary blob with Chutes
// ML-KEM-768 E2EE. Returns ChutesE2EE for the Preparer to inject headers.
// Requires raw.InstanceID and raw.E2ENonce from attestation.
func (c *E2EE) EncryptRequest(body []byte, raw *attestation.RawAttestation) ([]byte, e2ee.Decryptor, *e2ee.ChutesE2EE, error) {
	encPayload, session, err := e2ee.EncryptChatRequestChutes(body, raw.SigningKey)
	if err != nil {
		return nil, nil, nil, err
	}

	if raw.InstanceID == "" || raw.E2ENonce == "" {
		session.Zero()
		return nil, nil, nil, errors.New("chutes E2EE requires instance_id and e2e_nonce from attestation")
	}

	// Extract model name from request body for X-Chute-Id header.
	var req struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		session.Zero()
		return nil, nil, nil, fmt.Errorf("chutes E2EE: parse model from request body: %w", err)
	}

	meta := &e2ee.ChutesE2EE{
		ChuteID:    req.Model,
		InstanceID: raw.InstanceID,
		E2ENonce:   raw.E2ENonce,
		Session:    session,
	}
	return encPayload, nil, meta, nil
}
