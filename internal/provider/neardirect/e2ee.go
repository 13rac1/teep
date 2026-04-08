package neardirect

import (
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
)

// E2EE implements provider.RequestEncryptor for NEAR AI E2EE
// (Ed25519/X25519 + XChaCha20-Poly1305). Used by both neardirect (pinned path)
// and nearcloud (gateway path).
type E2EE struct{}

// NewE2EE returns a NEAR AI RequestEncryptor.
func NewE2EE() *E2EE { return &E2EE{} }

// EncryptRequest encrypts request fields with NEAR AI E2EE. The endpointPath
// determines which fields are encrypted:
//   - /v1/chat/completions: encrypts messages[].content (text or serialized VL array)
//   - /v1/images/generations: encrypts the prompt field
//
// Unsupported endpoint paths fail closed — the TEE does not forward E2EE
// headers for other endpoints (embeddings, audio, rerank), so encrypting them
// would leave the model TEE unable to decrypt.
func (n *E2EE) EncryptRequest(body []byte, raw *attestation.RawAttestation, endpointPath string) ([]byte, e2ee.Decryptor, *e2ee.ChutesE2EE, error) {
	switch endpointPath {
	case "/v1/chat/completions":
		encBody, session, err := e2ee.EncryptChatMessagesNearCloud(body, raw.SigningKey)
		if err != nil {
			return nil, nil, nil, err
		}
		return encBody, session, nil, nil
	case "/v1/images/generations":
		encBody, session, err := e2ee.EncryptImagePromptNearCloud(body, raw.SigningKey)
		if err != nil {
			return nil, nil, nil, err
		}
		return encBody, session, nil, nil
	default:
		return nil, nil, nil, fmt.Errorf("NEAR AI E2EE not supported for endpoint %q", endpointPath)
	}
}
