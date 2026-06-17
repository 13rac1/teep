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

// EncryptRequest encrypts the request body for the given endpoint type using
// NEAR AI E2EE (Ed25519/X25519 + XChaCha20-Poly1305).
//
// Supported endpoint types:
//   - chat: encrypts messages[].content (string or serialized VL array)
//   - images: encrypts prompt
//   - embeddings: encrypts input (string or string array)
//   - rerank: encrypts query and documents[]
//   - score: encrypts text_1 and text_2
//
// Unsupported endpoints fail closed.
func (n *E2EE) EncryptRequest(body []byte, raw *attestation.RawAttestation, endpoint e2ee.EndpointType) (e2ee.EncryptResult, error) {
	switch endpoint {
	case e2ee.EndpointChat:
		encBody, session, err := e2ee.EncryptChatMessagesNearCloud(body, raw.SigningKey)
		if err != nil {
			return e2ee.EncryptResult{}, err
		}
		return e2ee.EncryptResult{Body: encBody, Session: session}, nil
	case e2ee.EndpointImages:
		encBody, session, err := e2ee.EncryptImagePromptNearCloud(body, raw.SigningKey)
		if err != nil {
			return e2ee.EncryptResult{}, err
		}
		return e2ee.EncryptResult{Body: encBody, Session: session}, nil
	case e2ee.EndpointEmbeddings:
		encBody, session, err := e2ee.EncryptEmbeddingsNearCloud(body, raw.SigningKey)
		if err != nil {
			return e2ee.EncryptResult{}, err
		}
		return e2ee.EncryptResult{Body: encBody, Session: session}, nil
	case e2ee.EndpointRerank:
		encBody, session, err := e2ee.EncryptRerankNearCloud(body, raw.SigningKey)
		if err != nil {
			return e2ee.EncryptResult{}, err
		}
		return e2ee.EncryptResult{Body: encBody, Session: session}, nil
	case e2ee.EndpointScore:
		encBody, session, err := e2ee.EncryptScoreNearCloud(body, raw.SigningKey)
		if err != nil {
			return e2ee.EncryptResult{}, err
		}
		return e2ee.EncryptResult{Body: encBody, Session: session}, nil
	default:
		return e2ee.EncryptResult{}, fmt.Errorf("NearAI E2EE not supported for endpoint %q", endpoint)
	}
}
