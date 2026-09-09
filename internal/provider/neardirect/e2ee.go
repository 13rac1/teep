package neardirect

import (
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
)

// E2EE implements provider.RequestEncryptor for NEAR AI E2EE
// (Ed25519/X25519 + XChaCha20-Poly1305). Used by both neardirect
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
	modelKey, err := e2ee.ParseNearModelKey(raw.SigningKey)
	if err != nil {
		return e2ee.EncryptResult{}, err
	}
	return n.EncryptRequestWithModelKey(body, modelKey, endpoint)
}

// EncryptRequestWithModelKey uses the key from the acquired authorization.
// Each call creates independent ephemeral encryption and response session material.
func (n *E2EE) EncryptRequestWithModelKey(body []byte, modelKey e2ee.NearModelKey, endpoint e2ee.EndpointType) (e2ee.EncryptResult, error) {
	var encrypt func([]byte, e2ee.NearModelKey) ([]byte, *e2ee.NearCloudSession, error)
	switch endpoint {
	case e2ee.EndpointChat:
		encrypt = e2ee.EncryptChatMessagesNearCloud
	case e2ee.EndpointImages:
		encrypt = e2ee.EncryptImagePromptNearCloud
	case e2ee.EndpointEmbeddings:
		encrypt = e2ee.EncryptEmbeddingsNearCloud
	case e2ee.EndpointRerank:
		encrypt = e2ee.EncryptRerankNearCloud
	case e2ee.EndpointScore:
		encrypt = e2ee.EncryptScoreNearCloud
	default:
		return e2ee.EncryptResult{}, fmt.Errorf("NearAI E2EE not supported for endpoint %q", endpoint)
	}
	encBody, session, err := encrypt(body, modelKey)
	if err != nil {
		return e2ee.EncryptResult{}, err
	}
	return e2ee.EncryptResult{Body: encBody, Session: session}, nil
}
