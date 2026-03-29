package venice

import (
	"encoding/json"
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
)

// E2EE implements provider.RequestEncryptor for Venice E2EE
// (secp256k1 ECDH + AES-256-GCM).
type E2EE struct{}

// NewE2EE returns a Venice RequestEncryptor.
func NewE2EE() *E2EE { return &E2EE{} }

// chatMessage is one message in the chat history.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// EncryptRequest encrypts each message content with Venice E2EE and forces
// stream=true. The raw.SigningKey must be a 130-char hex secp256k1 public key.
func (v *E2EE) EncryptRequest(body []byte, raw *attestation.RawAttestation) ([]byte, *e2ee.Session, error) {
	session, err := e2ee.NewVeniceSession()
	if err != nil {
		return nil, nil, fmt.Errorf("create venice E2EE session: %w", err)
	}
	if err := session.SetModelKey(raw.SigningKey); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("set model key: %w", err)
	}

	var req struct {
		Messages []chatMessage `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("parse body for venice E2EE: %w", err)
	}

	encMessages := make([]chatMessage, len(req.Messages))
	for i, msg := range req.Messages {
		ciphertext, err := e2ee.EncryptVenice([]byte(msg.Content), session.ModelPubKey())
		if err != nil {
			session.Zero()
			return nil, nil, fmt.Errorf("encrypt message %d: %w", i, err)
		}
		encMessages[i] = chatMessage{Role: msg.Role, Content: ciphertext}
	}

	// Reassemble the full request preserving unknown fields.
	var full map[string]json.RawMessage
	if err := json.Unmarshal(body, &full); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("re-parse body for venice E2EE rewrite: %w", err)
	}

	messagesJSON, err := json.Marshal(encMessages)
	if err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("marshal encrypted messages: %w", err)
	}
	full["messages"] = messagesJSON
	full["stream"] = json.RawMessage("true")

	out, err := json.Marshal(full)
	if err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("marshal venice E2EE request body: %w", err)
	}
	return out, session, nil
}
