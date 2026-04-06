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

// EncryptRequest encrypts each message content with Venice E2EE and forces
// stream=true. The raw.SigningKey must be a 130-char hex secp256k1 public key.
// The endpointPath is unused — Venice only supports chat completions.
func (v *E2EE) EncryptRequest(body []byte, raw *attestation.RawAttestation, _ string) ([]byte, e2ee.Decryptor, *e2ee.ChutesE2EE, error) {
	session, err := e2ee.NewVeniceSession()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create venice E2EE session: %w", err)
	}
	if err := session.SetModelKey(raw.SigningKey); err != nil {
		session.Zero()
		return nil, nil, nil, fmt.Errorf("set model key: %w", err)
	}

	// Single unmarshal: extract messages for encryption, preserve all other fields.
	var full map[string]json.RawMessage
	if err := json.Unmarshal(body, &full); err != nil {
		session.Zero()
		return nil, nil, nil, fmt.Errorf("parse body for venice E2EE: %w", err)
	}

	var messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(full["messages"], &messages); err != nil {
		session.Zero()
		return nil, nil, nil, fmt.Errorf("parse messages for venice E2EE: %w", err)
	}

	type encMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	enc := make([]encMsg, len(messages))
	for i, msg := range messages {
		ciphertext, err := e2ee.EncryptVenice([]byte(msg.Content), session.ModelPubKey())
		if err != nil {
			session.Zero()
			return nil, nil, nil, fmt.Errorf("encrypt message %d: %w", i, err)
		}
		enc[i] = encMsg{Role: msg.Role, Content: ciphertext}
	}

	messagesJSON, err := json.Marshal(enc)
	if err != nil {
		session.Zero()
		return nil, nil, nil, fmt.Errorf("marshal encrypted messages: %w", err)
	}
	full["messages"] = messagesJSON
	full["stream"] = json.RawMessage("true")

	out, err := json.Marshal(full)
	if err != nil {
		session.Zero()
		return nil, nil, nil, fmt.Errorf("marshal venice E2EE request body: %w", err)
	}
	return out, session, nil, nil
}
