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

	// Parse messages preserving ALL fields — each message is a raw JSON map.
	// Only the content field is encrypted in-place; all other fields
	// (tool_calls, tool_call_id, name, reasoning_content, etc.) pass through.
	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(full["messages"], &messages); err != nil {
		session.Zero()
		return nil, nil, nil, fmt.Errorf("parse messages for venice E2EE: %w", err)
	}

	for i, msg := range messages {
		if err := encryptVeniceMessageContent(msg, i, session); err != nil {
			session.Zero()
			return nil, nil, nil, err
		}
	}

	messagesJSON, err := json.Marshal(messages)
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

// encryptVeniceMessageContent encrypts the content field of a single chat
// message in-place using Venice E2EE (secp256k1 ECDH + AES-256-GCM).
// Messages with null or absent content (e.g. assistant tool-call messages)
// are left unchanged.
func encryptVeniceMessageContent(msg map[string]json.RawMessage, idx int, session *e2ee.VeniceSession) error {
	contentRaw, ok := msg["content"]
	if !ok {
		return nil // no content field at all (valid for some message types)
	}

	// Null content: standard format for assistant tool-call messages.
	if e2ee.IsJSONNull(contentRaw) {
		return nil
	}

	// Venice content is always a string — unmarshal to get decoded value.
	var s string
	if err := json.Unmarshal(contentRaw, &s); err != nil {
		return fmt.Errorf("message %d: parse content: %w", idx, err)
	}

	ciphertext, err := e2ee.EncryptVenice([]byte(s), session.ModelPubKey())
	if err != nil {
		return fmt.Errorf("encrypt venice message %d: %w", idx, err)
	}

	ctJSON, err := json.Marshal(ciphertext)
	if err != nil {
		return fmt.Errorf("marshal encrypted content %d: %w", idx, err)
	}
	msg["content"] = ctJSON
	return nil
}
