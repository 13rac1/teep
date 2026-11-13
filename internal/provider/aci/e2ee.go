package aci

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
)

// E2EE implements provider.RequestEncryptor for E2EE v2 of the
// private-ai-gateway with the secp256k1 suite (spec/e2ee-v2.md). It encrypts
// each message content to the gateway E2EE key that the gateway quote binds,
// and forces stream=true so that the response is an SSE stream, which the
// session decrypts field by field.
type E2EE struct {
	now func() time.Time
}

// NewE2EE returns the E2EE v2 RequestEncryptor.
func NewE2EE() *E2EE { return &E2EE{now: time.Now} }

// EncryptRequest encrypts a chat completions request body for E2EE v2. The
// attestation must be ACI/1: only the gateway quote binds the key that E2EE
// v2 encrypts to. The body's top-level model is bound into every field's
// associated data, so a party that changes it makes the request fail.
func (a *E2EE) EncryptRequest(body []byte, raw *attestation.RawAttestation, endpoint e2ee.EndpointType) (e2ee.EncryptResult, error) {
	if endpoint != e2ee.EndpointChat {
		return e2ee.EncryptResult{}, fmt.Errorf("E2EE v2 unsupported endpoint %q", endpoint)
	}
	if raw.BackendFormat != attestation.FormatACI1 {
		return e2ee.EncryptResult{}, fmt.Errorf("E2EE v2 requires an ACI/1 attestation, got format %q", raw.BackendFormat)
	}
	var full map[string]json.RawMessage
	if err := json.Unmarshal(body, &full); err != nil {
		return e2ee.EncryptResult{}, fmt.Errorf("parse body for E2EE v2: %w", err)
	}
	var model string
	if err := json.Unmarshal(full["model"], &model); err != nil || model == "" {
		return e2ee.EncryptResult{}, errors.New("E2EE v2 requires a string model in the request body")
	}
	if raw, ok := full["n"]; ok && !e2ee.IsJSONNull(raw) && string(bytes.TrimSpace(raw)) != "1" {
		return e2ee.EncryptResult{}, errors.New("E2EE v2 supports only n=1: the response relay reads one choice")
	}
	if err := refuseUnencryptedFreeText(full); err != nil {
		return e2ee.EncryptResult{}, err
	}
	session, err := e2ee.NewACIv2Session(raw.SigningKey, model, a.now())
	if err != nil {
		return e2ee.EncryptResult{}, err
	}
	out, err := encryptMessages(full, session)
	if err != nil {
		session.Zero()
		return e2ee.EncryptResult{}, err
	}
	return e2ee.EncryptResult{Body: out, Session: session}, nil
}

// refuseUnencryptedFreeText refuses a request that carries free text in a
// field that E2EE v2 cannot encrypt: the gateway's E2EE v2 defines field
// paths only for message content, and it has no mode that encrypts every
// field. Short identifiers (model, messages[].name, stop, tool_choice and
// the top-level function_call, which name a function) and the other request
// parameters pass through in plaintext.
func refuseUnencryptedFreeText(full map[string]json.RawMessage) error {
	for _, key := range []string{"prediction", "tools", "functions"} {
		if hasValue(full[key]) {
			return unencryptableFieldError(key)
		}
	}
	if raw := full["response_format"]; hasValue(raw) {
		var format map[string]json.RawMessage
		if err := json.Unmarshal(raw, &format); err != nil {
			return fmt.Errorf("parse response_format for E2EE v2: %w", err)
		}
		if hasValue(format["json_schema"]) {
			return unencryptableFieldError("response_format.json_schema")
		}
	}
	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(full["messages"], &messages); err != nil {
		return fmt.Errorf("parse messages for E2EE v2: %w", err)
	}
	for i, msg := range messages {
		for _, key := range []string{"tool_calls", "function_call", "refusal", "audio"} {
			if hasValue(msg[key]) {
				return unencryptableFieldError(fmt.Sprintf("messages.%d.%s", i, key))
			}
		}
	}
	return nil
}

// hasValue reports whether raw is present and not null, "", [] or {}.
func hasValue(raw json.RawMessage) bool {
	if raw == nil || e2ee.IsJSONNull(raw) {
		return false
	}
	switch string(bytes.TrimSpace(raw)) {
	case `""`, "[]", "{}":
		return false
	}
	return true
}

func unencryptableFieldError(field string) error {
	return fmt.Errorf("E2EE v2 request refused: %s holds free text, and E2EE v2 of the gateway defines no field path for it", field)
}

// encryptMessages encrypts every message content in place under the field
// path messages.{m}.content and returns the request body with stream=true.
// refuseUnencryptedFreeText has refused the message fields that hold free
// text; the other message fields (role, name, tool_call_id) pass through.
func encryptMessages(full map[string]json.RawMessage, session *e2ee.ACIv2Session) ([]byte, error) {
	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(full["messages"], &messages); err != nil {
		return nil, fmt.Errorf("parse messages for E2EE v2: %w", err)
	}
	encrypted := 0
	for i, msg := range messages {
		raw, ok := msg["content"]
		if !ok || e2ee.IsJSONNull(raw) {
			continue
		}
		plaintext, err := contentPlaintext(raw, i)
		if err != nil {
			return nil, err
		}
		ct, err := session.EncryptRequestField(fmt.Sprintf("messages.%d.content", i), plaintext)
		if err != nil {
			return nil, fmt.Errorf("encrypt message %d: %w", i, err)
		}
		msg["content"], _ = json.Marshal(ct) //nolint:errchkjson // strings always marshal
		encrypted++
	}
	if encrypted == 0 {
		return nil, errors.New("E2EE v2 request has no message content to encrypt")
	}
	messagesJSON, err := json.Marshal(messages)
	if err != nil {
		return nil, fmt.Errorf("marshal encrypted messages: %w", err)
	}
	full["messages"] = messagesJSON
	full["stream"] = json.RawMessage("true")
	return json.Marshal(full)
}

// contentPlaintext returns the plaintext of a message content: the string
// itself, or the compact JSON of a structured content array, which the
// gateway restores as structured content (spec §5).
func contentPlaintext(raw json.RawMessage, idx int) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	switch {
	case len(trimmed) > 0 && trimmed[0] == '"':
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return nil, fmt.Errorf("message %d: parse string content: %w", idx, err)
		}
		return []byte(s), nil
	case len(trimmed) > 0 && trimmed[0] == '[':
		var compact bytes.Buffer
		if err := json.Compact(&compact, trimmed); err != nil {
			return nil, fmt.Errorf("message %d: compact content array: %w", idx, err)
		}
		return compact.Bytes(), nil
	default:
		return nil, fmt.Errorf("message %d: unsupported content type", idx)
	}
}
