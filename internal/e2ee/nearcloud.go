package e2ee

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// NearCloudSession holds ephemeral Ed25519/X25519 key material for one
// NearCloud E2EE request/response cycle.
type NearCloudSession struct {
	// ed25519PubHex is the client's Ed25519 public key (64 hex chars),
	// sent in the X-Client-Pub-Key header.
	ed25519PubHex string
	// modelEd25519Hex is the model's Ed25519 public key (64 hex chars).
	modelEd25519Hex string
	// x25519Priv is the client's X25519 private key (derived from Ed25519
	// seed) used for decrypting incoming response chunks.
	x25519Priv *ecdh.PrivateKey
	// modelX25519 is the model's X25519 public key (converted from its
	// Ed25519 public key) used for encrypting outgoing messages.
	modelX25519 *ecdh.PublicKey
}

// NewNearCloudSession generates a fresh Ed25519 key pair and derives the X25519
// private key.
func NewNearCloudSession() (*NearCloudSession, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	x25519Priv, err := ed25519SeedToX25519(priv.Seed())
	if err != nil {
		return nil, fmt.Errorf("derive x25519 private key: %w", err)
	}
	return &NearCloudSession{
		ed25519PubHex: hex.EncodeToString(pub),
		x25519Priv:    x25519Priv,
	}, nil
}

// ClientEd25519PubHex returns the client's Ed25519 public key as 64 hex chars.
func (s *NearCloudSession) ClientEd25519PubHex() string { return s.ed25519PubHex }

// SetModelKeyEd25519 parses and validates the model's Ed25519 public key (64 hex
// chars) and converts it to an X25519 public key for encryption.
func (s *NearCloudSession) SetModelKeyEd25519(ed25519PubHex string) error {
	if len(ed25519PubHex) != 64 {
		return fmt.Errorf("model ed25519 public key must be 64 hex chars, got %d", len(ed25519PubHex))
	}
	edPubBytes, err := hex.DecodeString(ed25519PubHex)
	if err != nil {
		return fmt.Errorf("model ed25519 key is not valid hex: %w", err)
	}
	x25519Pub, err := Ed25519PubToX25519(edPubBytes)
	if err != nil {
		return fmt.Errorf("convert model ed25519 to x25519: %w", err)
	}
	s.modelEd25519Hex = ed25519PubHex
	s.modelX25519 = x25519Pub
	return nil
}

// ModelX25519Pub returns the model's X25519 public key.
func (s *NearCloudSession) ModelX25519Pub() *ecdh.PublicKey {
	return s.modelX25519
}

// IsEncryptedChunk returns true if val looks like a NearCloud E2EE encrypted chunk.
func (s *NearCloudSession) IsEncryptedChunk(val string) bool {
	return IsEncryptedChunkXChaCha20(val)
}

// Decrypt decrypts a hex-encoded NearCloud ciphertext using the session's X25519 key.
func (s *NearCloudSession) Decrypt(ciphertextHex string) ([]byte, error) {
	return DecryptXChaCha20(ciphertextHex, s.x25519Priv)
}

// Zero nils key references so the GC can collect the key material.
// Unlike VeniceSession, crypto/ecdh does not expose a method to overwrite
// key bytes in place. The actual key material persists until GC reclaims it.
func (s *NearCloudSession) Zero() {
	s.x25519Priv = nil
	s.modelX25519 = nil
}

// IsResponseFieldEncrypted reports whether a response field is encrypted in
// NearCloud E2EE responses under X-Encrypt-All-Fields mode.
// Per api_support.md, encrypted fields include: content, refusal, tool_calls.*,
// audio.data, logprobs.*.{token,bytes}, etc.
// Plaintext fields are structural: role, finish_reason, index, usage.*, object,
// created, id, system_fingerprint.
// SPECIAL CASE: score endpoint data[].score is plaintext due to known upstream limitation.
// Actual upstream paths: /v1/chat/completions (chat), /v1/embeddings, etc.
func (s *NearCloudSession) IsResponseFieldEncrypted(fieldPath string, endpoint EndpointType) bool {
	if fieldPath == "usage" || strings.HasPrefix(fieldPath, "usage.") {
		return false
	}

	// Plaintext structural/metadata fields and container paths.
	// Container paths (arrays and objects) are listed here so callers traversing
	// the response tree can distinguish structural nodes from encrypted leaves;
	// the fail-closed default at the end of this function applies only to unknown
	// leaf candidates, not to these known structural containers.
	switch fieldPath {
	case "role", "finish_reason", "index", "object", "created", "id", "system_fingerprint",
		"tool_call_id", "tool_calls[].id", "tool_calls[].type", "tool_calls[].index",
		// Structural container paths (arrays / objects — not encrypted leaves).
		"tool_calls", "tool_calls[]", "tool_calls[].function",
		"audio", "function_call",
		// content[] is the structural element container for multimodal content-part
		// arrays; the encrypted leaf is content[].text, not the container itself.
		"content[]",
		"logprobs", "logprobs.content", "logprobs.content[]",
		"logprobs.refusal", "logprobs.refusal[]",
		"logprobs.content[].top_logprobs", "logprobs.content[].top_logprobs[]",
		"logprobs.refusal[].top_logprobs", "logprobs.refusal[].top_logprobs[]":
		return false
	}

	// Known encrypted chat response leaves under X-Encrypt-All-Fields.
	switch fieldPath {
	case EncFieldContent, EncFieldContentText,
		EncFieldRefusal, EncFieldReasoning, EncFieldReasoningContent, EncFieldName,
		EncFieldAudioData,
		EncFieldFuncCallName, EncFieldFuncCallArgs,
		EncFieldToolCallsFuncName, EncFieldToolCallsFuncArgs,
		EncFieldLogprobsContentToken, EncFieldLogprobsContentBytes,
		EncFieldLogprobsRefusalToken, EncFieldLogprobsRefusalBytes,
		EncFieldB64JSON, EncFieldRevisedPrompt,
		EncFieldEmbedding, EncFieldRerankDocumentText:
		return true
	}

	// Special case: score endpoint response data[].score is plaintext per api_support.md
	// "Score: data[].score plaintext numeric response (known upstream NearAI limitation)"
	// Upstream path: /v1/score
	if endpoint == EndpointScore && fieldPath == EncFieldScore {
		return false
	}

	// Fail closed for full-field mode: unknown leaves are expected encrypted.
	return true
}

// hkdfInfoEd25519 is the HKDF info string for the NearCloud Ed25519/XChaCha20
// E2EE protocol.
const hkdfInfoEd25519 = "ed25519_encryption"

// EncryptXChaCha20 encrypts plaintext for the recipient's X25519 public key
// using per-message ephemeral X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305.
//
// Wire format (hex-encoded):
//
//	ephemeral_x25519_pub (32 bytes) || nonce (24 bytes) || ciphertext+tag
//
// HKDF info = "ed25519_encryption", no salt. Matches the NEAR AI protocol.
func EncryptXChaCha20(plaintext []byte, recipientX25519Pub *ecdh.PublicKey) (string, error) {
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ephemeral x25519 key: %w", err)
	}

	shared, err := ephPriv.ECDH(recipientX25519Pub)
	if err != nil {
		return "", fmt.Errorf("x25519 ecdh: %w", err)
	}

	key := deriveKeyEd25519(shared)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", fmt.Errorf("create xchacha20: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX) // 24 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ct := aead.Seal(nil, nonce, plaintext, nil)

	// Wire: ephemeral_pub(32) + nonce(24) + ciphertext+tag
	wire := make([]byte, 0, 32+24+len(ct))
	wire = append(wire, ephPriv.PublicKey().Bytes()...)
	wire = append(wire, nonce...)
	wire = append(wire, ct...)

	return hex.EncodeToString(wire), nil
}

// DecryptXChaCha20 decrypts a hex-encoded NearCloud E2EE ciphertext using the
// session's X25519 private key. Returns an error if decryption fails.
func DecryptXChaCha20(ciphertextHex string, x25519Priv *ecdh.PrivateKey) ([]byte, error) {
	raw, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}

	// Minimum: 32 (ephemeral pub) + 24 (nonce) + 16 (poly1305 tag) = 72 bytes
	if len(raw) < 72 {
		return nil, fmt.Errorf("ciphertext too short: %d bytes (minimum 72)", len(raw))
	}

	ephPubBytes := raw[:32]
	nonce := raw[32:56]
	ciphertext := raw[56:]

	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}

	shared, err := x25519Priv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("x25519 ecdh: %w", err)
	}

	key := deriveKeyEd25519(shared)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create xchacha20: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("authentication failed")
	}
	return plaintext, nil
}

// IsEncryptedChunkXChaCha20 returns true if s looks like a hex-encoded NearCloud
// E2EE payload. Minimum 144 hex chars (72 bytes: 32 ephemeral pub + 24 nonce +
// 16 tag), and all characters are valid hex.
func IsEncryptedChunkXChaCha20(s string) bool {
	if len(s) < 144 {
		return false
	}
	for _, c := range s {
		if !isHexRune(c) {
			return false
		}
	}
	return true
}

// EncryptChatMessagesNearCloud creates a NearCloud E2EE session, encrypts chat
// request fields supported by inference-proxy's X-Encrypt-All-Fields mode, and
// forces stream=true. The signingKey is the model's Ed25519 public key
// (64 hex chars) from the attestation response.
//
// Encrypted message fields: content, reasoning_content, reasoning, refusal,
// name, audio.data, tool_calls[].function.{name,arguments}, and
// function_call.{name,arguments}. Encrypted top-level fields: tools[].function
// name/description/parameters, tool_choice.function.name,
// function_call.name (object form only). Other fields are preserved unchanged.
func EncryptChatMessagesNearCloud(body []byte, signingKey string) ([]byte, *NearCloudSession, error) {
	session, err := NewNearCloudSession()
	if err != nil {
		return nil, nil, fmt.Errorf("create NearCloud E2EE session: %w", err)
	}
	if err := session.SetModelKeyEd25519(signingKey); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("set model key ed25519: %w", err)
	}

	// Parse top-level body, preserving all fields (tools, model, etc.).
	var full map[string]json.RawMessage
	if err := json.Unmarshal(body, &full); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("parse body for NearCloud E2EE: %w", err)
	}

	// Parse messages preserving ALL fields — each message is a raw JSON map.
	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(full["messages"], &messages); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("parse messages for NearCloud E2EE: %w", err)
	}

	for i, msg := range messages {
		if err := encryptMessageFields(msg, i, session); err != nil {
			session.Zero()
			return nil, nil, err
		}
	}

	if err := encryptTopLevelFields(full, session); err != nil {
		session.Zero()
		return nil, nil, err
	}

	messagesJSON, _ := json.Marshal(messages) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	full["messages"] = messagesJSON
	full["stream"] = json.RawMessage("true")

	out, _ := json.Marshal(full) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	return out, session, nil
}

// encryptMessageFields encrypts all supported fields of a single chat message.
func encryptMessageFields(msg map[string]json.RawMessage, idx int, session *NearCloudSession) error {
	if err := encryptMessageContent(msg, idx, session); err != nil {
		return err
	}
	if err := encryptOptionalStringField(msg, "reasoning_content", session); err != nil {
		return fmt.Errorf("message %d reasoning_content: %w", idx, err)
	}
	if err := encryptOptionalStringField(msg, "reasoning", session); err != nil {
		return fmt.Errorf("message %d reasoning: %w", idx, err)
	}
	if err := encryptOptionalStringField(msg, "refusal", session); err != nil {
		return fmt.Errorf("message %d refusal: %w", idx, err)
	}
	if err := encryptOptionalStringField(msg, "name", session); err != nil {
		return fmt.Errorf("message %d name: %w", idx, err)
	}
	if err := encryptAudioDataField(msg, idx, session); err != nil {
		return err
	}
	if err := encryptToolCallsField(msg, idx, session); err != nil {
		return err
	}
	if err := encryptFunctionCallField(msg, idx, session); err != nil {
		return err
	}
	return nil
}

// encryptMessageContent encrypts the content field of a single chat message
// in-place. Messages with null or absent content (e.g. assistant tool-call
// messages) are left unchanged.
func encryptMessageContent(msg map[string]json.RawMessage, idx int, session *NearCloudSession) error {
	contentRaw, ok := msg["content"]
	if !ok {
		return nil // no content field at all (valid for some message types)
	}

	// Null content: standard format for assistant tool-call messages.
	// Pass through unchanged — the inference-proxy handles null content.
	if IsJSONNull(contentRaw) {
		return nil
	}

	plaintext, err := contentPlaintext(contentRaw)
	if err != nil {
		return fmt.Errorf("message %d content: %w", idx, err)
	}
	ct, err := EncryptXChaCha20(plaintext, session.ModelX25519Pub())
	if err != nil {
		return fmt.Errorf("encrypt NearCloud message %d: %w", idx, err)
	}
	ctJSON, _ := json.Marshal(ct) //nolint:errchkjson // strings always marshal
	msg["content"] = ctJSON
	return nil
}

func encryptTopLevelFields(full map[string]json.RawMessage, session *NearCloudSession) error {
	if err := encryptToolsDefinitions(full, session); err != nil {
		return err
	}
	if err := encryptToolChoiceFunctionName(full, session); err != nil {
		return err
	}
	if err := encryptTopLevelFunctionCallName(full, session); err != nil {
		return err
	}
	return nil
}

func encryptToolsDefinitions(full map[string]json.RawMessage, session *NearCloudSession) error {
	toolsRaw, ok := full["tools"]
	if !ok || IsJSONNull(toolsRaw) {
		return nil
	}
	var tools []map[string]json.RawMessage
	if err := json.Unmarshal(toolsRaw, &tools); err != nil {
		return fmt.Errorf("parse tools: %w", err)
	}
	for i := range tools {
		fnRaw, ok := tools[i]["function"]
		if !ok || IsJSONNull(fnRaw) {
			continue
		}
		var fn map[string]json.RawMessage
		if err := json.Unmarshal(fnRaw, &fn); err != nil {
			return fmt.Errorf("parse tools[%d].function: %w", i, err)
		}
		if err := encryptOptionalStringField(fn, "name", session); err != nil {
			return fmt.Errorf("tools[%d].function.name: %w", i, err)
		}
		if err := encryptOptionalStringField(fn, "description", session); err != nil {
			return fmt.Errorf("tools[%d].function.description: %w", i, err)
		}
		if err := encryptParametersField(fn, session); err != nil {
			return fmt.Errorf("tools[%d].function.parameters: %w", i, err)
		}
		fnOut, _ := json.Marshal(fn) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
		tools[i]["function"] = fnOut
	}
	toolsOut, _ := json.Marshal(tools) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	full["tools"] = toolsOut
	return nil
}

func encryptToolChoiceFunctionName(full map[string]json.RawMessage, session *NearCloudSession) error {
	tcRaw, ok := full["tool_choice"]
	if !ok || IsJSONNull(tcRaw) {
		return nil
	}
	if !jsonRawStartsWithToken(tcRaw, '{') {
		// tool_choice can be a string ("auto", "none", "required").
		return nil
	}
	var tc map[string]json.RawMessage
	if err := json.Unmarshal(tcRaw, &tc); err != nil {
		return fmt.Errorf("parse tool_choice: %w", err)
	}
	fnRaw, ok := tc["function"]
	if !ok || IsJSONNull(fnRaw) {
		return nil
	}
	var fn map[string]json.RawMessage
	if err := json.Unmarshal(fnRaw, &fn); err != nil {
		return fmt.Errorf("parse tool_choice.function: %w", err)
	}
	if err := encryptOptionalStringField(fn, "name", session); err != nil {
		return fmt.Errorf("tool_choice.function.name: %w", err)
	}
	fnOut, _ := json.Marshal(fn) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	tc["function"] = fnOut
	tcOut, _ := json.Marshal(tc) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	full["tool_choice"] = tcOut
	return nil
}

func encryptTopLevelFunctionCallName(full map[string]json.RawMessage, session *NearCloudSession) error {
	fcRaw, ok := full["function_call"]
	if !ok || IsJSONNull(fcRaw) {
		return nil
	}
	if !jsonRawStartsWithToken(fcRaw, '{') {
		// function_call can be a string ("auto"/"none"). Keep unchanged.
		return nil
	}
	var fc map[string]json.RawMessage
	if err := json.Unmarshal(fcRaw, &fc); err != nil {
		return fmt.Errorf("parse function_call: %w", err)
	}
	if err := encryptOptionalStringField(fc, "name", session); err != nil {
		return fmt.Errorf("function_call.name: %w", err)
	}
	fcOut, _ := json.Marshal(fc) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	full["function_call"] = fcOut
	return nil
}

func encryptAudioDataField(msg map[string]json.RawMessage, idx int, session *NearCloudSession) error {
	audioRaw, ok := msg["audio"]
	if !ok || IsJSONNull(audioRaw) {
		return nil
	}
	var audio map[string]json.RawMessage
	if err := json.Unmarshal(audioRaw, &audio); err != nil {
		return fmt.Errorf("message %d audio: %w", idx, err)
	}
	if err := encryptOptionalStringField(audio, "data", session); err != nil {
		return fmt.Errorf("message %d audio.data: %w", idx, err)
	}
	audioOut, _ := json.Marshal(audio) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	msg["audio"] = audioOut
	return nil
}

func encryptToolCallsField(msg map[string]json.RawMessage, idx int, session *NearCloudSession) error {
	toolCallsRaw, ok := msg["tool_calls"]
	if !ok || IsJSONNull(toolCallsRaw) {
		return nil
	}
	var toolCalls []map[string]json.RawMessage
	if err := json.Unmarshal(toolCallsRaw, &toolCalls); err != nil {
		return fmt.Errorf("message %d tool_calls: %w", idx, err)
	}
	for j := range toolCalls {
		fnRaw, ok := toolCalls[j]["function"]
		if !ok || IsJSONNull(fnRaw) {
			continue
		}
		var fn map[string]json.RawMessage
		if err := json.Unmarshal(fnRaw, &fn); err != nil {
			return fmt.Errorf("message %d tool_calls[%d].function: %w", idx, j, err)
		}
		for _, field := range functionObjectFields {
			if err := encryptOptionalStringField(fn, field, session); err != nil {
				return fmt.Errorf("message %d tool_calls[%d].function.%s: %w", idx, j, field, err)
			}
		}
		fnOut, _ := json.Marshal(fn) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
		toolCalls[j]["function"] = fnOut
	}
	toolCallsOut, _ := json.Marshal(toolCalls) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	msg["tool_calls"] = toolCallsOut
	return nil
}

func encryptFunctionCallField(msg map[string]json.RawMessage, idx int, session *NearCloudSession) error {
	fcRaw, ok := msg["function_call"]
	if !ok || IsJSONNull(fcRaw) {
		return nil
	}
	if !jsonRawStartsWithToken(fcRaw, '{') {
		// Deprecated function_call can be a string ("auto"/"none"). Keep unchanged.
		return nil
	}
	var fc map[string]json.RawMessage
	if err := json.Unmarshal(fcRaw, &fc); err != nil {
		return fmt.Errorf("message %d function_call: %w", idx, err)
	}
	for _, field := range functionObjectFields {
		if err := encryptOptionalStringField(fc, field, session); err != nil {
			return fmt.Errorf("message %d function_call.%s: %w", idx, field, err)
		}
	}
	fcOut, _ := json.Marshal(fc) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	msg["function_call"] = fcOut
	return nil
}

func encryptOptionalStringField(obj map[string]json.RawMessage, key string, session *NearCloudSession) error {
	raw, ok := obj[key]
	if !ok || IsJSONNull(raw) {
		return nil
	}
	var plaintext string
	if err := json.Unmarshal(raw, &plaintext); err != nil {
		return fmt.Errorf("parse string field %q: %w", key, err)
	}
	ct, err := EncryptXChaCha20([]byte(plaintext), session.ModelX25519Pub())
	if err != nil {
		return fmt.Errorf("encrypt field %q: %w", key, err)
	}
	ctJSON, _ := json.Marshal(ct) //nolint:errchkjson // strings always marshal
	obj[key] = ctJSON
	return nil
}

func encryptParametersField(fn map[string]json.RawMessage, session *NearCloudSession) error {
	paramsRaw, ok := fn["parameters"]
	if !ok || IsJSONNull(paramsRaw) {
		return nil
	}
	var plaintext []byte
	trimmed := bytes.TrimSpace(paramsRaw)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return fmt.Errorf("parse string parameters: %w", err)
		}
		plaintext = []byte(s)
	} else {
		plaintext = trimmed
	}
	ct, err := EncryptXChaCha20(plaintext, session.ModelX25519Pub())
	if err != nil {
		return fmt.Errorf("encrypt parameters: %w", err)
	}
	ctJSON, _ := json.Marshal(ct) //nolint:errchkjson // strings always marshal
	fn["parameters"] = ctJSON
	return nil
}

// IsJSONNull returns true if raw represents a JSON null value.
// Leading and trailing whitespace is trimmed before comparison.
func IsJSONNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || string(trimmed) == "null"
}

// contentPlaintext extracts the plaintext bytes to encrypt from a message's
// content field. For string content, returns the string bytes directly. For VL
// structured content arrays (e.g. [{"type":"text",...},{"type":"image_url",...}]),
// serializes the array to a JSON string — the inference-proxy's decrypt_chat_message_fields
// detects the JSON array after decryption and restores the structured content.
func contentPlaintext(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty content")
	}
	// String content: unmarshal to get the decoded string value.
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("parse string content: %w", err)
		}
		return []byte(s), nil
	}
	// Array content (VL): serialize the raw JSON array as the plaintext.
	// The inference-proxy decrypts it, detects the JSON array, and restores
	// the structured content.
	if raw[0] == '[' {
		return []byte(raw), nil
	}
	return nil, fmt.Errorf("unsupported content type (starts with %q)", raw[0])
}

// newNearCloudSessionAndBody creates a NearCloud E2EE session, validates the model key,
// and parses the request body. On any error, the session is zeroed and error is returned.
// This eliminates repeated boilerplate across endpoint-specific encryptors.
func newNearCloudSessionAndBody(body []byte, signingKey, contextName string) (*NearCloudSession, map[string]json.RawMessage, error) {
	session, err := NewNearCloudSession()
	if err != nil {
		return nil, nil, fmt.Errorf("create NearCloud E2EE session: %w", err)
	}
	if err := session.SetModelKeyEd25519(signingKey); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("set model key ed25519: %w", err)
	}

	var full map[string]json.RawMessage
	if err := json.Unmarshal(body, &full); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("parse body for %s E2EE: %w", contextName, err)
	}

	return session, full, nil
}

// EncryptImagePromptNearCloud creates a NearCloud E2EE session and encrypts
// the "prompt" field in an image generation request. The signingKey is the
// model's Ed25519 public key (64 hex chars) from the attestation response.
func EncryptImagePromptNearCloud(body []byte, signingKey string) ([]byte, *NearCloudSession, error) {
	session, full, err := newNearCloudSessionAndBody(body, signingKey, "image")
	if err != nil {
		return nil, nil, err
	}

	promptRaw, ok := full["prompt"]
	if !ok {
		session.Zero()
		return nil, nil, errors.New("image generation body missing 'prompt' field")
	}
	var prompt string
	if err := json.Unmarshal(promptRaw, &prompt); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("parse prompt for NearCloud image E2EE: %w", err)
	}

	ct, err := EncryptXChaCha20([]byte(prompt), session.ModelX25519Pub())
	if err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("encrypt NearCloud image prompt: %w", err)
	}

	encPrompt, _ := json.Marshal(ct) //nolint:errchkjson // strings always marshal
	full["prompt"] = encPrompt

	out, _ := json.Marshal(full) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	return out, session, nil
}

// EncryptEmbeddingsNearCloud creates a NearCloud E2EE session and encrypts the
// "input" field of an embeddings request. The signingKey is the model's Ed25519
// public key (64 hex chars) from the attestation response.
//
// Encrypted field: input when present and non-null. Supported shapes are a JSON
// string or an array of JSON strings.
// The pinned handler sets the X-Encrypt-All-Fields header; this helper only
// rewrites the request body and returns the session for response decryption.
func EncryptEmbeddingsNearCloud(body []byte, signingKey string) ([]byte, *NearCloudSession, error) {
	session, full, err := newNearCloudSessionAndBody(body, signingKey, "embeddings")
	if err != nil {
		return nil, nil, err
	}

	inputRaw, ok := full["input"]
	if ok && !IsJSONNull(inputRaw) {
		// Input can be either a single string or an array of strings.
		// Unsupported element types fail closed.
		trimmed := bytes.TrimSpace(inputRaw)
		switch {
		case len(trimmed) > 0 && trimmed[0] == '"':
			// Single string: encrypt it directly.
			var s string
			if err := json.Unmarshal(inputRaw, &s); err != nil {
				session.Zero()
				return nil, nil, fmt.Errorf("parse input string: %w", err)
			}
			ct, err := EncryptXChaCha20([]byte(s), session.ModelX25519Pub())
			if err != nil {
				session.Zero()
				return nil, nil, fmt.Errorf("encrypt input: %w", err)
			}
			ctJSON, _ := json.Marshal(ct) //nolint:errchkjson // strings always marshal
			full["input"] = ctJSON
		case len(trimmed) > 0 && trimmed[0] == '[':
			// Array: every element must be a string.
			var arr []json.RawMessage
			if err := json.Unmarshal(inputRaw, &arr); err != nil {
				session.Zero()
				return nil, nil, fmt.Errorf("parse input array: %w", err)
			}
			for i, item := range arr {
				itemTrimmed := bytes.TrimSpace(item)
				if len(itemTrimmed) == 0 || itemTrimmed[0] != '"' {
					session.Zero()
					return nil, nil, fmt.Errorf("input[%d]: unsupported embeddings input element type for E2EE", i)
				}
				var s string
				if err := json.Unmarshal(item, &s); err != nil {
					session.Zero()
					return nil, nil, fmt.Errorf("parse input[%d]: %w", i, err)
				}
				ct, err := EncryptXChaCha20([]byte(s), session.ModelX25519Pub())
				if err != nil {
					session.Zero()
					return nil, nil, fmt.Errorf("encrypt input[%d]: %w", i, err)
				}
				ctJSON, _ := json.Marshal(ct) //nolint:errchkjson // strings always marshal
				arr[i] = ctJSON
			}
			arrOut, _ := json.Marshal(arr) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
			full["input"] = arrOut
		default:
			session.Zero()
			return nil, nil, errors.New("unsupported embeddings input type for E2EE")
		}
	}

	out, _ := json.Marshal(full) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	return out, session, nil
}

// EncryptRerankNearCloud creates a NearCloud E2EE session and encrypts the
// "query" and "documents" fields of a rerank request. The signingKey is the
// model's Ed25519 public key (64 hex chars) from the attestation response.
//
// Encrypted fields: query (string); documents as either strings or objects with
// a text field. Object-form documents keep non-text metadata plaintext to match
// NearAI's actual field-level encryption behavior.
func EncryptRerankNearCloud(body []byte, signingKey string) ([]byte, *NearCloudSession, error) {
	session, full, err := newNearCloudSessionAndBody(body, signingKey, "rerank")
	if err != nil {
		return nil, nil, err
	}

	// Encrypt query field.
	if err := encryptOptionalStringField(full, "query", session); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("query: %w", err)
	}

	// Encrypt documents array.
	if docsRaw, ok := full["documents"]; ok && !IsJSONNull(docsRaw) {
		var docs []json.RawMessage
		if err := json.Unmarshal(docsRaw, &docs); err != nil {
			session.Zero()
			return nil, nil, fmt.Errorf("parse documents: %w", err)
		}
		for i, doc := range docs {
			encryptedDoc, err := encryptRerankDocument(doc, i, session)
			if err != nil {
				session.Zero()
				return nil, nil, err
			}
			docs[i] = encryptedDoc
		}
		docsOut, _ := json.Marshal(docs) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
		full["documents"] = docsOut
	}

	out, _ := json.Marshal(full) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	return out, session, nil
}

func encryptRerankDocument(docRaw json.RawMessage, idx int, session *NearCloudSession) (json.RawMessage, error) {
	trimmed := bytes.TrimSpace(docRaw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return docRaw, nil
	}

	switch trimmed[0] {
	case '"':
		var doc string
		if err := json.Unmarshal(docRaw, &doc); err != nil {
			return nil, fmt.Errorf("parse document %d string: %w", idx, err)
		}
		ct, err := EncryptXChaCha20([]byte(doc), session.ModelX25519Pub())
		if err != nil {
			return nil, fmt.Errorf("encrypt document %d: %w", idx, err)
		}
		out, _ := json.Marshal(ct) //nolint:errchkjson // strings always marshal
		return out, nil
	case '{':
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(docRaw, &doc); err != nil {
			return nil, fmt.Errorf("parse document %d object: %w", idx, err)
		}
		if err := encryptOptionalStringField(doc, "text", session); err != nil {
			return nil, fmt.Errorf("encrypt document %d text: %w", idx, err)
		}
		out, _ := json.Marshal(doc) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
		return out, nil
	default:
		return nil, fmt.Errorf("documents[%d]: unsupported rerank document type for E2EE", idx)
	}
}

// EncryptScoreNearCloud creates a NearCloud E2EE session and encrypts the
// "text_1" and "text_2" fields of a score request. The signingKey is the
// model's Ed25519 public key (64 hex chars) from the attestation response.
//
// Encrypted fields: text_1 (string), text_2 (string).
func EncryptScoreNearCloud(body []byte, signingKey string) ([]byte, *NearCloudSession, error) {
	session, full, err := newNearCloudSessionAndBody(body, signingKey, "score")
	if err != nil {
		return nil, nil, err
	}

	// Encrypt text_1 and text_2 fields.
	for _, key := range []string{"text_1", "text_2"} {
		if err := encryptOptionalStringField(full, key, session); err != nil {
			session.Zero()
			return nil, nil, fmt.Errorf("%s: %w", key, err)
		}
	}

	out, _ := json.Marshal(full) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	return out, session, nil
}

// ValidateModelKeyEd25519 checks if the given hex string is a valid Ed25519
// public key suitable for NearCloud E2EE.
func ValidateModelKeyEd25519(ed25519PubHex string) error {
	if len(ed25519PubHex) != 64 {
		return fmt.Errorf("expected 64 hex chars, got %d", len(ed25519PubHex))
	}
	b, err := hex.DecodeString(ed25519PubHex)
	if err != nil {
		return fmt.Errorf("not valid hex: %w", err)
	}
	_, err = Ed25519PubToX25519(b)
	if err != nil {
		return fmt.Errorf("not a valid ed25519 point: %w", err)
	}
	return nil
}

// deriveKeyEd25519 derives a 32-byte encryption key from a shared secret using
// HKDF-SHA256 with info="ed25519_encryption" and no salt.
func deriveKeyEd25519(sharedSecret []byte) []byte {
	r := hkdf.New(sha256.New, sharedSecret, nil, []byte(hkdfInfoEd25519))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		panic(fmt.Sprintf("BUG: hkdf expand: %v", err))
	}
	return key
}

// ed25519SeedToX25519 derives an X25519 private key from an Ed25519 seed
// (32 bytes). This matches the standard conversion: SHA-512 the seed, clamp
// the first 32 bytes.
func ed25519SeedToX25519(seed []byte) (*ecdh.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	h := sha512.Sum512(seed)
	// Clamp per RFC 7748.
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	return ecdh.X25519().NewPrivateKey(h[:32])
}

// Ed25519PubToX25519 converts an Ed25519 public key (32 bytes) to an X25519
// public key using the birational map from the Edwards to Montgomery form:
// u = (1 + y) / (1 - y) mod p.
func Ed25519PubToX25519(edPub []byte) (*ecdh.PublicKey, error) {
	if len(edPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(edPub))
	}
	p, err := new(edwards25519.Point).SetBytes(edPub)
	if err != nil {
		return nil, fmt.Errorf("invalid ed25519 point: %w", err)
	}
	montgomeryBytes := p.BytesMontgomery()
	return ecdh.X25519().NewPublicKey(montgomeryBytes)
}
