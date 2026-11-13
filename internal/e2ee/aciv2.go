package e2ee

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ACI E2EE v2 (secp256k1 suite) of the private-ai-gateway, spec/e2ee-v2.md:
// per-field secp256k1 ECDH + HKDF-SHA256 + AES-256-GCM, with RFC 8785 JCS
// associated data that binds each ciphertext to its field path, the request
// model, the request nonce and timestamp, and, for a response, the response
// id. The field wire format is the same as Venice's:
//
//	ephemeral_pub_uncompressed (65) || nonce (12) || ciphertext || tag (16)
const (
	// ACIv2Version is the X-E2EE-Version header value.
	ACIv2Version = "2"
	// ACIv2Algo is the workload keyset algo of the secp256k1 suite.
	ACIv2Algo = "secp256k1-aes-256-gcm-hkdf-sha256"

	aciv2HKDFInfo         = "aci.e2ee.v2.secp256k1"
	aciv2RequestPurpose   = "aci.e2ee.request.v2"
	aciv2ResponsePurpose  = "aci.e2ee.response.v2"
	aciv2RequestNonceSize = 32
)

// ACIv2Session holds the ephemeral client key and the request context of one
// E2EE v2 request and its response. The response context (model, nonce,
// timestamp) is fixed when the session is created, so every response field
// is checked against the request that the session encrypted.
type ACIv2Session struct {
	privateKey   *secp256k1.PrivateKey
	publicKeyHex string
	modelKeyHex  string
	modelPubKey  *secp256k1.PublicKey
	model        string
	nonceHex     string
	timestamp    int64
	decrypted    int
	// responseID is the id of the first chunk with a choice; every later
	// chunk with a choice must carry the same id.
	responseID *string
}

// NewACIv2Session creates a session for one request to model, encrypted to
// the attested secp256k1 E2EE key modelKeyHex (130 hex characters,
// uncompressed). The request nonce comes from crypto/rand.
func NewACIv2Session(modelKeyHex, model string, now time.Time) (*ACIv2Session, error) {
	if model == "" {
		return nil, errors.New("E2EE v2 requires the request model")
	}
	pub, err := parseUncompressedSecp256k1(modelKeyHex)
	if err != nil {
		return nil, fmt.Errorf("E2EE v2 model key: %w", err)
	}
	nonce := make([]byte, aciv2RequestNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate E2EE v2 request nonce: %w", err)
	}
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	return &ACIv2Session{
		privateKey:   priv,
		publicKeyHex: hex.EncodeToString(priv.PubKey().SerializeUncompressed()),
		modelKeyHex:  modelKeyHex,
		modelPubKey:  pub,
		model:        model,
		nonceHex:     hex.EncodeToString(nonce),
		timestamp:    now.Unix(),
	}, nil
}

// parseUncompressedSecp256k1 parses a 130-hex-character uncompressed
// secp256k1 public key.
func parseUncompressedSecp256k1(pubKeyHex string) (*secp256k1.PublicKey, error) {
	if len(pubKeyHex) != 130 || pubKeyHex[:2] != "04" {
		return nil, errors.New("must be 130 hex characters starting with 04 (uncompressed)")
	}
	b, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("not valid hex: %w", err)
	}
	pub, err := secp256k1.ParsePubKey(b)
	if err != nil {
		return nil, fmt.Errorf("not a valid secp256k1 point: %w", err)
	}
	return pub, nil
}

// Headers returns the five E2EE v2 request headers (spec §3.1).
func (s *ACIv2Session) Headers() map[string]string {
	return map[string]string{
		"X-E2EE-Version":   ACIv2Version,
		"X-Client-Pub-Key": s.publicKeyHex,
		"X-Model-Pub-Key":  s.modelKeyHex,
		"X-E2EE-Nonce":     s.nonceHex,
		"X-E2EE-Timestamp": strconv.FormatInt(s.timestamp, 10),
	}
}

// DecryptedFields returns the number of response fields that the session
// decrypted.
func (s *ACIv2Session) DecryptedFields() int { return s.decrypted }

// aciv2AADInput holds the members of one E2EE v2 associated data object.
// responseID is nil for a request field.
type aciv2AADInput struct {
	purpose, algo, model, field, nonce string
	ts                                 int64
	responseID                         *string
}

// aciv2AAD returns the RFC 8785 JCS associated data of one field (spec §6).
func aciv2AAD(in *aciv2AADInput) ([]byte, error) {
	m := map[string]any{
		"purpose": in.purpose,
		"algo":    in.algo,
		"model":   in.model,
		"field":   in.field,
		"nonce":   in.nonce,
		"ts":      in.ts,
	}
	if in.responseID != nil {
		m["id"] = *in.responseID
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal E2EE v2 AAD: %w", err)
	}
	return jsoncanonicalizer.Transform(raw)
}

// EncryptRequestField encrypts plaintext for the request field path field
// (for example "messages.0.content") to the attested model key.
func (s *ACIv2Session) EncryptRequestField(field string, plaintext []byte) (string, error) {
	aad, err := s.aad(aciv2RequestPurpose, field, nil)
	if err != nil {
		return "", err
	}
	return sealACIv2(plaintext, s.modelPubKey, aad)
}

// sealACIv2 encrypts plaintext with a fresh ephemeral key and AES-GCM nonce.
func sealACIv2(plaintext []byte, recipient *secp256k1.PublicKey, aad []byte) (string, error) {
	ephemeral, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return "", fmt.Errorf("generate ephemeral key: %w", err)
	}
	defer ephemeral.Zero()
	key := deriveKeySecp256k1(ephemeral, recipient, aciv2HKDFInfo)
	defer clear(key)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := aesgcmSealAAD(key, nonce, plaintext, aad)
	wire := make([]byte, 0, 65+12+len(ciphertext))
	wire = append(wire, ephemeral.PubKey().SerializeUncompressed()...)
	wire = append(wire, nonce...)
	wire = append(wire, ciphertext...)
	return hex.EncodeToString(wire), nil
}

// openACIv2 decrypts one hex field value with the recipient private key.
func openACIv2(ciphertextHex string, priv *secp256k1.PrivateKey, aad []byte) ([]byte, error) {
	raw, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	if len(raw) < 65+12+16 {
		return nil, fmt.Errorf("ciphertext too short: %d bytes (minimum 93)", len(raw))
	}
	ephemeral, err := secp256k1.ParsePubKey(raw[:65])
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}
	key := deriveKeySecp256k1(priv, ephemeral, aciv2HKDFInfo)
	defer clear(key)
	plaintext, err := aesgcmOpenAAD(key, raw[65:77], raw[77:], aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// aciv2ResponseField reports the delta fields that E2EE v2 encrypts in a chat
// stream (spec §5). A delta may carry "role" in plaintext; every other field
// with a value is not covered by E2EE v2 and fails the chunk.
func aciv2ResponseField(key string) bool {
	switch key {
	case EncFieldContent, EncFieldReasoning, EncFieldReasoningContent:
		return true
	}
	return false
}

// DecryptChunk decrypts, in place, every encrypted field of one chat
// completion SSE chunk. It fails closed when a content field is not
// encrypted, when a field does not decrypt under its field path and the
// request context, when the chunk carries content that E2EE v2 does not
// encrypt (a non-stream "message" or "text", logprobs, tool calls, refusals
// or audio), when it carries more than one choice, or when its response id
// differs from the id of the first chunk with a choice.
//
// The decryption shows that the content is confidential, not who encrypted
// it: the gateway encrypts each field to the client key with a fresh
// ephemeral key, and the associated data is public, so a relay can encrypt
// fields of its own. Only the signed ACI receipt authenticates the
// response, and teep does not verify it.
func (s *ACIv2Session) DecryptChunk(full map[string]json.RawMessage) error {
	responseID := ""
	if raw, ok := full["id"]; ok && !IsJSONNull(raw) {
		if err := json.Unmarshal(raw, &responseID); err != nil {
			return fmt.Errorf("%w: E2EE v2 response id is not a string", ErrDecryptionFailed)
		}
	}
	choicesRaw, ok := full["choices"]
	if !ok || IsJSONNull(choicesRaw) {
		return nil
	}
	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(choicesRaw, &choices); err != nil {
		return fmt.Errorf("%w: parse choices array: %w", ErrDecryptionFailed, err)
	}
	if len(choices) == 0 {
		return nil
	}
	// teep sends n=1; the reassembled response reads only one choice.
	if len(choices) > 1 {
		return fmt.Errorf("%w: E2EE v2 chunk carries %d choices, want 1", ErrDecryptionFailed, len(choices))
	}
	if s.responseID == nil {
		s.responseID = &responseID
	} else if *s.responseID != responseID {
		return fmt.Errorf("%w: E2EE v2 chunk response id %q differs from the stream's id %q", ErrDecryptionFailed, responseID, *s.responseID)
	}
	for pos, choice := range choices {
		if err := s.decryptChoice(choice, pos, responseID); err != nil {
			return err
		}
	}
	out, err := json.Marshal(choices)
	if err != nil {
		return fmt.Errorf("marshal decrypted choices: %w", err)
	}
	full["choices"] = out
	return nil
}

// isEmptyJSONValue reports whether raw is "", [] or {}: a value that carries
// no content.
func isEmptyJSONValue(raw json.RawMessage) bool {
	switch string(raw) {
	case `""`, "[]", "{}":
		return true
	}
	return false
}

// IsEncryptedChunk reports whether val has the E2EE v2 field wire format.
func (s *ACIv2Session) IsEncryptedChunk(val string) bool { return IsEncryptedChunkVenice(val) }

// Decrypt fails: an E2EE v2 field decrypts only with its field path and
// response id, which DecryptChunk supplies. A relay path that reaches this
// method does not know E2EE v2 and must not pass the field through.
func (s *ACIv2Session) Decrypt(string) ([]byte, error) {
	return nil, errors.New("E2EE v2 fields decrypt only through DecryptChunk")
}

// IsResponseFieldEncrypted reports the chat stream fields that E2EE v2
// encrypts. E2EE v2 in teep is defined only for chat completions.
func (s *ACIv2Session) IsResponseFieldEncrypted(fieldPath string, endpoint EndpointType) bool {
	return endpoint == EndpointChat && aciv2ResponseField(fieldPath)
}

// Zero clears the session private key.
func (s *ACIv2Session) Zero() {
	if s.privateKey != nil {
		s.privateKey.Zero()
		s.privateKey = nil
	}
}

// aad returns the JCS associated data of one field of this session.
func (s *ACIv2Session) aad(purpose, field string, responseID *string) ([]byte, error) {
	return aciv2AAD(&aciv2AADInput{
		purpose: purpose, algo: ACIv2Algo, model: s.model, field: field,
		nonce: s.nonceHex, ts: s.timestamp, responseID: responseID,
	})
}

// decryptResponseField decrypts one response field. The AAD binds the field
// path, the response id and the request context of the session.
func (s *ACIv2Session) decryptResponseField(ciphertextHex, responseID, field string) ([]byte, error) {
	if s.privateKey == nil {
		return nil, errors.New("E2EE v2 session key was zeroed")
	}
	aad, err := s.aad(aciv2ResponsePurpose, field, &responseID)
	if err != nil {
		return nil, err
	}
	return openACIv2(ciphertextHex, s.privateKey, aad)
}

// decryptChoice decrypts the delta of one streaming choice. The field path
// index is the choice's "index" member when present and its array position
// otherwise (spec §5).
func (s *ACIv2Session) decryptChoice(choice map[string]json.RawMessage, pos int, responseID string) error {
	if choice == nil {
		return fmt.Errorf("%w: choices.%d is not an object", ErrDecryptionFailed, pos)
	}
	index := pos
	if raw, ok := choice["index"]; ok {
		if IsJSONNull(raw) {
			return fmt.Errorf("%w: choices.%d.index is null", ErrDecryptionFailed, pos)
		}
		if err := json.Unmarshal(raw, &index); err != nil || index < 0 {
			return fmt.Errorf("%w: choices.%d.index is not a non-negative integer", ErrDecryptionFailed, pos)
		}
	}
	for _, key := range []string{"message", "text", "logprobs"} {
		if raw, ok := choice[key]; ok && !IsJSONNull(raw) {
			return fmt.Errorf("%w: choices.%d.%s is not encrypted by E2EE v2", ErrDecryptionFailed, index, key)
		}
	}
	deltaRaw, ok := choice["delta"]
	if !ok || IsJSONNull(deltaRaw) {
		return nil
	}
	var delta map[string]json.RawMessage
	if err := json.Unmarshal(deltaRaw, &delta); err != nil {
		return fmt.Errorf("%w: choices.%d.delta is not an object", ErrDecryptionFailed, index)
	}
	for key, raw := range delta {
		if key == "role" || IsJSONNull(raw) || isEmptyJSONValue(raw) {
			continue
		}
		if !aciv2ResponseField(key) {
			return fmt.Errorf("%w: choices.%d.delta.%s is not encrypted by E2EE v2", ErrDecryptionFailed, index, key)
		}
		field := fmt.Sprintf("choices.%d.delta.%s", index, key)
		var ciphertext string
		if err := json.Unmarshal(raw, &ciphertext); err != nil {
			return fmt.Errorf("%w: %s: expected encrypted string, got %s", ErrDecryptionFailed, field, rawTypeDescription(raw))
		}
		if !IsEncryptedChunkVenice(ciphertext) {
			return fmt.Errorf("%w: %s: expected encrypted string but not recognised", ErrDecryptionFailed, field)
		}
		plaintext, err := s.decryptResponseField(ciphertext, responseID, field)
		if err != nil {
			return fmt.Errorf("%w: decrypt %s: %w", ErrDecryptionFailed, field, err)
		}
		delta[key], _ = json.Marshal(string(plaintext)) //nolint:errchkjson // strings always marshal
		s.decrypted++
	}
	out, err := json.Marshal(delta)
	if err != nil {
		return fmt.Errorf("marshal decrypted delta: %w", err)
	}
	choice["delta"] = out
	return nil
}
