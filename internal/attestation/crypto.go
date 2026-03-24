// Package attestation provides TEE attestation types, verification, and E2EE
// cryptographic primitives for the teep proxy.
package attestation

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/hkdf"
)

// hkdfInfo is the HKDF info string required by the Venice E2EE protocol.
// Do not change — this value must match the TEE server implementation.
const hkdfInfo = "ecdsa_encryption"

// Session holds ephemeral key material for one E2EE request/response cycle.
// Create with NewSession, set the model key with SetModelKey, use Encrypt
// to encrypt outgoing messages, Decrypt to decrypt incoming response chunks,
// and call Zero when done.
type Session struct {
	PrivateKey   *secp256k1.PrivateKey
	PublicKeyHex string // 130 hex chars, uncompressed, starts with "04"
	ModelKeyHex  string // model's public key from attestation
	modelPubKey  *secp256k1.PublicKey
}

// NewSession generates a fresh ephemeral secp256k1 key pair.
func NewSession() (*Session, error) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	pub := priv.PubKey()
	return &Session{
		PrivateKey:   priv,
		PublicKeyHex: hex.EncodeToString(pub.SerializeUncompressed()),
	}, nil
}

// SetModelKey parses and validates the enclave's public key from the
// attestation response. The key must be 130 hex chars, start with "04"
// (uncompressed), represent a point on the secp256k1 curve, and not be the
// identity element.
func (s *Session) SetModelKey(pubKeyHex string) error {
	if len(pubKeyHex) != 130 {
		return fmt.Errorf("enclave public key must be 130 hex chars, got %d", len(pubKeyHex))
	}
	if pubKeyHex[:2] != "04" {
		return fmt.Errorf("enclave public key must start with '04' (uncompressed), got %q", pubKeyHex[:2])
	}
	b, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return fmt.Errorf("enclave public key is not valid hex: %w", err)
	}
	pub, err := secp256k1.ParsePubKey(b)
	if err != nil {
		return fmt.Errorf("enclave public key is not a valid secp256k1 point: %w", err)
	}
	// ParsePubKey already validates the point is on the curve and not the
	// identity element. We store both representations for later use.
	s.ModelKeyHex = pubKeyHex
	s.modelPubKey = pub
	return nil
}

// ModelPubKey returns the parsed secp256k1 public key set by SetModelKey.
func (s *Session) ModelPubKey() *secp256k1.PublicKey {
	return s.modelPubKey
}

// Zero clears private key bytes from memory. This is best-effort under the
// current Go runtime — the GC may have already copied the key material.
// TODO: migrate to runtime/secret (Go proposal #57001) when available.
func (s *Session) Zero() {
	if s.PrivateKey == nil {
		return
	}
	s.PrivateKey.Zero()
	s.PrivateKey = nil
}

// Encrypt encrypts plaintext for the model's public key using per-message
// ephemeral ECDH + HKDF-SHA256 + AES-256-GCM.
//
// Wire format (hex-encoded):
//
//	ephemeral_pub_uncompressed (65 bytes) || nonce (12 bytes) || ciphertext+tag
//
// HKDF is used without salt per the Venice protocol. info="ecdsa_encryption".
// This is a known limitation — see docs/planning/FUTURE.md for details.
func Encrypt(plaintext []byte, recipientPubKey *secp256k1.PublicKey) (string, error) {
	ephemeralPriv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return "", fmt.Errorf("generate ephemeral key: %w", err)
	}

	aesKey, err := deriveKey(ephemeralPriv, recipientPubKey)
	if err != nil {
		return "", fmt.Errorf("derive key: %w", err)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext, err := aesgcmSeal(aesKey, nonce, plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}

	ephemeralPub := ephemeralPriv.PubKey().SerializeUncompressed() // 65 bytes
	wire := make([]byte, 0, 65+12+len(ciphertext))
	wire = append(wire, ephemeralPub...)
	wire = append(wire, nonce...)
	wire = append(wire, ciphertext...)

	return hex.EncodeToString(wire), nil
}

// Decrypt decrypts a hex-encoded E2EE ciphertext using the session's private
// key. Returns an error if decryption fails. Callers must not fall through to
// plaintext on error.
func Decrypt(ciphertextHex string, privateKey *secp256k1.PrivateKey) ([]byte, error) {
	raw, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}

	// Minimum: 65 (ephemeral pub) + 12 (nonce) + 16 (AES-GCM tag) = 93 bytes
	if len(raw) < 93 {
		return nil, fmt.Errorf("ciphertext too short: %d bytes (minimum 93)", len(raw))
	}

	ephemeralPubBytes := raw[:65]
	nonce := raw[65:77]
	ciphertext := raw[77:]

	ephemeralPub, err := secp256k1.ParsePubKey(ephemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}

	aesKey, err := deriveKey(privateKey, ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	plaintext, err := aesgcmOpen(aesKey, nonce, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// IsEncryptedChunk returns true if s looks like a hex-encoded E2EE payload.
// Minimum 186 hex chars (93 bytes: 65 ephemeral pub + 12 nonce + 16 tag),
// all hex characters, and starts with "04" (uncompressed EC point prefix).
func IsEncryptedChunk(s string) bool {
	if len(s) < 186 {
		return false
	}
	if s[:2] != "04" {
		return false
	}
	for _, c := range s {
		if !isHexRune(c) {
			return false
		}
	}
	return true
}

// deriveKey performs ECDH and derives a 32-byte AES key via HKDF-SHA256.
// The ECDH shared secret is the x-coordinate of the shared point.
// HKDF uses no salt and info="ecdsa_encryption" per the Venice protocol.
func deriveKey(priv *secp256k1.PrivateKey, pub *secp256k1.PublicKey) ([]byte, error) {
	// ECDH: scalar multiplication, take x-coordinate as shared secret.
	var point, pubJacobian secp256k1.JacobianPoint
	pub.AsJacobian(&pubJacobian)
	secp256k1.ScalarMultNonConst(&priv.Key, &pubJacobian, &point)
	point.ToAffine()
	sharedSecret := point.X.Bytes() // [32]byte

	// HKDF-SHA256 with no salt, info="ecdsa_encryption", 32 bytes output.
	r := hkdf.New(sha256.New, sharedSecret[:], nil, []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}
	return key, nil
}

// aesgcmSeal encrypts plaintext with AES-256-GCM using the given key and nonce.
func aesgcmSeal(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

// aesgcmOpen decrypts ciphertext (with appended tag) using AES-256-GCM.
func aesgcmOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("authentication failed")
	}
	return plaintext, nil
}

// isHexRune reports whether c is a valid lowercase or uppercase hex digit.
func isHexRune(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// EncryptChatMessages creates an E2EE session, encrypts each message's
// content in body for the model's signing key, and forces stream=true
// (required for per-chunk decryption). Returns the rewritten body and
// session, or an error. Callers must call session.Zero() when done.
func EncryptChatMessages(body []byte, signingKey string) ([]byte, *Session, error) {
	session, err := NewSession()
	if err != nil {
		return nil, nil, fmt.Errorf("create E2EE session: %w", err)
	}
	if err := session.SetModelKey(signingKey); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("set model key: %w", err)
	}

	// Minimal parse: only extract messages for encryption, preserve all other fields.
	var full map[string]json.RawMessage
	if err := json.Unmarshal(body, &full); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("parse body for E2EE: %w", err)
	}

	var messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(full["messages"], &messages); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("parse messages for E2EE: %w", err)
	}

	type encMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	enc := make([]encMsg, len(messages))
	for i, msg := range messages {
		ct, encErr := Encrypt([]byte(msg.Content), session.ModelPubKey())
		if encErr != nil {
			session.Zero()
			return nil, nil, fmt.Errorf("encrypt message %d: %w", i, encErr)
		}
		enc[i] = encMsg{Role: msg.Role, Content: ct}
	}

	messagesJSON, err := json.Marshal(enc)
	if err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("marshal encrypted messages: %w", err)
	}
	full["messages"] = messagesJSON
	full["stream"] = json.RawMessage("true")

	out, err := json.Marshal(full)
	if err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("marshal E2EE body: %w", err)
	}
	return out, session, nil
}
