package e2ee

import (
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
	x25519Pub, err := ed25519PubToX25519(edPubBytes)
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
func (s *NearCloudSession) Zero() {
	s.x25519Priv = nil
	s.modelX25519 = nil
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

	key, err := deriveKeyEd25519(shared)
	if err != nil {
		return "", fmt.Errorf("derive key: %w", err)
	}

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

	key, err := deriveKeyEd25519(shared)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

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

// EncryptChatMessagesNearCloud creates a NearCloud E2EE session, encrypts each
// message's content, and forces stream=true. The signingKey is the model's
// Ed25519 public key (64 hex chars) from the attestation response.
func EncryptChatMessagesNearCloud(body []byte, signingKey string) ([]byte, *NearCloudSession, error) {
	session, err := NewNearCloudSession()
	if err != nil {
		return nil, nil, fmt.Errorf("create NearCloud E2EE session: %w", err)
	}
	if err := session.SetModelKeyEd25519(signingKey); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("set model key ed25519: %w", err)
	}

	// Minimal parse: only extract messages for encryption, preserve all other fields.
	var full map[string]json.RawMessage
	if err := json.Unmarshal(body, &full); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("parse body for NearCloud E2EE: %w", err)
	}

	var messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(full["messages"], &messages); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("parse messages for NearCloud E2EE: %w", err)
	}

	type encMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	enc := make([]encMsg, len(messages))
	for i, msg := range messages {
		ct, encErr := EncryptXChaCha20([]byte(msg.Content), session.ModelX25519Pub())
		if encErr != nil {
			session.Zero()
			return nil, nil, fmt.Errorf("encrypt NearCloud message %d: %w", i, encErr)
		}
		enc[i] = encMsg{Role: msg.Role, Content: ct}
	}

	messagesJSON, err := json.Marshal(enc)
	if err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("marshal NearCloud encrypted messages: %w", err)
	}
	full["messages"] = messagesJSON
	full["stream"] = json.RawMessage("true")

	out, err := json.Marshal(full)
	if err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("marshal NearCloud E2EE body: %w", err)
	}
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
	_, err = ed25519PubToX25519(b)
	if err != nil {
		return fmt.Errorf("not a valid ed25519 point: %w", err)
	}
	return nil
}

// deriveKeyEd25519 derives a 32-byte encryption key from a shared secret using
// HKDF-SHA256 with info="ed25519_encryption" and no salt.
func deriveKeyEd25519(sharedSecret []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, sharedSecret, nil, []byte(hkdfInfoEd25519))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}
	return key, nil
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

// ed25519PubToX25519 converts an Ed25519 public key (32 bytes) to an X25519
// public key using the birational map from the Edwards to Montgomery form:
// u = (1 + y) / (1 - y) mod p.
func ed25519PubToX25519(edPub []byte) (*ecdh.PublicKey, error) {
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
