// Package attestation provides TEE attestation types, verification, and E2EE
// cryptographic primitives for the teep proxy.
package attestation

import (
	"crypto/aes"
	"crypto/cipher"
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
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// hkdfInfo is the HKDF info string required by the Venice E2EE protocol (v1 ECDSA).
// Do not change — this value must match the TEE server implementation.
const hkdfInfo = "ecdsa_encryption"

// hkdfInfoV2 is the HKDF info string for the v2 Ed25519/XChaCha20 E2EE protocol.
const hkdfInfoV2 = "ed25519_encryption"

// E2EE protocol version constants.
const (
	E2EEv1 = 1 // Legacy: secp256k1 ECDH + AES-256-GCM (Venice)
	E2EEv2 = 2 // Ed25519/X25519 ECDH + XChaCha20-Poly1305 (nearcloud)
)

// Session holds ephemeral key material for one E2EE request/response cycle.
// Create with NewSession (v1) or NewSessionV2 (v2), set the model key with
// SetModelKey/SetModelKeyV2, use Encrypt/EncryptV2 to encrypt outgoing
// messages, and call Zero when done.
type Session struct {
	// Version selects the E2EE protocol: E2EEv1 (legacy ECDSA) or E2EEv2
	// (Ed25519/XChaCha20-Poly1305). Controls dispatch in decrypt.go.
	Version int

	// --- V1 (legacy ECDSA) fields ---
	PrivateKey   *secp256k1.PrivateKey
	PublicKeyHex string // 130 hex chars, uncompressed, starts with "04"
	ModelKeyHex  string // model's public key from attestation
	modelPubKey  *secp256k1.PublicKey

	// --- V2 (Ed25519/X25519) fields ---
	// Ed25519PubHex is the client's Ed25519 public key (64 hex chars),
	// sent in the X-Client-Pub-Key header.
	Ed25519PubHex string
	// ModelEd25519Hex is the model's Ed25519 public key (64 hex chars),
	// sent in the X-Model-Pub-Key header.
	ModelEd25519Hex string
	// x25519Priv is the client's X25519 private key (derived from Ed25519
	// seed) used for decrypting incoming response chunks.
	x25519Priv *ecdh.PrivateKey
	// modelX25519 is the model's X25519 public key (converted from its
	// Ed25519 public key) used for encrypting outgoing messages.
	modelX25519 *ecdh.PublicKey
}

// NewSession generates a fresh ephemeral secp256k1 key pair (v1 ECDSA).
func NewSession() (*Session, error) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	pub := priv.PubKey()
	return &Session{
		Version:      E2EEv1,
		PrivateKey:   priv,
		PublicKeyHex: hex.EncodeToString(pub.SerializeUncompressed()),
	}, nil
}

// NewSessionV2 generates a fresh Ed25519 key pair and derives the X25519
// private key for v2 E2EE (Ed25519/XChaCha20-Poly1305). The Ed25519 public
// key is used in the X-Client-Pub-Key header; the X25519 private key is used
// to decrypt incoming response chunks.
func NewSessionV2() (*Session, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	// Derive X25519 private key from Ed25519 seed.
	x25519Priv, err := ed25519SeedToX25519(priv.Seed())
	if err != nil {
		return nil, fmt.Errorf("derive x25519 private key: %w", err)
	}

	return &Session{
		Version:       E2EEv2,
		Ed25519PubHex: hex.EncodeToString(pub),
		x25519Priv:    x25519Priv,
	}, nil
}

// SetModelKey parses and validates the enclave's public key from the
// attestation response (v1 ECDSA). The key must be 130 hex chars, start with
// "04" (uncompressed), represent a point on the secp256k1 curve, and not be
// the identity element.
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

// SetModelKeyV2 parses and validates the model's Ed25519 public key (64 hex
// chars) and converts it to an X25519 public key for v2 E2EE encryption.
func (s *Session) SetModelKeyV2(ed25519PubHex string) error {
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
	s.ModelEd25519Hex = ed25519PubHex
	s.modelX25519 = x25519Pub
	return nil
}

// ModelPubKey returns the parsed secp256k1 public key set by SetModelKey.
func (s *Session) ModelPubKey() *secp256k1.PublicKey {
	return s.modelPubKey
}

// ModelX25519Pub returns the model's X25519 public key set by SetModelKeyV2.
func (s *Session) ModelX25519Pub() *ecdh.PublicKey {
	return s.modelX25519
}

// X25519Priv returns the client's X25519 private key for v2 decryption.
func (s *Session) X25519Priv() *ecdh.PrivateKey {
	return s.x25519Priv
}

// Zero clears private key bytes from memory. This is best-effort under the
// current Go runtime — the GC may have already copied the key material.
// TODO: migrate to runtime/secret (Go proposal #57001) when available.
func (s *Session) Zero() {
	if s.PrivateKey != nil {
		s.PrivateKey.Zero()
		s.PrivateKey = nil
	}
	// V2 keys: ecdh.PrivateKey has no Zero method; nil the reference
	// so the GC can collect the key material.
	s.x25519Priv = nil
	s.modelX25519 = nil
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

// EncryptChatMessages creates a v1 ECDSA E2EE session, encrypts each message's
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

// EncryptChatMessagesV2 creates a v2 Ed25519/XChaCha20 E2EE session, encrypts
// each message's content, and forces stream=true. The signingKey is the model's
// Ed25519 public key (64 hex chars) from the attestation response.
func EncryptChatMessagesV2(body []byte, signingKey string) ([]byte, *Session, error) {
	session, err := NewSessionV2()
	if err != nil {
		return nil, nil, fmt.Errorf("create v2 E2EE session: %w", err)
	}
	if err := session.SetModelKeyV2(signingKey); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("set model key v2: %w", err)
	}

	// Minimal parse: only extract messages for encryption, preserve all other fields.
	var full map[string]json.RawMessage
	if err := json.Unmarshal(body, &full); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("parse body for E2EE v2: %w", err)
	}

	var messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(full["messages"], &messages); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("parse messages for E2EE v2: %w", err)
	}

	type encMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	enc := make([]encMsg, len(messages))
	for i, msg := range messages {
		ct, encErr := EncryptV2([]byte(msg.Content), session.ModelX25519Pub())
		if encErr != nil {
			session.Zero()
			return nil, nil, fmt.Errorf("encrypt v2 message %d: %w", i, encErr)
		}
		enc[i] = encMsg{Role: msg.Role, Content: ct}
	}

	messagesJSON, err := json.Marshal(enc)
	if err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("marshal v2 encrypted messages: %w", err)
	}
	full["messages"] = messagesJSON
	full["stream"] = json.RawMessage("true")

	out, err := json.Marshal(full)
	if err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("marshal v2 E2EE body: %w", err)
	}
	return out, session, nil
}

// ───────────────────────────────────────────────────────────────────────
// V2 E2EE: Ed25519/X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305
// ───────────────────────────────────────────────────────────────────────

// EncryptV2 encrypts plaintext for the recipient's X25519 public key using
// per-message ephemeral X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305.
//
// Wire format (hex-encoded):
//
//	ephemeral_x25519_pub (32 bytes) || nonce (24 bytes) || ciphertext+tag
//
// HKDF info = "ed25519_encryption", no salt. Matches the NEAR AI v2 protocol.
func EncryptV2(plaintext []byte, recipientX25519Pub *ecdh.PublicKey) (string, error) {
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ephemeral x25519 key: %w", err)
	}

	shared, err := ephPriv.ECDH(recipientX25519Pub)
	if err != nil {
		return "", fmt.Errorf("x25519 ecdh: %w", err)
	}

	key, err := deriveKeyV2(shared)
	if err != nil {
		return "", fmt.Errorf("derive v2 key: %w", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", fmt.Errorf("create xchacha20: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX) // 24 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate v2 nonce: %w", err)
	}

	ct := aead.Seal(nil, nonce, plaintext, nil)

	// Wire: ephemeral_pub(32) + nonce(24) + ciphertext+tag
	wire := make([]byte, 0, 32+24+len(ct))
	wire = append(wire, ephPriv.PublicKey().Bytes()...)
	wire = append(wire, nonce...)
	wire = append(wire, ct...)

	return hex.EncodeToString(wire), nil
}

// DecryptV2 decrypts a hex-encoded v2 E2EE ciphertext using the session's
// X25519 private key. Returns an error if decryption fails.
func DecryptV2(ciphertextHex string, x25519Priv *ecdh.PrivateKey) ([]byte, error) {
	raw, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, fmt.Errorf("decode v2 hex: %w", err)
	}

	// Minimum: 32 (ephemeral pub) + 24 (nonce) + 16 (poly1305 tag) = 72 bytes
	if len(raw) < 72 {
		return nil, fmt.Errorf("v2 ciphertext too short: %d bytes (minimum 72)", len(raw))
	}

	ephPubBytes := raw[:32]
	nonce := raw[32:56]
	ciphertext := raw[56:]

	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse v2 ephemeral public key: %w", err)
	}

	shared, err := x25519Priv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("v2 x25519 ecdh: %w", err)
	}

	key, err := deriveKeyV2(shared)
	if err != nil {
		return nil, fmt.Errorf("derive v2 key: %w", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create v2 xchacha20: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("v2 authentication failed")
	}
	return plaintext, nil
}

// IsEncryptedChunkV2 returns true if s looks like a hex-encoded v2 E2EE payload.
// Minimum 144 hex chars (72 bytes: 32 ephemeral pub + 24 nonce + 16 tag),
// and all characters are valid hex.
func IsEncryptedChunkV2(s string) bool {
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

// IsEncryptedChunkForSession returns true if s looks like an encrypted chunk
// for the given session's protocol version.
func IsEncryptedChunkForSession(s string, session *Session) bool {
	if session.Version == E2EEv2 {
		return IsEncryptedChunkV2(s)
	}
	return IsEncryptedChunk(s)
}

// DecryptForSession decrypts a ciphertext hex string using the appropriate
// protocol for the session version (v1 ECDSA or v2 Ed25519/XChaCha20).
func DecryptForSession(ciphertextHex string, session *Session) ([]byte, error) {
	if session.Version == E2EEv2 {
		return DecryptV2(ciphertextHex, session.X25519Priv())
	}
	return Decrypt(ciphertextHex, session.PrivateKey)
}

// deriveKeyV2 derives a 32-byte encryption key from a shared secret using
// HKDF-SHA256 with info="ed25519_encryption" and no salt.
func deriveKeyV2(sharedSecret []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, sharedSecret, nil, []byte(hkdfInfoV2))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf v2 expand: %w", err)
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

// ValidateModelKeyV2 checks if the given hex string is a valid Ed25519 public
// key suitable for v2 E2EE. Used by report.go for the e2ee_capable factor.
func ValidateModelKeyV2(ed25519PubHex string) error {
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
