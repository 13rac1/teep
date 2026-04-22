package e2ee

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/hkdf"
)

// VeniceSession holds ephemeral secp256k1 key material for one Venice E2EE
// request/response cycle.
type VeniceSession struct {
	privateKey   *secp256k1.PrivateKey
	publicKeyHex string // 130 hex chars, uncompressed, starts with "04"
	modelKeyHex  string // model's public key from attestation
	modelPubKey  *secp256k1.PublicKey
}

// NewVeniceSession generates a fresh ephemeral secp256k1 key pair for Venice E2EE.
func NewVeniceSession() (*VeniceSession, error) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	pub := priv.PubKey()
	return &VeniceSession{
		privateKey:   priv,
		publicKeyHex: hex.EncodeToString(pub.SerializeUncompressed()),
	}, nil
}

// ClientPubKey returns the session's ephemeral secp256k1 public key.
// Used by tests that simulate server-side encryption. Panics after Zero().
func (s *VeniceSession) ClientPubKey() *secp256k1.PublicKey { return s.privateKey.PubKey() }

// ClientPubKeyHex returns the session's ephemeral public key as 130 hex chars.
func (s *VeniceSession) ClientPubKeyHex() string { return s.publicKeyHex }

// ModelKeyHex returns the model's attested public key as 130 hex chars.
func (s *VeniceSession) ModelKeyHex() string { return s.modelKeyHex }

// SetModelKey parses and validates the enclave's secp256k1 public key from the
// attestation response. The key must be 130 hex chars, start with "04"
// (uncompressed), and be a valid point on the secp256k1 curve.
func (s *VeniceSession) SetModelKey(pubKeyHex string) error {
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
	s.modelKeyHex = pubKeyHex
	s.modelPubKey = pub
	return nil
}

// ModelPubKey returns the parsed secp256k1 public key set by SetModelKey.
func (s *VeniceSession) ModelPubKey() *secp256k1.PublicKey {
	return s.modelPubKey
}

// IsEncryptedChunk returns true if val looks like a Venice E2EE encrypted chunk.
func (s *VeniceSession) IsEncryptedChunk(val string) bool {
	return IsEncryptedChunkVenice(val)
}

// Decrypt decrypts a hex-encoded Venice ciphertext using the session's private key.
func (s *VeniceSession) Decrypt(ciphertextHex string) ([]byte, error) {
	return DecryptVenice(ciphertextHex, s.privateKey)
}

// Zero clears private key bytes from memory.
func (s *VeniceSession) Zero() {
	if s.privateKey != nil {
		s.privateKey.Zero()
		s.privateKey = nil
	}
}

// hkdfInfoVenice is the HKDF info string required by the Venice E2EE protocol.
// Do not change — this value must match the TEE server implementation.
const hkdfInfoVenice = "ecdsa_encryption"

// EncryptVenice encrypts plaintext for the model's public key using per-message
// ephemeral ECDH + HKDF-SHA256 + AES-256-GCM.
//
// Wire format (hex-encoded):
//
//	ephemeral_pub_uncompressed (65 bytes) || nonce (12 bytes) || ciphertext+tag
//
// HKDF is used without salt per the Venice protocol. info="ecdsa_encryption".
func EncryptVenice(plaintext []byte, recipientPubKey *secp256k1.PublicKey) (string, error) {
	ephemeralPriv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return "", fmt.Errorf("generate ephemeral key: %w", err)
	}

	aesKey := deriveKeyVenice(ephemeralPriv, recipientPubKey)

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aesgcmSeal(aesKey, nonce, plaintext)

	ephemeralPub := ephemeralPriv.PubKey().SerializeUncompressed() // 65 bytes
	wire := make([]byte, 0, 65+12+len(ciphertext))
	wire = append(wire, ephemeralPub...)
	wire = append(wire, nonce...)
	wire = append(wire, ciphertext...)

	return hex.EncodeToString(wire), nil
}

// DecryptVenice decrypts a hex-encoded Venice E2EE ciphertext using the session's
// private key. Returns an error if decryption fails.
func DecryptVenice(ciphertextHex string, privateKey *secp256k1.PrivateKey) ([]byte, error) {
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

	aesKey := deriveKeyVenice(privateKey, ephemeralPub)

	plaintext, err := aesgcmOpen(aesKey, nonce, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// IsEncryptedChunkVenice returns true if s looks like a hex-encoded Venice E2EE
// payload. Minimum 186 hex chars (93 bytes: 65 ephemeral pub + 12 nonce + 16 tag),
// all hex characters, and starts with "04" (uncompressed EC point prefix).
func IsEncryptedChunkVenice(s string) bool {
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

// deriveKeyVenice performs ECDH and derives a 32-byte AES key via HKDF-SHA256.
// The ECDH shared secret is the x-coordinate of the shared point.
// HKDF uses no salt and info="ecdsa_encryption" per the Venice protocol.
func deriveKeyVenice(priv *secp256k1.PrivateKey, pub *secp256k1.PublicKey) []byte {
	var point, pubJacobian secp256k1.JacobianPoint
	pub.AsJacobian(&pubJacobian)
	secp256k1.ScalarMultNonConst(&priv.Key, &pubJacobian, &point)
	point.ToAffine()
	sharedSecret := point.X.Bytes()

	r := hkdf.New(sha256.New, sharedSecret[:], nil, []byte(hkdfInfoVenice))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		panic(fmt.Sprintf("BUG: hkdf expand: %v", err))
	}
	return key
}

// aesgcmSeal encrypts plaintext with AES-256-GCM using the given key and nonce.
func aesgcmSeal(key, nonce, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Sprintf("BUG: aes.NewCipher: %v", err))
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(fmt.Sprintf("BUG: cipher.NewGCM: %v", err))
	}
	return gcm.Seal(nil, nonce, plaintext, nil)
}

// aesgcmOpen decrypts ciphertext (with appended tag) using AES-256-GCM.
func aesgcmOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Sprintf("BUG: aes.NewCipher: %v", err))
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(fmt.Sprintf("BUG: cipher.NewGCM: %v", err))
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
