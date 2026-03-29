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

	aesKey, err := deriveKeyVenice(ephemeralPriv, recipientPubKey)
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

	aesKey, err := deriveKeyVenice(privateKey, ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

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
func deriveKeyVenice(priv *secp256k1.PrivateKey, pub *secp256k1.PublicKey) ([]byte, error) {
	var point, pubJacobian secp256k1.JacobianPoint
	pub.AsJacobian(&pubJacobian)
	secp256k1.ScalarMultNonConst(&priv.Key, &pubJacobian, &point)
	point.ToAffine()
	sharedSecret := point.X.Bytes()

	r := hkdf.New(sha256.New, sharedSecret[:], nil, []byte(hkdfInfoVenice))
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
