// Package e2ee provides end-to-end encryption primitives and relay functions
// for all TEE provider protocols. Each provider uses a different E2EE scheme:
//
//   - Venice:    secp256k1 ECDH + AES-256-GCM
//   - NearCloud: Ed25519/X25519 ECDH + XChaCha20-Poly1305
//   - Chutes:    ML-KEM-768 + ChaCha20-Poly1305
//
// Dependency flow: attestation → e2ee → provider → proxy → cmd
package e2ee

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Session holds ephemeral key material for one E2EE request/response cycle.
// Create with NewVeniceSession, NewNearCloudSession, or NewChutesSession.
// Set the model key with the appropriate setter, then use Encrypt/Decrypt
// methods. Call Zero when done.
type Session struct {
	// --- Venice (secp256k1 ECDH + AES-256-GCM) fields ---
	PrivateKey   *secp256k1.PrivateKey
	PublicKeyHex string // 130 hex chars, uncompressed, starts with "04"
	ModelKeyHex  string // model's public key from attestation
	modelPubKey  *secp256k1.PublicKey

	// --- NearCloud (Ed25519/X25519 + XChaCha20-Poly1305) fields ---
	// Ed25519PubHex is the client's Ed25519 public key (64 hex chars),
	// sent in the X-Client-Pub-Key header.
	Ed25519PubHex string
	// ModelEd25519Hex is the model's Ed25519 public key (64 hex chars),
	// used internally for key derivation.
	ModelEd25519Hex string
	// x25519Priv is the client's X25519 private key (derived from Ed25519
	// seed) used for decrypting incoming response chunks.
	x25519Priv *ecdh.PrivateKey
	// modelX25519 is the model's X25519 public key (converted from its
	// Ed25519 public key) used for encrypting outgoing messages.
	modelX25519 *ecdh.PublicKey

	// --- Chutes (ML-KEM-768 + ChaCha20-Poly1305) fields ---
	// mlkemDecapKey is the client's ephemeral ML-KEM-768 decapsulation key
	// (private key), used to decapsulate the response shared secret.
	mlkemDecapKey *mlkem.DecapsulationKey768
	// mlkemEncapKey is the client's ephemeral ML-KEM-768 encapsulation key
	// (public key), embedded in the encrypted request payload.
	mlkemEncapKey *mlkem.EncapsulationKey768
	// modelMLKEMPub is the instance's ML-KEM-768 public key from attestation.
	modelMLKEMPub *mlkem.EncapsulationKey768
	// RequestCiphertext is the KEM ciphertext from request encapsulation,
	// used as HKDF salt (first 16 bytes) for key derivation.
	RequestCiphertext []byte

	// ChuteID is the chute identifier for X-Chute-Id header (Chutes).
	ChuteID string
	// InstanceID is the selected instance for X-Instance-Id header (Chutes).
	InstanceID string
	// E2ENonce is the single-use nonce token for X-E2E-Nonce header (Chutes).
	E2ENonce string
	// Stream indicates whether this is a streaming request.
	Stream bool
	// ChatPath is the API path for the chat endpoint (Chutes X-E2E-Path header).
	ChatPath string
}

// NewVeniceSession generates a fresh ephemeral secp256k1 key pair for Venice E2EE.
func NewVeniceSession() (*Session, error) {
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

// NewNearCloudSession generates a fresh Ed25519 key pair and derives the X25519
// private key for NearCloud E2EE (Ed25519/XChaCha20-Poly1305).
func NewNearCloudSession() (*Session, error) {
	return newNearCloudSession()
}

// NewChutesSession generates a fresh ephemeral ML-KEM-768 key pair for Chutes E2EE.
func NewChutesSession() (*Session, error) {
	decapKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("generate ml-kem-768 key: %w", err)
	}
	return &Session{
		mlkemDecapKey: decapKey,
		mlkemEncapKey: decapKey.EncapsulationKey(),
	}, nil
}

// SetModelKey parses and validates the enclave's secp256k1 public key from the
// attestation response (Venice). The key must be 130 hex chars, start with
// "04" (uncompressed), and be a valid point on the secp256k1 curve.
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
	s.ModelKeyHex = pubKeyHex
	s.modelPubKey = pub
	return nil
}

// SetModelKeyEd25519 parses and validates the model's Ed25519 public key (64 hex
// chars) and converts it to an X25519 public key for NearCloud E2EE encryption.
func (s *Session) SetModelKeyEd25519(ed25519PubHex string) error {
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

// SetModelKeyMLKEM parses a base64-encoded ML-KEM-768 public key (1184 bytes)
// from the attestation response and stores it for request encryption (Chutes).
func (s *Session) SetModelKeyMLKEM(pubKeyBase64 string) error {
	b, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return fmt.Errorf("ml-kem-768 public key invalid base64: %w", err)
	}
	if len(b) != mlkem.EncapsulationKeySize768 {
		return fmt.Errorf("ml-kem-768 public key wrong size: %d bytes, want %d", len(b), mlkem.EncapsulationKeySize768)
	}
	pub, err := mlkem.NewEncapsulationKey768(b)
	if err != nil {
		return fmt.Errorf("ml-kem-768 public key invalid: %w", err)
	}
	s.modelMLKEMPub = pub
	return nil
}

// ModelPubKey returns the parsed secp256k1 public key set by SetModelKey.
func (s *Session) ModelPubKey() *secp256k1.PublicKey {
	return s.modelPubKey
}

// ModelX25519Pub returns the model's X25519 public key set by SetModelKeyEd25519.
func (s *Session) ModelX25519Pub() *ecdh.PublicKey {
	return s.modelX25519
}

// X25519Priv returns the client's X25519 private key for NearCloud decryption.
func (s *Session) X25519Priv() *ecdh.PrivateKey {
	return s.x25519Priv
}

// MLKEMClientPubKeyBase64 returns the client's ephemeral ML-KEM-768 public
// key as base64, for embedding in the encrypted request payload.
func (s *Session) MLKEMClientPubKeyBase64() string {
	return base64.StdEncoding.EncodeToString(s.mlkemEncapKey.Bytes())
}

// Decrypt decrypts a hex-encoded ciphertext using the session's key material.
// Dispatches based on which key type is present: x25519 → NearCloud,
// secp256k1 → Venice. Chutes sessions use DecryptStreamInitChutes/
// DecryptStreamChunkChutes/DecryptResponseBlobChutes directly.
func (s *Session) Decrypt(ciphertextHex string) ([]byte, error) {
	if s.x25519Priv != nil {
		return DecryptXChaCha20(ciphertextHex, s.x25519Priv)
	}
	if s.PrivateKey != nil {
		return DecryptVenice(ciphertextHex, s.PrivateKey)
	}
	return nil, errors.New("session has no decryption key (Chutes sessions use DecryptStreamInitChutes)")
}

// IsEncryptedChunk returns true if s looks like an encrypted chunk for this
// session's protocol.
func (s *Session) IsEncryptedChunk(val string) bool {
	if s.x25519Priv != nil {
		return IsEncryptedChunkXChaCha20(val)
	}
	return IsEncryptedChunkVenice(val)
}

// Zero clears private key bytes from memory. This is best-effort under the
// current Go runtime — the GC may have already copied the key material.
// TODO: migrate to runtime/secret (Go proposal #57001) when available.
func (s *Session) Zero() {
	if s.PrivateKey != nil {
		s.PrivateKey.Zero()
		s.PrivateKey = nil
	}
	// NearCloud keys: ecdh.PrivateKey has no Zero method; nil the reference
	// so the GC can collect the key material.
	s.x25519Priv = nil
	s.modelX25519 = nil
	// Chutes keys: nil references so the GC can collect.
	s.mlkemDecapKey = nil
	s.mlkemEncapKey = nil
	s.modelMLKEMPub = nil
	s.RequestCiphertext = nil
}
