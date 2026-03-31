package e2ee

import (
	"bytes"
	"compress/gzip"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// ChutesSession holds ephemeral ML-KEM-768 key material for one Chutes E2EE
// request/response cycle.
type ChutesSession struct {
	mlkemDecapKey *mlkem.DecapsulationKey768
	mlkemEncapKey *mlkem.EncapsulationKey768
	modelMLKEMPub *mlkem.EncapsulationKey768
	// RequestCiphertext is the KEM ciphertext from request encapsulation,
	// used as HKDF salt (first 16 bytes) for key derivation.
	RequestCiphertext []byte
}

// NewChutesSession generates a fresh ephemeral ML-KEM-768 key pair for Chutes E2EE.
func NewChutesSession() (*ChutesSession, error) {
	decapKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("generate ml-kem-768 key: %w", err)
	}
	return &ChutesSession{
		mlkemDecapKey: decapKey,
		mlkemEncapKey: decapKey.EncapsulationKey(),
	}, nil
}

// SetModelKeyMLKEM parses a base64-encoded ML-KEM-768 public key (1184 bytes)
// from the attestation response and stores it for request encryption.
func (s *ChutesSession) SetModelKeyMLKEM(pubKeyBase64 string) error {
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

// MLKEMClientPubKeyBase64 returns the client's ephemeral ML-KEM-768 public
// key as base64, for embedding in the encrypted request payload.
func (s *ChutesSession) MLKEMClientPubKeyBase64() string {
	return base64.StdEncoding.EncodeToString(s.mlkemEncapKey.Bytes())
}

// Zero nils key references so the GC can collect the key material.
func (s *ChutesSession) Zero() {
	s.mlkemDecapKey = nil
	s.mlkemEncapKey = nil
	s.modelMLKEMPub = nil
	s.RequestCiphertext = nil
}

// HKDF info strings for the Chutes E2EE protocol.
const (
	hkdfInfoChutesReq    = "e2e-req-v1"
	hkdfInfoChutesResp   = "e2e-resp-v1"
	hkdfInfoChutesStream = "e2e-stream-v1"
)

// EncryptChatRequestChutes creates a Chutes ML-KEM-768 E2EE session, encrypts
// the entire JSON request body as a binary blob, and returns the encrypted payload.
// The modelPubKeyBase64 is the instance's ML-KEM-768 public key from attestation.
// The client's ephemeral public key is embedded in the JSON before encryption
// so the instance can encapsulate the response shared secret.
func EncryptChatRequestChutes(body []byte, modelPubKeyBase64 string) ([]byte, *ChutesSession, error) {
	session, err := NewChutesSession()
	if err != nil {
		return nil, nil, fmt.Errorf("create Chutes E2EE session: %w", err)
	}
	if err := session.SetModelKeyMLKEM(modelPubKeyBase64); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("set model key ml-kem: %w", err)
	}

	// KEM encapsulate with the model's public key.
	sharedSecret, kemCiphertext := session.modelMLKEMPub.Encapsulate()
	session.RequestCiphertext = kemCiphertext

	// Derive request encryption key.
	requestKey, err := deriveKeyMLKEM(sharedSecret, kemCiphertext, hkdfInfoChutesReq)
	if err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("derive Chutes request key: %w", err)
	}

	// Embed the client's ephemeral public key in the request body.
	var full map[string]json.RawMessage
	if err := json.Unmarshal(body, &full); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("parse body for Chutes E2EE: %w", err)
	}
	clientPubJSON, err := json.Marshal(session.MLKEMClientPubKeyBase64())
	if err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("marshal Chutes client pubkey: %w", err)
	}
	full["e2e_response_pk"] = clientPubJSON

	enrichedBody, err := json.Marshal(full)
	if err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("marshal Chutes enriched body: %w", err)
	}

	// Gzip + ChaCha20-Poly1305 encrypt.
	encrypted, err := encryptPayloadChaCha20(enrichedBody, requestKey)
	if err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("encrypt Chutes payload: %w", err)
	}

	// Wire format: mlkem_ct(1088) + nonce(12) + ciphertext + tag(16)
	blob := make([]byte, 0, len(kemCiphertext)+len(encrypted))
	blob = append(blob, kemCiphertext...)
	blob = append(blob, encrypted...)
	return blob, session, nil
}

// decryptPayloadChaCha20 decrypts a ChaCha20-Poly1305 encrypted payload and gunzips.
// Wire format: nonce (12 bytes) || ciphertext || tag (16 bytes).
func decryptPayloadChaCha20(encrypted, key []byte) ([]byte, error) {
	nonceSize := chacha20poly1305.NonceSize
	// Minimum: nonce(12) + tag(16) = 28 bytes
	if len(encrypted) < nonceSize+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("encrypted payload too short: %d bytes", len(encrypted))
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("create chacha20: %w", err)
	}

	nonce := encrypted[:nonceSize]
	ct := encrypted[nonceSize:]

	compressed, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("authentication failed")
	}

	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	plaintext, err := io.ReadAll(io.LimitReader(gz, 10<<20)) // 10 MiB max decompressed
	if err != nil {
		return nil, fmt.Errorf("gzip decompress: %w", err)
	}
	return plaintext, nil
}

// DecryptStreamInitChutes decapsulates a KEM ciphertext using the client's
// decapsulation key and derives the stream key via HKDF.
func (s *ChutesSession) DecryptStreamInitChutes(kemCiphertextBase64 string) ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(kemCiphertextBase64)
	if err != nil {
		return nil, fmt.Errorf("stream init: invalid base64: %w", err)
	}
	if len(ct) != mlkem.CiphertextSize768 {
		return nil, fmt.Errorf("stream init: ciphertext wrong size: %d bytes, want %d", len(ct), mlkem.CiphertextSize768)
	}
	sharedSecret, err := s.mlkemDecapKey.Decapsulate(ct)
	if err != nil {
		return nil, fmt.Errorf("stream init: decapsulate: %w", err)
	}
	return deriveKeyMLKEM(sharedSecret, ct, hkdfInfoChutesStream)
}

// DecryptStreamChunkChutes decrypts a single stream chunk with ChaCha20-Poly1305.
// The chunk is NOT gzipped (unlike the request/response payload).
// Wire format: nonce (12 bytes) || ciphertext || tag (16 bytes).
func DecryptStreamChunkChutes(encrypted, streamKey []byte) ([]byte, error) {
	nonceSize := chacha20poly1305.NonceSize
	if len(encrypted) < nonceSize+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("stream chunk too short: %d bytes", len(encrypted))
	}

	aead, err := chacha20poly1305.New(streamKey)
	if err != nil {
		return nil, fmt.Errorf("stream chacha20: %w", err)
	}

	nonce := encrypted[:nonceSize]
	ct := encrypted[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("stream authentication failed")
	}
	return plaintext, nil
}

// DecryptResponseBlobChutes decrypts a non-streaming Chutes response blob.
// Wire format: mlkem_ct(1088) + nonce(12) + ciphertext + tag(16).
func (s *ChutesSession) DecryptResponseBlobChutes(blob []byte) ([]byte, error) {
	if len(blob) < mlkem.CiphertextSize768+chacha20poly1305.NonceSize+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("response blob too short: %d bytes", len(blob))
	}
	ct := blob[:mlkem.CiphertextSize768]
	encrypted := blob[mlkem.CiphertextSize768:]

	sharedSecret, err := s.mlkemDecapKey.Decapsulate(ct)
	if err != nil {
		return nil, fmt.Errorf("response: decapsulate: %w", err)
	}
	responseKey, err := deriveKeyMLKEM(sharedSecret, ct, hkdfInfoChutesResp)
	if err != nil {
		return nil, fmt.Errorf("response: derive key: %w", err)
	}
	return decryptPayloadChaCha20(encrypted, responseKey)
}

// deriveKeyMLKEM derives a 32-byte encryption key from a shared secret using
// HKDF-SHA256 with salt=ciphertext[:16] and the given info string.
func deriveKeyMLKEM(sharedSecret, ciphertext []byte, info string) ([]byte, error) {
	if len(ciphertext) < 16 {
		return nil, fmt.Errorf("ciphertext too short for salt: %d bytes", len(ciphertext))
	}
	salt := ciphertext[:16]
	r := hkdf.New(sha256.New, sharedSecret, salt, []byte(info))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}
	return key, nil
}

// encryptPayloadChaCha20 gzips plaintext and encrypts it with ChaCha20-Poly1305.
// Wire format: nonce (12 bytes) || ciphertext || tag (16 bytes).
func encryptPayloadChaCha20(plaintext, key []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(plaintext); err != nil {
		return nil, fmt.Errorf("gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("gzip close: %w", err)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("create chacha20: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSize) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ct := aead.Seal(nil, nonce, buf.Bytes(), nil)

	// Wire: nonce(12) + ciphertext+tag
	wire := make([]byte, 0, len(nonce)+len(ct))
	wire = append(wire, nonce...)
	wire = append(wire, ct...)
	return wire, nil
}
