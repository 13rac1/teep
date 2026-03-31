// Package e2ee provides end-to-end encryption primitives and relay functions
// for all TEE provider protocols. Each provider uses a different E2EE scheme:
//
//   - Venice:    secp256k1 ECDH + AES-256-GCM
//   - NearCloud: Ed25519/X25519 ECDH + XChaCha20-Poly1305
//   - Chutes:    ML-KEM-768 + ChaCha20-Poly1305
//
// Dependency flow: attestation → e2ee → provider → proxy → cmd
package e2ee

// Decryptor is implemented by all E2EE session types. It provides the
// minimum surface that relay functions and the proxy need to decrypt
// response content and clean up key material.
type Decryptor interface {
	IsEncryptedChunk(val string) bool
	Decrypt(ciphertextHex string) ([]byte, error)
	Zero()
}

// ChutesE2EE carries the per-request state for the Chutes E2EE protocol:
// routing metadata (headers) and the crypto session (for relay decryption).
// It is returned by EncryptRequest and passed through the proxy to both
// PrepareRequest (for headers) and the relay functions (for decryption).
type ChutesE2EE struct {
	ChuteID    string         // X-Chute-Id header value (the model name)
	InstanceID string         // X-Instance-Id header value
	E2ENonce   string         // X-E2E-Nonce header value (single-use token)
	Session    *ChutesSession // ML-KEM session for relay decryption
}
