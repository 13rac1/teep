package e2ee

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// ---- Chutes (ML-KEM-768 / ChaCha20-Poly1305) tests -------------------------

// TestNewChutesSession verifies NewChutesSession produces a valid session with
// ML-KEM-768 keys.
func TestNewChutesSession(t *testing.T) {
	s, err := NewChutesSession()
	if err != nil {
		t.Fatalf("NewChutesSession: %v", err)
	}
	if s.mlkemDecapKey == nil {
		t.Fatal("mlkemDecapKey is nil")
	}
	if s.mlkemEncapKey == nil {
		t.Fatal("mlkemEncapKey is nil")
	}

	// Verify the encapsulation key is the expected size.
	pubBytes := s.mlkemEncapKey.Bytes()
	t.Logf("ML-KEM-768 encapsulation key: %d bytes", len(pubBytes))
	if len(pubBytes) != mlkem.EncapsulationKeySize768 {
		t.Errorf("encapsulation key size = %d, want %d", len(pubBytes), mlkem.EncapsulationKeySize768)
	}

	// Verify MLKEMClientPubKeyBase64 produces valid base64.
	b64 := s.MLKEMClientPubKeyBase64()
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("MLKEMClientPubKeyBase64 is not valid base64: %v", err)
	}
	if len(decoded) != mlkem.EncapsulationKeySize768 {
		t.Errorf("decoded base64 key size = %d, want %d", len(decoded), mlkem.EncapsulationKeySize768)
	}
}

// TestSetModelKeyMLKEM validates parsing of a base64-encoded ML-KEM-768 public key.
func TestSetModelKeyMLKEM(t *testing.T) {
	// Generate a real ML-KEM-768 key pair to get a valid public key.
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768: %v", err)
	}
	validPub := base64.StdEncoding.EncodeToString(dk.EncapsulationKey().Bytes())

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid key", validPub, false},
		{"invalid base64", "not-base64!!!", true},
		{"wrong size", base64.StdEncoding.EncodeToString(make([]byte, 100)), true},
		{"empty", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Session{}
			err := s.SetModelKeyMLKEM(tc.input)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tc.wantErr && s.modelMLKEMPub == nil {
				t.Error("modelMLKEMPub is nil after successful SetModelKeyMLKEM")
			}
		})
	}
}

// TestChutesEncryptDecrypt verifies the full Chutes encrypt/decrypt round-trip:
// gzip + ChaCha20-Poly1305 with HKDF-derived key.
func TestChutesEncryptDecrypt(t *testing.T) {
	// Generate a key pair and do KEM encapsulation to get a shared secret.
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768: %v", err)
	}
	sharedSecret, ciphertext := dk.EncapsulationKey().Encapsulate()

	// Derive a key.
	key, err := deriveKeyMLKEM(sharedSecret, ciphertext, hkdfInfoChutesReq)
	if err != nil {
		t.Fatalf("deriveKeyMLKEM: %v", err)
	}
	t.Logf("derived key: %s", hex.EncodeToString(key))

	// Encrypt and decrypt.
	plaintext := []byte(`{"model":"test","messages":[{"role":"user","content":"hello"}]}`)
	encrypted, err := encryptPayloadChaCha20(plaintext, key)
	if err != nil {
		t.Fatalf("encryptPayloadChaCha20: %v", err)
	}
	t.Logf("encrypted payload: %d bytes (plaintext: %d bytes)", len(encrypted), len(plaintext))

	decrypted, err := DecryptPayloadChaCha20(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptPayloadChaCha20: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

// TestChutesEncryptDecryptWrongKey verifies that decryption with the wrong key fails.
func TestChutesEncryptDecryptWrongKey(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768: %v", err)
	}
	sharedSecret, ciphertext := dk.EncapsulationKey().Encapsulate()

	key, err := deriveKeyMLKEM(sharedSecret, ciphertext, hkdfInfoChutesReq)
	if err != nil {
		t.Fatalf("deriveKeyMLKEM: %v", err)
	}

	plaintext := []byte("secret message")
	encrypted, err := encryptPayloadChaCha20(plaintext, key)
	if err != nil {
		t.Fatalf("encryptPayloadChaCha20: %v", err)
	}

	// Derive a different key.
	wrongKey, err := deriveKeyMLKEM(sharedSecret, ciphertext, hkdfInfoChutesResp)
	if err != nil {
		t.Fatalf("deriveKeyMLKEM (wrong): %v", err)
	}

	_, err = DecryptPayloadChaCha20(encrypted, wrongKey)
	if err == nil {
		t.Fatal("DecryptPayloadChaCha20 with wrong key must return error")
	}
	t.Logf("wrong key correctly returned: %v", err)
}

// TestDeriveKeyMLKEM validates HKDF-SHA256 key derivation with salt=ciphertext[:16].
func TestDeriveKeyMLKEM(t *testing.T) {
	sharedSecret := make([]byte, 32)
	copy(sharedSecret, "test shared secret v3")

	ciphertext := make([]byte, 1088) // ML-KEM-768 ciphertext size
	copy(ciphertext, "test ciphertext salt")

	reqKey, err := deriveKeyMLKEM(sharedSecret, ciphertext, hkdfInfoChutesReq)
	if err != nil {
		t.Fatalf("deriveKeyMLKEM (req): %v", err)
	}

	respKey, err := deriveKeyMLKEM(sharedSecret, ciphertext, hkdfInfoChutesResp)
	if err != nil {
		t.Fatalf("deriveKeyMLKEM (resp): %v", err)
	}

	streamKey, err := deriveKeyMLKEM(sharedSecret, ciphertext, hkdfInfoChutesStream)
	if err != nil {
		t.Fatalf("deriveKeyMLKEM (stream): %v", err)
	}

	t.Logf("req    key: %s", hex.EncodeToString(reqKey))
	t.Logf("resp   key: %s", hex.EncodeToString(respKey))
	t.Logf("stream key: %s", hex.EncodeToString(streamKey))

	// All three must be different.
	if bytes.Equal(reqKey, respKey) {
		t.Error("req and resp keys must differ")
	}
	if bytes.Equal(reqKey, streamKey) {
		t.Error("req and stream keys must differ")
	}
	if bytes.Equal(respKey, streamKey) {
		t.Error("resp and stream keys must differ")
	}

	// Keys must be 32 bytes.
	for name, key := range map[string][]byte{"req": reqKey, "resp": respKey, "stream": streamKey} {
		if len(key) != 32 {
			t.Errorf("%s key length = %d, want 32", name, len(key))
		}
	}
}

// TestDeriveKeyMLKEMShortCiphertext verifies that a ciphertext shorter than 16
// bytes returns an error.
func TestDeriveKeyMLKEMShortCiphertext(t *testing.T) {
	_, err := deriveKeyMLKEM(make([]byte, 32), make([]byte, 10), hkdfInfoChutesReq)
	if err == nil {
		t.Fatal("deriveKeyMLKEM with short ciphertext must return error")
	}
	t.Logf("short ciphertext correctly returned: %v", err)
}

// TestDecryptStreamChutes verifies the stream init + chunk decrypt round-trip.
func TestDecryptStreamChutes(t *testing.T) {
	// Generate client key pair.
	clientDK, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768 (client): %v", err)
	}
	clientSession := &Session{
		mlkemDecapKey: clientDK,
		mlkemEncapKey: clientDK.EncapsulationKey(),
	}

	// Simulate server-side: encapsulate with client's public key.
	sharedSecret, kemCiphertext := clientSession.mlkemEncapKey.Encapsulate()

	// Derive the stream key (server-side).
	streamKey, err := deriveKeyMLKEM(sharedSecret, kemCiphertext, hkdfInfoChutesStream)
	if err != nil {
		t.Fatalf("deriveKeyMLKEM (server): %v", err)
	}

	// Client-side: decrypt stream init to get the stream key.
	kemCTBase64 := base64.StdEncoding.EncodeToString(kemCiphertext)
	clientStreamKey, err := clientSession.DecryptStreamInitChutes(kemCTBase64)
	if err != nil {
		t.Fatalf("DecryptStreamInitChutes: %v", err)
	}

	if !bytes.Equal(streamKey, clientStreamKey) {
		t.Fatal("server and client stream keys differ")
	}
	t.Logf("stream key: %s", hex.EncodeToString(clientStreamKey))

	// Encrypt a chunk server-side with the stream key.
	chunk := []byte(`{"choices":[{"delta":{"content":"hello"}}]}`)
	encrypted, err := encryptStreamChunkChutes(chunk, streamKey)
	if err != nil {
		t.Fatalf("encryptStreamChunkChutes: %v", err)
	}

	// Decrypt client-side.
	decrypted, err := DecryptStreamChunkChutes(encrypted, clientStreamKey)
	if err != nil {
		t.Fatalf("DecryptStreamChunkChutes: %v", err)
	}
	if !bytes.Equal(decrypted, chunk) {
		t.Errorf("stream chunk round-trip: got %q, want %q", decrypted, chunk)
	}
}

// encryptStreamChunkChutes is a test helper that encrypts a stream chunk with
// ChaCha20-Poly1305 (no gzip — stream chunks are not compressed).
func encryptStreamChunkChutes(plaintext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	wire := make([]byte, 0, len(nonce)+len(ct))
	wire = append(wire, nonce...)
	wire = append(wire, ct...)
	return wire, nil
}

// TestEncryptChatRequestChutes tests the high-level Chutes encryption function.
func TestEncryptChatRequestChutes(t *testing.T) {
	// Generate a "model" key pair.
	modelDK, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768 (model): %v", err)
	}
	modelPubBase64 := base64.StdEncoding.EncodeToString(modelDK.EncapsulationKey().Bytes())

	body := []byte(`{"model":"test","messages":[{"role":"user","content":"hello"}]}`)
	encrypted, session, err := EncryptChatRequestChutes(body, modelPubBase64)
	if err != nil {
		t.Fatalf("EncryptChatRequestChutes: %v", err)
	}
	defer session.Zero()

	t.Logf("encrypted blob: %d bytes (KEM ct prefix + encrypted payload)", len(encrypted))

	if len(session.RequestCiphertext) != mlkem.CiphertextSize768 {
		t.Errorf("RequestCiphertext size = %d, want %d", len(session.RequestCiphertext), mlkem.CiphertextSize768)
	}

	// Verify blob starts with KEM ciphertext.
	if len(encrypted) < mlkem.CiphertextSize768 {
		t.Fatalf("blob too short for KEM ciphertext prefix: %d bytes", len(encrypted))
	}
	kemCT := encrypted[:mlkem.CiphertextSize768]
	encPayload := encrypted[mlkem.CiphertextSize768:]

	// Decrypt server-side: decapsulate KEM ciphertext, derive request key, decrypt payload.
	sharedSecret, err := modelDK.Decapsulate(kemCT)
	if err != nil {
		t.Fatalf("server decapsulate: %v", err)
	}
	requestKey, err := deriveKeyMLKEM(sharedSecret, kemCT, hkdfInfoChutesReq)
	if err != nil {
		t.Fatalf("server deriveKeyMLKEM: %v", err)
	}
	plaintext, err := DecryptPayloadChaCha20(encPayload, requestKey)
	if err != nil {
		t.Fatalf("server DecryptPayloadChaCha20: %v", err)
	}

	t.Logf("decrypted payload: %s", plaintext)

	// Verify the decrypted payload contains the original fields plus e2e_response_pk.
	var decryptedBody map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &decryptedBody); err != nil {
		t.Fatalf("unmarshal decrypted body: %v", err)
	}
	if _, ok := decryptedBody["e2e_response_pk"]; !ok {
		t.Error("decrypted body missing e2e_response_pk")
	}
	if _, ok := decryptedBody["model"]; !ok {
		t.Error("decrypted body missing model field")
	}
	if _, ok := decryptedBody["messages"]; !ok {
		t.Error("decrypted body missing messages field")
	}

	// Verify the embedded client public key is valid.
	var clientPubB64 string
	if err := json.Unmarshal(decryptedBody["e2e_response_pk"], &clientPubB64); err != nil {
		t.Fatalf("unmarshal client pubkey: %v", err)
	}
	clientPubBytes, err := base64.StdEncoding.DecodeString(clientPubB64)
	if err != nil {
		t.Fatalf("decode client pubkey: %v", err)
	}
	if len(clientPubBytes) != mlkem.EncapsulationKeySize768 {
		t.Errorf("client pubkey size = %d, want %d", len(clientPubBytes), mlkem.EncapsulationKeySize768)
	}
}

// TestChutesSessionZero verifies Zero clears Chutes key material.
func TestChutesSessionZero(t *testing.T) {
	s, err := NewChutesSession()
	if err != nil {
		t.Fatalf("NewChutesSession: %v", err)
	}
	s.Zero()
	if s.mlkemDecapKey != nil {
		t.Error("mlkemDecapKey should be nil after Zero")
	}
	if s.mlkemEncapKey != nil {
		t.Error("mlkemEncapKey should be nil after Zero")
	}
	if s.modelMLKEMPub != nil {
		t.Error("modelMLKEMPub should be nil after Zero")
	}
	if s.RequestCiphertext != nil {
		t.Error("RequestCiphertext should be nil after Zero")
	}
}

// TestDecryptPayloadChaCha20TooShort verifies DecryptPayloadChaCha20 returns an
// error on payloads shorter than nonce + tag.
func TestDecryptPayloadChaCha20TooShort(t *testing.T) {
	key := make([]byte, 32)
	_, err := DecryptPayloadChaCha20(make([]byte, 10), key)
	if err == nil {
		t.Fatal("DecryptPayloadChaCha20 with short payload must return error")
	}
	t.Logf("short payload correctly returned: %v", err)
}

// TestDecryptStreamChunkChutesTooShort verifies DecryptStreamChunkChutes returns
// an error on chunks shorter than nonce + tag.
func TestDecryptStreamChunkChutesTooShort(t *testing.T) {
	key := make([]byte, 32)
	_, err := DecryptStreamChunkChutes(make([]byte, 5), key)
	if err == nil {
		t.Fatal("DecryptStreamChunkChutes with short chunk must return error")
	}
	t.Logf("short chunk correctly returned: %v", err)
}
