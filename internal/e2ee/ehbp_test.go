package e2ee

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// ---- EHBP (HPKE X25519 / AES-256-GCM) tests --------------------------------

// serverDecryptRequest is a test helper simulating the server side:
// it performs HPKE SetupBaseR to decrypt multi-chunk EHBP request body.
func serverDecryptRequest(t *testing.T, privKey *ecdh.PrivateKey, encapKey []byte, body io.Reader) []byte {
	t.Helper()

	hpkePriv, err := hpke.NewDHKEMPrivateKey(privKey)
	if err != nil {
		t.Fatalf("server NewDHKEMPrivateKey: %v", err)
	}
	recipient, err := hpke.NewRecipient(encapKey, hpkePriv, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("ehbp request"))
	if err != nil {
		t.Fatalf("server NewRecipient: %v", err)
	}

	var result []byte
	for {
		var lenBuf [4]byte
		_, err := io.ReadFull(body, lenBuf[:])
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			t.Fatalf("server read chunk length: %v", err)
		}
		chunkLen := binary.BigEndian.Uint32(lenBuf[:])
		ciphertext := make([]byte, chunkLen)
		if _, err := io.ReadFull(body, ciphertext); err != nil {
			t.Fatalf("server read chunk ciphertext: %v", err)
		}
		plaintext, err := recipient.Open(nil, ciphertext)
		if err != nil {
			t.Fatalf("server Open: %v", err)
		}
		result = append(result, plaintext...)
	}
	return result
}

// serverEncryptResponse is a test helper simulating the server side:
// it derives response keys and encrypts a response body into EHBP chunk framing.
// Returns the encrypted body and the hex-encoded response nonce.
func serverEncryptResponse(t *testing.T, privKey *ecdh.PrivateKey, encapKey []byte, chunks [][]byte) (encBody []byte, nonceHex string) {
	t.Helper()

	hpkePriv, err := hpke.NewDHKEMPrivateKey(privKey)
	if err != nil {
		t.Fatalf("server NewDHKEMPrivateKey: %v", err)
	}
	recipient, err := hpke.NewRecipient(encapKey, hpkePriv, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("ehbp request"))
	if err != nil {
		t.Fatalf("server NewRecipient: %v", err)
	}

	// Generate response nonce.
	responseNonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, responseNonce); err != nil {
		t.Fatalf("generate response nonce: %v", err)
	}

	// Derive response AEAD key and nonce (same derivation as client).
	secret, err := recipient.Export("ehbp response", 32)
	if err != nil {
		t.Fatalf("server Export: %v", err)
	}

	salt := make([]byte, 0, len(encapKey)+len(responseNonce))
	salt = append(salt, encapKey...)
	salt = append(salt, responseNonce...)

	prk := hkdf.Extract(sha256.New, secret, salt)

	aeadKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("key")), aeadKey); err != nil {
		t.Fatalf("server HKDF expand key: %v", err)
	}
	aeadNonce := make([]byte, 12)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("nonce")), aeadNonce); err != nil {
		t.Fatalf("server HKDF expand nonce: %v", err)
	}

	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		t.Fatalf("server aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("server cipher.NewGCM: %v", err)
	}

	var buf bytes.Buffer
	for i, chunk := range chunks {
		nonce := make([]byte, 12)
		copy(nonce, aeadNonce)
		var counterBuf [8]byte
		binary.BigEndian.PutUint64(counterBuf[:], uint64(i))
		for j := range 8 {
			nonce[4+j] ^= counterBuf[j]
		}

		ct := gcm.Seal(nil, nonce, chunk, nil)
		if err := binary.Write(&buf, binary.BigEndian, uint32(len(ct))); err != nil {
			t.Fatalf("server write chunk length: %v", err)
		}
		buf.Write(ct)
	}

	return buf.Bytes(), hex.EncodeToString(responseNonce)
}

func generateX25519KeyPair(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	return priv
}

// TestEHBPRoundTrip verifies full encrypt request + decrypt response cycle.
func TestEHBPRoundTrip(t *testing.T) {
	priv := generateX25519KeyPair(t)
	pubBytes := priv.PublicKey().Bytes()

	session, err := NewEHBPSession(pubBytes)
	if err != nil {
		t.Fatalf("NewEHBPSession: %v", err)
	}
	defer session.Zero()

	// Encrypt request.
	requestBody := []byte(`{"model":"test","messages":[{"role":"user","content":"hello"}]}`)
	encReader := session.EncryptRequest(bytes.NewReader(requestBody))

	// Decode the encap key from session.
	encapKey := session.encapKey
	t.Logf("encap key: %d bytes", len(encapKey))

	// Server side: decrypt request.
	decryptedRequest := serverDecryptRequest(t, priv, encapKey, encReader)
	if !bytes.Equal(decryptedRequest, requestBody) {
		t.Fatalf("request round-trip failed:\n  got:  %q\n  want: %q", decryptedRequest, requestBody)
	}
	t.Logf("request decrypted successfully: %s", decryptedRequest)

	// Server side: encrypt response.
	responseChunks := [][]byte{
		[]byte(`data: {"choices":[{"delta":{"content":"Hello"}}]}`),
		[]byte(`data: {"choices":[{"delta":{"content":" world"}}]}`),
		[]byte(`data: [DONE]`),
	}
	encResponse, nonceHex := serverEncryptResponse(t, priv, encapKey, responseChunks)
	t.Logf("response nonce: %s", nonceHex)

	// Client side: decrypt response.
	rc, err := session.DecryptResponse(bytes.NewReader(encResponse), nonceHex)
	if err != nil {
		t.Fatalf("DecryptResponse: %v", err)
	}
	defer rc.Close()

	// Read all decrypted chunks.
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll decrypted response: %v", err)
	}

	want := bytes.Join(responseChunks, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("response round-trip failed:\n  got:  %q\n  want: %q", got, want)
	}
	t.Logf("response decrypted successfully: %s", got)
}

// TestEHBPSingleChunk verifies a response with exactly one chunk.
func TestEHBPSingleChunk(t *testing.T) {
	priv := generateX25519KeyPair(t)
	session, err := NewEHBPSession(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("NewEHBPSession: %v", err)
	}
	defer session.Zero()

	// Must call EncryptRequest first to advance the HPKE context.
	// EncryptRequest is streaming; drain it to advance the HPKE context.
	if _, err := io.ReadAll(session.EncryptRequest(bytes.NewReader([]byte(`{}`)))); err != nil {
		t.Fatalf("EncryptRequest drain: %v", err)
	}

	chunk := []byte(`{"result":"ok"}`)
	encResponse, nonceHex := serverEncryptResponse(t, priv, session.encapKey, [][]byte{chunk})

	rc, err := session.DecryptResponse(bytes.NewReader(encResponse), nonceHex)
	if err != nil {
		t.Fatalf("DecryptResponse: %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, chunk) {
		t.Fatalf("single chunk: got %q, want %q", got, chunk)
	}
}

// TestEHBPMultipleChunks verifies a response with many chunks.
func TestEHBPMultipleChunks(t *testing.T) {
	priv := generateX25519KeyPair(t)
	session, err := NewEHBPSession(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("NewEHBPSession: %v", err)
	}
	defer session.Zero()

	// EncryptRequest is streaming; drain it to advance the HPKE context.
	if _, err := io.ReadAll(session.EncryptRequest(bytes.NewReader([]byte(`{}`)))); err != nil {
		t.Fatalf("EncryptRequest drain: %v", err)
	}

	chunks := make([][]byte, 100)
	for i := range chunks {
		chunks[i] = []byte(strings.Repeat("x", i+1))
	}

	encResponse, nonceHex := serverEncryptResponse(t, priv, session.encapKey, chunks)
	rc, err := session.DecryptResponse(bytes.NewReader(encResponse), nonceHex)
	if err != nil {
		t.Fatalf("DecryptResponse: %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	want := bytes.Join(chunks, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("multiple chunks: got %d bytes, want %d bytes", len(got), len(want))
	}
}

// TestEHBPMultiChunkRequest verifies request encryption produces multiple
// chunks for bodies larger than ehbpChunkSize (8 KiB).
func TestEHBPMultiChunkRequest(t *testing.T) {
	priv := generateX25519KeyPair(t)
	session, err := NewEHBPSession(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("NewEHBPSession: %v", err)
	}
	defer session.Zero()

	// 3x chunk size to produce at least 3 chunks.
	requestBody := bytes.Repeat([]byte("A"), ehbpChunkSize*3)
	encReader := session.EncryptRequest(bytes.NewReader(requestBody))

	decrypted := serverDecryptRequest(t, priv, session.encapKey, encReader)
	if !bytes.Equal(decrypted, requestBody) {
		t.Fatalf("multi-chunk request: got %d bytes, want %d bytes", len(decrypted), len(requestBody))
	}
	t.Logf("multi-chunk request round-trip OK: %d bytes", len(decrypted))
}

// TestEHBPEmptyBody verifies encrypting an empty request body.
func TestEHBPEmptyBody(t *testing.T) {
	priv := generateX25519KeyPair(t)
	session, err := NewEHBPSession(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("NewEHBPSession: %v", err)
	}
	defer session.Zero()

	encReader := session.EncryptRequest(bytes.NewReader(nil))
	decrypted := serverDecryptRequest(t, priv, session.encapKey, encReader)
	if len(decrypted) != 0 {
		t.Fatalf("empty body: got %d bytes, want 0", len(decrypted))
	}
}

// TestEHBPOversizedChunkRejected verifies that a chunk length prefix > 16 MiB
// is rejected before allocation.
func TestEHBPOversizedChunkRejected(t *testing.T) {
	priv := generateX25519KeyPair(t)
	session, err := NewEHBPSession(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("NewEHBPSession: %v", err)
	}
	defer session.Zero()

	// EncryptRequest is streaming; drain it to advance the HPKE context.
	if _, err := io.ReadAll(session.EncryptRequest(bytes.NewReader([]byte(`{}`)))); err != nil {
		t.Fatalf("EncryptRequest drain: %v", err)
	}

	// Craft a fake response with an oversized length prefix.
	responseNonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, responseNonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}

	var buf bytes.Buffer
	// Write a length prefix of maxChunkSize + 1.
	if err := binary.Write(&buf, binary.BigEndian, uint32(maxChunkSize+1)); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	buf.Write(make([]byte, 100)) // dummy data, won't be read

	rc, err := session.DecryptResponse(&buf, hex.EncodeToString(responseNonce))
	if err != nil {
		t.Fatalf("DecryptResponse setup: %v", err)
	}
	defer rc.Close()

	_, err = io.ReadAll(rc)
	if err == nil {
		t.Fatal("expected error for oversized chunk, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("expected 'exceeds maximum' error, got: %v", err)
	}
	t.Logf("oversized chunk correctly rejected: %v", err)
}

// TestEHBPMissingResponseNonce verifies that an empty response nonce is rejected.
func TestEHBPMissingResponseNonce(t *testing.T) {
	priv := generateX25519KeyPair(t)
	session, err := NewEHBPSession(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("NewEHBPSession: %v", err)
	}
	defer session.Zero()

	// EncryptRequest is streaming; drain it to advance the HPKE context.
	if _, err := io.ReadAll(session.EncryptRequest(bytes.NewReader([]byte(`{}`)))); err != nil {
		t.Fatalf("EncryptRequest drain: %v", err)
	}

	_, err = session.DecryptResponse(bytes.NewReader(nil), "")
	if err == nil {
		t.Fatal("expected error for empty response nonce")
	}
	t.Logf("missing nonce correctly rejected: %v", err)
}

// TestEHBPInvalidResponseNonceHex verifies bad hex in response nonce.
func TestEHBPInvalidResponseNonceHex(t *testing.T) {
	priv := generateX25519KeyPair(t)
	session, err := NewEHBPSession(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("NewEHBPSession: %v", err)
	}
	defer session.Zero()

	// EncryptRequest is streaming; drain it to advance the HPKE context.
	if _, err := io.ReadAll(session.EncryptRequest(bytes.NewReader([]byte(`{}`)))); err != nil {
		t.Fatalf("EncryptRequest drain: %v", err)
	}

	_, err = session.DecryptResponse(bytes.NewReader(nil), "not-hex-at-all!!")
	if err == nil {
		t.Fatal("expected error for invalid hex nonce")
	}
	t.Logf("invalid hex nonce correctly rejected: %v", err)
}

// TestEHBPWrongSizeResponseNonce verifies nonce of wrong length is rejected.
func TestEHBPWrongSizeResponseNonce(t *testing.T) {
	priv := generateX25519KeyPair(t)
	session, err := NewEHBPSession(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("NewEHBPSession: %v", err)
	}
	defer session.Zero()

	// EncryptRequest is streaming; drain it to advance the HPKE context.
	if _, err := io.ReadAll(session.EncryptRequest(bytes.NewReader([]byte(`{}`)))); err != nil {
		t.Fatalf("EncryptRequest drain: %v", err)
	}

	// 16 bytes instead of 32.
	shortNonce := hex.EncodeToString(make([]byte, 16))
	_, err = session.DecryptResponse(bytes.NewReader(nil), shortNonce)
	if err == nil {
		t.Fatal("expected error for wrong-size nonce")
	}
	if !strings.Contains(err.Error(), "wrong size") {
		t.Fatalf("expected 'wrong size' error, got: %v", err)
	}
	t.Logf("wrong-size nonce correctly rejected: %v", err)
}

// TestEHBPCorruptedCiphertext verifies AEAD auth failure on corrupted data.
func TestEHBPCorruptedCiphertext(t *testing.T) {
	priv := generateX25519KeyPair(t)
	session, err := NewEHBPSession(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("NewEHBPSession: %v", err)
	}
	defer session.Zero()

	// EncryptRequest is streaming; drain it to advance the HPKE context.
	if _, err := io.ReadAll(session.EncryptRequest(bytes.NewReader([]byte(`{}`)))); err != nil {
		t.Fatalf("EncryptRequest drain: %v", err)
	}

	// Build a valid response then corrupt the ciphertext.
	chunks := [][]byte{[]byte("hello")}
	encResponse, nonceHex := serverEncryptResponse(t, priv, session.encapKey, chunks)

	// Corrupt a byte in the ciphertext (after the 4-byte length prefix).
	if len(encResponse) > 5 {
		encResponse[5] ^= 0xff
	}

	rc, err := session.DecryptResponse(bytes.NewReader(encResponse), nonceHex)
	if err != nil {
		t.Fatalf("DecryptResponse setup: %v", err)
	}
	defer rc.Close()

	_, err = io.ReadAll(rc)
	if err == nil {
		t.Fatal("expected AEAD auth failure on corrupted ciphertext")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected 'authentication failed' error, got: %v", err)
	}
	t.Logf("corrupted ciphertext correctly rejected: %v", err)
}

// TestEHBPTruncatedChunk verifies error on a chunk that is shorter than declared.
func TestEHBPTruncatedChunk(t *testing.T) {
	priv := generateX25519KeyPair(t)
	session, err := NewEHBPSession(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("NewEHBPSession: %v", err)
	}
	defer session.Zero()

	// EncryptRequest is streaming; drain it to advance the HPKE context.
	if _, err := io.ReadAll(session.EncryptRequest(bytes.NewReader([]byte(`{}`)))); err != nil {
		t.Fatalf("EncryptRequest drain: %v", err)
	}

	responseNonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, responseNonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}

	// Write a length prefix claiming 1000 bytes but only provide 10.
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(1000)); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	buf.Write(make([]byte, 10))

	rc, err := session.DecryptResponse(&buf, hex.EncodeToString(responseNonce))
	if err != nil {
		t.Fatalf("DecryptResponse setup: %v", err)
	}
	defer rc.Close()

	_, err = io.ReadAll(rc)
	if err == nil {
		t.Fatal("expected error for truncated chunk")
	}
	t.Logf("truncated chunk correctly rejected: %v", err)
}

// TestEHBPNonceXORCounter verifies the nonce XOR counter logic produces
// distinct nonces for different chunk indices.
func TestEHBPNonceXORCounter(t *testing.T) {
	baseNonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		t.Fatalf("generate base nonce: %v", err)
	}

	seen := make(map[string]uint64)
	for i := range uint64(1000) {
		nonce := make([]byte, 12)
		copy(nonce, baseNonce)
		var counterBuf [8]byte
		binary.BigEndian.PutUint64(counterBuf[:], i)
		for j := range 8 {
			nonce[4+j] ^= counterBuf[j]
		}
		key := string(nonce)
		if prev, exists := seen[key]; exists {
			t.Fatalf("nonce collision: chunk %d and %d produce same nonce", prev, i)
		}
		seen[key] = i
	}
}

// TestEHBPChunkIndexOverflow verifies that reaching 2^31-1 chunk index fails closed.
func TestEHBPChunkIndexOverflow(t *testing.T) {
	// Set chunkIdx to exactly maxChunkIdx — the >= check should reject.
	r := &ehbpResponseReader{
		body:      bytes.NewReader(nil),
		baseNonce: make([]byte, 12),
		chunkIdx:  maxChunkIdx,
	}

	p := make([]byte, 100)
	_, err := r.Read(p)
	if err == nil {
		t.Fatal("expected error for chunk index overflow")
	}
	if !strings.Contains(err.Error(), "chunk index overflow") {
		t.Fatalf("expected 'chunk index overflow' error, got: %v", err)
	}
	t.Logf("chunk index overflow correctly rejected: %v", err)
}

// TestEHBPZeroLengthChunk verifies that a zero-length chunk is rejected by
// AEAD (no authentication tag present in empty ciphertext).
func TestEHBPZeroLengthChunk(t *testing.T) {
	priv := generateX25519KeyPair(t)
	session, err := NewEHBPSession(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("NewEHBPSession: %v", err)
	}
	defer session.Zero()

	// EncryptRequest is streaming; drain it to advance the HPKE context.
	if _, err := io.ReadAll(session.EncryptRequest(bytes.NewReader([]byte(`{}`)))); err != nil {
		t.Fatalf("EncryptRequest drain: %v", err)
	}

	responseNonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, responseNonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}

	// Write a chunk with length prefix 0.
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(0)); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}

	rc, err := session.DecryptResponse(&buf, hex.EncodeToString(responseNonce))
	if err != nil {
		t.Fatalf("DecryptResponse setup: %v", err)
	}
	defer rc.Close()

	_, err = io.ReadAll(rc)
	if err == nil {
		t.Fatal("expected AEAD error for zero-length chunk")
	}
	t.Logf("zero-length chunk correctly rejected: %v", err)
}

// TestEHBPEncapKeyHex verifies EncapKeyHex returns valid lowercase hex
// of the 32-byte encapsulated key (64 hex chars).
func TestEHBPEncapKeyHex(t *testing.T) {
	priv := generateX25519KeyPair(t)
	session, err := NewEHBPSession(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("NewEHBPSession: %v", err)
	}
	defer session.Zero()

	h := session.EncapKeyHex()
	if h == "" {
		t.Fatal("EncapKeyHex returned empty string")
	}
	if len(h) != 64 {
		t.Errorf("EncapKeyHex length = %d, want 64", len(h))
	}
	if _, err := hex.DecodeString(h); err != nil {
		t.Errorf("EncapKeyHex not valid hex: %v", err)
	}
	t.Logf("encap key hex: %s", h)
}

// TestEHBPNewSessionBadKey verifies NewEHBPSession rejects invalid public keys.
func TestEHBPNewSessionBadKey(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"empty", nil},
		{"too short", make([]byte, 16)},
		{"too long", make([]byte, 64)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEHBPSession(tc.key)
			if err == nil {
				t.Fatal("expected error for invalid public key")
			}
			t.Logf("invalid key correctly rejected: %v", err)
		})
	}
}

// TestEHBPZero verifies Zero clears key material.
func TestEHBPZero(t *testing.T) {
	priv := generateX25519KeyPair(t)
	session, err := NewEHBPSession(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("NewEHBPSession: %v", err)
	}
	session.Zero()
	if session.encapKey != nil {
		t.Error("encapKey should be nil after Zero")
	}
	if session.senderCtx != nil {
		t.Error("senderCtx should be nil after Zero")
	}
}

// TestEHBPEmptyResponse verifies that an empty response body returns EOF.
func TestEHBPEmptyResponse(t *testing.T) {
	priv := generateX25519KeyPair(t)
	session, err := NewEHBPSession(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("NewEHBPSession: %v", err)
	}
	defer session.Zero()

	// EncryptRequest is streaming; drain it to advance the HPKE context.
	if _, err := io.ReadAll(session.EncryptRequest(bytes.NewReader([]byte(`{}`)))); err != nil {
		t.Fatalf("EncryptRequest drain: %v", err)
	}

	responseNonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, responseNonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}

	rc, err := session.DecryptResponse(bytes.NewReader(nil), hex.EncodeToString(responseNonce))
	if err != nil {
		t.Fatalf("DecryptResponse: %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty response, got %d bytes", len(got))
	}
}
