package proxy

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
	"testing"

	"golang.org/x/crypto/hkdf"
)

func decryptAuthorizedTestRequest(t *testing.T, privKey *ecdh.PrivateKey, encapKey []byte, body io.Reader) []byte {
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
		if chunkLen > 1<<20 {
			t.Fatal("EHBP test frame exceeds limit")
		}
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

// encryptAuthorizedTestResponse is a test helper simulating the server side:
// it derives response keys and encrypts a response body into EHBP chunk framing.
// Returns the encrypted body and the hex-encoded response nonce.
func encryptAuthorizedTestResponse(t *testing.T, privKey *ecdh.PrivateKey, encapKey []byte, chunks [][]byte) (encBody []byte, nonceHex string) {
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
	defer clear(secret)
	if err != nil {
		t.Fatalf("server Export: %v", err)
	}

	salt := make([]byte, 0, len(encapKey)+len(responseNonce))
	salt = append(salt, encapKey...)
	salt = append(salt, responseNonce...)

	prk := hkdf.Extract(sha256.New, secret, salt)
	defer clear(prk)

	aeadKey := make([]byte, 32)
	defer clear(aeadKey)
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

func authorizedTestKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	return priv
}
