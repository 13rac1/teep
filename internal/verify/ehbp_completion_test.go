package verify

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
	"github.com/13rac1/teep/internal/e2ee"
	"golang.org/x/crypto/hkdf"
	"io"
	"net/http"
	"testing"
)

func TestStandaloneEHBPStreamCompletion(t *testing.T) {
	for _, mode := range []string{"complete", "truncated", "invalid_tag"} {
		t.Run(mode, func(t *testing.T) {
			private, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			session, err := e2ee.NewEHBPSession(private.PublicKey().Bytes())
			if err != nil {
				t.Fatal(err)
			}
			defer session.Zero()
			encap, err := hex.DecodeString(session.EncapKeyHex())
			if err != nil {
				t.Fatal(err)
			}
			body, nonce := encryptCompletionResponse(t, private, encap, [][]byte{[]byte("data: {}\n\ndata: [DONE]\n\n"), []byte("\n")})
			switch mode {
			case "truncated":
				body = append(body, 0, 0)
			case "invalid_tag":
				body[len(body)-1] ^= 1
			}
			resp := &http.Response{Header: http.Header{"Ehbp-Response-Nonce": {nonce}}, Body: io.NopCloser(bytes.NewReader(body))}
			result := verifyEHBPStreamResponse(resp, session)
			if (result.Err == nil) != (mode == "complete") {
				t.Fatalf("completion error: %v", result.Err)
			}
			if mode == "truncated" && !errors.Is(result.Err, io.ErrUnexpectedEOF) {
				t.Fatalf("lost truncation error: %v", result.Err)
			}
			if mode == "invalid_tag" && !errors.Is(result.Err, e2ee.ErrDecryptionFailed) {
				t.Fatalf("lost authentication error: %v", result.Err)
			}
		})
	}
}

// encryptCompletionResponse is a test helper simulating the server side:
// it derives response keys and encrypts a response body into EHBP chunk framing.
// Returns the encrypted body and the hex-encoded response nonce.
func encryptCompletionResponse(t *testing.T, privKey *ecdh.PrivateKey, encapKey []byte, chunks [][]byte) (encBody []byte, nonceHex string) {
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
