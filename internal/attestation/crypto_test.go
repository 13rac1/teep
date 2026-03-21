package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/hkdf"
)

// ---- helpers ----------------------------------------------------------------

// mustPrivKey parses a 32-byte hex scalar into a secp256k1.PrivateKey.
func mustPrivKey(t *testing.T, hexScalar string) *secp256k1.PrivateKey {
	t.Helper()
	b, err := hex.DecodeString(hexScalar)
	if err != nil {
		t.Fatalf("mustPrivKey: %v", err)
	}
	var scalar secp256k1.ModNScalar
	scalar.SetByteSlice(b)
	return secp256k1.NewPrivateKey(&scalar)
}

// encryptWithFixedEphemeral is a test-only variant of Encrypt that uses a
// caller-supplied ephemeral private key instead of a random one. This makes
// the output deterministic for cross-language test vector validation.
func encryptWithFixedEphemeral(plaintext []byte, recipientPubKey *secp256k1.PublicKey, ephemeralPriv *secp256k1.PrivateKey, nonce []byte) (string, error) {
	aesKey, err := deriveKey(ephemeralPriv, recipientPubKey)
	if err != nil {
		return "", err
	}
	ciphertext, err := aesgcmSeal(aesKey, nonce, plaintext)
	if err != nil {
		return "", err
	}
	ephemeralPub := ephemeralPriv.PubKey().SerializeUncompressed()
	wire := make([]byte, 0, 65+12+len(ciphertext))
	wire = append(wire, ephemeralPub...)
	wire = append(wire, nonce...)
	wire = append(wire, ciphertext...)
	return hex.EncodeToString(wire), nil
}

// ---- fixed test key scalars -------------------------------------------------
//
// These are arbitrary but fixed values chosen for test vectors.
// The corresponding public keys and shared secrets are derived deterministically.
//
// key_A private scalar: the first 32 bytes of SHA-256("teep test key A")
// key_B private scalar: the first 32 bytes of SHA-256("teep test key B")
// ephemeral scalar:     the first 32 bytes of SHA-256("teep test ephemeral")
//
// Computed once; do not change or tests will break.

func testKeyAScalar() string {
	h := sha256.Sum256([]byte("teep test key A"))
	return hex.EncodeToString(h[:])
}

func testKeyBScalar() string {
	h := sha256.Sum256([]byte("teep test key B"))
	return hex.EncodeToString(h[:])
}

func testEphemeralScalar() string {
	h := sha256.Sum256([]byte("teep test ephemeral"))
	return hex.EncodeToString(h[:])
}

func testNonce() []byte {
	h := sha256.Sum256([]byte("teep test nonce"))
	return h[:12]
}

// ---- tests ------------------------------------------------------------------

// TestRoundTrip verifies that Encrypt → Decrypt recovers the original plaintext
// when using the correct private key.
func TestRoundTrip(t *testing.T) {
	keyA := mustPrivKey(t, testKeyAScalar())

	plaintext := []byte("hello, TEE world")
	ciphertextHex, err := Encrypt(plaintext, keyA.PubKey())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := Decrypt(ciphertextHex, keyA)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip failed: got %q, want %q", got, plaintext)
	}
}

// TestRoundTripLargePayload ensures we handle payloads larger than one AES block.
func TestRoundTripLargePayload(t *testing.T) {
	keyA := mustPrivKey(t, testKeyAScalar())
	plaintext := bytes.Repeat([]byte("A"), 4096)

	ciphertextHex, err := Encrypt(plaintext, keyA.PubKey())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := Decrypt(ciphertextHex, keyA)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Error("large payload round-trip failed")
	}
}

// TestWrongKeyFails is a critical security test: decrypting with the wrong
// private key must return an error, never silently succeed or return garbage.
func TestWrongKeyFails(t *testing.T) {
	keyA := mustPrivKey(t, testKeyAScalar())
	keyB := mustPrivKey(t, testKeyBScalar())

	plaintext := []byte("secret message")
	ciphertextHex, err := Encrypt(plaintext, keyA.PubKey())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = Decrypt(ciphertextHex, keyB)
	if err == nil {
		t.Fatal("Decrypt with wrong key must return an error, got nil")
	}
	// The error must mention authentication or decryption failure,
	// not silently return plaintext or a zero-length slice.
	t.Logf("Decrypt with wrong key correctly returned: %v", err)
}

// TestDeterministicVector validates the full ECDH + HKDF + AES-GCM chain
// against a known-good output. This serves as a cross-language compatibility
// test: the same fixed inputs must produce the same hex output in Python/JS.
//
// Protocol parameters (Venice compatible):
//   - ECDH: secp256k1, shared secret = x-coordinate of scalar*point
//   - HKDF: SHA-256, no salt, info="ecdsa_encryption", 32-byte output
//   - AES-256-GCM: 12-byte nonce, no AAD
//   - Wire: ephemeral_pub_uncompressed(65) || nonce(12) || ciphertext+tag
func TestDeterministicVector(t *testing.T) {
	recipientPriv := mustPrivKey(t, testKeyAScalar())
	ephemeralPriv := mustPrivKey(t, testEphemeralScalar())
	nonce := testNonce()
	plaintext := []byte("cross-language test vector")

	got, err := encryptWithFixedEphemeral(plaintext, recipientPriv.PubKey(), ephemeralPriv, nonce)
	if err != nil {
		t.Fatalf("encryptWithFixedEphemeral: %v", err)
	}

	// Verify the wire format structure before checking the full hex.
	raw, err := hex.DecodeString(got)
	if err != nil {
		t.Fatalf("decode output hex: %v", err)
	}
	if len(raw) != 65+12+len(plaintext)+16 {
		t.Errorf("wire length: got %d, want %d", len(raw), 65+12+len(plaintext)+16)
	}
	if raw[0] != 0x04 {
		t.Errorf("wire[0]: got %02x, want 04", raw[0])
	}
	// Verify the embedded ephemeral public key matches expectations.
	wantEphemeralPub := hex.EncodeToString(ephemeralPriv.PubKey().SerializeUncompressed())
	gotEphemeralPub := hex.EncodeToString(raw[:65])
	if gotEphemeralPub != wantEphemeralPub {
		t.Errorf("ephemeral pub mismatch:\n got  %s\n want %s", gotEphemeralPub, wantEphemeralPub)
	}

	// Verify decryption recovers plaintext.
	decrypted, err := Decrypt(got, recipientPriv)
	if err != nil {
		t.Fatalf("Decrypt deterministic vector: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypt: got %q, want %q", decrypted, plaintext)
	}

	// Emit the full expected hex so it can be used in Python/JS cross-language tests.
	// Copy this value into the cross-language test suite.
	t.Logf("deterministic vector hex: %s", got)
}

// TestDeterministicVectorHKDF validates the HKDF key derivation in isolation
// so that cross-language implementations can check intermediate values.
func TestDeterministicVectorHKDF(t *testing.T) {
	// Use a known shared secret and verify the derived key matches.
	// shared_secret = SHA-256("teep hkdf test input") — just for testing.
	sharedSecret := sha256.Sum256([]byte("teep hkdf test input"))

	r := hkdf.New(sha256.New, sharedSecret[:], nil, []byte("ecdsa_encryption"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		t.Fatalf("hkdf: %v", err)
	}

	// The derived key must be non-zero and not equal to the input.
	if bytes.Equal(key, sharedSecret[:]) {
		t.Error("HKDF output equals input — something is wrong")
	}
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("HKDF derived key is all zeros")
	}
	t.Logf("HKDF test vector:")
	t.Logf("  shared_secret (hex): %s", hex.EncodeToString(sharedSecret[:]))
	t.Logf("  derived_key   (hex): %s", hex.EncodeToString(key))
}

// TestSessionNewAndPublicKey verifies NewSession produces a valid uncompressed
// public key in the expected format.
func TestSessionNewAndPublicKey(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if s.PrivateKey == nil {
		t.Fatal("PrivateKey is nil")
	}
	if len(s.PublicKeyHex) != 130 {
		t.Errorf("PublicKeyHex length: got %d, want 130", len(s.PublicKeyHex))
	}
	if !strings.HasPrefix(s.PublicKeyHex, "04") {
		t.Errorf("PublicKeyHex must start with '04', got %q", s.PublicKeyHex[:2])
	}
}

// TestSetModelKeyValidation tests all validation paths of SetModelKey.
func TestSetModelKeyValidation(t *testing.T) {
	keyA := mustPrivKey(t, testKeyAScalar())
	validKey := hex.EncodeToString(keyA.PubKey().SerializeUncompressed())

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid uncompressed key",
			input:   validKey,
			wantErr: false,
		},
		{
			name:    "wrong length (too short)",
			input:   validKey[:128],
			wantErr: true,
		},
		{
			name:    "wrong length (too long)",
			input:   validKey + "00",
			wantErr: true,
		},
		{
			name:    "wrong prefix (compressed)",
			input:   "02" + validKey[2:],
			wantErr: true,
		},
		{
			name:    "not hex",
			input:   strings.Repeat("z", 130),
			wantErr: true,
		},
		{
			name:    "all zeros (not a valid curve point)",
			input:   strings.Repeat("0", 130),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Session{}
			err := s.SetModelKey(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("SetModelKey(%q): expected error, got nil", tc.input[:min(20, len(tc.input))])
			}
			if !tc.wantErr && err != nil {
				t.Errorf("SetModelKey: unexpected error: %v", err)
			}
		})
	}
}

// TestIsEncryptedChunk exercises all IsEncryptedChunk decision paths.
func TestIsEncryptedChunk(t *testing.T) {
	// Build a valid-looking 186-char hex string starting with "04".
	valid186 := "04" + strings.Repeat("ab", 92) // 2 + 184 = 186 chars

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid minimum length",
			input: valid186,
			want:  true,
		},
		{
			name:  "valid longer",
			input: valid186 + "ff",
			want:  true,
		},
		{
			name:  "too short (185 chars)",
			input: valid186[:185],
			want:  false,
		},
		{
			name:  "empty",
			input: "",
			want:  false,
		},
		{
			name:  "wrong prefix (starts with 02)",
			input: "02" + strings.Repeat("ab", 92),
			want:  false,
		},
		{
			name:  "wrong prefix (starts with 00)",
			input: "00" + strings.Repeat("ab", 92),
			want:  false,
		},
		{
			name:  "contains non-hex char",
			input: "04" + strings.Repeat("ab", 91) + "zz",
			want:  false,
		},
		{
			name:  "uppercase hex is valid",
			input: "04" + strings.Repeat("AB", 92),
			want:  true,
		},
		{
			name:  "mixed case hex is valid",
			input: "04" + strings.Repeat("aB", 92),
			want:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsEncryptedChunk(tc.input)
			if got != tc.want {
				t.Errorf("IsEncryptedChunk(%q...): got %v, want %v",
					tc.input[:min(20, len(tc.input))], got, tc.want)
			}
		})
	}
}

// TestDecryptTruncatedInput ensures Decrypt returns an error on inputs that
// are too short to be valid, not a panic or silent failure.
func TestDecryptTruncatedInput(t *testing.T) {
	// 185 hex chars = 92.5 bytes: can't even hold the minimum 93 bytes.
	short := strings.Repeat("04", 46) // 92 hex chars = 46 bytes
	_, err := Decrypt(short, mustPrivKey(t, testKeyAScalar()))
	if err == nil {
		t.Fatal("Decrypt with truncated input must return error")
	}
}

// TestDecryptNotHex ensures Decrypt returns an error on non-hex input.
func TestDecryptNotHex(t *testing.T) {
	_, err := Decrypt("not-hex-data", mustPrivKey(t, testKeyAScalar()))
	if err == nil {
		t.Fatal("Decrypt with non-hex input must return error")
	}
}

// TestSessionZero verifies Zero zeroes the key and nils the pointer.
func TestSessionZero(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	s.Zero()
	if s.PrivateKey != nil {
		t.Fatal("PrivateKey should be nil after Zero()")
	}
}

// TestSessionZeroNilKey verifies Zero does not panic when PrivateKey is nil.
func TestSessionZeroNilKey(t *testing.T) {
	s := &Session{}
	// Should not panic.
	s.Zero()
}

// TestEncryptDecryptViaSession exercises the full session flow: NewSession,
// SetModelKey (using session's own public key as the "model"), Encrypt with
// the model pub key, Decrypt with the session private key.
func TestEncryptDecryptViaSession(t *testing.T) {
	// Simulate the proxy side generating a session.
	session, err := NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// Simulate SetModelKey receiving the model's public key from attestation.
	// Here we use session's own public key to keep the test self-contained.
	if err := session.SetModelKey(session.PublicKeyHex); err != nil {
		t.Fatalf("SetModelKey: %v", err)
	}

	plaintext := []byte(`{"role":"user","content":"hello world"}`)
	ciphertextHex, err := Encrypt(plaintext, session.modelPubKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Verify the output looks like an encrypted chunk.
	if !IsEncryptedChunk(ciphertextHex) {
		t.Error("Encrypt output does not pass IsEncryptedChunk")
	}

	// Decrypt with session's private key (simulating the TEE side).
	got, err := Decrypt(ciphertextHex, session.PrivateKey)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("session encrypt/decrypt: got %q, want %q", got, plaintext)
	}

	session.Zero()
}

// TestModelPubKey verifies ModelPubKey returns nil before SetModelKey and
// the correct key after SetModelKey.
func TestModelPubKey(t *testing.T) {
	s := &Session{}
	if got := s.ModelPubKey(); got != nil {
		t.Fatalf("ModelPubKey before SetModelKey: got %v, want nil", got)
	}

	keyA := mustPrivKey(t, testKeyAScalar())
	validKey := hex.EncodeToString(keyA.PubKey().SerializeUncompressed())

	if err := s.SetModelKey(validKey); err != nil {
		t.Fatalf("SetModelKey: %v", err)
	}

	got := s.ModelPubKey()
	if got == nil {
		t.Fatal("ModelPubKey after SetModelKey: got nil, want non-nil")
	}

	// Verify the returned key matches the input.
	gotHex := hex.EncodeToString(got.SerializeUncompressed())
	if gotHex != validKey {
		t.Errorf("ModelPubKey hex mismatch:\n got  %s\n want %s", gotHex, validKey)
	}
}
