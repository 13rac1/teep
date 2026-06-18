package tinfoil_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider/tinfoil"
)

func x25519PubHex(t *testing.T) string {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	return hex.EncodeToString(priv.PublicKey().Bytes())
}

// TestE2EE_EncryptRequest validates the provider adapter: EncryptResult fields,
// encrypted body non-empty, and encap key present. Crypto round-trip
// (encrypt/decrypt) is tested in internal/e2ee/ehbp_test.go.
func TestE2EE_EncryptRequest(t *testing.T) {
	pubHex := x25519PubHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex, SigningAlgo: "x25519-hpke"}

	enc := tinfoil.NewE2EE()
	er, err := enc.EncryptRequest([]byte(`{"model":"test","messages":[{"role":"user","content":"hello"}]}`), raw, e2ee.EndpointChat)
	if err != nil {
		t.Fatalf("EncryptRequest: %v", err)
	}

	if er.Session != nil {
		t.Error("expected nil Decryptor for Tinfoil EHBP")
	}
	if er.Chutes != nil {
		t.Error("expected nil ChutesE2EE for Tinfoil EHBP")
	}
	if er.EHBP == nil {
		t.Fatal("expected non-nil EHBP")
	}
	defer er.EHBP.Zero()

	if er.BodyReader == nil {
		t.Fatal("expected non-nil BodyReader for EHBP streaming")
	}
	if er.Body != nil {
		t.Error("expected nil Body when BodyReader is set")
	}

	// Drain the streaming reader to verify it produces data.
	encrypted, err := io.ReadAll(er.BodyReader)
	if err != nil {
		t.Fatalf("ReadAll BodyReader: %v", err)
	}
	if len(encrypted) == 0 {
		t.Fatal("encrypted body is empty")
	}
	// Encrypted body should be longer than plaintext due to AEAD overhead + chunk framing.
	if len(encrypted) < 10 {
		t.Errorf("encrypted body too short: %d bytes", len(encrypted))
	}

	// EncapKeyHex should be non-empty.
	encapKey := er.EHBP.EncapKeyHex()
	if encapKey == "" {
		t.Error("EncapKeyHex returned empty string")
	}
	t.Logf("encrypted body length: %d, encap key: %s", len(encrypted), encapKey)
}

func TestE2EE_EncryptRequest_MissingSigningKey(t *testing.T) {
	raw := &attestation.RawAttestation{SigningKey: ""}
	enc := tinfoil.NewE2EE()
	_, err := enc.EncryptRequest([]byte(`{}`), raw, e2ee.EndpointChat)
	if err == nil {
		t.Fatal("expected error for missing signing key")
	}
	t.Logf("error (expected): %v", err)
}

func TestE2EE_EncryptRequest_InvalidHexSigningKey(t *testing.T) {
	raw := &attestation.RawAttestation{SigningKey: "not-valid-hex"}
	enc := tinfoil.NewE2EE()
	_, err := enc.EncryptRequest([]byte(`{}`), raw, e2ee.EndpointChat)
	if err == nil {
		t.Fatal("expected error for invalid hex signing key")
	}
	t.Logf("error (expected): %v", err)
}

func TestE2EE_EncryptRequest_WrongKeyLength(t *testing.T) {
	// 16 bytes instead of 32
	raw := &attestation.RawAttestation{SigningKey: hex.EncodeToString(make([]byte, 16))}
	enc := tinfoil.NewE2EE()
	_, err := enc.EncryptRequest([]byte(`{}`), raw, e2ee.EndpointChat)
	if err == nil {
		t.Fatal("expected error for wrong key length")
	}
	t.Logf("error (expected): %v", err)
}
