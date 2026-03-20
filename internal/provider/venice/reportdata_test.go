package venice_test

import (
	"encoding/hex"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/venice"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

// keccakAddress computes the keccak256-derived address (20 bytes) from an
// uncompressed secp256k1 public key (65 bytes starting with 0x04).
func keccakAddress(pubKeyUncompressed []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(pubKeyUncompressed[1:]) // skip 04 prefix
	hash := h.Sum(nil)
	return hash[12:32]
}

func TestReportDataVerifier_CorrectBinding(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	pubKeyBytes := priv.PubKey().SerializeUncompressed()
	addr := keccakAddress(pubKeyBytes)

	var reportData [64]byte
	copy(reportData[:20], addr)

	raw := &attestation.RawAttestation{
		SigningKey: hex.EncodeToString(pubKeyBytes),
	}

	v := venice.ReportDataVerifier{}
	detail, err := v.VerifyReportData(reportData, raw, attestation.Nonce{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if detail == "" {
		t.Error("expected non-empty detail on success")
	}
	t.Logf("detail: %s", detail)
}

func TestReportDataVerifier_SigningAddressMatch(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	pubKeyBytes := priv.PubKey().SerializeUncompressed()
	addr := keccakAddress(pubKeyBytes)

	var reportData [64]byte
	copy(reportData[:20], addr)

	raw := &attestation.RawAttestation{
		SigningKey:     hex.EncodeToString(pubKeyBytes),
		SigningAddress: "0x" + hex.EncodeToString(addr),
	}

	v := venice.ReportDataVerifier{}
	_, err = v.VerifyReportData(reportData, raw, attestation.Nonce{})
	if err != nil {
		t.Fatalf("unexpected error with matching signing_address: %v", err)
	}
}

func TestReportDataVerifier_SigningAddressMismatch(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	pubKeyBytes := priv.PubKey().SerializeUncompressed()
	addr := keccakAddress(pubKeyBytes)

	var reportData [64]byte
	copy(reportData[:20], addr)

	raw := &attestation.RawAttestation{
		SigningKey:     hex.EncodeToString(pubKeyBytes),
		SigningAddress: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
	}

	v := venice.ReportDataVerifier{}
	_, err = v.VerifyReportData(reportData, raw, attestation.Nonce{})
	if err == nil {
		t.Error("expected error for mismatched signing_address, got nil")
	}
	t.Logf("expected error: %v", err)
}

func TestReportDataVerifier_WrongKey(t *testing.T) {
	privA, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey A: %v", err)
	}
	privB, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey B: %v", err)
	}

	addrA := keccakAddress(privA.PubKey().SerializeUncompressed())
	var reportData [64]byte
	copy(reportData[:20], addrA)

	raw := &attestation.RawAttestation{
		SigningKey: hex.EncodeToString(privB.PubKey().SerializeUncompressed()),
	}

	v := venice.ReportDataVerifier{}
	_, err = v.VerifyReportData(reportData, raw, attestation.Nonce{})
	if err == nil {
		t.Error("expected error for mismatched key, got nil")
	}
}

func TestReportDataVerifier_InvalidHex(t *testing.T) {
	raw := &attestation.RawAttestation{
		SigningKey: "not-hex-!!!",
	}

	v := venice.ReportDataVerifier{}
	_, err := v.VerifyReportData([64]byte{}, raw, attestation.Nonce{})
	if err == nil {
		t.Error("expected error for invalid hex, got nil")
	}
}

func TestReportDataVerifier_CompressedKey(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}

	raw := &attestation.RawAttestation{
		SigningKey: hex.EncodeToString(priv.PubKey().SerializeCompressed()),
	}

	v := venice.ReportDataVerifier{}
	_, err = v.VerifyReportData([64]byte{}, raw, attestation.Nonce{})
	if err == nil {
		t.Error("expected error for compressed key, got nil")
	}
}
