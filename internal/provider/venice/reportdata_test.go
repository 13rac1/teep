package venice_test

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
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

// buildReportData constructs a Venice-style 64-byte REPORTDATA:
// [0:20] = keccak256 address, [20:32] = zero, [32:64] = nonce.
func buildReportData(addr []byte, nonce attestation.Nonce) [64]byte {
	var rd [64]byte
	copy(rd[:20], addr)
	copy(rd[32:64], nonce[:])
	return rd
}

// randomNonce generates a random 32-byte nonce for testing.
func randomNonce(t *testing.T) attestation.Nonce {
	t.Helper()
	var n attestation.Nonce
	if _, err := rand.Read(n[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return n
}

func TestReportDataVerifier_CorrectBinding(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	pubKeyBytes := priv.PubKey().SerializeUncompressed()
	addr := keccakAddress(pubKeyBytes)
	nonce := randomNonce(t)
	reportData := buildReportData(addr, nonce)

	raw := &attestation.RawAttestation{
		SigningKey: hex.EncodeToString(pubKeyBytes),
	}

	v := venice.ReportDataVerifier{}
	detail, err := v.VerifyReportData(reportData, raw, nonce)
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
	nonce := randomNonce(t)
	reportData := buildReportData(addr, nonce)

	raw := &attestation.RawAttestation{
		SigningKey:     hex.EncodeToString(pubKeyBytes),
		SigningAddress: "0x" + hex.EncodeToString(addr),
	}

	v := venice.ReportDataVerifier{}
	_, err = v.VerifyReportData(reportData, raw, nonce)
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

func TestReportDataVerifier_NonceBinding(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	pubKeyBytes := priv.PubKey().SerializeUncompressed()
	addr := keccakAddress(pubKeyBytes)
	nonce := randomNonce(t)
	reportData := buildReportData(addr, nonce)

	raw := &attestation.RawAttestation{
		SigningKey: hex.EncodeToString(pubKeyBytes),
	}

	v := venice.ReportDataVerifier{}
	detail, err := v.VerifyReportData(reportData, raw, nonce)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Logf("detail: %s", detail)

	// Verify the nonce bytes in REPORTDATA match what we set.
	if reportData[32] == 0 && reportData[33] == 0 {
		t.Error("nonce bytes should be non-zero")
	}
}

func TestReportDataVerifier_EmptyKey(t *testing.T) {
	raw := &attestation.RawAttestation{
		SigningKey: "", // empty hex → empty bytes
	}

	v := venice.ReportDataVerifier{}
	_, err := v.VerifyReportData([64]byte{}, raw, attestation.Nonce{})
	if err == nil {
		t.Fatal("expected error for empty signing key, got nil")
	}
	t.Logf("expected error: %v", err)
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error = %q, want it to mention 'empty'", err)
	}
}

func TestReportDataVerifier_WrongNonce(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	pubKeyBytes := priv.PubKey().SerializeUncompressed()
	addr := keccakAddress(pubKeyBytes)

	// Set one nonce in REPORTDATA, pass a different nonce to verifier.
	nonceInReport := randomNonce(t)
	differentNonce := randomNonce(t)
	reportData := buildReportData(addr, nonceInReport)

	raw := &attestation.RawAttestation{
		SigningKey: hex.EncodeToString(pubKeyBytes),
	}

	v := venice.ReportDataVerifier{}
	_, err = v.VerifyReportData(reportData, raw, differentNonce)
	if err == nil {
		t.Error("expected error for mismatched nonce, got nil")
	}
	t.Logf("expected error: %v", err)
}
