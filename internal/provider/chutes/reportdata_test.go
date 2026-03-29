package chutes_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/chutes"
)

func TestReportDataVerifier_Success(t *testing.T) {
	nonce := attestation.NewNonce()
	e2ePubKey := "dGVzdC1wdWJrZXk="

	// Build REPORTDATA: [0:32] = SHA256(nonce_hex + e2e_pubkey_base64)
	preimage := nonce.Hex() + e2ePubKey
	hash := sha256.Sum256([]byte(preimage))
	var reportData [64]byte
	copy(reportData[:32], hash[:])

	raw := &attestation.RawAttestation{
		Nonce:      nonce.Hex(),
		SigningKey: e2ePubKey,
	}

	v := chutes.ReportDataVerifier{}
	detail, err := v.VerifyReportData(reportData, raw, nonce)
	if err != nil {
		t.Fatalf("VerifyReportData: %v", err)
	}
	t.Logf("detail: %s", detail)
	if detail == "" {
		t.Error("expected non-empty detail string")
	}
}

func TestReportDataVerifier_Mismatch(t *testing.T) {
	nonce := attestation.NewNonce()

	var reportData [64]byte // all zeros — won't match

	raw := &attestation.RawAttestation{
		Nonce:      nonce.Hex(),
		SigningKey: "dGVzdC1wdWJrZXk=",
	}

	v := chutes.ReportDataVerifier{}
	_, err := v.VerifyReportData(reportData, raw, nonce)
	if err == nil {
		t.Fatal("expected error for mismatched REPORTDATA")
	}
	t.Logf("error: %v", err)
}

func TestReportDataVerifier_MissingSigningKey(t *testing.T) {
	nonce := attestation.NewNonce()
	var reportData [64]byte

	raw := &attestation.RawAttestation{
		Nonce:      nonce.Hex(),
		SigningKey: "",
	}

	v := chutes.ReportDataVerifier{}
	_, err := v.VerifyReportData(reportData, raw, nonce)
	if err == nil {
		t.Fatal("expected error for missing signing key")
	}
	t.Logf("error: %v", err)
}

func TestReportDataVerifier_MissingNonce(t *testing.T) {
	nonce := attestation.NewNonce()
	var reportData [64]byte

	raw := &attestation.RawAttestation{
		Nonce:      "",
		SigningKey: "dGVzdC1wdWJrZXk=",
	}

	v := chutes.ReportDataVerifier{}
	_, err := v.VerifyReportData(reportData, raw, nonce)
	if err == nil {
		t.Fatal("expected error for missing nonce")
	}
	t.Logf("error: %v", err)
}

func TestReportDataVerifier_DifferentNonceDifferentHash(t *testing.T) {
	nonce1 := attestation.NewNonce()
	nonce2 := attestation.NewNonce()
	e2ePubKey := "dGVzdC1wdWJrZXk="

	// Build REPORTDATA with nonce1
	preimage := nonce1.Hex() + e2ePubKey
	hash := sha256.Sum256([]byte(preimage))
	var reportData [64]byte
	copy(reportData[:32], hash[:])

	// Try to verify with nonce2's hex in the raw response
	raw := &attestation.RawAttestation{
		Nonce:      nonce2.Hex(),
		SigningKey: e2ePubKey,
	}

	v := chutes.ReportDataVerifier{}
	_, err := v.VerifyReportData(reportData, raw, nonce2)
	if err == nil {
		t.Fatal("expected error for nonce mismatch")
	}
	t.Logf("error (expected): %v", err)

	// Verify the hex values are different
	preimage2 := nonce2.Hex() + e2ePubKey
	hash2 := sha256.Sum256([]byte(preimage2))
	if hex.EncodeToString(hash[:]) == hex.EncodeToString(hash2[:]) {
		t.Fatal("hashes should differ for different nonces")
	}
}
