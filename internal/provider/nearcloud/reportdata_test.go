package nearcloud_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/nearcloud"
)

// buildGatewayReportData constructs a valid REPORTDATA for the gateway scheme:
// [0:32] = sha256(fpBytes), [32:64] = nonce.
func buildGatewayReportData(fpBytes []byte, nonce attestation.Nonce) [64]byte {
	var rd [64]byte
	h := sha256.Sum256(fpBytes)
	copy(rd[:32], h[:])
	copy(rd[32:], nonce[:])
	return rd
}

func TestGatewayReportDataVerifier_HappyPath(t *testing.T) {
	nonce := attestation.NewNonce()
	fpBytes := []byte("test-fingerprint-bytes")
	fpHex := hex.EncodeToString(fpBytes)
	rd := buildGatewayReportData(fpBytes, nonce)

	v := nearcloud.GatewayReportDataVerifier{}
	detail, err := v.Verify(rd, fpHex, nonce)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	t.Logf("detail: %s", detail)
	if detail == "" {
		t.Error("expected non-empty detail string")
	}
	if !strings.Contains(detail, "sha256(tls_fingerprint)") {
		t.Errorf("detail should mention scheme, got: %s", detail)
	}
}

func TestGatewayReportDataVerifier_WrongNonce(t *testing.T) {
	nonce := attestation.NewNonce()
	fpBytes := []byte("test-fingerprint-bytes")
	fpHex := hex.EncodeToString(fpBytes)
	rd := buildGatewayReportData(fpBytes, nonce)

	// Corrupt the nonce half.
	differentNonce := attestation.NewNonce()

	v := nearcloud.GatewayReportDataVerifier{}
	_, err := v.Verify(rd, fpHex, differentNonce)
	if err == nil {
		t.Fatal("expected error for wrong nonce")
	}
	t.Logf("error: %v", err)
	if !strings.Contains(err.Error(), "nonce mismatch") {
		t.Errorf("error should mention 'nonce mismatch': %v", err)
	}
}

func TestGatewayReportDataVerifier_WrongFingerprint(t *testing.T) {
	nonce := attestation.NewNonce()
	fpBytes := []byte("correct-fingerprint")
	rd := buildGatewayReportData(fpBytes, nonce)

	// Provide a different fingerprint.
	wrongFPHex := hex.EncodeToString([]byte("wrong-fingerprint"))

	v := nearcloud.GatewayReportDataVerifier{}
	_, err := v.Verify(rd, wrongFPHex, nonce)
	if err == nil {
		t.Fatal("expected error for wrong fingerprint")
	}
	t.Logf("error: %v", err)
	if !strings.Contains(err.Error(), "REPORTDATA[0:32]") {
		t.Errorf("error should mention REPORTDATA[0:32]: %v", err)
	}
}

func TestGatewayReportDataVerifier_EmptyFingerprint(t *testing.T) {
	nonce := attestation.NewNonce()
	var rd [64]byte
	copy(rd[32:], nonce[:])

	v := nearcloud.GatewayReportDataVerifier{}
	_, err := v.Verify(rd, "", nonce)
	if err == nil {
		t.Fatal("expected error for empty fingerprint")
	}
	t.Logf("error: %v", err)
	if !strings.Contains(err.Error(), "absent") {
		t.Errorf("error should mention 'absent': %v", err)
	}
}

func TestGatewayReportDataVerifier_InvalidHex(t *testing.T) {
	nonce := attestation.NewNonce()
	var rd [64]byte
	copy(rd[32:], nonce[:])

	v := nearcloud.GatewayReportDataVerifier{}
	_, err := v.Verify(rd, "not-valid-hex!", nonce)
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
	t.Logf("error: %v", err)
	if !strings.Contains(err.Error(), "hex") {
		t.Errorf("error should mention 'hex': %v", err)
	}
}
