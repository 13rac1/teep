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
// [0:32] = sha256(signingAddressBytes || fpBytes), [32:64] = nonce.
func buildGatewayReportData(signingAddressBytes, fpBytes []byte, nonce attestation.Nonce) [64]byte {
	var rd [64]byte
	h := sha256.Sum256(append(signingAddressBytes, fpBytes...))
	copy(rd[:32], h[:])
	copy(rd[32:], nonce[:])
	return rd
}

func TestGatewayReportDataVerifier_HappyPath(t *testing.T) {
	nonce := attestation.NewNonce()
	addrBytes := []byte("12345678901234567890123456789012")
	addrHex := hex.EncodeToString(addrBytes)
	fpBytes := []byte("abcdefghijklmnopqrstuvwxyz123456")
	fpHex := hex.EncodeToString(fpBytes)
	rd := buildGatewayReportData(addrBytes, fpBytes, nonce)

	v := nearcloud.GatewayReportDataVerifier{}
	detail, err := v.Verify(rd, addrHex, fpHex, nonce)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	t.Logf("detail: %s", detail)
	if detail == "" {
		t.Error("expected non-empty detail string")
	}
	if !strings.Contains(detail, "sha256(signing_address + tls_fingerprint)") {
		t.Errorf("detail should mention scheme, got: %s", detail)
	}
}

func TestGatewayReportDataVerifier_WrongNonce(t *testing.T) {
	nonce := attestation.NewNonce()
	addrBytes := []byte("12345678901234567890123456789012")
	addrHex := hex.EncodeToString(addrBytes)
	fpBytes := []byte("abcdefghijklmnopqrstuvwxyz123456")
	fpHex := hex.EncodeToString(fpBytes)
	rd := buildGatewayReportData(addrBytes, fpBytes, nonce)

	// Corrupt the nonce half.
	differentNonce := attestation.NewNonce()

	v := nearcloud.GatewayReportDataVerifier{}
	_, err := v.Verify(rd, addrHex, fpHex, differentNonce)
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
	addrBytes := []byte("12345678901234567890123456789012")
	addrHex := hex.EncodeToString(addrBytes)
	fpBytes := []byte("right-fingerprint----32-byte-val")
	rd := buildGatewayReportData(addrBytes, fpBytes, nonce)

	// Provide a different fingerprint.
	wrongFPHex := hex.EncodeToString([]byte("wrong-fingerprint----32-byte-val"))

	v := nearcloud.GatewayReportDataVerifier{}
	_, err := v.Verify(rd, addrHex, wrongFPHex, nonce)
	if err == nil {
		t.Fatal("expected error for wrong fingerprint")
	}
	t.Logf("error: %v", err)
	if !strings.Contains(err.Error(), "REPORTDATA[0:32]") {
		t.Errorf("error should mention REPORTDATA[0:32]: %v", err)
	}
}

func TestGatewayReportDataVerifier_EmptySigningAddress(t *testing.T) {
	nonce := attestation.NewNonce()
	var rd [64]byte
	copy(rd[32:], nonce[:])
	fpHex := hex.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz123456"))

	v := nearcloud.GatewayReportDataVerifier{}
	_, err := v.Verify(rd, "", fpHex, nonce)
	if err == nil {
		t.Fatal("expected error for empty signing_address")
	}
	t.Logf("error: %v", err)
	if !strings.Contains(err.Error(), "signing_address") {
		t.Errorf("error should mention signing_address: %v", err)
	}
}

func TestGatewayReportDataVerifier_EmptyFingerprint(t *testing.T) {
	nonce := attestation.NewNonce()
	var rd [64]byte
	copy(rd[32:], nonce[:])
	addrHex := hex.EncodeToString([]byte("12345678901234567890123456789012"))

	v := nearcloud.GatewayReportDataVerifier{}
	_, err := v.Verify(rd, addrHex, "", nonce)
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
	fpHex := hex.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz123456"))

	v := nearcloud.GatewayReportDataVerifier{}
	_, err := v.Verify(rd, "not-valid-hex!", fpHex, nonce)
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
	t.Logf("error: %v", err)
	if !strings.Contains(err.Error(), "hex") {
		t.Errorf("error should mention 'hex': %v", err)
	}
}

func TestGatewayReportDataVerifier_VerifyReportData_NilRaw(t *testing.T) {
	v := nearcloud.GatewayReportDataVerifier{}
	_, err := v.VerifyReportData([64]byte{}, nil, attestation.Nonce{})
	if err == nil {
		t.Fatal("expected error for nil raw")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("error should mention nil: %v", err)
	}
}

func TestGatewayReportDataVerifier_VerifyReportData_HappyPath(t *testing.T) {
	nonce := attestation.NewNonce()
	addrBytes := []byte("12345678901234567890123456789012")
	addrHex := hex.EncodeToString(addrBytes)
	fpBytes := []byte("abcdefghijklmnopqrstuvwxyz123456")
	fpHex := hex.EncodeToString(fpBytes)
	rd := buildGatewayReportData(addrBytes, fpBytes, nonce)

	raw := &attestation.RawAttestation{
		GatewaySigningAddress: addrHex,
		GatewayTLSFingerprint: fpHex,
	}
	v := nearcloud.GatewayReportDataVerifier{}
	detail, err := v.VerifyReportData(rd, raw, nonce)
	if err != nil {
		t.Fatalf("VerifyReportData: %v", err)
	}
	t.Logf("detail: %s", detail)
}
