package phalacloud_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/phalacloud"
)

// buildPhalaReportData constructs a valid Phala-scheme REPORTDATA from
// signing address bytes and nonce. The address is left-padded with zeros to
// 32 bytes.
func buildPhalaReportData(addrBytes []byte, nonce attestation.Nonce) [64]byte {
	var rd [64]byte
	// Left-pad address to 32 bytes.
	copy(rd[32-len(addrBytes):32], addrBytes)
	copy(rd[32:64], nonce[:])
	return rd
}

func TestReportDataVerifier_CorrectBinding_ECDSA(t *testing.T) {
	// 20-byte ECDSA address: left-padded to 32 bytes in REPORTDATA[0:32].
	addrBytes := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}
	nonce := attestation.NewNonce()
	reportData := buildPhalaReportData(addrBytes, nonce)
	raw := &attestation.RawAttestation{
		SigningAddress: hex.EncodeToString(addrBytes),
	}
	v := phalacloud.ReportDataVerifier{}

	detail, err := v.VerifyReportData(reportData, raw, nonce)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if detail == "" {
		t.Error("expected non-empty detail on success")
	}
	t.Logf("detail: %s", detail)
}

func TestReportDataVerifier_CorrectBinding_Ed25519(t *testing.T) {
	// 32-byte Ed25519 public key: fills all of REPORTDATA[0:32].
	addrBytes := make([]byte, 32)
	for i := range addrBytes {
		addrBytes[i] = byte(0xa0 + i)
	}
	nonce := attestation.NewNonce()
	reportData := buildPhalaReportData(addrBytes, nonce)
	raw := &attestation.RawAttestation{
		SigningAddress: hex.EncodeToString(addrBytes),
	}
	v := phalacloud.ReportDataVerifier{}

	detail, err := v.VerifyReportData(reportData, raw, nonce)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if detail == "" {
		t.Error("expected non-empty detail on success")
	}
}

func TestReportDataVerifier_0xPrefixedAddress(t *testing.T) {
	addrBytes := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	nonce := attestation.NewNonce()
	reportData := buildPhalaReportData(addrBytes, nonce)
	raw := &attestation.RawAttestation{
		SigningAddress: "0x" + hex.EncodeToString(addrBytes),
	}
	v := phalacloud.ReportDataVerifier{}

	_, err := v.VerifyReportData(reportData, raw, nonce)
	if err != nil {
		t.Fatalf("unexpected error with 0x prefix: %v", err)
	}
}

func TestReportDataVerifier_WrongAddress(t *testing.T) {
	addrBytes := make([]byte, 20)
	for i := range addrBytes {
		addrBytes[i] = byte(i + 1)
	}
	nonce := attestation.NewNonce()
	reportData := buildPhalaReportData(addrBytes, nonce)

	wrongAddr := make([]byte, 20)
	for i := range wrongAddr {
		wrongAddr[i] = byte(0xff - i)
	}
	raw := &attestation.RawAttestation{
		SigningAddress: hex.EncodeToString(wrongAddr),
	}
	v := phalacloud.ReportDataVerifier{}

	_, err := v.VerifyReportData(reportData, raw, nonce)
	if err == nil {
		t.Fatal("expected error for wrong signing address, got nil")
	}
	if !strings.Contains(err.Error(), "REPORTDATA[0:32]") {
		t.Errorf("error should mention REPORTDATA[0:32], got: %v", err)
	}
}

func TestReportDataVerifier_WrongNonce(t *testing.T) {
	addrBytes := make([]byte, 20)
	for i := range addrBytes {
		addrBytes[i] = byte(i + 1)
	}
	nonce1 := attestation.NewNonce()
	nonce2 := attestation.NewNonce()
	reportData := buildPhalaReportData(addrBytes, nonce1)
	raw := &attestation.RawAttestation{
		SigningAddress: hex.EncodeToString(addrBytes),
	}
	v := phalacloud.ReportDataVerifier{}

	_, err := v.VerifyReportData(reportData, raw, nonce2)
	if err == nil {
		t.Fatal("expected error for wrong nonce, got nil")
	}
	if !strings.Contains(err.Error(), "nonce mismatch") {
		t.Errorf("error should mention nonce mismatch, got: %v", err)
	}
}

func TestReportDataVerifier_MissingSigningAddress(t *testing.T) {
	nonce := attestation.NewNonce()
	raw := &attestation.RawAttestation{
		SigningAddress: "",
	}
	v := phalacloud.ReportDataVerifier{}

	_, err := v.VerifyReportData([64]byte{}, raw, nonce)
	if err == nil {
		t.Fatal("expected error for missing signing_address")
	}
	if !strings.Contains(err.Error(), "signing_address absent") {
		t.Errorf("error should mention signing_address absent, got: %v", err)
	}
}

func TestReportDataVerifier_InvalidHexAddress(t *testing.T) {
	nonce := attestation.NewNonce()
	raw := &attestation.RawAttestation{
		SigningAddress: "not-valid-hex",
	}
	v := phalacloud.ReportDataVerifier{}

	_, err := v.VerifyReportData([64]byte{}, raw, nonce)
	if err == nil {
		t.Fatal("expected error for invalid hex address")
	}
	if !strings.Contains(err.Error(), "not valid hex") {
		t.Errorf("error should mention invalid hex, got: %v", err)
	}
}

func TestReportDataVerifier_WrongAddressLength(t *testing.T) {
	// 16 bytes: neither 20 nor 32.
	addrBytes := make([]byte, 16)
	nonce := attestation.NewNonce()
	raw := &attestation.RawAttestation{
		SigningAddress: hex.EncodeToString(addrBytes),
	}
	v := phalacloud.ReportDataVerifier{}

	_, err := v.VerifyReportData([64]byte{}, raw, nonce)
	if err == nil {
		t.Fatal("expected error for wrong address length")
	}
	if !strings.Contains(err.Error(), "20 or 32 bytes") {
		t.Errorf("error should mention expected sizes, got: %v", err)
	}
}
