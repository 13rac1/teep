package nearai_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/nearai"
)

// buildNEARReportData constructs a valid NEAR-scheme REPORTDATA from
// signing address bytes, TLS fingerprint bytes, and nonce.
func buildNEARReportData(addrBytes, fpBytes []byte, nonce attestation.Nonce) [64]byte {
	hash := sha256.Sum256(append(addrBytes, fpBytes...))
	var rd [64]byte
	copy(rd[:32], hash[:])
	copy(rd[32:64], nonce[:])
	return rd
}

func TestReportDataVerifier_CorrectBinding(t *testing.T) {
	addrBytes := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}
	fpBytes := make([]byte, 32)
	for i := range fpBytes {
		fpBytes[i] = byte(0xa0 + i)
	}
	nonce := attestation.NewNonce()
	reportData := buildNEARReportData(addrBytes, fpBytes, nonce)

	raw := &attestation.RawAttestation{
		SigningAddress: hex.EncodeToString(addrBytes),
		TLSFingerprint: hex.EncodeToString(fpBytes),
	}

	v := nearai.ReportDataVerifier{}
	detail, err := v.VerifyReportData(reportData, raw, nonce)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if detail == "" {
		t.Error("expected non-empty detail on success")
	}
	t.Logf("detail: %s", detail)
}

func TestReportDataVerifier_0xPrefixedAddress(t *testing.T) {
	addrBytes := []byte{0xde, 0xad, 0xbe, 0xef}
	fpBytes := []byte{0xca, 0xfe}
	nonce := attestation.NewNonce()
	reportData := buildNEARReportData(addrBytes, fpBytes, nonce)

	raw := &attestation.RawAttestation{
		SigningAddress: "0x" + hex.EncodeToString(addrBytes),
		TLSFingerprint: hex.EncodeToString(fpBytes),
	}

	v := nearai.ReportDataVerifier{}
	_, err := v.VerifyReportData(reportData, raw, nonce)
	if err != nil {
		t.Fatalf("unexpected error with 0x prefix: %v", err)
	}
}

func TestReportDataVerifier_WrongAddress(t *testing.T) {
	addrBytes := []byte{0x01, 0x02, 0x03, 0x04}
	fpBytes := []byte{0x0a, 0x0b}
	nonce := attestation.NewNonce()
	reportData := buildNEARReportData(addrBytes, fpBytes, nonce)

	raw := &attestation.RawAttestation{
		SigningAddress: hex.EncodeToString([]byte{0xff, 0xfe, 0xfd, 0xfc}), // different
		TLSFingerprint: hex.EncodeToString(fpBytes),
	}

	v := nearai.ReportDataVerifier{}
	_, err := v.VerifyReportData(reportData, raw, nonce)
	if err == nil {
		t.Error("expected error for wrong signing address, got nil")
	}
}

func TestReportDataVerifier_WrongFingerprint(t *testing.T) {
	addrBytes := []byte{0x01, 0x02}
	fpBytes := []byte{0x0a, 0x0b}
	nonce := attestation.NewNonce()
	reportData := buildNEARReportData(addrBytes, fpBytes, nonce)

	raw := &attestation.RawAttestation{
		SigningAddress: hex.EncodeToString(addrBytes),
		TLSFingerprint: hex.EncodeToString([]byte{0xff, 0xff}), // different
	}

	v := nearai.ReportDataVerifier{}
	_, err := v.VerifyReportData(reportData, raw, nonce)
	if err == nil {
		t.Error("expected error for wrong TLS fingerprint, got nil")
	}
}

func TestReportDataVerifier_WrongNonce(t *testing.T) {
	addrBytes := []byte{0x01}
	fpBytes := []byte{0x02}
	nonce1 := attestation.NewNonce()
	nonce2 := attestation.NewNonce()
	reportData := buildNEARReportData(addrBytes, fpBytes, nonce1)

	raw := &attestation.RawAttestation{
		SigningAddress: hex.EncodeToString(addrBytes),
		TLSFingerprint: hex.EncodeToString(fpBytes),
	}

	v := nearai.ReportDataVerifier{}
	_, err := v.VerifyReportData(reportData, raw, nonce2) // different nonce
	if err == nil {
		t.Error("expected error for wrong nonce, got nil")
	}
}

func TestReportDataVerifier_MissingSigningAddress(t *testing.T) {
	raw := &attestation.RawAttestation{
		TLSFingerprint: "aabb",
	}

	v := nearai.ReportDataVerifier{}
	_, err := v.VerifyReportData([64]byte{}, raw, attestation.Nonce{})
	if err == nil {
		t.Error("expected error for missing signing_address, got nil")
	}
}

func TestReportDataVerifier_MissingTLSFingerprint(t *testing.T) {
	raw := &attestation.RawAttestation{
		SigningAddress: "aabb",
	}

	v := nearai.ReportDataVerifier{}
	_, err := v.VerifyReportData([64]byte{}, raw, attestation.Nonce{})
	if err == nil {
		t.Error("expected error for missing tls_cert_fingerprint, got nil")
	}
}
