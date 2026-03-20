package nearai

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/13rac1/teep/internal/attestation"
)

// ReportDataVerifier validates NEAR AI's REPORTDATA binding scheme:
//
//	[0:32]  = sha256(signing_address_bytes || tls_fingerprint_bytes)
//	[32:64] = nonce (raw 32 bytes)
//
// This binds the signing identity and TLS certificate to the TDX quote,
// ensuring the proxy is talking to the exact machine that was attested.
type ReportDataVerifier struct{}

// VerifyReportData checks that reportData matches the NEAR binding scheme.
func (ReportDataVerifier) VerifyReportData(reportData [64]byte, raw *attestation.RawAttestation, nonce attestation.Nonce) (string, error) {
	if raw.SigningAddress == "" {
		return "", fmt.Errorf("signing_address absent from attestation response")
	}
	if raw.TLSFingerprint == "" {
		return "", fmt.Errorf("tls_cert_fingerprint absent from attestation response")
	}

	// Decode signing address — strip optional "0x" prefix.
	addrHex := strings.TrimPrefix(raw.SigningAddress, "0x")
	addrBytes, err := hex.DecodeString(addrHex)
	if err != nil {
		return "", fmt.Errorf("signing_address is not valid hex: %w", err)
	}

	fpBytes, err := hex.DecodeString(raw.TLSFingerprint)
	if err != nil {
		return "", fmt.Errorf("tls_cert_fingerprint is not valid hex: %w", err)
	}

	// [0:32] = sha256(signing_address_bytes || tls_fingerprint_bytes)
	expected := sha256.Sum256(append(addrBytes, fpBytes...))
	if subtle.ConstantTimeCompare(expected[:], reportData[:32]) != 1 {
		return "", fmt.Errorf("REPORTDATA[0:32] = %s, expected sha256(signing_address + tls_fingerprint) = %s",
			hex.EncodeToString(reportData[:32]), hex.EncodeToString(expected[:]))
	}

	// [32:64] = nonce (raw 32 bytes)
	var nonceBytes [32]byte
	copy(nonceBytes[:], nonce[:])
	if subtle.ConstantTimeCompare(nonceBytes[:], reportData[32:64]) != 1 {
		return "", fmt.Errorf("REPORTDATA[32:64] nonce mismatch: got %s, want %s",
			hex.EncodeToString(reportData[32:64]), hex.EncodeToString(nonceBytes[:]))
	}

	return "REPORTDATA binds sha256(signing_address + tls_fingerprint) + nonce", nil
}
