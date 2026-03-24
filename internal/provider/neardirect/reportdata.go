package neardirect

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
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
		return "", errors.New("signing_address absent from attestation response")
	}
	if raw.TLSFingerprint == "" {
		return "", errors.New("tls_cert_fingerprint absent from attestation response")
	}

	// Decode signing address — strip optional "0x" prefix.
	addrHex := strings.TrimPrefix(raw.SigningAddress, "0x")
	addrBytes, err := hex.DecodeString(addrHex)
	if err != nil {
		return "", fmt.Errorf("signing_address is not valid hex: %w", err)
	}
	// Accept 20 bytes (keccak256-derived address, same format as EIP-55, for
	// ECDSA) or 32 bytes (Ed25519 public key hash for v2 protocol).
	if len(addrBytes) != 20 && len(addrBytes) != 32 {
		return "", fmt.Errorf("signing_address must decode to 20 or 32 bytes, got %d", len(addrBytes))
	}

	fpBytes, err := hex.DecodeString(raw.TLSFingerprint)
	if err != nil {
		return "", fmt.Errorf("tls_cert_fingerprint is not valid hex: %w", err)
	}
	if len(fpBytes) != 32 {
		return "", fmt.Errorf("tls_cert_fingerprint must decode to 32 bytes, got %d", len(fpBytes))
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
