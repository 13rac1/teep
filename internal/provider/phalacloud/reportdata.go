package phalacloud

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/13rac1/teep/internal/attestation"
)

// ReportDataVerifier validates Phala Cloud's REPORTDATA binding scheme:
//
//	[0:32]  = signing_address_bytes left-padded with zeros to 32 bytes
//	[32:64] = nonce (raw 32 bytes)
//
// For ECDSA (20-byte Ethereum address), the first 12 bytes are zero.
// For Ed25519 (32-byte public key), the full 32 bytes are the key.
//
// This differs from NEAR AI's scheme which uses sha256(signing_address +
// tls_fingerprint) for the first 32 bytes. Phala embeds the signing address
// directly, making the binding simpler but without TLS fingerprint integration.
type ReportDataVerifier struct{}

// VerifyReportData checks that reportData matches the Phala binding scheme.
func (ReportDataVerifier) VerifyReportData(reportData [64]byte, raw *attestation.RawAttestation, nonce attestation.Nonce) (string, error) {
	if raw.SigningAddress == "" {
		return "", errors.New("signing_address absent from attestation response")
	}

	// Decode signing address — strip optional "0x" prefix.
	addrHex := strings.TrimPrefix(raw.SigningAddress, "0x")
	addrBytes, err := hex.DecodeString(addrHex)
	if err != nil {
		return "", fmt.Errorf("signing_address is not valid hex: %w", err)
	}
	// Accept 20 bytes (keccak256-derived address for ECDSA) or 32 bytes
	// (Ed25519 public key).
	if len(addrBytes) != 20 && len(addrBytes) != 32 {
		return "", fmt.Errorf("signing_address must decode to 20 or 32 bytes, got %d", len(addrBytes))
	}

	// Left-pad the address to 32 bytes.
	var expectedAddr [32]byte
	copy(expectedAddr[32-len(addrBytes):], addrBytes)

	if subtle.ConstantTimeCompare(expectedAddr[:], reportData[:32]) != 1 {
		return "", fmt.Errorf("REPORTDATA[0:32] = %s, expected left-padded signing_address = %s",
			hex.EncodeToString(reportData[:32])[:16]+"...",
			hex.EncodeToString(expectedAddr[:])[:16]+"...")
	}

	// [32:64] = nonce (raw 32 bytes)
	if subtle.ConstantTimeCompare(nonce[:], reportData[32:64]) != 1 {
		return "", fmt.Errorf("REPORTDATA[32:64] nonce mismatch: got %s, want %s",
			hex.EncodeToString(reportData[32:64])[:16]+"...",
			hex.EncodeToString(nonce[:])[:16]+"...")
	}

	return "REPORTDATA binds left-padded signing_address + nonce", nil
}
