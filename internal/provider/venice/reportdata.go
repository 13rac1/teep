package venice

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
	"golang.org/x/crypto/sha3"
)

// ReportDataVerifier validates Venice's REPORTDATA binding scheme:
// REPORTDATA[0:20] = keccak256(pubkey_bytes_without_04_prefix)[12:32]
// This is the standard Ethereum address derivation from an uncompressed
// secp256k1 public key.
type ReportDataVerifier struct{}

// VerifyReportData checks that reportData[0:20] matches the Ethereum address
// derived from the signing key in raw.SigningKey.
func (ReportDataVerifier) VerifyReportData(reportData [64]byte, raw *attestation.RawAttestation, _ attestation.Nonce) (string, error) {
	signingKeyBytes, err := hex.DecodeString(raw.SigningKey)
	if err != nil {
		return "", fmt.Errorf("signing key is not valid hex: %w", err)
	}
	if len(signingKeyBytes) != 65 || signingKeyBytes[0] != 0x04 {
		return "", fmt.Errorf("signing key is not an uncompressed secp256k1 public key (got %d bytes, first byte 0x%02x)",
			len(signingKeyBytes), signingKeyBytes[0])
	}

	// Ethereum address = keccak256(pubkey_without_04_prefix)[12:32]
	h := sha3.NewLegacyKeccak256()
	h.Write(signingKeyBytes[1:]) // skip 04 prefix
	hash := h.Sum(nil)
	ethAddr := hash[12:32] // last 20 bytes

	if subtle.ConstantTimeCompare(ethAddr, reportData[:20]) != 1 {
		return "", fmt.Errorf("REPORTDATA[0:20] = %s, expected Ethereum address %s (keccak256 of signing key)",
			hex.EncodeToString(reportData[:20]), hex.EncodeToString(ethAddr))
	}

	return fmt.Sprintf("REPORTDATA binds signing key via Ethereum address (0x%s)", hex.EncodeToString(ethAddr)), nil
}
