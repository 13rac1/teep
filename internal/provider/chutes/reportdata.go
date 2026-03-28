package chutes

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
)

// ReportDataVerifier validates the Chutes REPORTDATA binding scheme:
//
//	[0:32] = SHA256(nonce_hex_string + e2e_pubkey_base64_string)
//
// This binds the client nonce and ML-KEM-768 public key to the TDX quote.
type ReportDataVerifier struct{}

// VerifyReportData checks that reportData matches the Chutes binding scheme.
func (ReportDataVerifier) VerifyReportData(reportData [64]byte, raw *attestation.RawAttestation, nonce attestation.Nonce) (string, error) {
	if raw.SigningKey == "" {
		return "", errors.New("e2e_pubkey absent from attestation response")
	}
	if raw.Nonce == "" {
		return "", errors.New("nonce absent from attestation response")
	}

	// Chutes binding: SHA256(nonce_hex_string + e2e_pubkey_base64_string)
	// Both values are their string representations, concatenated directly.
	preimage := raw.Nonce + raw.SigningKey
	expected := sha256.Sum256([]byte(preimage))

	if subtle.ConstantTimeCompare(expected[:], reportData[:32]) != 1 {
		return "", fmt.Errorf("REPORTDATA[0:32] = %s, expected SHA256(nonce + e2e_pubkey) = %s",
			hex.EncodeToString(reportData[:32]), hex.EncodeToString(expected[:]))
	}

	return "REPORTDATA binds SHA256(nonce_hex + e2e_pubkey_base64)", nil
}
