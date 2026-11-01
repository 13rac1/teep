package chutes

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
)

// GPURequesterNonce returns the SPDM requester nonce that the GPU evidence of
// a Chutes attestation must answer: SHA256(nonce_hex + e2e_pubkey_base64),
// the value that REPORTDATA[0:32] binds. nonce is the client's nonce, never
// the nonce that a response states (raw.Nonce is server-controlled in the
// chutes format that gateways relay). Evidence that answers this value is
// bound to the client nonce and the instance's ML-KEM-768 key.
func GPURequesterNonce(nonce attestation.Nonce, e2ePubKey string) (attestation.Nonce, error) {
	if e2ePubKey == "" {
		return attestation.Nonce{}, errors.New("e2e_pubkey absent from attestation response")
	}
	return sha256.Sum256([]byte(nonce.Hex() + e2ePubKey)), nil
}

// ReportDataVerifier validates the Chutes REPORTDATA binding scheme:
//
//	[0:32] = SHA256(nonce_hex_string + e2e_pubkey_base64_string)
//
// This binds the client nonce and ML-KEM-768 public key to the TDX quote.
type ReportDataVerifier struct{}

// VerifyReportData checks that reportData matches the Chutes binding scheme.
// The client-generated nonce is used for the preimage — never raw.Nonce, which
// is server-controlled and must match the client nonce exactly.
func (ReportDataVerifier) VerifyReportData(reportData [64]byte, raw *attestation.RawAttestation, nonce attestation.Nonce) (string, error) {
	if raw.SigningKey == "" {
		return "", errors.New("e2e_pubkey absent from attestation response")
	}
	if subtle.ConstantTimeCompare([]byte(raw.Nonce), []byte(nonce.Hex())) != 1 {
		return "", fmt.Errorf("nonce mismatch: attestation response nonce %q does not match client nonce", raw.Nonce)
	}

	// Chutes binding: SHA256(nonce_hex_string + e2e_pubkey_base64_string)
	// Uses client-generated nonce, not the server-echoed value.
	preimage := nonce.Hex() + raw.SigningKey
	expected := sha256.Sum256([]byte(preimage))

	if subtle.ConstantTimeCompare(expected[:], reportData[:32]) != 1 {
		return "", fmt.Errorf("REPORTDATA[0:32] = %s, expected SHA256(nonce + e2e_pubkey) = %s",
			hex.EncodeToString(reportData[:32]), hex.EncodeToString(expected[:]))
	}

	return "REPORTDATA binds SHA256(nonce_hex + e2e_pubkey_base64)", nil
}
