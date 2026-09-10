package venice

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/13rac1/teep/internal/attestation"
	"golang.org/x/crypto/sha3"
)

// ReportDataVerifier validates Venice's REPORTDATA binding scheme:
// REPORTDATA[0:20] = keccak256(pubkey_bytes_without_04_prefix)[12:32]
// This is the keccak256-derived address of the uncompressed secp256k1 public
// key — the same derivation used by dstack to identify enclave keys.
//
// Reused unchanged for ACI/1: the caller always passes the 64 REPORTDATA
// bytes parsed from the binary intel_quote (in.TDX.ReportData — see
// internal/verify/attest.go and internal/proxy/proxy.go), and that binding
// scheme is identical across both Venice formats (same keccak256(signing
// key)+nonce layout). The ACI/1 JSON response also carries top-level
// "report_data" / "quote_report_data" fields, but those are informational
// echoes of the same bytes, not a separate binding to verify — this verifier
// does not read them. Do not add ACI/1-specific branching here; if ACI/1
// ever changes its REPORTDATA layout, that is a new format requiring its own
// verifier registered via multi.Verifier.
type ReportDataVerifier struct{}

// VerifyReportData checks that reportData[0:20] matches the keccak256-derived
// address of the enclave public key in raw.SigningKey.
func (ReportDataVerifier) VerifyReportData(reportData [64]byte, raw *attestation.RawAttestation, nonce attestation.Nonce) (string, error) {
	signingKeyBytes, err := hex.DecodeString(raw.SigningKey)
	if err != nil {
		return "", fmt.Errorf("enclave public key is not valid hex: %w", err)
	}
	if len(signingKeyBytes) == 0 {
		return "", errors.New("enclave public key is empty")
	}
	if len(signingKeyBytes) != 65 || signingKeyBytes[0] != 0x04 {
		return "", fmt.Errorf("enclave public key is not an uncompressed secp256k1 point (got %d bytes, first byte 0x%02x)",
			len(signingKeyBytes), signingKeyBytes[0])
	}

	// keccak256-derived address = keccak256(pubkey_without_04_prefix)[12:32]
	h := sha3.NewLegacyKeccak256()
	h.Write(signingKeyBytes[1:]) // skip 04 prefix
	hash := h.Sum(nil)
	derivedAddr := hash[12:32] // last 20 bytes

	if subtle.ConstantTimeCompare(derivedAddr, reportData[:20]) != 1 {
		return "", fmt.Errorf("REPORTDATA[0:20] = %s, expected keccak256-derived address %s",
			hex.EncodeToString(reportData[:20]), hex.EncodeToString(derivedAddr))
	}

	derived := "0x" + hex.EncodeToString(derivedAddr)

	// Verify the signing_address claimed in the response matches what we derived.
	// Lowercase both before constant-time comparison: providers may return
	// EIP-55 checksummed addresses (mixed case) while we derive lowercase.
	if raw.SigningAddress != "" {
		if subtle.ConstantTimeCompare(
			[]byte(strings.ToLower(raw.SigningAddress)),
			[]byte(strings.ToLower(derived)),
		) != 1 {
			return "", fmt.Errorf("signing_address %s does not match keccak256-derived address %s",
				raw.SigningAddress, derived)
		}
	}

	// REPORTDATA layout: [0:20] = keccak256 address, [20:32] = zero, [32:64] = nonce.
	reportNonce := reportData[32:64]
	if subtle.ConstantTimeCompare(nonce[:], reportNonce) != 1 {
		return "", fmt.Errorf("REPORTDATA[32:64] = %s, expected nonce %s",
			hex.EncodeToString(reportNonce), nonce.Hex())
	}

	return fmt.Sprintf("REPORTDATA binds enclave key (%s) and nonce", derived), nil
}
