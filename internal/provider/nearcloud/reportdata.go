package nearcloud

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/13rac1/teep/internal/attestation"
)

// GatewayReportDataVerifier validates the gateway's REPORTDATA binding.
//
//	[0:32]  = sha256(signing_address_bytes || tls_fingerprint_bytes)
//	[32:64] = nonce (raw 32 bytes)
//
// NearCloud's gateway now exposes a signing_address and uses the same identity
// half as the model backend. If the gateway changes scheme, this factor fails
// closed unless explicitly allow-failed by policy.
type GatewayReportDataVerifier struct{}

// VerifyReportData satisfies provider.ReportDataVerifier, extracting the
// gateway TLS fingerprint from raw attestation data.
func (GatewayReportDataVerifier) VerifyReportData(reportData [64]byte, raw *attestation.RawAttestation, nonce attestation.Nonce) (string, error) {
	if raw == nil {
		return "", errors.New("raw attestation is nil; cannot verify REPORTDATA")
	}
	return GatewayReportDataVerifier{}.Verify(reportData, raw.GatewaySigningAddress, raw.GatewayTLSFingerprint, nonce)
}

// Verify checks that reportData matches the expected gateway binding scheme.
func (GatewayReportDataVerifier) Verify(
	reportData [64]byte,
	signingAddress string,
	tlsFingerprint string,
	nonce attestation.Nonce,
) (string, error) {
	// Check nonce half: REPORTDATA[32:64] == nonce
	if subtle.ConstantTimeCompare(nonce[:], reportData[32:64]) != 1 {
		return "", fmt.Errorf("REPORTDATA[32:64] nonce mismatch: got %s, want %s",
			hex.EncodeToString(reportData[32:64])[:16]+"...",
			hex.EncodeToString(nonce[:])[:16]+"...")
	}

	if signingAddress == "" {
		return "", errors.New("signing_address absent; cannot verify REPORTDATA[0:32]")
	}
	if tlsFingerprint == "" {
		return "", errors.New("tls_cert_fingerprint absent; cannot verify REPORTDATA[0:32]")
	}

	addrHex := strings.TrimPrefix(signingAddress, "0x")
	addrBytes, err := hex.DecodeString(addrHex)
	if err != nil {
		return "", fmt.Errorf("signing_address is not valid hex: %w", err)
	}
	if len(addrBytes) != 20 && len(addrBytes) != 32 {
		return "", fmt.Errorf("signing_address must decode to 20 or 32 bytes, got %d", len(addrBytes))
	}

	fpBytes, err := hex.DecodeString(tlsFingerprint)
	if err != nil {
		return "", fmt.Errorf("tls_cert_fingerprint is not valid hex: %w", err)
	}
	if len(fpBytes) != 32 {
		return "", fmt.Errorf("tls_cert_fingerprint must decode to 32 bytes, got %d", len(fpBytes))
	}

	// Check identity half: REPORTDATA[0:32] = sha256(signing_address_bytes || tls_fingerprint_bytes)
	expected := sha256.Sum256(append(addrBytes, fpBytes...))
	if subtle.ConstantTimeCompare(expected[:], reportData[:32]) != 1 {
		return "", fmt.Errorf("REPORTDATA[0:32] = %s, expected sha256(signing_address + tls_fingerprint) = %s",
			hex.EncodeToString(reportData[:32])[:16]+"...",
			hex.EncodeToString(expected[:])[:16]+"...")
	}

	return "gateway REPORTDATA binds sha256(signing_address + tls_fingerprint) + nonce", nil
}
