package nearcloud

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
)

// GatewayReportDataVerifier validates the gateway's REPORTDATA binding.
//
// The model backend uses: REPORTDATA[0:32] = sha256(signing_address || tls_fingerprint),
// REPORTDATA[32:64] = nonce. The gateway does not expose a signing_address, so we
// try: REPORTDATA[0:32] = sha256(tls_fingerprint), REPORTDATA[32:64] = nonce.
//
// If the gateway uses a different scheme, this factor will fail — which is the
// correct security behavior (unknown REPORTDATA = don't trust it).
type GatewayReportDataVerifier struct{}

// VerifyReportData satisfies provider.ReportDataVerifier, extracting the
// gateway TLS fingerprint from raw attestation data.
func (GatewayReportDataVerifier) VerifyReportData(reportData [64]byte, raw *attestation.RawAttestation, nonce attestation.Nonce) (string, error) {
	return GatewayReportDataVerifier{}.Verify(reportData, raw.GatewayTLSFingerprint, nonce)
}

// Verify checks that reportData matches the expected gateway binding scheme.
func (GatewayReportDataVerifier) Verify(reportData [64]byte, tlsFingerprint string, nonce attestation.Nonce) (string, error) {
	// Check nonce half: REPORTDATA[32:64] == nonce
	if subtle.ConstantTimeCompare(nonce[:], reportData[32:64]) != 1 {
		return "", fmt.Errorf("REPORTDATA[32:64] nonce mismatch: got %s, want %s",
			hex.EncodeToString(reportData[32:64])[:16]+"...",
			hex.EncodeToString(nonce[:])[:16]+"...")
	}

	if tlsFingerprint == "" {
		return "", errors.New("tls_cert_fingerprint absent; cannot verify REPORTDATA[0:32]")
	}

	fpBytes, err := hex.DecodeString(tlsFingerprint)
	if err != nil {
		return "", fmt.Errorf("tls_cert_fingerprint is not valid hex: %w", err)
	}

	// Check identity half: REPORTDATA[0:32] = sha256(tls_fingerprint_bytes)
	expected := sha256.Sum256(fpBytes)
	if subtle.ConstantTimeCompare(expected[:], reportData[:32]) != 1 {
		return "", fmt.Errorf("REPORTDATA[0:32] = %s, expected sha256(tls_fingerprint) = %s",
			hex.EncodeToString(reportData[:32])[:16]+"...",
			hex.EncodeToString(expected[:])[:16]+"...")
	}

	return "gateway REPORTDATA binds sha256(tls_fingerprint) + nonce", nil
}
