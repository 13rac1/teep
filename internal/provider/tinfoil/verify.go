package tinfoil

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
)

// ReportDataVerifier validates the Tinfoil v3 REPORT_DATA binding:
//
//	crypto_material_hash = SHA-256(crypto_material section bytes)
//	device_evidence_hash = SHA-256(device_evidence section bytes)
//	REPORT_DATA[0:32]    = SHA-256(algorithm URI || nonce || crypto_material_hash || device_evidence_hash)
//	REPORT_DATA[32:64]   = zeros
//
// The algorithm URI is written first as a domain separation label. The three
// inputs that follow are 32 bytes each.
//
// The hardware signs REPORT_DATA. A match therefore authenticates the TLS
// fingerprint, the HPKE key, the client nonce, and the device evidence
// together, as one enclave's claim at one moment.
type ReportDataVerifier struct{}

// VerifyReportData checks that reportData matches the Tinfoil v3 binding.
//
// The nonce parameter is the authority for freshness. The value the enclave
// echoes is checked against it and never substituted for it.
func (ReportDataVerifier) VerifyReportData(reportData [64]byte, raw *attestation.RawAttestation, nonce attestation.Nonce) (string, error) {
	var zeros [32]byte
	if subtle.ConstantTimeCompare(reportData[32:], zeros[:]) != 1 {
		return "", fmt.Errorf("REPORTDATA[32:64] is not all zeros: %s", hex.EncodeToString(reportData[32:]))
	}

	responseNonce, err := hex.DecodeString(raw.Nonce)
	if err != nil {
		return "", fmt.Errorf("decode response nonce hex: %w", err)
	}
	if subtle.ConstantTimeCompare(responseNonce, nonce[:]) != 1 {
		return "", fmt.Errorf("nonce mismatch: attestation response nonce %q does not match client nonce",
			attestation.NoncePrefix(raw.Nonce))
	}

	cryptoHash, err := checkEndorsedSection("crypto_material",
		raw.TinfoilCryptoMaterialBytes, raw.TinfoilEndorsedCryptoHash)
	if err != nil {
		return "", err
	}
	deviceHash, err := checkEndorsedSection("device_evidence",
		raw.TinfoilDeviceEvidenceBytes, raw.TinfoilEndorsedDeviceHash)
	if err != nil {
		return "", err
	}

	expected := computeReportData(nonce[:], cryptoHash, deviceHash)
	if subtle.ConstantTimeCompare(expected[:], reportData[:]) != 1 {
		return "", fmt.Errorf("REPORTDATA = %s, expected %s",
			hex.EncodeToString(reportData[:]), hex.EncodeToString(expected[:]))
	}

	// challenge.report_data is the enclave's own statement of what it asked the
	// hardware to sign. The quote above already settled the question, so a
	// mismatch here means the document contradicts itself.
	expectedHex := hex.EncodeToString(expected[:])
	if subtle.ConstantTimeCompare([]byte(expectedHex), []byte(raw.TinfoilChallengeReportData)) != 1 {
		return "", fmt.Errorf("challenge.report_data %s does not match the verified REPORTDATA %s",
			raw.TinfoilChallengeReportData, expectedHex)
	}

	// The device_evidence hash is in REPORT_DATA, so GPU evidence, when the
	// enclave reports any, is bound to this quote.
	return fmt.Sprintf("v3: reportdata_hash verified, nonce_bound=true, gpu_bound=%t", raw.NvidiaPayload != ""), nil
}

// checkEndorsedSection recomputes the hash of one endorsed section and checks
// it against the hash the enclave bound into REPORT_DATA. It returns the
// recomputed hash, which is the value the caller must use.
//
// The hash covers the exact base64-decoded section bytes. Re-serializing the
// section produces different bytes and therefore a different hash.
func checkEndorsedSection(name string, sectionBytes []byte, endorsedHex string) ([]byte, error) {
	if len(sectionBytes) == 0 {
		return nil, fmt.Errorf("%s section bytes are absent", name)
	}
	computed := sha256.Sum256(sectionBytes)
	computedHex := hex.EncodeToString(computed[:])
	if subtle.ConstantTimeCompare([]byte(computedHex), []byte(endorsedHex)) != 1 {
		return nil, fmt.Errorf("%s hash %s does not match cpu_evidence.endorsed %s",
			name, computedHex, endorsedHex)
	}
	return computed[:], nil
}

// computeReportData derives the 64-byte REPORT_DATA. The inputs must be 32
// bytes each; the caller has already checked every one.
func computeReportData(nonce, cryptoMaterialHash, deviceEvidenceHash []byte) [64]byte {
	h := sha256.New()
	h.Write([]byte(ReportDataV1Algorithm))
	h.Write(nonce)
	h.Write(cryptoMaterialHash)
	h.Write(deviceEvidenceHash)

	var out [64]byte
	copy(out[:32], h.Sum(nil))
	return out
}

// TDX policy constants for Tinfoil.
//
// These values are the little-endian uint64 interpretation of the raw
// TDX quote bytes, matching the Tinfoil SPEC §4.8 defaults:
//   - TD_ATTRIBUTES: 0000001000000000 (raw bytes) = SEPT_VE_DISABLE only
//   - XFAM: e702060000000000 (raw bytes) = FP+SSE+required features
//
// The TDX quote stores TD_ATTRIBUTES and XFAM as 8-byte little-endian
// fields. binary.LittleEndian.Uint64() reads the raw bytes into a uint64,
// so the constants must be the LE-interpreted values, not the big-endian
// hex display.
var (
	expectedTDAttributes uint64 = 0x0000000010000000
	expectedXFAM         uint64 = 0x00000000000602e7

	// minTeeTCBSVN is the minimum TEE_TCB_SVN (16 bytes).
	minTeeTCBSVN = [16]byte{0x03, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

// TDXPolicyResult holds the results of Tinfoil-specific TDX policy checks.
// Checked: TDAttributes, XFAM, MRConfigID, MROwner, MROwnerConfig,
// RTMR3, TeeTCBSVN, MRSeam.
type TDXPolicyResult struct {
	TDAttributesErr  error
	XFAMErr          error
	MRConfigIDErr    error
	MROwnerErr       error
	MROwnerConfigErr error
	RTMR3Err         error
	TeeTCBSVNErr     error
	MRSeamErr        error
}

// Err returns a combined error from all checked policy fields, or nil if all pass.
func (r *TDXPolicyResult) Err() error {
	return errors.Join(
		r.TDAttributesErr,
		r.XFAMErr,
		r.MRConfigIDErr,
		r.MROwnerErr,
		r.MROwnerConfigErr,
		r.RTMR3Err,
		r.TeeTCBSVNErr,
		r.MRSeamErr,
	)
}

// CheckTDXPolicy performs Tinfoil-specific TDX policy checks on the quote fields.
// mrSeamAllow is the set of accepted MR_SEAM hex values (Intel TDX module hashes).
// These checks are only applicable for the TDX platform.
func CheckTDXPolicy(tdx *attestation.TDXVerifyResult, mrSeamAllow map[string]struct{}) *TDXPolicyResult {
	result := &TDXPolicyResult{}

	// TD_ATTRIBUTES must match expected value.
	if len(tdx.TDAttributes) >= 8 {
		got := binary.LittleEndian.Uint64(tdx.TDAttributes[:8])
		if got != expectedTDAttributes {
			result.TDAttributesErr = fmt.Errorf("TD_ATTRIBUTES = 0x%016x, want 0x%016x", got, expectedTDAttributes)
		}
	} else {
		result.TDAttributesErr = fmt.Errorf("TD_ATTRIBUTES has %d bytes, want at least 8", len(tdx.TDAttributes))
	}

	// XFAM must match expected value.
	if len(tdx.XFAM) >= 8 {
		got := binary.LittleEndian.Uint64(tdx.XFAM[:8])
		if got != expectedXFAM {
			result.XFAMErr = fmt.Errorf("XFAM = 0x%016x, want 0x%016x", got, expectedXFAM)
		}
	} else {
		result.XFAMErr = fmt.Errorf("XFAM has %d bytes, want at least 8", len(tdx.XFAM))
	}

	// MR_CONFIG_ID must be all zeros.
	if !isAllZeros(tdx.MRConfigID) {
		result.MRConfigIDErr = fmt.Errorf("MR_CONFIG_ID is not all zeros: %s", hex.EncodeToString(tdx.MRConfigID))
	}

	// MR_OWNER must be all zeros.
	if !isAllZeros(tdx.MROwner) {
		result.MROwnerErr = fmt.Errorf("MR_OWNER is not all zeros: %s", hex.EncodeToString(tdx.MROwner))
	}

	// MR_OWNER_CONFIG must be all zeros.
	if !isAllZeros(tdx.MROwnerConfig) {
		result.MROwnerConfigErr = fmt.Errorf("MR_OWNER_CONFIG is not all zeros: %s", hex.EncodeToString(tdx.MROwnerConfig))
	}

	// RTMR3 must be all zeros.
	if !isAllZeros(tdx.RTMRs[3][:]) {
		result.RTMR3Err = fmt.Errorf("RTMR3 is not all zeros: %s", hex.EncodeToString(tdx.RTMRs[3][:]))
	}

	// TEE_TCB_SVN >= minimum.
	if len(tdx.TeeTCBSVN) < 16 {
		result.TeeTCBSVNErr = fmt.Errorf("TEE_TCB_SVN has %d bytes, want at least 16", len(tdx.TeeTCBSVN))
	} else if !tcbSVNGTE(tdx.TeeTCBSVN[:16], minTeeTCBSVN[:]) {
		result.TeeTCBSVNErr = fmt.Errorf("TEE_TCB_SVN %s < minimum %s",
			hex.EncodeToString(tdx.TeeTCBSVN[:16]), hex.EncodeToString(minTeeTCBSVN[:]))
	}

	// MR_SEAM must be in the Intel TDX module allowlist.
	if len(mrSeamAllow) == 0 {
		result.MRSeamErr = errors.New("no MR_SEAM allowlist configured")
	} else {
		mrSeamHex := hex.EncodeToString(tdx.MRSeam)
		if _, ok := mrSeamAllow[mrSeamHex]; !ok {
			result.MRSeamErr = fmt.Errorf("MR_SEAM not in allowlist: %s", mrSeamHex)
		}
	}

	return result
}

// isAllZeros returns true if every byte in b is zero (constant-time).
func isAllZeros(b []byte) bool {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	return subtle.ConstantTimeByteEq(acc, 0) == 1
}

// tcbSVNGTE returns true if a >= b byte-by-byte (each byte is an independent component).
func tcbSVNGTE(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := 1
	for i := range a {
		result &= subtle.ConstantTimeLessOrEq(int(b[i]), int(a[i]))
	}
	return result == 1
}
