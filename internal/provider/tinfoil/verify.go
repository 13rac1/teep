package tinfoil

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/13rac1/teep/internal/attestation"
)

// ReportDataVerifier validates the Tinfoil V3 REPORTDATA binding scheme:
//
//	REPORTDATA[0:32] = SHA-256(tls_key_fp || hpke_key || nonce || gpu_evidence_hash || nvswitch_evidence_hash)
//	REPORTDATA[32:64] = all zeros
//
// Where each field is the 32-byte decoded hex value, and nvswitch_evidence_hash
// contributes zero bytes (empty) if NVSwitch is absent.
type ReportDataVerifier struct{}

// VerifyReportData checks that reportData matches the Tinfoil V3 binding.
func (ReportDataVerifier) VerifyReportData(reportData [64]byte, raw *attestation.RawAttestation, nonce attestation.Nonce) (string, error) {
	// Verify REPORTDATA[32:64] is all zeros.
	var zeros [32]byte
	if subtle.ConstantTimeCompare(reportData[32:], zeros[:]) != 1 {
		return "", fmt.Errorf("REPORTDATA[32:64] is not all zeros: %s", hex.EncodeToString(reportData[32:]))
	}

	// Verify nonce matches (constant-time, decoded bytes per spec).
	responseNonce, err := hex.DecodeString(raw.Nonce)
	if err != nil {
		return "", fmt.Errorf("decode response nonce hex: %w", err)
	}
	if subtle.ConstantTimeCompare(responseNonce, nonce[:]) != 1 {
		return "", fmt.Errorf("nonce mismatch: attestation response nonce %q does not match client nonce",
			attestation.NoncePrefix(raw.Nonce))
	}

	// GPU evidence is required per spec. When absent, REPORTDATA verification
	// still succeeds (the hash matches what the server computed) but gpu_bound
	// will be false, causing gpu-related factors to fail closed in BuildReport.
	hasGPU := raw.TinfoilGPUEvidenceHash != "" && len(raw.GPURawJSON) > 0
	nvswitchExpected := false
	nvswitchHashVerified := false
	if hasGPU {
		if err := verifyGPUEvidenceHash(raw); err != nil {
			return "", fmt.Errorf("GPU evidence hash verification: %w", err)
		}
		var nsErr error
		nvswitchExpected, nsErr = isNVSwitchExpected(raw.GPURawJSON)
		if nsErr != nil {
			return "", fmt.Errorf("NVSwitch normalization: %w", nsErr)
		}
		if nvswitchExpected {
			// Check NVSwitch evidence hash against raw JSON bytes. If this
			// fails (e.g. due to server-side JSON re-encoding), we still
			// proceed to verify the REPORTDATA hash using the reported
			// nvswitch_evidence_hash. This authenticates the TLS SPKI,
			// HPKE key, nonce, and GPU evidence hash via the hardware-signed
			// REPORTDATA, even when the NVSwitch hash binding is broken.
			// The nvswitch_binding factor will still fail closed.
			if err := verifyNVSwitchEvidenceHash(raw); err != nil {
				slog.Warn("NVSwitch evidence hash mismatch — proceeding with REPORTDATA verification using reported hash",
					"err", err)
			} else {
				nvswitchHashVerified = true
			}
		}
	}

	// Build the preimage using the reported hashes from report_data.
	// These are the values the server bound into REPORTDATA, so the
	// preimage should match what the hardware signed.
	preimage, err := buildReportDataPreimage(raw)
	if err != nil {
		return "", fmt.Errorf("build REPORTDATA preimage: %w", err)
	}

	expected := sha256.Sum256(preimage)
	if subtle.ConstantTimeCompare(expected[:], reportData[:32]) != 1 {
		return "", fmt.Errorf("REPORTDATA[0:32] = %s, expected SHA-256(preimage) = %s",
			hex.EncodeToString(reportData[:32]), hex.EncodeToString(expected[:]))
	}

	detail := "v3: reportdata_hash verified, nonce_bound=true"
	if hasGPU {
		detail += ", gpu_bound=true"
		if nvswitchExpected {
			if nvswitchHashVerified {
				detail += ", nvswitch_bound=true"
			} else {
				detail += ", nvswitch_bound=false"
			}
		}
	} else {
		detail += ", gpu_bound=false"
	}
	return detail, nil
}

// buildReportDataPreimage constructs the hash preimage for REPORTDATA[0:32].
// The preimage is: tls_key_fp || hpke_key || nonce [|| gpu_hash [|| nvswitch_hash]]
// GPU and NVSwitch hashes are included when present in the attestation response.
// The preimage must match what the server computed to verify REPORTDATA binding.
func buildReportDataPreimage(raw *attestation.RawAttestation) ([]byte, error) {
	tlsKeyFP, err := hex.DecodeString(raw.TinfoilTLSKeyFP)
	if err != nil {
		return nil, fmt.Errorf("decode tls_key_fp: %w", err)
	}
	hpkeKey, err := hex.DecodeString(raw.TinfoilHPKEKey)
	if err != nil {
		return nil, fmt.Errorf("decode hpke_key: %w", err)
	}
	nonceBytes, err := hex.DecodeString(raw.TinfoilNonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	const fieldSize = 32
	preimage := make([]byte, 0, 5*fieldSize)
	preimage = append(preimage, tlsKeyFP...)
	preimage = append(preimage, hpkeKey...)
	preimage = append(preimage, nonceBytes...)

	if raw.TinfoilGPUEvidenceHash != "" {
		gpuHash, err := hex.DecodeString(raw.TinfoilGPUEvidenceHash)
		if err != nil {
			return nil, fmt.Errorf("decode gpu_evidence_hash: %w", err)
		}
		preimage = append(preimage, gpuHash...)
	}
	if raw.TinfoilNVSwitchEvidenceHash != "" {
		nvswitchHash, err := hex.DecodeString(raw.TinfoilNVSwitchEvidenceHash)
		if err != nil {
			return nil, fmt.Errorf("decode nvswitch_evidence_hash: %w", err)
		}
		preimage = append(preimage, nvswitchHash...)
	}

	return preimage, nil
}

// verifyGPUEvidenceHash checks that report_data.gpu_evidence_hash matches
// SHA-256 of the raw GPU JSON bytes.
func verifyGPUEvidenceHash(raw *attestation.RawAttestation) error {
	if len(raw.GPURawJSON) == 0 {
		return errors.New("gpu field is empty")
	}

	computed := sha256.Sum256(raw.GPURawJSON)
	computedHex := hex.EncodeToString(computed[:])

	if subtle.ConstantTimeCompare([]byte(computedHex), []byte(raw.TinfoilGPUEvidenceHash)) != 1 {
		return fmt.Errorf("gpu_evidence_hash mismatch: computed %s, reported %s",
			computedHex, raw.TinfoilGPUEvidenceHash)
	}
	return nil
}

// verifyNVSwitchEvidenceHash checks that report_data.nvswitch_evidence_hash
// matches SHA-256 of the raw NVSwitch JSON bytes.
func verifyNVSwitchEvidenceHash(raw *attestation.RawAttestation) error {
	if len(raw.NVSwitchRawJSON) == 0 {
		return errors.New("nvswitch field is empty but nvswitch_expected=true")
	}
	if raw.TinfoilNVSwitchEvidenceHash == "" {
		return errors.New("nvswitch_evidence_hash is empty but nvswitch_expected=true")
	}

	computed := sha256.Sum256(raw.NVSwitchRawJSON)
	computedHex := hex.EncodeToString(computed[:])

	if subtle.ConstantTimeCompare([]byte(computedHex), []byte(raw.TinfoilNVSwitchEvidenceHash)) != 1 {
		return fmt.Errorf("nvswitch_evidence_hash mismatch: computed %s, reported %s",
			computedHex, raw.TinfoilNVSwitchEvidenceHash)
	}
	return nil
}

// isNVSwitchExpected determines whether NVSwitch evidence is expected based on
// the GPU evidence array. The normalization algorithm:
//  1. Parse GPU JSON, require "evidences" array
//  2. gpu_count = len(evidences)
//  3. Inspect arch values
//  4. If gpu_count == 8 AND any arch is unrecognized: fail closed
//  5. If gpu_count == 8 AND at least one arch is HOPPER: nvswitch_expected = true
//  6. Otherwise: nvswitch_expected = false
//  7. Malformed gpu evidences: fail closed
func isNVSwitchExpected(gpuRawJSON []byte) (bool, error) {
	if len(gpuRawJSON) == 0 {
		return false, errors.New("gpu field is empty")
	}

	var gpu v3GPUEvidences
	if err := json.Unmarshal(gpuRawJSON, &gpu); err != nil {
		return false, fmt.Errorf("malformed gpu evidences: %w", err)
	}

	gpuCount := len(gpu.Evidences)
	if gpuCount != 8 {
		return false, nil
	}

	hasHopper := false
	for _, e := range gpu.Evidences {
		switch e.Arch {
		case ArchHopper:
			hasHopper = true
		case ArchBlackwell:
			// known, continue
		default:
			return false, fmt.Errorf("8-GPU config with unrecognized arch %q: fail closed", e.Arch)
		}
	}

	return hasHopper, nil
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
