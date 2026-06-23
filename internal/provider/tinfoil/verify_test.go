package tinfoil

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
)

// makeRawForReportData builds a RawAttestation with the given fields for REPORTDATA testing.
func makeRawForReportData(t *testing.T, withNVSwitch bool) (*attestation.RawAttestation, attestation.Nonce, [64]byte) {
	t.Helper()

	nonce := attestation.NewNonce()
	tlsKeyFP := makeHex32(0x01)
	hpkeKey := makeHex32(0x02)

	gpu := []byte(`{"evidences":[{"arch":"HOPPER","certificate":"Y2VydA==","evidence":"ZXZpZA==","nonce":"` + makeHex32(0xaa) + `"}]}`)
	gpuHash := sha256.Sum256(gpu)
	gpuHashHex := hex.EncodeToString(gpuHash[:])

	var nvswitch []byte
	var nvswitchHashHex string
	if withNVSwitch {
		nvswitch = []byte(`{"evidences":["c3dpdGNo"]}`)
		nvswitchHash := sha256.Sum256(nvswitch)
		nvswitchHashHex = hex.EncodeToString(nvswitchHash[:])
	}

	raw := &attestation.RawAttestation{
		BackendFormat:               attestation.FormatTinfoil,
		Nonce:                       nonce.Hex(),
		TinfoilTLSKeyFP:             tlsKeyFP,
		TinfoilHPKEKey:              hpkeKey,
		TinfoilNonce:                nonce.Hex(),
		TinfoilGPUEvidenceHash:      gpuHashHex,
		TinfoilNVSwitchEvidenceHash: nvswitchHashHex,
		GPURawJSON:                  gpu,
		NVSwitchRawJSON:             nvswitch,
	}

	// Build the expected REPORTDATA.
	tlsBytes, _ := hex.DecodeString(tlsKeyFP)
	hpkeBytes, _ := hex.DecodeString(hpkeKey)
	nonceBytes := nonce[:]
	gpuHashBytes := gpuHash[:]

	preimage := make([]byte, 0, 128+32)
	preimage = append(preimage, tlsBytes...)
	preimage = append(preimage, hpkeBytes...)
	preimage = append(preimage, nonceBytes...)
	preimage = append(preimage, gpuHashBytes...)
	if withNVSwitch {
		nvswitchHash := sha256.Sum256(nvswitch)
		preimage = append(preimage, nvswitchHash[:]...)
	}

	hash := sha256.Sum256(preimage)
	var reportData [64]byte
	copy(reportData[:32], hash[:])
	// [32:64] stays zeros.

	return raw, nonce, reportData
}

func TestVerifyReportData_Valid(t *testing.T) {
	raw, nonce, reportData := makeRawForReportData(t, false)

	v := ReportDataVerifier{}
	detail, err := v.VerifyReportData(reportData, raw, nonce)
	if err != nil {
		t.Fatalf("VerifyReportData failed: %v", err)
	}
	if detail == "" {
		t.Error("expected non-empty detail string")
	}
	t.Logf("detail: %s", detail)
}

func TestVerifyReportData_ValidWithNVSwitch(t *testing.T) {
	raw, nonce, reportData := makeRawForReportData(t, true)

	// Need to build a GPU with 8 HOPPERs to trigger nvswitch expected.
	var gpu8Builder strings.Builder
	gpu8Builder.WriteString(`{"evidences":[`)
	for i := range 8 {
		if i > 0 {
			gpu8Builder.WriteString(",")
		}
		gpu8Builder.WriteString(`{"arch":"HOPPER","certificate":"Y2VydA==","evidence":"ZXZpZA==","nonce":"` + makeHex32(byte(i)) + `"}`)
	}
	gpu8Builder.WriteString(`]}`)
	gpu8 := gpu8Builder.String()
	gpuHash := sha256.Sum256([]byte(gpu8))
	raw.GPURawJSON = []byte(gpu8)
	raw.TinfoilGPUEvidenceHash = hex.EncodeToString(gpuHash[:])

	// Recalculate REPORTDATA.
	tlsBytes, _ := hex.DecodeString(raw.TinfoilTLSKeyFP)
	hpkeBytes, _ := hex.DecodeString(raw.TinfoilHPKEKey)
	nonceBytes, _ := hex.DecodeString(raw.TinfoilNonce)
	gpuHashBytes := gpuHash[:]
	nvswitchHash := sha256.Sum256(raw.NVSwitchRawJSON)

	preimage := make([]byte, 0, 160)
	preimage = append(preimage, tlsBytes...)
	preimage = append(preimage, hpkeBytes...)
	preimage = append(preimage, nonceBytes...)
	preimage = append(preimage, gpuHashBytes...)
	preimage = append(preimage, nvswitchHash[:]...)

	hash := sha256.Sum256(preimage)
	copy(reportData[:32], hash[:])

	v := ReportDataVerifier{}
	detail, err := v.VerifyReportData(reportData, raw, nonce)
	if err != nil {
		t.Fatalf("VerifyReportData failed: %v", err)
	}
	if detail == "" {
		t.Error("expected non-empty detail string")
	}
	t.Logf("detail: %s", detail)
}

func TestVerifyReportData_InvalidHash(t *testing.T) {
	raw, nonce, reportData := makeRawForReportData(t, false)

	// Corrupt the hash.
	reportData[0] ^= 0xFF

	v := ReportDataVerifier{}
	_, err := v.VerifyReportData(reportData, raw, nonce)
	if err == nil {
		t.Fatal("expected error for invalid REPORTDATA hash")
	}
}

func TestVerifyReportData_NonZeroUpper32(t *testing.T) {
	raw, nonce, reportData := makeRawForReportData(t, false)

	// Set REPORTDATA[32:64] to non-zero.
	reportData[32] = 0xFF

	v := ReportDataVerifier{}
	_, err := v.VerifyReportData(reportData, raw, nonce)
	if err == nil {
		t.Fatal("expected error for non-zero REPORTDATA[32:64]")
	}
}

func TestVerifyReportData_NonceMismatch(t *testing.T) {
	raw, _, reportData := makeRawForReportData(t, false)

	// Use a different nonce.
	differentNonce := attestation.NewNonce()

	v := ReportDataVerifier{}
	_, err := v.VerifyReportData(reportData, raw, differentNonce)
	if err == nil {
		t.Fatal("expected error for nonce mismatch")
	}
}

func TestVerifyGPUEvidenceHash_Valid(t *testing.T) {
	gpu := []byte(`{"evidences":[]}`)
	gpuHash := sha256.Sum256(gpu)

	raw := &attestation.RawAttestation{
		GPURawJSON:             gpu,
		TinfoilGPUEvidenceHash: hex.EncodeToString(gpuHash[:]),
	}

	if err := verifyGPUEvidenceHash(raw); err != nil {
		t.Fatalf("verifyGPUEvidenceHash failed: %v", err)
	}
}

func TestVerifyGPUEvidenceHash_Mismatch(t *testing.T) {
	gpu := []byte(`{"evidences":[]}`)

	raw := &attestation.RawAttestation{
		GPURawJSON:             gpu,
		TinfoilGPUEvidenceHash: makeHex32(0xFF), // wrong hash
	}

	if err := verifyGPUEvidenceHash(raw); err == nil {
		t.Fatal("expected error for GPU hash mismatch")
	}
}

func TestVerifyGPUEvidenceHash_EmptyGPU(t *testing.T) {
	raw := &attestation.RawAttestation{
		TinfoilGPUEvidenceHash: makeHex32(0x01),
	}

	if err := verifyGPUEvidenceHash(raw); err == nil {
		t.Fatal("expected error for empty GPU field")
	}
}

func TestIsNVSwitchExpected_SingleGPU(t *testing.T) {
	gpu := []byte(`{"evidences":[{"arch":"HOPPER","certificate":"","evidence":"","nonce":"` + makeHex32(0x01) + `"}]}`)
	expected, err := isNVSwitchExpected(gpu)
	if err != nil {
		t.Fatalf("isNVSwitchExpected failed: %v", err)
	}
	if expected {
		t.Error("single GPU should not expect NVSwitch")
	}
}

func TestIsNVSwitchExpected_8GPUHopper(t *testing.T) {
	gpu := buildGPUJSON(8, ArchHopper)
	expected, err := isNVSwitchExpected(gpu)
	if err != nil {
		t.Fatalf("isNVSwitchExpected failed: %v", err)
	}
	if !expected {
		t.Error("8-GPU HOPPER should expect NVSwitch")
	}
}

func TestIsNVSwitchExpected_8GPUBlackwell(t *testing.T) {
	gpu := buildGPUJSON(8, ArchBlackwell)
	expected, err := isNVSwitchExpected(gpu)
	if err != nil {
		t.Fatalf("isNVSwitchExpected failed: %v", err)
	}
	if expected {
		t.Error("8-GPU BLACKWELL should not expect NVSwitch")
	}
}

func TestIsNVSwitchExpected_8GPUMixedHopperBlackwell(t *testing.T) {
	// Mix of HOPPER and BLACKWELL — at least one HOPPER means nvswitch expected.
	var evBuilder strings.Builder
	evBuilder.WriteString("[")
	for i := range 8 {
		if i > 0 {
			evBuilder.WriteString(",")
		}
		arch := ArchBlackwell
		if i == 0 {
			arch = ArchHopper
		}
		evBuilder.Write(fmt.Appendf(nil, `{"arch":%q,"certificate":"","evidence":"","nonce":%q}`, arch, makeHex32(byte(i))))
	}
	evBuilder.WriteString("]")
	gpu := fmt.Appendf(nil, `{"evidences":%s}`, evBuilder.String())

	expected, err := isNVSwitchExpected(gpu)
	if err != nil {
		t.Fatalf("isNVSwitchExpected failed: %v", err)
	}
	if !expected {
		t.Error("8-GPU with at least one HOPPER should expect NVSwitch")
	}
}

func TestIsNVSwitchExpected_8GPUUnknownArch(t *testing.T) {
	gpu := buildGPUJSON(8, "UNKNOWN_ARCH")
	_, err := isNVSwitchExpected(gpu)
	if err == nil {
		t.Fatal("expected error for 8-GPU with unknown arch")
	}
}

func TestIsNVSwitchExpected_MalformedJSON(t *testing.T) {
	_, err := isNVSwitchExpected([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestIsNVSwitchExpected_EmptyGPU(t *testing.T) {
	_, err := isNVSwitchExpected(nil)
	if err == nil {
		t.Fatal("expected error for empty GPU")
	}
}

// buildGPUJSON builds a GPU evidences JSON with count GPUs all of the given arch.
func buildGPUJSON(count int, arch string) []byte {
	var evBuilder strings.Builder
	evBuilder.WriteString("[")
	for i := range count {
		if i > 0 {
			evBuilder.WriteString(",")
		}
		evBuilder.Write(fmt.Appendf(nil, `{"arch":%q,"certificate":"","evidence":"","nonce":%q}`, arch, makeHex32(byte(i))))
	}
	evBuilder.WriteString("]")
	return fmt.Appendf(nil, `{"evidences":%s}`, evBuilder.String())
}

// testMRSeam is a 48-byte MR_SEAM value used in policy tests.
var testMRSeam = bytes.Repeat([]byte{0xAA}, 48)

// testMRSeamAllow is an allowlist containing testMRSeam.
var testMRSeamAllow = map[string]struct{}{
	hex.EncodeToString(testMRSeam): {},
}

// validTDXForPolicy builds a TDXVerifyResult that passes all Tinfoil TDX policy checks.
// Uses the same LE uint64 constants as the production code to ensure the
// raw bytes match what binary.LittleEndian.Uint64 reads in CheckTDXPolicy.
func validTDXForPolicy() *attestation.TDXVerifyResult {
	tdAttrs := make([]byte, 8)
	binary.LittleEndian.PutUint64(tdAttrs, expectedTDAttributes)
	xfam := make([]byte, 8)
	binary.LittleEndian.PutUint64(xfam, expectedXFAM)
	return &attestation.TDXVerifyResult{
		TDAttributes:  tdAttrs,
		XFAM:          xfam,
		MRConfigID:    make([]byte, 48),
		MROwner:       make([]byte, 48),
		MROwnerConfig: make([]byte, 48),
		MRSeam:        append([]byte(nil), testMRSeam...),
		RTMRs:         [4][48]byte{},
		TeeTCBSVN: []byte{0x03, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
}

func TestCheckTDXPolicy_Valid(t *testing.T) {
	tdx := validTDXForPolicy()
	result := CheckTDXPolicy(tdx, testMRSeamAllow)
	if err := result.Err(); err != nil {
		t.Errorf("unexpected policy error: %v", err)
	}
}

func TestCheckTDXPolicy_WrongTDAttributes(t *testing.T) {
	tdx := validTDXForPolicy()
	binary.LittleEndian.PutUint64(tdx.TDAttributes, 0xFFFF)
	result := CheckTDXPolicy(tdx, testMRSeamAllow)
	if result.TDAttributesErr == nil {
		t.Error("expected TDAttributesErr for wrong TD_ATTRIBUTES")
	}
}

func TestCheckTDXPolicy_WrongXFAM(t *testing.T) {
	tdx := validTDXForPolicy()
	binary.LittleEndian.PutUint64(tdx.XFAM, 0xFFFF)
	result := CheckTDXPolicy(tdx, testMRSeamAllow)
	if result.XFAMErr == nil {
		t.Error("expected XFAMErr for wrong XFAM")
	}
}

func TestCheckTDXPolicy_EmptyTDAttributes(t *testing.T) {
	tdx := validTDXForPolicy()
	tdx.TDAttributes = nil
	result := CheckTDXPolicy(tdx, testMRSeamAllow)
	if result.TDAttributesErr == nil {
		t.Error("expected TDAttributesErr for empty TD_ATTRIBUTES")
	}
}

func TestCheckTDXPolicy_NonZeroMRConfigID(t *testing.T) {
	tdx := validTDXForPolicy()
	tdx.MRConfigID[0] = 0xFF
	result := CheckTDXPolicy(tdx, testMRSeamAllow)
	if result.MRConfigIDErr == nil {
		t.Error("expected MRConfigIDErr for non-zero MR_CONFIG_ID")
	}
}

func TestCheckTDXPolicy_NonZeroMROwner(t *testing.T) {
	tdx := validTDXForPolicy()
	tdx.MROwner[0] = 0xFF
	result := CheckTDXPolicy(tdx, testMRSeamAllow)
	if result.MROwnerErr == nil {
		t.Error("expected MROwnerErr for non-zero MR_OWNER")
	}
}

func TestCheckTDXPolicy_NonZeroMROwnerConfig(t *testing.T) {
	tdx := validTDXForPolicy()
	tdx.MROwnerConfig[0] = 0xFF
	result := CheckTDXPolicy(tdx, testMRSeamAllow)
	if result.MROwnerConfigErr == nil {
		t.Error("expected MROwnerConfigErr for non-zero MR_OWNER_CONFIG")
	}
}

func TestCheckTDXPolicy_NonZeroRTMR3(t *testing.T) {
	tdx := validTDXForPolicy()
	tdx.RTMRs[3][0] = 0xFF
	result := CheckTDXPolicy(tdx, testMRSeamAllow)
	if result.RTMR3Err == nil {
		t.Error("expected RTMR3Err for non-zero RTMR3")
	}
}

func TestCheckTDXPolicy_LowTeeTCBSVN(t *testing.T) {
	tdx := validTDXForPolicy()
	tdx.TeeTCBSVN = []byte{0x02, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	result := CheckTDXPolicy(tdx, testMRSeamAllow)
	if result.TeeTCBSVNErr == nil {
		t.Error("expected TeeTCBSVNErr for low TEE_TCB_SVN")
	}
}

func TestCheckTDXPolicy_EmptyTeeTCBSVN(t *testing.T) {
	tdx := validTDXForPolicy()
	tdx.TeeTCBSVN = nil
	result := CheckTDXPolicy(tdx, testMRSeamAllow)
	if result.TeeTCBSVNErr == nil {
		t.Error("expected TeeTCBSVNErr for empty TEE_TCB_SVN")
	}
}

func TestCheckTDXPolicy_HigherTeeTCBSVN(t *testing.T) {
	tdx := validTDXForPolicy()
	tdx.TeeTCBSVN = []byte{0x05, 0x02, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	result := CheckTDXPolicy(tdx, testMRSeamAllow)
	if result.TeeTCBSVNErr != nil {
		t.Errorf("unexpected TeeTCBSVNErr: %v", result.TeeTCBSVNErr)
	}
}

func TestCheckTDXPolicy_MRSeamMismatch(t *testing.T) {
	tdx := validTDXForPolicy()
	tdx.MRSeam = bytes.Repeat([]byte{0xBB}, 48)
	result := CheckTDXPolicy(tdx, testMRSeamAllow)
	if result.MRSeamErr == nil {
		t.Error("expected MRSeamErr for MR_SEAM not in allowlist")
	}
}

func TestCheckTDXPolicy_EmptyMRSeamAllow(t *testing.T) {
	tdx := validTDXForPolicy()
	result := CheckTDXPolicy(tdx, nil)
	if result.MRSeamErr == nil {
		t.Error("expected MRSeamErr for empty allowlist")
	}
}

func TestTDXPolicyResult_Err(t *testing.T) {
	result := &TDXPolicyResult{}
	if result.Err() != nil {
		t.Error("expected nil Err for all-passing policy")
	}
	result.MRConfigIDErr = errors.New("test error")
	if result.Err() == nil {
		t.Error("expected non-nil Err when a field has an error")
	}
}

func TestTDXPolicyResult_ErrIncludesMRSeam(t *testing.T) {
	result := &TDXPolicyResult{
		MRSeamErr: errors.New("MR_SEAM not in allowlist"),
	}
	if result.Err() == nil {
		t.Error("expected non-nil Err when MRSeamErr is set")
	}
}

func TestTcbSVNGTE(t *testing.T) {
	tests := []struct {
		a, b [16]byte
		want bool
	}{
		{[16]byte{3, 1, 2}, [16]byte{3, 1, 2}, true},  // equal
		{[16]byte{4, 1, 2}, [16]byte{3, 1, 2}, true},  // greater first byte
		{[16]byte{2, 1, 2}, [16]byte{3, 1, 2}, false}, // less first byte
		{[16]byte{3, 0, 2}, [16]byte{3, 1, 2}, false}, // less second byte
		{[16]byte{3, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, // last byte differs
			[16]byte{3, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, true},
	}

	for _, tt := range tests {
		got := tcbSVNGTE(tt.a[:], tt.b[:])
		if got != tt.want {
			t.Errorf("tcbSVNGTE(%x, %x) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestIsAllZeros(t *testing.T) {
	if !isAllZeros(make([]byte, 48)) {
		t.Error("48 zero bytes should be all zeros")
	}
	if !isAllZeros(nil) {
		t.Error("nil should be all zeros")
	}
	b := make([]byte, 48)
	b[47] = 1
	if isAllZeros(b) {
		t.Error("non-zero byte should not be all zeros")
	}
}

// ---------------------------------------------------------------------------
// buildReportDataPreimage — hex decode error paths
// ---------------------------------------------------------------------------

func TestBuildReportDataPreimage_InvalidTLSKeyFP(t *testing.T) {
	raw := &attestation.RawAttestation{TinfoilTLSKeyFP: "ZZZZ"}
	_, err := buildReportDataPreimage(raw)
	if err == nil {
		t.Fatal("expected error for invalid TLS key fp hex")
	}
}

func TestBuildReportDataPreimage_InvalidHPKEKey(t *testing.T) {
	raw := &attestation.RawAttestation{
		TinfoilTLSKeyFP: makeHex32(0x01),
		TinfoilHPKEKey:  "ZZZZ",
	}
	_, err := buildReportDataPreimage(raw)
	if err == nil {
		t.Fatal("expected error for invalid HPKE key hex")
	}
}

func TestBuildReportDataPreimage_InvalidNonce(t *testing.T) {
	raw := &attestation.RawAttestation{
		TinfoilTLSKeyFP: makeHex32(0x01),
		TinfoilHPKEKey:  makeHex32(0x02),
		TinfoilNonce:    "ZZZZ",
	}
	_, err := buildReportDataPreimage(raw)
	if err == nil {
		t.Fatal("expected error for invalid nonce hex")
	}
}

func TestBuildReportDataPreimage_InvalidGPUHash(t *testing.T) {
	raw := &attestation.RawAttestation{
		TinfoilTLSKeyFP:        makeHex32(0x01),
		TinfoilHPKEKey:         makeHex32(0x02),
		TinfoilNonce:           makeHex32(0x03),
		TinfoilGPUEvidenceHash: "not-hex",
	}
	_, err := buildReportDataPreimage(raw)
	if err == nil {
		t.Fatal("expected error for invalid GPU evidence hash hex")
	}
}

func TestBuildReportDataPreimage_InvalidNVSwitchHash(t *testing.T) {
	raw := &attestation.RawAttestation{
		TinfoilTLSKeyFP:             makeHex32(0x01),
		TinfoilHPKEKey:              makeHex32(0x02),
		TinfoilNonce:                makeHex32(0x03),
		TinfoilNVSwitchEvidenceHash: "not-hex",
	}
	_, err := buildReportDataPreimage(raw)
	if err == nil {
		t.Fatal("expected error for invalid NVSwitch evidence hash hex")
	}
}

// ---------------------------------------------------------------------------
// verifyNVSwitchEvidenceHash — all error branches
// ---------------------------------------------------------------------------

func TestVerifyNVSwitchEvidenceHash_EmptyJSON(t *testing.T) {
	raw := &attestation.RawAttestation{NVSwitchRawJSON: nil}
	err := verifyNVSwitchEvidenceHash(raw)
	if err == nil {
		t.Fatal("expected error for empty NVSwitch JSON")
	}
	if !strings.Contains(err.Error(), "nvswitch field is empty") {
		t.Errorf("error %q should mention nvswitch field is empty", err)
	}
}

func TestVerifyNVSwitchEvidenceHash_EmptyHash(t *testing.T) {
	raw := &attestation.RawAttestation{
		NVSwitchRawJSON:             []byte(`{"data":"test"}`),
		TinfoilNVSwitchEvidenceHash: "",
	}
	err := verifyNVSwitchEvidenceHash(raw)
	if err == nil {
		t.Fatal("expected error for empty NVSwitch evidence hash")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error %q should mention empty", err)
	}
}

func TestVerifyNVSwitchEvidenceHash_Mismatch(t *testing.T) {
	raw := &attestation.RawAttestation{
		NVSwitchRawJSON:             []byte(`{"data":"test"}`),
		TinfoilNVSwitchEvidenceHash: makeHex32(0xFF),
	}
	err := verifyNVSwitchEvidenceHash(raw)
	if err == nil {
		t.Fatal("expected error for NVSwitch hash mismatch")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error %q should mention mismatch", err)
	}
}

// ---------------------------------------------------------------------------
// tcbSVNGTE — mismatched lengths
// ---------------------------------------------------------------------------

func TestTcbSVNGTE_MismatchedLengths(t *testing.T) {
	if tcbSVNGTE([]byte{1, 2}, []byte{1}) {
		t.Error("mismatched lengths should return false")
	}
	if tcbSVNGTE([]byte{1}, []byte{1, 2}) {
		t.Error("mismatched lengths should return false")
	}
}

// ---------------------------------------------------------------------------
// VerifyReportData — GPU evidence hash mismatch
// ---------------------------------------------------------------------------

func TestVerifyReportData_GPUHashMismatch(t *testing.T) {
	raw, nonce, reportData := makeRawForReportData(t, false)
	// Set GPU hash to a wrong value while GPURawJSON is present.
	raw.TinfoilGPUEvidenceHash = makeHex32(0xFF)
	_, err := ReportDataVerifier{}.VerifyReportData(reportData, raw, nonce)
	if err == nil {
		t.Fatal("expected error for GPU evidence hash mismatch")
	}
}

// ---------------------------------------------------------------------------
// validateHexField — direct unit test
// ---------------------------------------------------------------------------

func TestValidateHexField_CorrectLenInvalidHex(t *testing.T) {
	err := validateHexField("test", strings.Repeat("ZZ", 32))
	if err == nil {
		t.Fatal("expected error for 64-char invalid hex")
	}
}

func TestValidateHexField_Valid(t *testing.T) {
	err := validateHexField("test", makeHex32(0xAB))
	if err != nil {
		t.Fatalf("unexpected error for valid hex: %v", err)
	}
}

// ---------------------------------------------------------------------------
// replaceSignatureValue — uncovered branches
// ---------------------------------------------------------------------------

func TestReplaceSignatureValue_NoClosingQuote(t *testing.T) {
	body := []byte(`{"signature":"ABCD`)
	_, err := replaceSignatureValue(body, "ABCD")
	if err == nil {
		t.Fatal("expected error for missing closing quote")
	}
}

func TestReplaceSignatureValue_ValueMismatch(t *testing.T) {
	body := []byte(`{"signature":"WRONG"}`)
	_, err := replaceSignatureValue(body, "RIGHT")
	if err == nil {
		t.Fatal("expected error for value mismatch")
	}
}

// ---------------------------------------------------------------------------
// verifyEnvelopeSignature — bad PEM, invalid DER
// ---------------------------------------------------------------------------

func TestVerifyEnvelopeSignature_NoPEM(t *testing.T) {
	resp := &v3Response{Certificate: "not a PEM block"}
	err := verifyEnvelopeSignature([]byte(`{}`), resp)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestVerifyEnvelopeSignature_InvalidDER(t *testing.T) {
	resp := &v3Response{
		Certificate: "-----BEGIN CERTIFICATE-----\nYmFkZGF0YQ==\n-----END CERTIFICATE-----",
	}
	err := verifyEnvelopeSignature([]byte(`{}`), resp)
	if err == nil {
		t.Fatal("expected error for invalid DER certificate")
	}
}
