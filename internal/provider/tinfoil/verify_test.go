package tinfoil

import (
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

// validTDXForPolicy builds a TDXVerifyResult that passes all Tinfoil TDX policy checks.
func validTDXForPolicy() *attestation.TDXVerifyResult {
	tdAttrs := make([]byte, 8)
	binary.LittleEndian.PutUint64(tdAttrs, 0x0000001000000000)
	xfam := make([]byte, 8)
	binary.LittleEndian.PutUint64(xfam, 0xe702060000000000)
	return &attestation.TDXVerifyResult{
		TDAttributes:  tdAttrs,
		XFAM:          xfam,
		MRConfigID:    make([]byte, 48),
		MROwner:       make([]byte, 48),
		MROwnerConfig: make([]byte, 48),
		RTMRs:         [4][48]byte{},
		TeeTCBSVN: []byte{0x03, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
}

func TestCheckTDXPolicy_Valid(t *testing.T) {
	tdx := validTDXForPolicy()
	result := CheckTDXPolicy(tdx)
	if err := result.Err(); err != nil {
		t.Errorf("unexpected policy error: %v", err)
	}
}

func TestCheckTDXPolicy_WrongTDAttributes(t *testing.T) {
	tdx := validTDXForPolicy()
	binary.LittleEndian.PutUint64(tdx.TDAttributes, 0xFFFF)
	result := CheckTDXPolicy(tdx)
	if result.TDAttributesErr == nil {
		t.Error("expected TDAttributesErr for wrong TD_ATTRIBUTES")
	}
}

func TestCheckTDXPolicy_WrongXFAM(t *testing.T) {
	tdx := validTDXForPolicy()
	binary.LittleEndian.PutUint64(tdx.XFAM, 0xFFFF)
	result := CheckTDXPolicy(tdx)
	if result.XFAMErr == nil {
		t.Error("expected XFAMErr for wrong XFAM")
	}
}

func TestCheckTDXPolicy_EmptyTDAttributes(t *testing.T) {
	tdx := validTDXForPolicy()
	tdx.TDAttributes = nil
	result := CheckTDXPolicy(tdx)
	if result.TDAttributesErr == nil {
		t.Error("expected TDAttributesErr for empty TD_ATTRIBUTES")
	}
}

func TestCheckTDXPolicy_NonZeroMRConfigID(t *testing.T) {
	tdx := validTDXForPolicy()
	tdx.MRConfigID[0] = 0xFF
	result := CheckTDXPolicy(tdx)
	if result.MRConfigIDErr == nil {
		t.Error("expected MRConfigIDErr for non-zero MR_CONFIG_ID")
	}
}

func TestCheckTDXPolicy_NonZeroMROwner(t *testing.T) {
	tdx := validTDXForPolicy()
	tdx.MROwner[0] = 0xFF
	result := CheckTDXPolicy(tdx)
	if result.MROwnerErr == nil {
		t.Error("expected MROwnerErr for non-zero MR_OWNER")
	}
}

func TestCheckTDXPolicy_NonZeroMROwnerConfig(t *testing.T) {
	tdx := validTDXForPolicy()
	tdx.MROwnerConfig[0] = 0xFF
	result := CheckTDXPolicy(tdx)
	if result.MROwnerConfigErr == nil {
		t.Error("expected MROwnerConfigErr for non-zero MR_OWNER_CONFIG")
	}
}

func TestCheckTDXPolicy_NonZeroRTMR3(t *testing.T) {
	tdx := validTDXForPolicy()
	tdx.RTMRs[3][0] = 0xFF
	result := CheckTDXPolicy(tdx)
	if result.RTMR3Err == nil {
		t.Error("expected RTMR3Err for non-zero RTMR3")
	}
}

func TestCheckTDXPolicy_LowTeeTCBSVN(t *testing.T) {
	tdx := validTDXForPolicy()
	tdx.TeeTCBSVN = []byte{0x02, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	result := CheckTDXPolicy(tdx)
	if result.TeeTCBSVNErr == nil {
		t.Error("expected TeeTCBSVNErr for low TEE_TCB_SVN")
	}
}

func TestCheckTDXPolicy_EmptyTeeTCBSVN(t *testing.T) {
	tdx := validTDXForPolicy()
	tdx.TeeTCBSVN = nil
	result := CheckTDXPolicy(tdx)
	if result.TeeTCBSVNErr == nil {
		t.Error("expected TeeTCBSVNErr for empty TEE_TCB_SVN")
	}
}

func TestCheckTDXPolicy_HigherTeeTCBSVN(t *testing.T) {
	tdx := validTDXForPolicy()
	tdx.TeeTCBSVN = []byte{0x05, 0x02, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	result := CheckTDXPolicy(tdx)
	if result.TeeTCBSVNErr != nil {
		t.Errorf("unexpected TeeTCBSVNErr: %v", result.TeeTCBSVNErr)
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
