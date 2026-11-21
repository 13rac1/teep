package tinfoil

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
)

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

func TestTcbSVNGTE_MismatchedLengths(t *testing.T) {
	if tcbSVNGTE([]byte{1, 2}, []byte{1}) {
		t.Error("mismatched lengths should return false")
	}
	if tcbSVNGTE([]byte{1}, []byte{1, 2}) {
		t.Error("mismatched lengths should return false")
	}
}

// parsedDocument builds a document, parses it, and returns the RawAttestation
// with the REPORT_DATA a quote must carry.
func parsedDocument(t *testing.T, b *docBuilder) (raw *attestation.RawAttestation, reportData [64]byte) {
	t.Helper()
	body, reportData := b.build(t)
	raw, err := parseV3Document(body)
	if err != nil {
		t.Fatalf("parseV3Document: %v", err)
	}
	return raw, reportData
}

func TestVerifyReportData_Valid(t *testing.T) {
	b := newDocBuilder()
	raw, reportData := parsedDocument(t, b)

	detail, err := ReportDataVerifier{}.VerifyReportData(reportData, raw, b.nonce)
	if err != nil {
		t.Fatalf("VerifyReportData: %v", err)
	}
	if !strings.Contains(detail, "reportdata_hash verified") {
		t.Errorf("detail = %q, want it to report a verified hash", detail)
	}
}

// gpu_bound reports whether the REPORT_DATA-bound device_evidence section
// carries GPU evidence. The supply chain step reads it for cpu_gpu_chain.
func TestVerifyReportData_GPUBound(t *testing.T) {
	for _, gpus := range []int{0, 2} {
		b := newDocBuilder()
		for i := range gpus {
			b.deviceItems = append(b.deviceItems, gpuItem(b, fmt.Sprintf("gpu%d", i)))
		}
		raw, reportData := parsedDocument(t, b)
		detail, err := ReportDataVerifier{}.VerifyReportData(reportData, raw, b.nonce)
		if err != nil {
			t.Fatalf("VerifyReportData: %v", err)
		}
		want := fmt.Sprintf("gpu_bound=%t", gpus > 0)
		if !strings.Contains(detail, want) {
			t.Errorf("%d GPUs: detail = %q, want %s", gpus, detail, want)
		}
	}
}

// The client nonce is the authority for freshness. A document that echoes a
// different nonce must be rejected even when it is internally consistent.
func TestVerifyReportData_NonceMismatch(t *testing.T) {
	b := newDocBuilder()
	raw, reportData := parsedDocument(t, b)

	other := attestation.NewNonce()
	if _, err := (ReportDataVerifier{}).VerifyReportData(reportData, raw, other); err == nil {
		t.Fatal("VerifyReportData accepted a nonce the client did not choose")
	}
}

func TestVerifyReportData_NonZeroUpper32(t *testing.T) {
	b := newDocBuilder()
	raw, reportData := parsedDocument(t, b)
	reportData[63] = 1

	_, err := ReportDataVerifier{}.VerifyReportData(reportData, raw, b.nonce)
	if err == nil || !strings.Contains(err.Error(), "not all zeros") {
		t.Fatalf("error = %v, want a non-zero upper half rejection", err)
	}
}

// The quote is the authority. A REPORT_DATA the hardware did not sign must not
// verify, whatever the document says.
func TestVerifyReportData_QuoteMismatch(t *testing.T) {
	b := newDocBuilder()
	raw, reportData := parsedDocument(t, b)
	reportData[0] ^= 0xff

	_, err := ReportDataVerifier{}.VerifyReportData(reportData, raw, b.nonce)
	if err == nil || !strings.Contains(err.Error(), "REPORTDATA") {
		t.Fatalf("error = %v, want a REPORTDATA mismatch", err)
	}
}

// The endorsed hash covers the exact section bytes. Changing one byte after the
// enclave hashed them must break the binding.
func TestVerifyReportData_TamperedSection(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(raw *attestation.RawAttestation)
	}{
		{
			name: "crypto_material",
			tamper: func(raw *attestation.RawAttestation) {
				raw.TinfoilCryptoMaterialBytes[10] ^= 0xff
			},
		},
		{
			name: "device_evidence",
			tamper: func(raw *attestation.RawAttestation) {
				raw.TinfoilDeviceEvidenceBytes[10] ^= 0xff
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newDocBuilder()
			raw, reportData := parsedDocument(t, b)
			tt.tamper(raw)

			_, err := ReportDataVerifier{}.VerifyReportData(reportData, raw, b.nonce)
			if err == nil || !strings.Contains(err.Error(), "cpu_evidence.endorsed") {
				t.Fatalf("error = %v, want an endorsed hash mismatch", err)
			}
		})
	}
}

// An absent section cannot be hashed, so it cannot be bound.
func TestVerifyReportData_AbsentSectionBytes(t *testing.T) {
	b := newDocBuilder()
	raw, reportData := parsedDocument(t, b)
	raw.TinfoilCryptoMaterialBytes = nil

	_, err := ReportDataVerifier{}.VerifyReportData(reportData, raw, b.nonce)
	if err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("error = %v, want an absent section error", err)
	}
}

// challenge.report_data is the enclave's own statement. A document whose claim
// contradicts the verified quote is self-inconsistent and must be rejected.
func TestVerifyReportData_ChallengeContradictsQuote(t *testing.T) {
	b := newDocBuilder()
	raw, reportData := parsedDocument(t, b)
	raw.TinfoilChallengeReportData = strings.Repeat("0", reportDataLen)

	_, err := ReportDataVerifier{}.VerifyReportData(reportData, raw, b.nonce)
	if err == nil || !strings.Contains(err.Error(), "challenge.report_data") {
		t.Fatalf("error = %v, want a challenge.report_data mismatch", err)
	}
}

// The derivation must reproduce what a live enclave computed. This recomputes
// REPORT_DATA from the captured sections and nonce and compares it against the
// value in the captured document.
func TestComputeReportData_MatchesCapturedDocuments(t *testing.T) {
	for _, path := range []string{fixtureCloudRouter, fixtureDirectGPU} {
		t.Run(path, func(t *testing.T) {
			var doc v3Document
			if err := json.Unmarshal(readFixture(t, path), &doc); err != nil {
				t.Fatalf("unmarshal fixture: %v", err)
			}
			cryptoBytes, err := base64.StdEncoding.DecodeString(doc.CryptoMaterial)
			if err != nil {
				t.Fatalf("decode crypto_material: %v", err)
			}
			deviceBytes, err := base64.StdEncoding.DecodeString(doc.DeviceEvidence)
			if err != nil {
				t.Fatalf("decode device_evidence: %v", err)
			}
			nonce, err := hex.DecodeString(doc.Challenge.Nonce)
			if err != nil {
				t.Fatalf("decode nonce: %v", err)
			}

			cryptoHash := sha256.Sum256(cryptoBytes)
			deviceHash := sha256.Sum256(deviceBytes)
			got := computeReportData(nonce, cryptoHash[:], deviceHash[:])

			if hex.EncodeToString(got[:]) != doc.Challenge.ReportData {
				t.Errorf("computed REPORT_DATA %s, captured %s",
					hex.EncodeToString(got[:]), doc.Challenge.ReportData)
			}
		})
	}
}
