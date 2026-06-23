package tinfoil

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
)

// makeHex48 returns a 96-char hex string (48 bytes) filled with b.
func makeHex48(b byte) string {
	var buf [48]byte
	for i := range buf {
		buf[i] = b
	}
	return hex.EncodeToString(buf[:])
}

func TestParseMultiPlatformPredicate(t *testing.T) {
	pred := MultiPlatformPredicate{
		SNPMeasurement: makeHex48(0x01),
		TDXMeasurement: TDXMeasurement{
			RTMR1: makeHex48(0x02),
			RTMR2: makeHex48(0x03),
		},
	}
	data, err := json.Marshal(pred)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	result, err := ParseMultiPlatformPredicate(data)
	if err != nil {
		t.Fatalf("ParseMultiPlatformPredicate failed: %v", err)
	}

	if result.SNPMeasurement != makeHex48(0x01) {
		t.Errorf("SNPMeasurement = %q, want %q", result.SNPMeasurement, makeHex48(0x01))
	}
	if result.RTMR1 != makeHex48(0x02) {
		t.Errorf("RTMR1 = %q, want %q", result.RTMR1, makeHex48(0x02))
	}
	if result.RTMR2 != makeHex48(0x03) {
		t.Errorf("RTMR2 = %q, want %q", result.RTMR2, makeHex48(0x03))
	}
}

func TestParseMultiPlatformPredicate_InvalidJSON(t *testing.T) {
	_, err := ParseMultiPlatformPredicate([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestCompareMultiPlatformTDX_Match(t *testing.T) {
	code := &CodeMeasurements{
		RTMR1: makeHex48(0x02),
		RTMR2: makeHex48(0x03),
	}
	enclave := &EnclaveMeasurements{
		RTMR1: makeHex48(0x02),
		RTMR2: makeHex48(0x03),
		RTMR3: makeHex48(0x00), // all zeros
	}

	err := CompareMultiPlatformTDX(code, enclave)
	if err != nil {
		t.Fatalf("CompareMultiPlatformTDX failed: %v", err)
	}
}

func TestCompareMultiPlatformTDX_RTMR1Mismatch(t *testing.T) {
	code := &CodeMeasurements{
		RTMR1: makeHex48(0x02),
		RTMR2: makeHex48(0x03),
	}
	enclave := &EnclaveMeasurements{
		RTMR1: makeHex48(0xFF), // different
		RTMR2: makeHex48(0x03),
		RTMR3: makeHex48(0x00),
	}

	err := CompareMultiPlatformTDX(code, enclave)
	if err == nil {
		t.Fatal("expected error for RTMR1 mismatch")
	}
	if !strings.Contains(err.Error(), "RTMR1 mismatch") {
		t.Errorf("error %q should mention RTMR1 mismatch", err)
	}
}

func TestCompareMultiPlatformTDX_RTMR2Mismatch(t *testing.T) {
	code := &CodeMeasurements{
		RTMR1: makeHex48(0x02),
		RTMR2: makeHex48(0x03),
	}
	enclave := &EnclaveMeasurements{
		RTMR1: makeHex48(0x02),
		RTMR2: makeHex48(0xFF), // different
		RTMR3: makeHex48(0x00),
	}

	err := CompareMultiPlatformTDX(code, enclave)
	if err == nil {
		t.Fatal("expected error for RTMR2 mismatch")
	}
	if !strings.Contains(err.Error(), "RTMR2 mismatch") {
		t.Errorf("error %q should mention RTMR2 mismatch", err)
	}
}

func TestCompareMultiPlatformTDX_NonZeroRTMR3(t *testing.T) {
	code := &CodeMeasurements{
		RTMR1: makeHex48(0x02),
		RTMR2: makeHex48(0x03),
	}
	enclave := &EnclaveMeasurements{
		RTMR1: makeHex48(0x02),
		RTMR2: makeHex48(0x03),
		RTMR3: makeHex48(0x01), // non-zero!
	}

	err := CompareMultiPlatformTDX(code, enclave)
	if err == nil {
		t.Fatal("expected error for non-zero RTMR3")
	}
	if !strings.Contains(err.Error(), "RTMR3") {
		t.Errorf("error %q should mention RTMR3", err)
	}
}

func TestCompareMultiPlatformSEVSNP_Match(t *testing.T) {
	code := &CodeMeasurements{
		SNPMeasurement: makeHex48(0xAA),
	}
	enclave := &EnclaveMeasurements{
		SEVMeasurement: makeHex48(0xAA),
	}

	err := CompareMultiPlatformSEVSNP(code, enclave)
	if err != nil {
		t.Fatalf("CompareMultiPlatformSEVSNP failed: %v", err)
	}
}

func TestCompareMultiPlatformSEVSNP_Mismatch(t *testing.T) {
	code := &CodeMeasurements{
		SNPMeasurement: makeHex48(0xAA),
	}
	enclave := &EnclaveMeasurements{
		SEVMeasurement: makeHex48(0xBB),
	}

	err := CompareMultiPlatformSEVSNP(code, enclave)
	if err == nil {
		t.Fatal("expected error for SEV-SNP measurement mismatch")
	}
}

func TestParseHardwareMeasurements(t *testing.T) {
	pred := HardwareMeasurementsPredicate{
		"hw-1": {MRTD: makeHex48(0x01), RTMR0: makeHex48(0x02)},
		"hw-2": {MRTD: makeHex48(0x03), RTMR0: makeHex48(0x04)},
	}
	data, err := json.Marshal(pred)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	entries, err := ParseHardwareMeasurements(data)
	if err != nil {
		t.Fatalf("ParseHardwareMeasurements failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if _, ok := entries["hw-1"]; !ok {
		t.Errorf("entries should contain key hw-1, got %d entries", len(entries))
	}
}

func TestParseHardwareMeasurements_InvalidJSON(t *testing.T) {
	_, err := ParseHardwareMeasurements([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestMatchHardwareMeasurements_Match(t *testing.T) {
	entries := HardwareMeasurementsPredicate{
		"hw-1": {MRTD: makeHex48(0x01), RTMR0: makeHex48(0x02)},
		"hw-2": {MRTD: makeHex48(0x03), RTMR0: makeHex48(0x04)},
	}
	enclave := &EnclaveMeasurements{
		MRTD:  makeHex48(0x03),
		RTMR0: makeHex48(0x04),
	}

	id, err := MatchHardwareMeasurements(entries, enclave)
	if err != nil {
		t.Fatalf("MatchHardwareMeasurements failed: %v", err)
	}
	if id != "hw-2" {
		t.Errorf("matched ID = %q, want hw-2", id)
	}
}

func TestMatchHardwareMeasurements_NoMatch(t *testing.T) {
	entries := HardwareMeasurementsPredicate{
		"hw-1": {MRTD: makeHex48(0x01), RTMR0: makeHex48(0x02)},
	}
	enclave := &EnclaveMeasurements{
		MRTD:  makeHex48(0xFF),
		RTMR0: makeHex48(0xFF),
	}

	_, err := MatchHardwareMeasurements(entries, enclave)
	if err == nil {
		t.Fatal("expected error when no entries match")
	}
}

func TestMatchHardwareMeasurements_PartialMatch(t *testing.T) {
	// MRTD matches but RTMR0 does not.
	entries := HardwareMeasurementsPredicate{
		"hw-1": {MRTD: makeHex48(0x01), RTMR0: makeHex48(0x02)},
	}
	enclave := &EnclaveMeasurements{
		MRTD:  makeHex48(0x01),
		RTMR0: makeHex48(0xFF),
	}

	_, err := MatchHardwareMeasurements(entries, enclave)
	if err == nil {
		t.Fatal("expected error when only MRTD matches but not RTMR0")
	}
}

func TestHexEqual(t *testing.T) {
	a := makeHex48(0xAA)
	b := makeHex48(0xAA)
	c := makeHex48(0xBB)

	if !hexEqual(a, b) {
		t.Error("identical hex strings should be equal")
	}
	if hexEqual(a, c) {
		t.Error("different hex strings should not be equal")
	}
	if hexEqual("invalid", a) {
		t.Error("invalid hex should not be equal")
	}
	if hexEqual(a, "invalid") {
		t.Error("invalid hex should not be equal")
	}
}

func TestHexEqual_CaseInsensitive(t *testing.T) {
	lower := "aabbccdd"
	upper := "AABBCCDD"
	if !hexEqual(lower, upper) {
		t.Error("hex comparison should be case-insensitive")
	}
}

func TestKnownRepos(t *testing.T) {
	for _, repo := range KnownRepos {
		if !strings.HasPrefix(repo, "tinfoilsh/") {
			t.Errorf("repo %q should start with tinfoilsh/", repo)
		}
	}
}

func TestRepoForModel(t *testing.T) {
	tests := []struct {
		model string
		want  string
	}{
		// Known mapping overrides.
		{"nomic-ai/nomic-embed-text-v1.5", "tinfoilsh/confidential-nomic-embed-text"},
		{"fixie-ai/ultravox-v0_4-1B-v20250115", "tinfoilsh/confidential-audio-processing"},
		{"Qwen/Qwen3-VL-30B", "tinfoilsh/confidential-qwen3-vl-30b"},
		// Convention fallback: take part after /, lowercase.
		{"meta-llama/Llama-4-Scout", "tinfoilsh/confidential-llama-4-scout"},
		{"deepseek-ai/DeepSeek-R1-0528", "tinfoilsh/confidential-deepseek-r1-0528"},
		// No slash — whole string lowercased.
		{"gemma4-31b", "tinfoilsh/confidential-gemma4-31b"},
	}
	for _, tt := range tests {
		got := RepoForModel(tt.model)
		if got != tt.want {
			t.Errorf("RepoForModel(%q) = %q, want %q", tt.model, got, tt.want)
		}
	}
}

func TestRepoForProvider(t *testing.T) {
	tests := []struct {
		provider string
		model    string
		want     string
	}{
		// Cloud provider always uses the router repo, regardless of model.
		{"tinfoil_v3_cloud", "llama3-3-70b", RouterRepo},
		{"tinfoil_v3_cloud", "gemma4-31b", RouterRepo},
		{"tinfoil_v3_cloud", "any-model", RouterRepo},
		// Direct provider uses per-model repo.
		{"tinfoil_v3_direct", "gemma4-31b", "tinfoilsh/confidential-gemma4-31b"},
		{"tinfoil_v3_direct", "llama3-3-70b", "tinfoilsh/confidential-llama3-3-70b"},
		{"tinfoil_v3_direct", "nomic-ai/nomic-embed-text-v1.5", "tinfoilsh/confidential-nomic-embed-text"},
	}
	for _, tt := range tests {
		got := RepoForProvider(tt.provider, tt.model)
		if got != tt.want {
			t.Errorf("RepoForProvider(%q, %q) = %q, want %q", tt.provider, tt.model, got, tt.want)
		}
	}
}

func TestEnclaveMeasurementsFromTDX(t *testing.T) {
	tdx := &attestation.TDXVerifyResult{
		MRTD: mustDecodeHex(t, makeHex48(0x01)),
	}
	// Set RTMRs.
	copy(tdx.RTMRs[0][:], mustDecodeHex(t, makeHex48(0x10)))
	copy(tdx.RTMRs[1][:], mustDecodeHex(t, makeHex48(0x11)))
	copy(tdx.RTMRs[2][:], mustDecodeHex(t, makeHex48(0x12)))
	copy(tdx.RTMRs[3][:], mustDecodeHex(t, makeHex48(0x13)))

	em := EnclaveMeasurementsFromTDX(tdx)
	if em.Platform != "tdx" {
		t.Errorf("Platform = %q, want tdx", em.Platform)
	}
	if em.MRTD != makeHex48(0x01) {
		t.Errorf("MRTD mismatch")
	}
	if em.RTMR0 != makeHex48(0x10) {
		t.Errorf("RTMR0 mismatch")
	}
	if em.RTMR1 != makeHex48(0x11) {
		t.Errorf("RTMR1 mismatch")
	}
	if em.RTMR2 != makeHex48(0x12) {
		t.Errorf("RTMR2 mismatch")
	}
	if em.RTMR3 != makeHex48(0x13) {
		t.Errorf("RTMR3 mismatch")
	}
}

func TestEnclaveMeasurementsFromSEV(t *testing.T) {
	sev := &attestation.SEVVerifyResult{
		Measurement: mustDecodeHex(t, makeHex48(0xab)),
	}
	em := EnclaveMeasurementsFromSEV(sev)
	if em.Platform != "sev-snp" {
		t.Errorf("Platform = %q, want sev-snp", em.Platform)
	}
	if em.SEVMeasurement != makeHex48(0xab) {
		t.Errorf("SEVMeasurement mismatch")
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s[:16]+"...", err)
	}
	return b
}
