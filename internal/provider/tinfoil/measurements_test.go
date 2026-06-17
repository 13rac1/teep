package tinfoil

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
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
		Entries: []HardwareMeasurementEntry{
			{ID: "hw-1", MRTD: makeHex48(0x01), RTMR0: makeHex48(0x02)},
			{ID: "hw-2", MRTD: makeHex48(0x03), RTMR0: makeHex48(0x04)},
		},
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
	if entries[0].ID != "hw-1" {
		t.Errorf("entries[0].ID = %q, want hw-1", entries[0].ID)
	}
}

func TestParseHardwareMeasurements_InvalidJSON(t *testing.T) {
	_, err := ParseHardwareMeasurements([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestMatchHardwareMeasurements_Match(t *testing.T) {
	entries := []HardwareMeasurementEntry{
		{ID: "hw-1", MRTD: makeHex48(0x01), RTMR0: makeHex48(0x02)},
		{ID: "hw-2", MRTD: makeHex48(0x03), RTMR0: makeHex48(0x04)},
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
	entries := []HardwareMeasurementEntry{
		{ID: "hw-1", MRTD: makeHex48(0x01), RTMR0: makeHex48(0x02)},
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
	entries := []HardwareMeasurementEntry{
		{ID: "hw-1", MRTD: makeHex48(0x01), RTMR0: makeHex48(0x02)},
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
