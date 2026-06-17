package tinfoil

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Predicate type URIs for Tinfoil Sigstore attestations.
const (
	PredicateMultiPlatform        = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
	PredicateHardwareMeasurements = "https://tinfoil.sh/predicate/hardware-measurements/v1"
)

// Known configuration repo mappings.
var KnownRepos = []string{
	"tinfoilsh/confidential-model-router",
	"tinfoilsh/confidential-nomic-embed-text",
	"tinfoilsh/confidential-audio-processing",
	"tinfoilsh/confidential-voxtral-small-24b",
	"tinfoilsh/confidential-qwen3-vl-30b",
	"tinfoilsh/confidential-qwen3-tts",
}

// MultiPlatformPredicate is the in-toto predicate for snp-tdx-multiplatform/v1.
type MultiPlatformPredicate struct {
	SNPMeasurement string         `json:"snp_measurement"`
	TDXMeasurement TDXMeasurement `json:"tdx_measurement"`
}

// TDXMeasurement holds the TDX-specific measurements from a multi-platform predicate.
type TDXMeasurement struct {
	RTMR1 string `json:"rtmr1"`
	RTMR2 string `json:"rtmr2"`
}

// HardwareMeasurementsPredicate is the in-toto predicate for hardware-measurements/v1.
type HardwareMeasurementsPredicate struct {
	Entries []HardwareMeasurementEntry `json:"entries"`
}

// HardwareMeasurementEntry is a single entry in the hardware measurements predicate.
type HardwareMeasurementEntry struct {
	ID    string `json:"id"`
	MRTD  string `json:"mrtd"`
	RTMR0 string `json:"rtmr0"`
}

// CodeMeasurements holds the measurements extracted from a multi-platform predicate.
// Register indices follow the predicate schema:
//   - Register 0: snp_measurement
//   - Register 1: tdx_measurement.rtmr1
//   - Register 2: tdx_measurement.rtmr2
type CodeMeasurements struct {
	SNPMeasurement string // register 0
	RTMR1          string // register 1
	RTMR2          string // register 2
}

// ParseMultiPlatformPredicate extracts code measurements from a multi-platform predicate.
func ParseMultiPlatformPredicate(predicateBytes []byte) (*CodeMeasurements, error) {
	var pred MultiPlatformPredicate
	if err := json.Unmarshal(predicateBytes, &pred); err != nil {
		return nil, fmt.Errorf("unmarshal multi-platform predicate: %w", err)
	}
	return &CodeMeasurements{
		SNPMeasurement: pred.SNPMeasurement,
		RTMR1:          pred.TDXMeasurement.RTMR1,
		RTMR2:          pred.TDXMeasurement.RTMR2,
	}, nil
}

// EnclaveMeasurements holds the measurements from a TDX or SEV-SNP enclave.
type EnclaveMeasurements struct {
	// TDX fields (hex-encoded, 96 chars = 48 bytes for SHA-384).
	MRTD  string // register 0
	RTMR0 string // register 1
	RTMR1 string // register 2 (maps from code register 1)
	RTMR2 string // register 3 (maps from code register 2)
	RTMR3 string // register 4 (must be zeros for TDX)

	// SEV-SNP fields.
	SEVMeasurement string // 48-byte launch measurement (hex)

	Platform string // "tdx" or "sev-snp"
}

// CompareMultiPlatformTDX compares code measurements against TDX enclave measurements.
// Code register 1 (RTMR1) == enclave register 2 (RTMR1)
// Code register 2 (RTMR2) == enclave register 3 (RTMR2)
// Also verifies RTMR3 == 0.
func CompareMultiPlatformTDX(code *CodeMeasurements, enclave *EnclaveMeasurements) error {
	// Code RTMR1 == enclave RTMR1 (enclave register index 2, but stored in RTMRs[1]).
	if !hexEqual(code.RTMR1, enclave.RTMR1) {
		return fmt.Errorf("RTMR1 mismatch: code=%s enclave=%s", code.RTMR1, enclave.RTMR1)
	}

	// Code RTMR2 == enclave RTMR2 (enclave register index 3, but stored in RTMRs[2]).
	if !hexEqual(code.RTMR2, enclave.RTMR2) {
		return fmt.Errorf("RTMR2 mismatch: code=%s enclave=%s", code.RTMR2, enclave.RTMR2)
	}

	// Verify RTMR3 is all zeros.
	rtmr3Bytes, err := hex.DecodeString(enclave.RTMR3)
	if err != nil {
		return fmt.Errorf("decode enclave RTMR3: %w", err)
	}
	if !isAllZeros(rtmr3Bytes) {
		return fmt.Errorf("RTMR3 is not all zeros: %s", enclave.RTMR3)
	}

	return nil
}

// CompareMultiPlatformSEVSNP compares code measurements against SEV-SNP enclave measurements.
// Code register 0 (snp_measurement) == enclave measurement.
func CompareMultiPlatformSEVSNP(code *CodeMeasurements, enclave *EnclaveMeasurements) error {
	if !hexEqual(code.SNPMeasurement, enclave.SEVMeasurement) {
		return fmt.Errorf("SEV-SNP measurement mismatch: code=%s enclave=%s",
			code.SNPMeasurement, enclave.SEVMeasurement)
	}
	return nil
}

// ParseHardwareMeasurements extracts hardware measurement entries from the predicate.
func ParseHardwareMeasurements(predicateBytes []byte) ([]HardwareMeasurementEntry, error) {
	var pred HardwareMeasurementsPredicate
	if err := json.Unmarshal(predicateBytes, &pred); err != nil {
		return nil, fmt.Errorf("unmarshal hardware measurements predicate: %w", err)
	}
	return pred.Entries, nil
}

// MatchHardwareMeasurements checks whether the enclave MRTD and RTMR0 match
// any entry in the hardware measurements list. TDX only.
func MatchHardwareMeasurements(entries []HardwareMeasurementEntry, enclave *EnclaveMeasurements) (string, error) {
	for _, e := range entries {
		if hexEqual(e.MRTD, enclave.MRTD) && hexEqual(e.RTMR0, enclave.RTMR0) {
			return e.ID, nil
		}
	}
	return "", fmt.Errorf("no hardware measurement entry matches enclave MRTD=%s RTMR0=%s",
		enclave.MRTD, enclave.RTMR0)
}

// hexEqual compares two hex strings constant-time after normalization.
func hexEqual(a, b string) bool {
	aBytes, err := hex.DecodeString(a)
	if err != nil {
		return false
	}
	bBytes, err := hex.DecodeString(b)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1
}
