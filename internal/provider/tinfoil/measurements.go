package tinfoil

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/13rac1/teep/internal/attestation"
)

// Predicate type URIs for Tinfoil Sigstore attestations.
const (
	PredicateMultiPlatform        = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
	PredicateHardwareMeasurements = "https://tinfoil.sh/predicate/hardware-measurements/v1"
)

// RouterRepo is the Sigstore GitHub repo for the Tinfoil confidential model
// router. The tinfoil_v3_cloud provider always verifies against this repo
// because it attests the router enclave, not per-model inference enclaves.
const RouterRepo = "tinfoilsh/confidential-model-router"

// KnownRepos lists the known Tinfoil configuration repo mappings.
var KnownRepos = []string{
	RouterRepo,
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

// HardwareMeasurementsPredicate is the in-toto predicate for
// hardware-measurements/v1. The predicate is a map of platform ID →
// measurement entry, not an array under an "entries" key.
type HardwareMeasurementsPredicate map[string]HardwareMeasurementEntry

// HardwareMeasurementEntry is a single entry in the hardware measurements
// predicate. The platform ID is the map key, not a field in the entry.
type HardwareMeasurementEntry struct {
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

// ParseHardwareMeasurements extracts hardware measurement entries from the
// predicate. The predicate is a map of platform ID → {mrtd, rtmr0}.
func ParseHardwareMeasurements(predicateBytes []byte) (map[string]HardwareMeasurementEntry, error) {
	var pred HardwareMeasurementsPredicate
	if err := json.Unmarshal(predicateBytes, &pred); err != nil {
		return nil, fmt.Errorf("unmarshal hardware measurements predicate: %w", err)
	}
	return pred, nil
}

// MatchHardwareMeasurements checks whether the enclave MRTD and RTMR0 match
// any entry in the hardware measurements map. TDX only. Returns the matching
// platform ID.
func MatchHardwareMeasurements(entries map[string]HardwareMeasurementEntry, enclave *EnclaveMeasurements) (string, error) {
	for id, e := range entries {
		if hexEqual(e.MRTD, enclave.MRTD) && hexEqual(e.RTMR0, enclave.RTMR0) {
			return id, nil
		}
	}
	return "", fmt.Errorf("no hardware measurement entry matches enclave MRTD=%s RTMR0=%s",
		enclave.MRTD, enclave.RTMR0)
}

// EnclaveMeasurementsFromTDX extracts EnclaveMeasurements from a TDX verification result.
func EnclaveMeasurementsFromTDX(tdx *attestation.TDXVerifyResult) *EnclaveMeasurements {
	return &EnclaveMeasurements{
		MRTD:     hex.EncodeToString(tdx.MRTD),
		RTMR0:    hex.EncodeToString(tdx.RTMRs[0][:]),
		RTMR1:    hex.EncodeToString(tdx.RTMRs[1][:]),
		RTMR2:    hex.EncodeToString(tdx.RTMRs[2][:]),
		RTMR3:    hex.EncodeToString(tdx.RTMRs[3][:]),
		Platform: "tdx",
	}
}

// EnclaveMeasurementsFromSEV extracts EnclaveMeasurements from a SEV-SNP verification result.
func EnclaveMeasurementsFromSEV(sev *attestation.SEVVerifyResult) *EnclaveMeasurements {
	return &EnclaveMeasurements{
		SEVMeasurement: hex.EncodeToString(sev.Measurement),
		Platform:       "sev-snp",
	}
}

// modelRepoMap maps Tinfoil model IDs to their Sigstore GitHub repos.
// Models not in this map fall back to the constructed convention:
// tinfoilsh/confidential-{model-slug-after-slash-lowercased}.
var modelRepoMap = map[string]string{
	"nomic-ai/nomic-embed-text-v1.5":           "tinfoilsh/confidential-nomic-embed-text",
	"fixie-ai/ultravox-v0_4-1B-v20250115":      "tinfoilsh/confidential-audio-processing",
	"mistralai/Mistral-Small-3.1-24B-Instruct": "tinfoilsh/confidential-voxtral-small-24b",
	"Qwen/Qwen3-VL-30B":                        "tinfoilsh/confidential-qwen3-vl-30b",
	"Qwen/Qwen3-TTS":                           "tinfoilsh/confidential-qwen3-tts",
}

// RepoForModel returns the Sigstore GitHub repo for a given model ID.
// Uses a known mapping table, falling back to the naming convention
// "tinfoilsh/confidential-{slug}" where slug is the lowercased part after
// the org prefix (e.g. "meta-llama/Llama-4-Scout" → "tinfoilsh/confidential-llama-4-scout").
// If the constructed repo doesn't exist, SigstoreVerifier.FetchAndVerify
// will fail closed.
func RepoForModel(model string) string {
	if repo, ok := modelRepoMap[model]; ok {
		return repo
	}
	// Convention: take the part after "/" (or the whole string), lowercase it.
	slug := model
	if i := strings.LastIndex(model, "/"); i >= 0 {
		slug = model[i+1:]
	}
	return "tinfoilsh/confidential-" + strings.ToLower(slug)
}

// RepoForProvider returns the Sigstore GitHub repo for supply chain
// verification based on the provider name and model. For tinfoil_v3_cloud,
// the router enclave is attested, so the repo is always the router repo.
// For tinfoil_v3_direct, the per-model inference enclave is attested, so
// the repo is resolved via RepoForModel.
func RepoForProvider(providerName, model string) string {
	switch providerName {
	case "tinfoil_v3_cloud":
		return RouterRepo
	case "tinfoil_v3_direct":
		return RepoForModel(model)
	default:
		return RepoForModel(model)
	}
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
