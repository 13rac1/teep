package tinfoil

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
)

// makeHex32 returns a 64-char hex string representing 32 bytes seeded by b.
func makeHex32(b byte) string {
	var buf [32]byte
	for i := range buf {
		buf[i] = b
	}
	return hex.EncodeToString(buf[:])
}

// makeValidV3JSON builds a valid V3 attestation JSON document.
func makeValidV3JSON(platform string) []byte {
	cpuReport := make([]byte, 64)
	for i := range cpuReport {
		cpuReport[i] = byte(i)
	}

	gpu := `{"evidences":[{"arch":"HOPPER","certificate":"Y2VydA==","evidence":"ZXZpZA==","nonce":"` + makeHex32(0xaa) + `"}]}`
	nvswitch := `{"evidences":["c3dpdGNo"]}`

	rd := v3ReportData{
		TLSKeyFP:             makeHex32(0x01),
		HPKEKey:              makeHex32(0x02),
		Nonce:                makeHex32(0x03),
		GPUEvidenceHash:      fmt.Sprintf("%x", sha256.Sum256([]byte(gpu))),
		NVSwitchEvidenceHash: fmt.Sprintf("%x", sha256.Sum256([]byte(nvswitch))),
	}

	doc := map[string]any{
		"format":      FormatURI,
		"report_data": rd,
		"cpu": map[string]any{
			"platform": platform,
			"report":   base64.StdEncoding.EncodeToString(cpuReport),
		},
		"gpu":         json.RawMessage(gpu),
		"nvswitch":    json.RawMessage(nvswitch),
		"certificate": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		"signature":   base64.StdEncoding.EncodeToString([]byte("sig")),
	}

	data, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return data
}

func TestParseV3Response_ValidTDX(t *testing.T) {
	body := makeValidV3JSON(PlatformTDX)
	raw, resp, err := parseV3Response(body)
	if err != nil {
		t.Fatalf("parseV3Response failed: %v", err)
	}

	if raw.BackendFormat != attestation.FormatTinfoil {
		t.Errorf("BackendFormat = %q, want %q", raw.BackendFormat, attestation.FormatTinfoil)
	}
	if raw.TEEHardware != HardwareIntelTDX {
		t.Errorf("TEEHardware = %q, want %q", raw.TEEHardware, HardwareIntelTDX)
	}
	if raw.IntelQuote == "" {
		t.Error("IntelQuote should be non-empty for TDX platform")
	}
	if raw.SigningAlgo != "x25519-hpke" {
		t.Errorf("SigningAlgo = %q, want x25519-hpke", raw.SigningAlgo)
	}
	if raw.NonceSource != "client" {
		t.Errorf("NonceSource = %q, want client", raw.NonceSource)
	}
	if raw.TLSFingerprint != makeHex32(0x01) {
		t.Errorf("TLSFingerprint = %q, want %q", raw.TLSFingerprint, makeHex32(0x01))
	}
	if raw.SigningKey != makeHex32(0x02) {
		t.Errorf("SigningKey = %q, want %q", raw.SigningKey, makeHex32(0x02))
	}
	if len(raw.GPURawJSON) == 0 {
		t.Error("GPURawJSON should be non-empty")
	}
	if len(raw.NVSwitchRawJSON) == 0 {
		t.Error("NVSwitchRawJSON should be non-empty")
	}
	if resp.Format != FormatURI {
		t.Errorf("resp.Format = %q, want %q", resp.Format, FormatURI)
	}
}

func TestParseV3Response_ValidSEVSNP(t *testing.T) {
	body := makeValidV3JSON(PlatformSEVSNP)
	raw, _, err := parseV3Response(body)
	if err != nil {
		t.Fatalf("parseV3Response failed: %v", err)
	}

	if raw.TEEHardware != HardwareAMDSEV {
		t.Errorf("TEEHardware = %q, want %q", raw.TEEHardware, HardwareAMDSEV)
	}
	if raw.IntelQuote != "" {
		t.Error("IntelQuote should be empty for SEV-SNP platform")
	}
	if len(raw.SEVReportBytes) == 0 {
		t.Error("SEVReportBytes should be non-empty for SEV-SNP platform")
	}
}

func TestParseV3Response_RejectV2(t *testing.T) {
	doc := map[string]any{
		"format": FormatURI,
		"body":   "some legacy body",
		"report_data": v3ReportData{
			TLSKeyFP:        makeHex32(0x01),
			HPKEKey:         makeHex32(0x02),
			Nonce:           makeHex32(0x03),
			GPUEvidenceHash: makeHex32(0x04),
		},
		"cpu": map[string]any{
			"platform": PlatformTDX,
			"report":   base64.StdEncoding.EncodeToString([]byte("report")),
		},
		"gpu":         json.RawMessage(`{}`),
		"certificate": "cert",
		"signature":   base64.StdEncoding.EncodeToString([]byte("sig")),
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	_, _, err = parseV3Response(data)
	if err == nil {
		t.Fatal("expected error for V2 format with 'body' field")
	}
	if !strings.Contains(err.Error(), "V2 response") {
		t.Errorf("error %q should mention V2 response", err)
	}
}

func TestParseV3Response_RejectWrongFormat(t *testing.T) {
	doc := map[string]any{
		"format": "https://example.com/wrong/format",
		"report_data": v3ReportData{
			TLSKeyFP:        makeHex32(0x01),
			HPKEKey:         makeHex32(0x02),
			Nonce:           makeHex32(0x03),
			GPUEvidenceHash: makeHex32(0x04),
		},
		"cpu": map[string]any{
			"platform": PlatformTDX,
			"report":   base64.StdEncoding.EncodeToString([]byte("report")),
		},
		"gpu":         json.RawMessage(`{}`),
		"certificate": "cert",
		"signature":   base64.StdEncoding.EncodeToString([]byte("sig")),
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	_, _, err = parseV3Response(data)
	if err == nil {
		t.Fatal("expected error for wrong format URI")
	}
	if !strings.Contains(err.Error(), "unexpected format") {
		t.Errorf("error %q should mention unexpected format", err)
	}
}

func TestParseV3Response_RejectUnknownPlatform(t *testing.T) {
	body := makeValidV3JSON("unknown-platform")
	_, _, err := parseV3Response(body)
	if err == nil {
		t.Fatal("expected error for unknown CPU platform")
	}
	if !strings.Contains(err.Error(), "unknown cpu.platform") {
		t.Errorf("error %q should mention unknown cpu.platform", err)
	}
}

func TestParseV3Response_RejectBadHexField(t *testing.T) {
	doc := map[string]any{
		"format": FormatURI,
		"report_data": map[string]any{
			"tls_key_fp":        "not_valid_hex_and_wrong_length",
			"hpke_key":          makeHex32(0x02),
			"nonce":             makeHex32(0x03),
			"gpu_evidence_hash": makeHex32(0x04),
		},
		"cpu": map[string]any{
			"platform": PlatformTDX,
			"report":   base64.StdEncoding.EncodeToString([]byte("report")),
		},
		"gpu":         json.RawMessage(`{}`),
		"certificate": "cert",
		"signature":   base64.StdEncoding.EncodeToString([]byte("sig")),
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	_, _, err = parseV3Response(data)
	if err == nil {
		t.Fatal("expected error for bad hex field")
	}
	if !strings.Contains(err.Error(), "tls_key_fp") {
		t.Errorf("error %q should mention tls_key_fp", err)
	}
}

func TestParseV3Response_RejectShortHexField(t *testing.T) {
	doc := map[string]any{
		"format": FormatURI,
		"report_data": map[string]any{
			"tls_key_fp":        "aabb", // too short
			"hpke_key":          makeHex32(0x02),
			"nonce":             makeHex32(0x03),
			"gpu_evidence_hash": makeHex32(0x04),
		},
		"cpu": map[string]any{
			"platform": PlatformTDX,
			"report":   base64.StdEncoding.EncodeToString([]byte("report")),
		},
		"gpu":         json.RawMessage(`{}`),
		"certificate": "cert",
		"signature":   base64.StdEncoding.EncodeToString([]byte("sig")),
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	_, _, err = parseV3Response(data)
	if err == nil {
		t.Fatal("expected error for short hex field")
	}
	if !strings.Contains(err.Error(), "must be 64 hex chars") {
		t.Errorf("error %q should mention hex char length", err)
	}
}

func TestParseV3Response_CPUReportSizeBound(t *testing.T) {
	// Create a CPU report that exceeds 10 MiB when decoded.
	oversized := make([]byte, maxCPUReportSize+1)
	for i := range oversized {
		oversized[i] = 0xAA
	}

	doc := map[string]any{
		"format": FormatURI,
		"report_data": v3ReportData{
			TLSKeyFP:        makeHex32(0x01),
			HPKEKey:         makeHex32(0x02),
			Nonce:           makeHex32(0x03),
			GPUEvidenceHash: makeHex32(0x04),
		},
		"cpu": map[string]any{
			"platform": PlatformTDX,
			"report":   base64.StdEncoding.EncodeToString(oversized),
		},
		"gpu":         json.RawMessage(`{}`),
		"certificate": "cert",
		"signature":   base64.StdEncoding.EncodeToString([]byte("sig")),
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	_, _, err = parseV3Response(data)
	if err == nil {
		t.Fatal("expected error for oversized CPU report")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("error %q should mention exceeds limit", err)
	}
}

func TestParseV3Response_OptionalNVSwitchEvidenceHash(t *testing.T) {
	// Build a V3 doc without nvswitch_evidence_hash.
	cpuReport := make([]byte, 64)
	gpu := `{"evidences":[]}`

	doc := map[string]any{
		"format": FormatURI,
		"report_data": map[string]any{
			"tls_key_fp":        makeHex32(0x01),
			"hpke_key":          makeHex32(0x02),
			"nonce":             makeHex32(0x03),
			"gpu_evidence_hash": fmt.Sprintf("%x", sha256.Sum256([]byte(gpu))),
			// nvswitch_evidence_hash intentionally omitted
		},
		"cpu": map[string]any{
			"platform": PlatformTDX,
			"report":   base64.StdEncoding.EncodeToString(cpuReport),
		},
		"gpu":         json.RawMessage(gpu),
		"certificate": "cert",
		"signature":   base64.StdEncoding.EncodeToString([]byte("sig")),
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	raw, _, err := parseV3Response(data)
	if err != nil {
		t.Fatalf("parseV3Response failed: %v", err)
	}
	if raw.TinfoilNVSwitchEvidenceHash != "" {
		t.Errorf("TinfoilNVSwitchEvidenceHash should be empty when omitted, got %q", raw.TinfoilNVSwitchEvidenceHash)
	}
}

func TestParseV3Response_PreservesRawGPUJSON(t *testing.T) {
	body := makeValidV3JSON(PlatformTDX)
	raw, _, err := parseV3Response(body)
	if err != nil {
		t.Fatalf("parseV3Response failed: %v", err)
	}

	// Verify the GPU raw JSON is valid JSON.
	var gpuParsed json.RawMessage
	if err := json.Unmarshal(raw.GPURawJSON, &gpuParsed); err != nil {
		t.Fatalf("GPURawJSON is not valid JSON: %v", err)
	}

	// Verify the hash of GPURawJSON matches the reported gpu_evidence_hash.
	computed := sha256.Sum256(raw.GPURawJSON)
	computedHex := hex.EncodeToString(computed[:])
	if computedHex != raw.TinfoilGPUEvidenceHash {
		t.Errorf("GPU hash mismatch: computed=%s reported=%s", computedHex, raw.TinfoilGPUEvidenceHash)
	}
}
