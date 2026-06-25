package tinfoil

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/jsonstrict"
)

// maxCPUReportSize is the upper bound on the decoded cpu.report field (10 MiB).
const maxCPUReportSize = 10 << 20

// maxBodySize is the maximum V3 response body size (4 MiB).
const maxBodySize = 4 << 20

// hexFieldLen is the required length of hex-encoded 32-byte fields (64 chars).
const hexFieldLen = 64

// v3Response is the top-level JSON structure of a V3 attestation response.
// gpu and nvswitch are kept as json.RawMessage to preserve raw bytes for hashing.
type v3Response struct {
	Format     string          `json:"format"`
	ReportData v3ReportData    `json:"report_data"`
	CPU        v3CPU           `json:"cpu"`
	GPU        json.RawMessage `json:"gpu"`
	NVSwitch   json.RawMessage `json:"nvswitch"`

	Certificate string `json:"certificate"` // PEM certificate
	Signature   string `json:"signature"`   // base64 ECDSA DER

	// Body is a legacy V2 field — its presence causes rejection.
	Body *json.RawMessage `json:"body"`
}

// v3ReportData holds the parsed report_data fields.
type v3ReportData struct {
	TLSKeyFP             string `json:"tls_key_fp"`
	HPKEKey              string `json:"hpke_key"`
	Nonce                string `json:"nonce"`
	GPUEvidenceHash      string `json:"gpu_evidence_hash"`
	NVSwitchEvidenceHash string `json:"nvswitch_evidence_hash"`
}

// v3CPU holds the CPU attestation report.
type v3CPU struct {
	Platform string `json:"platform"` // "tdx" or "sev-snp"
	Report   string `json:"report"`   // base64-encoded
}

// v3GPUEvidences is used only for parsing the gpu.evidences array when needed
// (e.g., NVSwitch normalization). Not used for hashing — raw bytes are used instead.
type v3GPUEvidences struct {
	Evidences []v3GPUEvidence `json:"evidences"`
}

// v3GPUEvidence is a single GPU evidence entry.
type v3GPUEvidence struct {
	Arch        string `json:"arch"`
	Certificate string `json:"certificate"`
	Evidence    string `json:"evidence"`
	Nonce       string `json:"nonce"`
}

// parseV3Response parses a V3 attestation JSON document into a RawAttestation.
// It validates the format, rejects V2 documents, decodes the CPU report,
// and extracts report_data fields.
func parseV3Response(body []byte) (*attestation.RawAttestation, *v3Response, error) {
	var resp v3Response
	unknownFields, missingFields, err := jsonstrict.UnmarshalWarn(body, &resp, "tinfoil V3")
	if err != nil {
		return nil, nil, fmt.Errorf("tinfoil: unmarshal V3 response: %w", err)
	}

	// Reject legacy V2 format (has "body" field).
	if resp.Body != nil {
		return nil, nil, errors.New("tinfoil: response contains 'body' field — this is a V2 response, not V3")
	}

	// Validate format URI.
	if resp.Format != FormatURI {
		return nil, nil, fmt.Errorf("tinfoil: unexpected format %q, want %q", resp.Format, FormatURI)
	}

	// Validate report_data hex fields.
	if err := validateHexField("tls_key_fp", resp.ReportData.TLSKeyFP); err != nil {
		return nil, nil, err
	}
	if err := validateHexField("hpke_key", resp.ReportData.HPKEKey); err != nil {
		return nil, nil, err
	}
	if err := validateHexField("nonce", resp.ReportData.Nonce); err != nil {
		return nil, nil, err
	}
	// GPU evidence is required per spec. When absent, we still parse the
	// response so that BuildReport can produce factor-level failures, but
	// we emit a loud warning. Missing GPU evidence means cpu_gpu_chain and
	// all nvidia factors will fail closed.
	if resp.ReportData.GPUEvidenceHash == "" || len(resp.GPU) == 0 {
		slog.Warn("tinfoil V3 response missing required GPU evidence",
			"has_gpu_field", len(resp.GPU) > 0,
			"has_gpu_evidence_hash", resp.ReportData.GPUEvidenceHash != "",
		)
	}
	if resp.ReportData.GPUEvidenceHash != "" {
		if err := validateHexField("gpu_evidence_hash", resp.ReportData.GPUEvidenceHash); err != nil {
			return nil, nil, err
		}
	}
	if resp.ReportData.NVSwitchEvidenceHash != "" {
		if err := validateHexField("nvswitch_evidence_hash", resp.ReportData.NVSwitchEvidenceHash); err != nil {
			return nil, nil, err
		}
	}

	// Decode and validate CPU report.
	cpuReportBytes, err := base64.StdEncoding.DecodeString(resp.CPU.Report)
	if err != nil {
		return nil, nil, fmt.Errorf("tinfoil: base64-decode cpu.report: %w", err)
	}
	if len(cpuReportBytes) > maxCPUReportSize {
		return nil, nil, fmt.Errorf("tinfoil: cpu.report decoded size %d exceeds limit %d", len(cpuReportBytes), maxCPUReportSize)
	}

	raw := &attestation.RawAttestation{
		BackendFormat:  attestation.FormatTinfoil,
		NonceSource:    "client",
		Nonce:          resp.ReportData.Nonce,
		SigningKey:     resp.ReportData.HPKEKey,
		SigningAlgo:    "x25519-hpke",
		TLSFingerprint: resp.ReportData.TLSKeyFP,
		UnknownFields:  unknownFields,
		MissingFields:  missingFields,
		RawBody:        body,

		// Tinfoil-specific fields.
		GPURawJSON:                  resp.GPU,
		NVSwitchRawJSON:             resp.NVSwitch,
		TinfoilTLSKeyFP:             resp.ReportData.TLSKeyFP,
		TinfoilHPKEKey:              resp.ReportData.HPKEKey,
		TinfoilNonce:                resp.ReportData.Nonce,
		TinfoilGPUEvidenceHash:      resp.ReportData.GPUEvidenceHash,
		TinfoilNVSwitchEvidenceHash: resp.ReportData.NVSwitchEvidenceHash,
	}

	// Parse GPU evidence for independent per-GPU SPDM verification.
	if len(resp.GPU) > 0 {
		var gpuEvs v3GPUEvidences
		if err := json.Unmarshal(resp.GPU, &gpuEvs); err != nil {
			return nil, nil, fmt.Errorf("parse GPU evidences: %w", err)
		}
		if len(gpuEvs.Evidences) > 0 {
			// Validate all evidence entries share the same SPDM nonce.
			nonce := gpuEvs.Evidences[0].Nonce
			for i := 1; i < len(gpuEvs.Evidences); i++ {
				if gpuEvs.Evidences[i].Nonce != nonce {
					return nil, nil, fmt.Errorf("GPU evidence nonce mismatch: gpu[0]=%s, gpu[%d]=%s",
						truncate(nonce, 16), i, truncate(gpuEvs.Evidences[i].Nonce, 16))
				}
			}
			evidence := make([]attestation.GPUEvidence, len(gpuEvs.Evidences))
			for i, e := range gpuEvs.Evidences {
				evidence[i] = attestation.GPUEvidence{
					Arch:        e.Arch,
					Certificate: e.Certificate,
					Evidence:    e.Evidence,
				}
			}
			raw.GPUEvidence = evidence
			raw.GPUNonce = nonce
		}
	}

	// Dispatch CPU platform.
	switch resp.CPU.Platform {
	case PlatformTDX:
		raw.TEEHardware = HardwareIntelTDX
		raw.IntelQuote = hex.EncodeToString(cpuReportBytes)
	case PlatformSEVSNP:
		raw.TEEHardware = HardwareAMDSEV
		raw.SEVReportBytes = cpuReportBytes
	default:
		return nil, nil, fmt.Errorf("tinfoil: unknown cpu.platform %q", resp.CPU.Platform)
	}

	return raw, &resp, nil
}

// validateHexField checks that s is exactly 64 hex characters (32 bytes).
func validateHexField(name, s string) error {
	if len(s) != hexFieldLen {
		return fmt.Errorf("tinfoil: report_data.%s must be %d hex chars, got %d", name, hexFieldLen, len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("tinfoil: report_data.%s invalid hex: %w", name, err)
	}
	return nil
}
