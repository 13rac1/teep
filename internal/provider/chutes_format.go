package provider

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/jsonstrict"
)

const (
	// maxChutesAttestations bounds the number of chutes attestation entries.
	maxChutesAttestations = 256

	// maxChutesGPUEvidence bounds the number of GPU evidence entries per attestation.
	maxChutesGPUEvidence = 64
)

// chutesAttestation is one entry in the gateway-wrapped chutes
// "all_attestations" array.
type chutesAttestation struct {
	InstanceID  string                    `json:"instance_id"`
	Nonce       string                    `json:"nonce"`
	E2EPubKey   string                    `json:"e2e_pubkey"`
	IntelQuote  string                    `json:"intel_quote"` // base64-encoded TDX quote
	GPUEvidence []attestation.GPUEvidence `json:"gpu_evidence"`
}

// chutesResponse is the top-level JSON shape returned by gateway providers
// (phalacloud/RedPill, NanoGPT) when the backend is a chutes-format provider.
type chutesResponse struct {
	AttestationType string              `json:"attestation_type"`
	Nonce           string              `json:"nonce"`
	AllAttestations []chutesAttestation `json:"all_attestations"`
}

// ParseChutesFormat parses the gateway-wrapped chutes attestation format.
// This format is returned by gateway providers like phalacloud/RedPill and
// NanoGPT when routing to chutes-based backends.
func ParseChutesFormat(body []byte, prefix string) (*attestation.RawAttestation, error) {
	var cr chutesResponse
	if err := jsonstrict.UnmarshalWarn(body, &cr, prefix+" chutes attestation response"); err != nil {
		return nil, fmt.Errorf("%s: unmarshal chutes response: %w", prefix, err)
	}

	if len(cr.AllAttestations) == 0 {
		return nil, fmt.Errorf("%s: all_attestations is empty", prefix)
	}
	if len(cr.AllAttestations) > maxChutesAttestations {
		return nil, fmt.Errorf("%s: all_attestations has %d entries, max %d",
			prefix, len(cr.AllAttestations), maxChutesAttestations)
	}

	first := cr.AllAttestations[0]

	for i, a := range cr.AllAttestations {
		if len(a.GPUEvidence) > maxChutesGPUEvidence {
			return nil, fmt.Errorf("%s: attestation[%d] has %d GPU evidence entries, max %d",
				prefix, i, len(a.GPUEvidence), maxChutesGPUEvidence)
		}
	}

	// Convert base64-encoded intel_quote to hex for TDX verification pipeline.
	var intelQuoteHex string
	if first.IntelQuote != "" {
		quoteBytes, err := base64.StdEncoding.DecodeString(first.IntelQuote)
		if err != nil {
			return nil, fmt.Errorf("%s: base64-decode intel_quote: %w", prefix, err)
		}
		intelQuoteHex = hex.EncodeToString(quoteBytes)
	}

	slog.Debug(prefix+" chutes attestation parsed",
		"type", cr.AttestationType,
		"instances", len(cr.AllAttestations),
		"instance_id", first.InstanceID,
		"gpus", len(first.GPUEvidence),
		"nonce_prefix", attestation.NoncePrefix(cr.Nonce),
	)

	return &attestation.RawAttestation{
		BackendFormat: attestation.FormatChutes,
		Nonce:         cr.Nonce,
		TEEProvider:   "TDX+NVIDIA",
		SigningKey:    first.E2EPubKey,
		SigningAlgo:   "ml-kem-768",
		IntelQuote:    intelQuoteHex,
		GPUEvidence:   first.GPUEvidence,

		TEEHardware: "intel-tdx",
		NonceSource: "server",

		CandidatesAvail: len(cr.AllAttestations),
		CandidatesEval:  1,

		RawBody: body,
	}, nil
}
