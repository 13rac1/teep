// Package formatdetect provides shared attestation format detection for
// gateway providers that route to multiple backends (nanogpt, phalacloud/RedPill).
//
// Detection is based on top-level JSON keys in the attestation response:
//
//	"format"              → tinfoil
//	"attestation_type"    → chutes
//	"gateway_attestation" → gateway (NEAR cloud)
//	"intel_quote"         → dstack (Venice/NEAR direct)
package formatdetect

import (
	"encoding/json"

	"github.com/13rac1/teep/internal/attestation"
)

// probe is the minimal struct for format detection — we only need to check
// whether specific top-level keys are present and non-empty.
type probe struct {
	Format             string          `json:"format"`
	AttestationType    string          `json:"attestation_type"`
	GatewayAttestation json.RawMessage `json:"gateway_attestation"`
	IntelQuote         string          `json:"intel_quote"`
}

// Detect inspects top-level JSON keys in body and returns the attestation
// BackendFormat. Returns "" if no known format is detected.
func Detect(body []byte) attestation.BackendFormat {
	var p probe
	if json.Unmarshal(body, &p) != nil {
		return ""
	}
	switch {
	case p.Format != "":
		return attestation.FormatTinfoil
	case p.AttestationType != "":
		return attestation.FormatChutes
	case len(p.GatewayAttestation) > 0 && string(p.GatewayAttestation) != "null":
		return attestation.FormatGateway
	case p.IntelQuote != "":
		return attestation.FormatDstack
	default:
		return ""
	}
}
