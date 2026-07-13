// Package formatdetect provides shared attestation format detection for
// gateway providers that route to multiple backends (nanogpt, phalacloud/RedPill,
// venice).
//
// Detection is based on top-level JSON keys in the attestation response:
//
//	"format"              → tinfoil
//	"attestation_type"    → chutes
//	"gateway_attestation" → gateway (NEAR cloud)
//	"api_version"=="aci/1"→ ACI/1 (Venice)
//	"intel_quote"         → dstack (Venice/NEAR direct)
//
// The api_version check is ordered before the intel_quote check because
// ACI/1 response bodies also carry a top-level intel_quote field (the raw
// TDX quote lives at the same JSON location in both formats) — without this
// ordering, an ACI/1 body would be misclassified as plain dstack. A
// recognized-but-non-"aci/1" api_version value is treated as unknown (Detect
// returns "") rather than silently falling through to the dstack rule, so
// callers fail closed on unrecognized attestation format versions instead of
// misparsing them.
package formatdetect

import (
	"encoding/json"

	"github.com/13rac1/teep/internal/attestation"
)

// probe is the minimal struct for format detection — we only need to check
// whether specific top-level keys are present. IntelQuote and
// GatewayAttestation use json.RawMessage (checked for key presence, not for
// a non-empty value) because dstack fixtures/tests legitimately send
// `"intel_quote":""` while probing other nil-guard paths; the key being
// present at all is what identifies the dstack response shape.
type probe struct {
	Format             string          `json:"format"`
	AttestationType    string          `json:"attestation_type"`
	GatewayAttestation json.RawMessage `json:"gateway_attestation"`
	APIVersion         string          `json:"api_version"`
	IntelQuote         json.RawMessage `json:"intel_quote"`
}

// hasJSONValue reports whether raw represents a present, non-null JSON value
// (as opposed to an absent key, which json.Unmarshal leaves as a nil
// json.RawMessage).
func hasJSONValue(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}

// Detect inspects top-level JSON keys in body and returns the attestation
// BackendFormat. Returns "" if no known format is detected, including when
// api_version is present but holds an unrecognized value — callers must
// treat "" as a hard error, never a silent fallback to another format.
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
	case hasJSONValue(p.GatewayAttestation):
		return attestation.FormatGateway
	case p.APIVersion == string(attestation.FormatACI1):
		return attestation.FormatACI1
	case p.APIVersion != "":
		// Unknown api_version — do not fall through to the intel_quote/dstack
		// rule below. Fail closed: an unrecognized attestation format version
		// must error out in the caller, not be silently misparsed as dstack.
		return ""
	case hasJSONValue(p.IntelQuote):
		return attestation.FormatDstack
	default:
		return ""
	}
}
