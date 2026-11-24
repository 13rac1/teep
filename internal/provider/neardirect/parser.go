package neardirect

import (
	"context"
	"errors"
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider/nearparse"
)

type attestationResponse struct {
	nearparse.ModelFields
	AllAttestations           nearparse.Models         `json:"all_attestations"`
	ComposeManagerAttestation nearparse.ComposeManager `json:"compose_manager_attestation,omitempty"`
	OHTTPAttestation          *nearparse.OHTTP         `json:"ohttp_attestation,omitempty"`
	OHTTPKeyConfig            string                   `json:"ohttp_key_config,omitempty"`
	Verified                  bool                     `json:"verified,omitempty"`
	unknown                   []string
}

func (a *attestationResponse) UnmarshalJSON(data []byte) error {
	type fields attestationResponse
	var out fields
	unknown, err := nearparse.Object(data, &out, "neardirect", "compose_manager_attestation")
	if err != nil {
		return err
	}
	out.unknown = unknown
	*a = attestationResponse(out)
	return nil
}

// ParseAttestationResponse accepts only the direct flat report repeated once
// in all_attestations. It validates both representations before comparison.
func ParseAttestationResponse(_ context.Context, body []byte, model string) (*attestation.RawAttestation, error) {
	if len(body) > nearparse.MaxEvidenceBytes {
		return nil, fmt.Errorf("NEAR attestation exceeds size limit %d bytes", nearparse.MaxEvidenceBytes)
	}
	var envelope attestationResponse
	if _, _, err := jsonstrict.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.AllAttestations) != 1 {
		return nil, errors.New("neardirect: all_attestations must contain exactly one report")
	}
	for _, field := range envelope.unknown {
		if field == "neardirect.model_attestations" || field == "neardirect.gateway_attestation" || field == "neardirect.tls_certificate" {
			return nil, errors.New("neardirect: forbidden gateway representation")
		}
	}
	flat := nearparse.Model{Fields: envelope.ModelFields}
	repeated := envelope.AllAttestations[0]
	match, err := nearparse.MatchModelName(model, flat.Fields.ModelName)
	if err != nil {
		return nil, fmt.Errorf("neardirect: %w", err)
	}
	if !flat.Equal(&repeated) {
		return nil, errors.New("neardirect: repeated attestation reports disagree")
	}
	unknown := envelope.unknown
	unknown = append(unknown, flat.UnknownFields("neardirect")...)
	unknown = append(unknown, repeated.UnknownFields("neardirect.all_attestations[0]")...)
	unknown = append(unknown, envelope.OHTTPAttestation.UnknownFields("neardirect")...)
	raw := flat.Raw(body)
	raw.ComposeManagerAttestation = []byte(envelope.ComposeManagerAttestation)
	raw.Verified, raw.UnknownFields = envelope.Verified, unknown
	raw.ModelNameMatch = string(match)
	return raw, nil
}
