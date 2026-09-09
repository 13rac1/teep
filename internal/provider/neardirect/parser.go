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
	AllAttestations           nearparse.Models           `json:"all_attestations"`
	ComposeManagerAttestation *composeManagerAttestation `json:"compose_manager_attestation,omitempty"`
	OHTTPAttestation          *nearparse.OHTTP           `json:"ohttp_attestation,omitempty"`
	OHTTPKeyConfig            string                     `json:"ohttp_key_config,omitempty"`
	Verified                  bool                       `json:"verified,omitempty"`
	unknown                   []string
}

func (a *attestationResponse) UnmarshalJSON(data []byte) error {
	type fields attestationResponse
	var out fields
	unknown, err := nearparse.Object(data, &out, "neardirect")
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
	if model == "" || flat.Fields.ModelName != model || repeated.Fields.ModelName != model {
		return nil, errors.New("neardirect: attestation does not match requested model")
	}
	if !flat.Equal(&repeated) {
		return nil, errors.New("neardirect: repeated attestation reports disagree")
	}
	unknown := envelope.unknown
	unknown = append(unknown, flat.UnknownFields("neardirect")...)
	unknown = append(unknown, repeated.UnknownFields("neardirect.all_attestations[0]")...)
	unknown = append(unknown, envelope.OHTTPAttestation.UnknownFields("neardirect")...)
	if envelope.ComposeManagerAttestation != nil {
		unknown = append(unknown, envelope.ComposeManagerAttestation.unknown...)
	}
	raw := flat.Raw(body)
	raw.Verified, raw.UnknownFields = envelope.Verified, unknown
	return raw, nil
}

type composeManagerAttestation struct {
	Actions     []composeAction `json:"actions"`
	ActionsHash string          `json:"actions_hash"`
	Nonce       string          `json:"nonce"`
	NonceSource string          `json:"nonce_source"`
	Quote       string          `json:"quote"`
	EventLog    string          `json:"event_log"`
	ReportData  string          `json:"report_data"`
	VMConfig    string          `json:"vm_config"`
	unknown     []string
}

func (m *composeManagerAttestation) UnmarshalJSON(data []byte) error {
	type fields composeManagerAttestation
	var out fields
	unknown, err := nearparse.Object(data, &out, "neardirect.compose_manager_attestation")
	if err != nil {
		return err
	}
	if len(out.Actions) > maxComposeManagerActions {
		return errors.New("compose-manager actions exceed limit")
	}
	for i := range out.Actions {
		action := &out.Actions[i]
		unknown = append(unknown, nearparse.Prefix(fmt.Sprintf("neardirect.compose_manager_attestation.actions[%d]", i), action.unknown)...)
	}
	out.unknown = unknown
	*m = composeManagerAttestation(out)
	return nil
}

type composeAction struct {
	Timestamp  string    `json:"timestamp"`
	Action     string    `json:"action"`
	Container  string    `json:"container,omitempty"`
	Image      string    `json:"image,omitempty"`
	Tag        string    `json:"tag,omitempty"`
	Commit     string    `json:"commit,omitempty"`
	File       string    `json:"file,omitempty"`
	FileSHA256 string    `json:"file_sha256,omitempty"`
	Services   []*string `json:"services,omitempty"`
	unknown    []string
}

func (a *composeAction) UnmarshalJSON(data []byte) error {
	type fields composeAction
	var out fields
	unknown, err := nearparse.Object(data, &out, "action")
	if err != nil {
		return err
	}
	for i, service := range out.Services {
		if service == nil {
			return fmt.Errorf("action.services[%d]: null is not permitted", i)
		}
	}
	out.unknown = unknown
	*a = composeAction(out)
	return nil
}
