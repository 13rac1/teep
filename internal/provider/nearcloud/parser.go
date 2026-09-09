package nearcloud

import (
	"context"
	"errors"
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider/nearparse"
)

type gatewayResponse struct {
	GatewayAttestation gatewayAttestation `json:"gateway_attestation"`
	ModelAttestations  nearparse.Models   `json:"model_attestations"`
	TLSCertificate     string             `json:"tls_certificate,omitempty"`
	OHTTPAttestation   *nearparse.OHTTP   `json:"ohttp_attestation,omitempty"`
	OHTTPKeyConfig     string             `json:"ohttp_key_config,omitempty"`
	unknown            []string
}

func (g *gatewayResponse) UnmarshalJSON(data []byte) error {
	type fields gatewayResponse
	var out fields
	unknown, err := nearparse.Object(data, &out, "nearcloud")
	if err != nil {
		return err
	}
	out.unknown = unknown
	*g = gatewayResponse(out)
	return nil
}

type gatewayAttestation struct {
	RequestNonce       string                    `json:"request_nonce"`
	SigningAddress     string                    `json:"signing_address"`
	SigningAlgo        string                    `json:"signing_algo"`
	IntelQuote         string                    `json:"intel_quote"`
	EventLog           nearparse.EncodedEventLog `json:"event_log"`
	TLSCertFingerprint string                    `json:"tls_cert_fingerprint"`
	ReportData         string                    `json:"report_data"`
	VPC                gatewayVPC                `json:"vpc"`
	Info               nearparse.DecodedInfo     `json:"info"`
	unknown            []string
}

func (g *gatewayAttestation) UnmarshalJSON(data []byte) error {
	type fields gatewayAttestation
	var out fields
	unknown, err := nearparse.Object(data, &out, "nearcloud.gateway_attestation")
	if err != nil {
		return err
	}
	unknown = append(unknown, out.Info.UnknownFields("nearcloud.gateway_attestation")...)
	unknown = append(unknown, out.EventLog.Log.UnknownFields("nearcloud.gateway_attestation.event_log")...)
	unknown = append(unknown, out.VPC.unknown...)
	out.unknown = unknown
	*g = gatewayAttestation(out)
	return nil
}

type gatewayVPC struct {
	ServerAppID string `json:"vpc_server_app_id"`
	Hostname    string `json:"vpc_hostname"`
	unknown     []string
}

func (v *gatewayVPC) UnmarshalJSON(data []byte) error {
	type fields gatewayVPC
	var out fields
	unknown, err := nearparse.Object(data, &out, "nearcloud.gateway_attestation.vpc")
	if err != nil {
		return err
	}
	out.unknown = unknown
	*v = gatewayVPC(out)
	return nil
}

// ParseGatewayResponse validates the gateway envelope and every model report.
// Provider selection occurs at the caller, before decoding any evidence.
func ParseGatewayResponse(_ context.Context, body []byte, model string) (*GatewayRaw, *attestation.RawAttestation, error) {
	if len(body) > nearparse.MaxEvidenceBytes {
		return nil, nil, fmt.Errorf("NEAR attestation exceeds size limit %d bytes", nearparse.MaxEvidenceBytes)
	}
	var envelope gatewayResponse
	if _, _, err := jsonstrict.Unmarshal(body, &envelope); err != nil {
		return nil, nil, err
	}
	for _, field := range envelope.unknown {
		switch field {
		case "nearcloud.all_attestations", "nearcloud.model_name", "nearcloud.intel_quote", "nearcloud.nvidia_payload",
			"nearcloud.signing_public_key", "nearcloud.signing_address", "nearcloud.signing_algo", "nearcloud.tls_cert_fingerprint",
			"nearcloud.request_nonce", "nearcloud.event_log", "nearcloud.info":
			return nil, nil, errors.New("nearcloud: forbidden direct representation")
		}
	}
	selected, unknown, err := envelope.ModelAttestations.Select(model, "nearcloud.model_attestations")
	if err != nil {
		return nil, nil, err
	}
	gateway := envelope.GatewayAttestation
	unknown = append(unknown, envelope.unknown...)
	unknown = append(unknown, gateway.unknown...)
	unknown = append(unknown, envelope.OHTTPAttestation.UnknownFields("nearcloud")...)
	raw := selected.Raw(body)
	raw.UnknownFields = unknown
	gw := &GatewayRaw{NonceHex: gateway.RequestNonce, SigningAddress: gateway.SigningAddress, IntelQuote: gateway.IntelQuote,
		AppCompose: gateway.Info.Info.TCBInfo.AppCompose, TLSCertFingerprint: gateway.TLSCertFingerprint, EventLog: gateway.EventLog.Log.Values()}
	return gw, raw, nil
}
