// Package nearcloud implements the Attester and PinnedHandler for the NEAR AI
// cloud gateway (cloud-api.near.ai). Unlike the neardirect package which connects
// to model-specific subdomains, nearcloud routes all traffic through a single
// TEE-attested API gateway that itself runs in an Intel TDX enclave.
//
// The gateway attestation response adds a gateway_attestation section alongside
// the standard model_attestations array. The gateway has its own TDX quote,
// event log, compose binding, and nonce, all verified as Tier 4 factors.
package nearcloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

const (
	// gatewayHost is the fixed host for the NEAR AI cloud gateway.
	gatewayHost = "cloud-api.near.ai"

	// attestationPath is the API path for TEE attestation reports.
	attestationPath = "/v1/attestation/report"
)

// gatewayResponse is the top-level JSON shape returned by the gateway
// attestation endpoint. It wraps the standard neardirect model_attestations
// with an additional gateway_attestation section.
type gatewayResponse struct {
	GatewayAttestation gatewayAttestation `json:"gateway_attestation"`
}

// gatewayAttestation holds the gateway's own TDX attestation data.
type gatewayAttestation struct {
	RequestNonce       string `json:"request_nonce"`
	IntelQuote         string `json:"intel_quote"`
	EventLog           string `json:"event_log"` // JSON string, not array
	TLSCertFingerprint string `json:"tls_cert_fingerprint"`
	Info               struct {
		TCBInfo json.RawMessage `json:"tcb_info"`
	} `json:"info"`
}

// GatewayRaw holds parsed gateway attestation fields ready for verification.
type GatewayRaw struct {
	NonceHex           string
	IntelQuote         string
	AppCompose         string
	TLSCertFingerprint string
	EventLog           []attestation.EventLogEntry
}

// ParseGatewayResponse extracts gateway attestation fields and delegates model
// attestation parsing to neardirect.ParseAttestationResponse. Returns both the
// gateway-specific data and the model RawAttestation.
func ParseGatewayResponse(body []byte, model string) (*GatewayRaw, *attestation.RawAttestation, error) {
	var gr gatewayResponse
	if err := jsonstrict.UnmarshalWarn(body, &gr, "nearcloud gateway response"); err != nil {
		return nil, nil, fmt.Errorf("nearcloud: unmarshal gateway response: %w", err)
	}

	appCompose, err := extractGatewayAppCompose(gr.GatewayAttestation.Info.TCBInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("nearcloud: %w", err)
	}

	gw := &GatewayRaw{
		NonceHex:           gr.GatewayAttestation.RequestNonce,
		IntelQuote:         gr.GatewayAttestation.IntelQuote,
		AppCompose:         appCompose,
		TLSCertFingerprint: gr.GatewayAttestation.TLSCertFingerprint,
	}

	// Gateway event_log is a JSON string (not a native array).
	if gr.GatewayAttestation.EventLog != "" {
		var rawEntries []json.RawMessage
		if err := json.Unmarshal([]byte(gr.GatewayAttestation.EventLog), &rawEntries); err != nil {
			return nil, nil, fmt.Errorf("nearcloud: parse gateway event_log string: %w", err)
		}
		entries := make([]attestation.EventLogEntry, 0, len(rawEntries))
		for i, r := range rawEntries {
			var e attestation.EventLogEntry
			if err := json.Unmarshal(r, &e); err != nil {
				return nil, nil, fmt.Errorf("nearcloud: gateway event_log entry %d: %w", i, err)
			}
			entries = append(entries, e)
		}
		gw.EventLog = entries
	}

	// Model attestation parsed by the shared neardirect parser.
	raw, err := neardirect.ParseAttestationResponse(body, model)
	if err != nil {
		return nil, nil, fmt.Errorf("nearcloud: parse model attestation: %w", err)
	}

	return gw, raw, nil
}

// extractGatewayAppCompose extracts app_compose from the gateway's tcb_info.
func extractGatewayAppCompose(tcbInfo json.RawMessage) (string, error) {
	if len(tcbInfo) == 0 {
		return "", nil
	}
	raw := tcbInfo
	// tcb_info may be a JSON string containing escaped JSON; unwrap it.
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		raw = json.RawMessage(str)
	}
	var obj struct {
		AppCompose string `json:"app_compose"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "", fmt.Errorf("parse gateway tcb_info: %w", err)
	}
	return obj.AppCompose, nil
}

// Attester fetches attestation from the NEAR AI cloud gateway for use by
// 'teep verify nearcloud'. The gateway endpoint is always cloud-api.near.ai.
type Attester struct {
	apiKey string
	client *http.Client
}

// NewAttester returns a nearcloud Attester.
func NewAttester(apiKey string, offline ...bool) *Attester {
	return &Attester{
		apiKey: apiKey,
		client: config.NewAttestationClient(offline...),
	}
}

// FetchAttestation fetches TEE attestation from the cloud gateway.
// The same nonce is used for both gateway and model attestation (the gateway
// shares the nonce with the model backend).
func (a *Attester) FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	endpoint, err := url.Parse("https://" + gatewayHost + attestationPath)
	if err != nil {
		return nil, fmt.Errorf("nearcloud: parse endpoint: %w", err)
	}
	q := endpoint.Query()
	q.Set("model", model)
	q.Set("nonce", nonce.Hex())
	q.Set("include_tls_fingerprint", "true")
	q.Set("signing_algo", "ecdsa")
	endpoint.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("nearcloud: build attestation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.apiKey)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nearcloud: GET %s: %w", endpoint.Host+endpoint.Path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2 MiB max (gateway responses are larger)
	if err != nil {
		return nil, fmt.Errorf("nearcloud: read attestation response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := string(body)
		if len(msg) > 512 {
			msg = msg[:512] + "...[truncated]"
		}
		return nil, fmt.Errorf("nearcloud: attestation endpoint returned HTTP %d: %s", resp.StatusCode, msg)
	}

	gwRaw, raw, err := ParseGatewayResponse(body, model)
	if err != nil {
		return nil, err
	}
	raw.GatewayIntelQuote = gwRaw.IntelQuote
	raw.GatewayNonceHex = gwRaw.NonceHex
	raw.GatewayAppCompose = gwRaw.AppCompose
	raw.GatewayEventLog = gwRaw.EventLog
	raw.GatewayTLSFingerprint = gwRaw.TLSCertFingerprint
	return raw, nil
}
