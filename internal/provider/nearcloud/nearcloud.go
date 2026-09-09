// Package nearcloud implements attestation fetching for the NEAR AI
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
	"fmt"
	"net/http"
	"net/url"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearparse"
	"github.com/13rac1/teep/internal/tlsct"
)

const (
	// gatewayHost is the fixed host for the NEAR AI cloud gateway.
	gatewayHost = "cloud-api.near.ai"

	// attestationPath is the API path for TEE attestation reports.
	attestationPath = "/v1/attestation/report"
)

// GatewayHost returns the authority used for gateway attestation and inference.
func GatewayHost() string { return gatewayHost }

// GatewayRaw holds parsed gateway attestation fields ready for verification.
type GatewayRaw struct {
	NonceHex           string
	SigningAddress     string
	IntelQuote         string
	AppCompose         string
	TLSCertFingerprint string
	EventLog           []attestation.EventLogEntry
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
		client: config.NewAttestationClient(len(offline) > 0 && offline[0]),
	}
}

// SetClient replaces the HTTP client used for attestation fetches.
func (a *Attester) SetClient(c *http.Client) { a.client = c }

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
	q.Set("signing_algo", "ed25519")
	endpoint.RawQuery = q.Encode()

	body, peerSPKI, err := provider.FetchAttestationWithTLS(ctx, a.client, endpoint.String(), a.apiKey, nearparse.MaxEvidenceBytes)
	if err != nil {
		return nil, fmt.Errorf("nearcloud: %w", err)
	}

	gwRaw, raw, err := ParseGatewayResponse(ctx, body, model)
	if err != nil {
		return nil, err
	}
	if err := tlsct.CompareSPKIFingerprints(peerSPKI, gwRaw.TLSCertFingerprint); err != nil {
		return nil, fmt.Errorf("nearcloud: gateway attestation TLS binding: %w", err)
	}
	raw.TransportTLSFingerprint = gwRaw.TLSCertFingerprint
	raw.TransportTLSAuthority = gatewayHost
	raw.GatewayIntelQuote = gwRaw.IntelQuote
	raw.GatewayNonceHex = gwRaw.NonceHex
	raw.GatewayAppCompose = gwRaw.AppCompose
	raw.GatewayEventLog = gwRaw.EventLog
	raw.GatewaySigningAddress = gwRaw.SigningAddress
	raw.GatewayTLSFingerprint = gwRaw.TLSCertFingerprint
	return raw, nil
}

// CloseIdleConnections releases idle connections owned by this component.
func (a *Attester) CloseIdleConnections() { a.client.CloseIdleConnections() }
