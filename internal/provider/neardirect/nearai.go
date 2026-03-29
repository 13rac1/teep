// Package neardirect implements the Attester and RequestPreparer interfaces for
// NEAR AI's direct TEE attestation API.
//
// NEAR AI attestation endpoint:
//
//	GET {base_url}/v1/attestation/report?nonce={nonce}&include_tls_fingerprint=true&signing_algo=ecdsa
//	Authorization: Bearer {api_key}
//
// The response contains a model_attestations array, where each element holds
// TDX and NVIDIA attestation payloads for one inference node, plus
// signing_address, tls_cert_fingerprint, and the echoed nonce.
//
// NEAR AI does not use E2EE; it relies on TLS certificate pinning via
// attestation. PrepareRequest injects the Authorization header only.
package neardirect

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
)

const (
	// attestationPath is the NEAR AI API path for TEE attestation reports.
	attestationPath = "/v1/attestation/report"

	// maxAttestationEntries caps the number of entries in all_attestations
	// and model_attestations arrays to prevent memory exhaustion from a
	// malicious response.
	maxAttestationEntries = 256
)

// tcbInfo holds the parsed info.tcb_info object from NEAR AI's attestation
// response. Contains the docker-compose manifest needed for supply-chain checks.
type tcbInfo struct {
	AppCompose string `json:"app_compose"`
}

// UnmarshalJSON handles tcb_info being either a direct JSON object or a
// JSON-encoded string containing JSON (double-encoded by some dstack versions).
func (t *tcbInfo) UnmarshalJSON(data []byte) error {
	type alias tcbInfo
	return json.Unmarshal(provider.UnwrapDoubleEncoded(data), (*alias)(t))
}

// modelAttestation represents one element of the model_attestations array
// returned by NEAR AI's attestation endpoint.
type modelAttestation struct {
	ModelName          string                      `json:"model_name"`
	IntelQuote         string                      `json:"intel_quote"`
	NvidiaPayload      string                      `json:"nvidia_payload"`
	SigningPublicKey   string                      `json:"signing_public_key"`
	SigningAddress     string                      `json:"signing_address"`
	SigningAlgo        string                      `json:"signing_algo"`
	TLSCertFingerprint string                      `json:"tls_cert_fingerprint"`
	RequestNonce       string                      `json:"request_nonce"`
	EventLog           []attestation.EventLogEntry `json:"event_log"`
	Info               struct {
		AppName     string  `json:"app_name"`
		ComposeHash string  `json:"compose_hash"`
		OSImageHash string  `json:"os_image_hash"`
		DeviceID    string  `json:"device_id"`
		TCBInfo     tcbInfo `json:"tcb_info"`
	} `json:"info"`
}

// attestationResponse is the JSON shape returned by NEAR AI's attestation
// endpoint. The server may return a single attestation or an array under
// model_attestations. Both forms are handled.
type attestationResponse struct {
	// ModelAttestations is the primary response field: an array of per-node
	// attestation records.
	ModelAttestations []modelAttestation `json:"model_attestations"`
	AllAttestations   []modelAttestation `json:"all_attestations"`

	// Top-level fields are present when the server returns a flat response
	// rather than the array form. Both forms are tolerated.
	ModelName          string                      `json:"model_name"`
	IntelQuote         string                      `json:"intel_quote"`
	NvidiaPayload      string                      `json:"nvidia_payload"`
	SigningPublicKey   string                      `json:"signing_public_key"`
	SigningAddress     string                      `json:"signing_address"`
	SigningAlgo        string                      `json:"signing_algo"`
	TLSCertFingerprint string                      `json:"tls_cert_fingerprint"`
	RequestNonce       string                      `json:"request_nonce"`
	Verified           bool                        `json:"verified"`
	EventLog           []attestation.EventLogEntry `json:"event_log"`
	Info               struct {
		AppName     string  `json:"app_name"`
		ComposeHash string  `json:"compose_hash"`
		OSImageHash string  `json:"os_image_hash"`
		DeviceID    string  `json:"device_id"`
		TCBInfo     tcbInfo `json:"tcb_info"`
	} `json:"info"`
}

// Attester fetches attestation data from NEAR AI's /v1/attestation/report
// endpoint. The nonce is sent as a query parameter and echoed back.
type Attester struct {
	baseURL  string
	apiKey   string
	client   *http.Client
	resolver DomainResolver
}

// NewAttester returns a NEAR AI Attester configured with the given base URL
// and API key. It uses a 30-second HTTP timeout via config.NewAttestationClient.
func NewAttester(baseURL, apiKey string, offline ...bool) *Attester {
	return NewAttesterWithResolver(baseURL, apiKey, NewEndpointResolver(offline...), offline...)
}

// NewAttesterWithResolver returns a NEAR AI Attester configured with the given
// base URL, API key, and model->domain resolver.
func NewAttesterWithResolver(baseURL, apiKey string, resolver DomainResolver, offline ...bool) *Attester {
	return &Attester{
		baseURL:  baseURL,
		apiKey:   apiKey,
		client:   config.NewAttestationClient(offline...),
		resolver: resolver,
	}
}

// FetchAttestation fetches TEE attestation from NEAR AI. The nonce is sent as
// a query parameter; NEAR AI echoes it back in the response. Query parameters
// include_tls_fingerprint=true and signing_algo=ecdsa are also sent so the
// response includes TLS certificate binding data. The model parameter selects
// which attestation to use when the response contains multiple entries.
func (a *Attester) FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	baseURL := a.baseURL

	base, err := url.Parse(a.baseURL)
	if err != nil {
		return nil, fmt.Errorf("nearai: parse base URL %q: %w", a.baseURL, err)
	}

	if shouldResolveModelDomain(base.Hostname()) && a.resolver != nil {
		domain, err := a.resolver.Resolve(ctx, model)
		if err != nil {
			return nil, fmt.Errorf("nearai: resolve model %q: %w", model, err)
		}
		baseURL = "https://" + domain
		slog.Debug("nearai model resolved", "model", model, "domain", domain)
	}

	endpoint, err := url.Parse(baseURL + attestationPath)
	if err != nil {
		return nil, fmt.Errorf("nearai: parse endpoint base URL %q: %w", baseURL, err)
	}
	q := endpoint.Query()
	q.Set("nonce", nonce.Hex())
	q.Set("include_tls_fingerprint", "true")
	q.Set("signing_algo", "ecdsa")
	endpoint.RawQuery = q.Encode()

	body, err := provider.FetchAttestationJSON(ctx, a.client, endpoint.String(), a.apiKey, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("nearai: %w", err)
	}

	return ParseAttestationResponse(body, model)
}

func shouldResolveModelDomain(host string) bool {
	host = strings.ToLower(host)
	return host == "api.near.ai" || host == "completions.near.ai"
}

// ParseAttestationResponse unmarshals a NEAR AI attestation JSON response body
// and selects the entry matching model. Used by both FetchAttestation (HTTP
// client path) and PinnedHandler (raw connection path).
func ParseAttestationResponse(body []byte, model string) (*attestation.RawAttestation, error) {
	var ar attestationResponse
	if err := jsonstrict.UnmarshalWarn(body, &ar, "nearai attestation response"); err != nil {
		return nil, fmt.Errorf("nearai: unmarshal attestation response: %w", err)
	}

	if len(ar.AllAttestations) > maxAttestationEntries {
		return nil, fmt.Errorf("nearai: all_attestations has %d entries, max %d", len(ar.AllAttestations), maxAttestationEntries)
	}
	if len(ar.ModelAttestations) > maxAttestationEntries {
		return nil, fmt.Errorf("nearai: model_attestations has %d entries, max %d", len(ar.ModelAttestations), maxAttestationEntries)
	}

	if len(ar.AllAttestations) > 0 {
		selected, err := selectByModel(ar.AllAttestations, model)
		if err != nil {
			return nil, err
		}
		return rawFromModelAttestation(selected, ar.Verified, body)
	}

	// If the response contains model_attestations, pick the entry matching
	// the requested model. Returns an error if no entry matches.
	if len(ar.ModelAttestations) > 0 {
		selected, err := selectByModel(ar.ModelAttestations, model)
		if err != nil {
			return nil, err
		}
		return rawFromModelAttestation(selected, ar.Verified, body)
	}

	// Flat response form: use top-level fields directly.
	raw := &attestation.RawAttestation{
		BackendFormat:  attestation.FormatNear,
		Verified:       ar.Verified,
		Nonce:          ar.RequestNonce,
		Model:          ar.ModelName,
		TEEProvider:    "TDX+NVIDIA",
		SigningKey:     provider.NormalizeUncompressedKey(ar.SigningPublicKey),
		SigningAddress: ar.SigningAddress,
		SigningAlgo:    ar.SigningAlgo,
		TLSFingerprint: ar.TLSCertFingerprint,
		IntelQuote:     ar.IntelQuote,
		NvidiaPayload:  ar.NvidiaPayload,
		AppCompose:     ar.Info.TCBInfo.AppCompose,
		AppName:        ar.Info.AppName,
		ComposeHash:    ar.Info.ComposeHash,
		OSImageHash:    ar.Info.OSImageHash,
		DeviceID:       ar.Info.DeviceID,
		EventLog:       ar.EventLog,
		EventLogCount:  len(ar.EventLog),
		RawBody:        body,
	}
	if raw.IntelQuote != "" {
		raw.TEEHardware = "intel-tdx"
	}
	return raw, nil
}

func selectByModel(list []modelAttestation, model string) (*modelAttestation, error) {
	for i := range list {
		if list[i].ModelName == model {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("nearai: model %q not found in %d attestation entries", model, len(list))
}

func rawFromModelAttestation(m *modelAttestation, verified bool, body []byte) (*attestation.RawAttestation, error) {
	raw := &attestation.RawAttestation{
		BackendFormat:  attestation.FormatNear,
		Verified:       verified,
		Nonce:          m.RequestNonce,
		Model:          m.ModelName,
		TEEProvider:    "TDX+NVIDIA",
		SigningKey:     provider.NormalizeUncompressedKey(m.SigningPublicKey),
		SigningAddress: m.SigningAddress,
		SigningAlgo:    m.SigningAlgo,
		TLSFingerprint: m.TLSCertFingerprint,
		IntelQuote:     m.IntelQuote,
		NvidiaPayload:  m.NvidiaPayload,
		AppCompose:     m.Info.TCBInfo.AppCompose,
		AppName:        m.Info.AppName,
		ComposeHash:    m.Info.ComposeHash,
		OSImageHash:    m.Info.OSImageHash,
		DeviceID:       m.Info.DeviceID,
		EventLog:       m.EventLog,
		EventLogCount:  len(m.EventLog),
		RawBody:        body,
	}
	if raw.IntelQuote != "" {
		raw.TEEHardware = "intel-tdx"
	}
	return raw, nil
}

// Preparer injects the NEAR AI Authorization header into an outgoing request.
// NEAR AI's E2EE protocol headers are not yet publicly specified; this
// implementation sets the Authorization header only. Additional headers will
// be added when the protocol is documented.
type Preparer struct {
	apiKey string
}

// NewPreparer returns a NEAR AI Preparer configured with the given API key.
func NewPreparer(apiKey string) *Preparer {
	return &Preparer{apiKey: apiKey}
}

// PrepareRequest injects the NEAR AI Authorization header into req. The session
// parameter is accepted for interface compatibility but is not used until NEAR
// AI's E2EE header protocol is specified.
func (p *Preparer) PrepareRequest(req *http.Request, _ *e2ee.Session) error {
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	return nil
}
