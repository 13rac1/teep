// Package neardirect implements the Attester and RequestPreparer interfaces for
// NEAR AI's direct TEE attestation API.
//
// NEAR AI attestation endpoint:
//
//	GET {base_url}/v1/attestation/report?nonce={nonce}&include_tls_fingerprint=true&signing_algo=ed25519
//	Authorization: Bearer {api_key}
//
// The response contains a model_attestations array, where each element holds
// TDX and NVIDIA attestation payloads for one inference node, plus
// signing_address, tls_cert_fingerprint, and the echoed nonce.
//
// When E2EE is enabled, the PinnedHandler encrypts the request body using the
// Ed25519/X25519/XChaCha20-Poly1305 protocol (same as nearcloud).
package neardirect

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/13rac1/teep/internal/tlsct"
)

const (
	// attestationPath is the NEAR AI API path for TEE attestation reports.
	attestationPath = "/v1/attestation/report"

	// maxAttestationEntries caps the number of entries in all_attestations
	// and model_attestations arrays to prevent memory exhaustion from a
	// malicious response.
	maxAttestationEntries = 256

	maxComposeManagerActions = 10_000
)

// tcbInfo holds the parsed info.tcb_info object from NEAR AI's attestation
// response. Contains the docker-compose manifest needed for supply-chain checks.
type tcbInfo struct {
	AppCompose string `json:"app_compose"`
}

type modelInfo struct {
	AppName     string  `json:"app_name"`
	ComposeHash string  `json:"compose_hash"`
	OSImageHash string  `json:"os_image_hash"`
	DeviceID    string  `json:"device_id"`
	TCBInfo     tcbInfo `json:"tcb_info"`
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
	Info               modelInfo                   `json:"info"`
}

type ohttpAttestation struct {
	SigningAlgo string `json:"signing_algo"`
	SigningKey  string `json:"signing_key"`
	KeyConfig   string `json:"key_config"`
	Signature   string `json:"signature"`
}

type composeManagerAttestation struct {
	Actions []struct {
		Timestamp string `json:"timestamp"`
		Action    string `json:"action"`
		Container string `json:"container"`
		Image     string `json:"image"`
	} `json:"actions"`
	ActionsHash string `json:"actions_hash"`
	Nonce       string `json:"nonce"`
	NonceSource string `json:"nonce_source"`
	Quote       string `json:"quote"`
	EventLog    string `json:"event_log"`
	ReportData  string `json:"report_data"`
	VMConfig    string `json:"vm_config"`
}

// attestationResponse is the JSON shape returned by NEAR AI's attestation
// endpoint. The server may return a single attestation or an array under
// model_attestations. Both forms are handled.
type attestationResponse struct {
	// ModelAttestations is the primary response field: an array of per-node
	// attestation records.
	ModelAttestations []modelAttestation `json:"model_attestations,omitempty"`
	AllAttestations   []modelAttestation `json:"all_attestations,omitempty"`

	// Top-level fields are present when the server returns a flat response
	// rather than the array form. Both forms are tolerated.
	ModelName          string                      `json:"model_name,omitempty"`
	IntelQuote         string                      `json:"intel_quote,omitempty"`
	NvidiaPayload      string                      `json:"nvidia_payload,omitempty"`
	SigningPublicKey   string                      `json:"signing_public_key,omitempty"`
	SigningAddress     string                      `json:"signing_address,omitempty"`
	SigningAlgo        string                      `json:"signing_algo,omitempty"`
	TLSCertFingerprint string                      `json:"tls_cert_fingerprint,omitempty"`
	RequestNonce       string                      `json:"request_nonce,omitempty"`
	Verified           bool                        `json:"verified,omitempty"`
	EventLog           []attestation.EventLogEntry `json:"event_log,omitempty"`
	Info               *modelInfo                  `json:"info,omitempty"`

	// Current inference-proxy responses can include deployment and OHTTP
	// attestations. This path does not use the compose-manager attestation.
	ComposeManagerAttestation *composeManagerAttestation `json:"compose_manager_attestation,omitempty"`
	OHTTPAttestation          *ohttpAttestation          `json:"ohttp_attestation,omitempty"`
	OHTTPKeyConfig            string                     `json:"ohttp_key_config,omitempty"`

	// NearCloud adds these fields around the model_attestations array. Its
	// parser performs the gateway attestation checks.
	GatewayAttestation map[string]any `json:"gateway_attestation,omitempty"`
	TLSCertificate     string         `json:"tls_certificate,omitempty"`
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
		client:   config.NewAttestationClient(len(offline) > 0 && offline[0]),
		resolver: resolver,
	}
}

// CloseIdleConnections releases idle attestation and discovery connections.
// Call SetClient only before concurrent use or cleanup.
func (a *Attester) CloseIdleConnections() {
	a.client.CloseIdleConnections()
	if closer, ok := a.resolver.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// SetClient shares the caller's client with attestation and endpoint discovery.
// Call it only before concurrent use or cleanup.
func (a *Attester) SetClient(c *http.Client) {
	a.client = c
	if setter, ok := a.resolver.(interface{ SetClient(*http.Client) }); ok {
		setter.SetClient(c)
	}
}

// FetchAttestation fetches TEE attestation from NEAR AI. The nonce is sent as
// a query parameter; NEAR AI echoes it back in the response. Query parameters
// include_tls_fingerprint=true and signing_algo=ed25519 are also sent so the
// response includes TLS certificate binding data and an Ed25519 signing key
// for E2EE key exchange. The model parameter selects which attestation to use
// when the response contains multiple entries.
func (a *Attester) FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	route, err := a.ResolveRoute(ctx, model)
	if err != nil {
		return nil, err
	}
	return fetchAttestationForRoute(ctx, a, route, model, nonce)
}

// FetchAttestationForRoute uses the supplied route without another resolution.
func (a *Attester) FetchAttestationForRoute(ctx context.Context, route provider.ResolvedRoute, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	return fetchAttestationForRoute(ctx, a, route, model, nonce)
}

func fetchAttestationForRoute(ctx context.Context, a *Attester, route provider.ResolvedRoute, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	if route.Authority() == "" {
		return nil, errors.New("nearai: attestation requires a resolved route")
	}
	baseURL := route.BaseURL()

	endpoint, err := url.Parse(baseURL + attestationPath)
	if err != nil {
		return nil, fmt.Errorf("nearai: parse endpoint base URL %q: %w", baseURL, err)
	}
	q := endpoint.Query()
	q.Set("nonce", nonce.Hex())
	q.Set("include_tls_fingerprint", "true")
	q.Set("signing_algo", "ed25519")
	endpoint.RawQuery = q.Encode()

	body, peerSPKI, err := provider.FetchAttestationWithTLS(ctx, a.client, endpoint.String(), a.apiKey, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("nearai: %w", err)
	}

	raw, err := ParseAttestationResponse(ctx, body, model)
	if err != nil {
		return nil, err
	}
	if err := tlsct.CompareSPKIFingerprints(peerSPKI, raw.TLSFingerprint); err != nil {
		return nil, fmt.Errorf("nearai: attestation TLS binding: %w", err)
	}
	raw.TransportTLSFingerprint = raw.TLSFingerprint
	raw.TransportTLSAuthority = route.Authority()
	return raw, nil
}

func shouldResolveModelDomain(host string) bool {
	host = strings.ToLower(host)
	return host == "api.near.ai" || host == "completions.near.ai"
}

// ParseAttestationResponse unmarshals a NEAR AI attestation JSON response body
// and selects the entry matching model. Used by both FetchAttestation (HTTP
// client path) and PinnedHandler (raw connection path).
func ParseAttestationResponse(_ context.Context, body []byte, model string) (*attestation.RawAttestation, error) {
	var ar attestationResponse
	unknown, missing, err := jsonstrict.UnmarshalWarn(body, &ar, "nearai attestation")
	if err != nil {
		return nil, fmt.Errorf("nearai: unmarshal attestation response: %w", err)
	}

	if len(ar.AllAttestations) > maxAttestationEntries {
		return nil, fmt.Errorf("nearai: all_attestations has %d entries, max %d", len(ar.AllAttestations), maxAttestationEntries)
	}
	if len(ar.ModelAttestations) > maxAttestationEntries {
		return nil, fmt.Errorf("nearai: model_attestations has %d entries, max %d", len(ar.ModelAttestations), maxAttestationEntries)
	}
	if ar.ComposeManagerAttestation != nil && len(ar.ComposeManagerAttestation.Actions) > maxComposeManagerActions {
		return nil, fmt.Errorf("nearai: compose_manager_attestation actions has %d entries, max %d", len(ar.ComposeManagerAttestation.Actions), maxComposeManagerActions)
	}

	if len(ar.AllAttestations) > 0 {
		selected, err := selectByModel(ar.AllAttestations, model)
		if err != nil {
			return nil, err
		}
		raw := rawFromModelAttestation(selected, ar.Verified, body)
		raw.UnknownFields = unknown
		raw.MissingFields = missing
		return raw, nil
	}

	// If the response contains model_attestations, pick the entry matching
	// the requested model. Returns an error if no entry matches.
	if len(ar.ModelAttestations) > 0 {
		selected, err := selectByModel(ar.ModelAttestations, model)
		if err != nil {
			return nil, err
		}
		raw := rawFromModelAttestation(selected, ar.Verified, body)
		raw.UnknownFields = unknown
		raw.MissingFields = missing
		return raw, nil
	}

	// Flat response form: use top-level fields directly.
	var info modelInfo
	if ar.Info != nil {
		info = *ar.Info
	}
	raw := &attestation.RawAttestation{
		BackendFormat:  attestation.FormatNear,
		Verified:       ar.Verified,
		Nonce:          ar.RequestNonce,
		Model:          ar.ModelName,
		TEEProvider:    "TDX+NVIDIA",
		SigningKey:     ar.SigningPublicKey,
		SigningAddress: ar.SigningAddress,
		SigningAlgo:    ar.SigningAlgo,
		TLSFingerprint: ar.TLSCertFingerprint,
		IntelQuote:     ar.IntelQuote,
		NvidiaPayload:  ar.NvidiaPayload,
		AppCompose:     info.TCBInfo.AppCompose,
		AppName:        info.AppName,
		ComposeHash:    info.ComposeHash,
		OSImageHash:    info.OSImageHash,
		DeviceID:       info.DeviceID,
		EventLog:       ar.EventLog,
		EventLogCount:  len(ar.EventLog),
		UnknownFields:  unknown,
		MissingFields:  missing,
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

func rawFromModelAttestation(m *modelAttestation, verified bool, body []byte) *attestation.RawAttestation {
	raw := &attestation.RawAttestation{
		BackendFormat:  attestation.FormatNear,
		Verified:       verified,
		Nonce:          m.RequestNonce,
		Model:          m.ModelName,
		TEEProvider:    "TDX+NVIDIA",
		SigningKey:     m.SigningPublicKey,
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
	return raw
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

// PrepareRequest injects the NEAR AI Authorization header into req.
func (p *Preparer) PrepareRequest(req *http.Request, headers http.Header, _ *e2ee.ChutesE2EE, _ bool, _ string) error {
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	if len(headers) == 0 {
		return nil
	}
	names := []string{"X-Signing-Algo", "X-Client-Pub-Key", "X-Encryption-Version", "X-Encrypt-All-Fields"}
	for _, name := range names {
		if len(headers.Values(name)) != 1 || headers.Get(name) == "" {
			return fmt.Errorf("incomplete NEAR E2EE headers: %s", name)
		}
	}
	if headers.Get("X-Signing-Algo") != "ed25519" || headers.Get("X-Encryption-Version") != "2" || headers.Get("X-Encrypt-All-Fields") != "true" {
		return errors.New("invalid NEAR E2EE protocol headers")
	}
	for _, name := range names {
		req.Header.Set(name, headers.Get(name))
	}
	return nil
}

// ResolveRoute selects the same origin that a standalone attestation will use.
func (a *Attester) ResolveRoute(ctx context.Context, model string) (provider.ResolvedRoute, error) {
	base, err := url.Parse(a.baseURL)
	if err != nil {
		return provider.ResolvedRoute{}, fmt.Errorf("nearai: parse base URL %q: %w", a.baseURL, err)
	}
	if shouldResolveModelDomain(base.Hostname()) {
		if a.resolver == nil {
			return provider.ResolvedRoute{}, errors.New("missing NEAR route resolver")
		}
		domain, err := a.resolver.Resolve(ctx, model)
		if err != nil {
			return provider.ResolvedRoute{}, fmt.Errorf("nearai: resolve model %q: %w", model, err)
		}
		slog.DebugContext(ctx, "nearai model resolved", "model", model, "domain", domain)
		return provider.NewResolvedRoute("https://"+domain, "")
	}
	return provider.NewResolvedRoute(a.baseURL, "")
}
