// Package nanogpt implements the Attester interface for NanoGPT's TEE
// attestation API.
//
// NanoGPT attestation endpoint:
//
//	GET {base_url}/v1/tee/attestation?model={model}&nonce={nonce}
//	Authorization: Bearer {api_key}
package nanogpt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/formatdetect"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
)

// attestationPath is the NanoGPT API path for TEE attestation.
const attestationPath = "/v1/tee/attestation"

// tcbInfo holds the parsed info.tcb_info object from NanoGPT's attestation
// response. Contains dstack measurements and the docker-compose manifest.
type tcbInfo struct {
	AppCompose  string                      `json:"app_compose"`
	ComposeHash string                      `json:"compose_hash"`
	DeviceID    string                      `json:"device_id"`
	EventLog    []attestation.EventLogEntry `json:"event_log"`
	MRTD        string                      `json:"mrtd"`
	OSImageHash string                      `json:"os_image_hash"`
	RTMR0       string                      `json:"rtmr0"`
	RTMR1       string                      `json:"rtmr1"`
	RTMR2       string                      `json:"rtmr2"`
	RTMR3       string                      `json:"rtmr3"`
}

// UnmarshalJSON handles tcb_info being either a direct JSON object or a
// JSON-encoded string containing JSON (double-encoded by some dstack versions).
func (t *tcbInfo) UnmarshalJSON(data []byte) error {
	type alias tcbInfo
	return json.Unmarshal(provider.UnwrapDoubleEncoded(data), (*alias)(t))
}

// nanogptInfo holds the nested "info" object from NanoGPT's attestation
// response, containing dstack environment metadata.
type nanogptInfo struct {
	AppCert      string  `json:"app_cert"`
	AppID        string  `json:"app_id"`
	AppName      string  `json:"app_name"`
	ComposeHash  string  `json:"compose_hash"`
	DeviceID     string  `json:"device_id"`
	InstanceID   string  `json:"instance_id"`
	KeyProvider  string  `json:"key_provider_info"`
	MRAggregated string  `json:"mr_aggregated"`
	OSImageHash  string  `json:"os_image_hash"`
	TCBInfo      tcbInfo `json:"tcb_info"`
	VMConfig     string  `json:"vm_config"`
}

// dstackAttestation holds the fields common to both the top-level dstack
// response and each entry in the all_attestations array. NanoGPT uses
// `signing_public_key` (not `signing_key`) and `event_log` may be either
// a JSON array or a JSON-encoded string.
type dstackAttestation struct {
	SigningPublicKey string           `json:"signing_public_key"`
	SigningAddress   string           `json:"signing_address"`
	SigningAlgo      string           `json:"signing_algo"`
	IntelQuote       string           `json:"intel_quote"`
	Quote            string           `json:"quote"`
	NvidiaPayload    string           `json:"nvidia_payload"`
	EventLog         eventLogFlexible `json:"event_log"`
	Info             nanogptInfo      `json:"info"`
	RequestNonce     string           `json:"request_nonce"`
	VMConfig         string           `json:"vm_config"`
}

// attestationResponse is the top-level JSON shape returned by NanoGPT's
// dstack-format attestation endpoint.
type attestationResponse struct {
	dstackAttestation
	AllAttestations []dstackAttestation `json:"all_attestations"`
}

// eventLogFlexible handles event_log being either a JSON array of objects or a
// JSON-encoded string containing the array.
type eventLogFlexible []attestation.EventLogEntry

func (e *eventLogFlexible) UnmarshalJSON(data []byte) error {
	// Try direct array first.
	var entries []attestation.EventLogEntry
	if json.Unmarshal(data, &entries) == nil {
		*e = entries
		return nil
	}
	// Try JSON-encoded string containing the array.
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("event_log: expected array or string, got: %.50s", data)
	}
	return json.Unmarshal([]byte(str), (*[]attestation.EventLogEntry)(e))
}

// Attester fetches attestation data from NanoGPT's /v1/tee/attestation
// endpoint. It sends the client-supplied nonce as a query parameter so NanoGPT
// echoes it back in the response for nonce_match verification.
type Attester struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewAttester returns a NanoGPT Attester configured with the given base URL and
// API key. It uses a 30-second HTTP timeout via config.NewAttestationClient.
func NewAttester(baseURL, apiKey string, offline ...bool) *Attester {
	return &Attester{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  config.NewAttestationClient(offline...),
	}
}

// FetchAttestation fetches TEE attestation for the given model from NanoGPT.
// The nonce is sent as a hex string query parameter; NanoGPT echoes it back in
// the response so callers can verify nonce_match.
func (a *Attester) FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	endpoint, err := url.Parse(a.baseURL + attestationPath)
	if err != nil {
		return nil, fmt.Errorf("nanogpt: parse base URL %q: %w", a.baseURL, err)
	}
	q := endpoint.Query()
	q.Set("model", model)
	q.Set("nonce", nonce.Hex())
	endpoint.RawQuery = q.Encode()

	body, err := provider.FetchAttestationJSON(ctx, a.client, endpoint.String(), a.apiKey, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("nanogpt: %w", err)
	}
	return ParseAttestationResponse(body)
}

// ParseAttestationResponse detects the attestation format from the JSON body
// and delegates to the appropriate parser. For dstack format (the primary
// NanoGPT backend), parsing is handled internally. Other formats (chutes)
// are delegated to their respective packages.
func ParseAttestationResponse(body []byte) (*attestation.RawAttestation, error) {
	format := formatdetect.Detect(body)
	slog.Debug("nanogpt format detected", "format", format)

	switch format {
	case attestation.FormatDstack:
		return parseDstack(body)
	case attestation.FormatChutes:
		return provider.ParseChutesFormat(body, "nanogpt")
	case attestation.FormatTinfoil:
		return nil, errors.New("nanogpt: tinfoil attestation format not yet supported")
	case attestation.FormatGateway:
		return nil, errors.New("nanogpt: gateway attestation format not yet supported")
	default:
		return nil, errors.New("nanogpt: unrecognized attestation format (no known format keys found)")
	}
}

// parseDstack handles the dstack attestation format with NanoGPT-specific
// quirks (signing_public_key instead of signing_key, eventLogFlexible,
// double-encoded tcb_info).
func parseDstack(body []byte) (*attestation.RawAttestation, error) {
	var ar attestationResponse
	if err := jsonstrict.UnmarshalWarn(body, &ar, "nanogpt attestation response"); err != nil {
		return nil, fmt.Errorf("nanogpt: unmarshal attestation response: %w", err)
	}

	entries := []attestation.EventLogEntry(ar.EventLog)
	slog.Debug("nanogpt event log", "entries", len(entries))
	for i, e := range entries {
		digest := e.Digest
		if len(digest) > 16 {
			digest = digest[:16] + "..."
		}
		slog.Debug("event log entry", "index", i, "imr", e.IMR,
			"event", e.Event, "type", e.EventType, "digest", digest)
	}

	return &attestation.RawAttestation{
		BackendFormat:  attestation.FormatDstack,
		Nonce:          ar.RequestNonce,
		SigningKey:     provider.NormalizeUncompressedKey(ar.SigningPublicKey),
		SigningAddress: ar.SigningAddress,
		IntelQuote:     ar.IntelQuote,
		NvidiaPayload:  ar.NvidiaPayload,

		SigningAlgo:   ar.SigningAlgo,
		AppName:       ar.Info.AppName,
		ComposeHash:   ar.Info.ComposeHash,
		OSImageHash:   ar.Info.OSImageHash,
		DeviceID:      ar.Info.DeviceID,
		AppCompose:    ar.Info.TCBInfo.AppCompose,
		EventLog:      entries,
		EventLogCount: len(entries),

		RawBody: body,
	}, nil
}
