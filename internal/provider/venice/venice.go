// Package venice implements the Attester and RequestPreparer interfaces for
// Venice AI's TEE attestation and E2EE API.
//
// Venice attestation endpoint:
//
//	GET {base_url}/api/v1/tee/attestation?model={model}&nonce={nonce}
//	Authorization: Bearer {api_key}
//
// Venice E2EE request headers (PrepareRequest):
//
//	X-Venice-TEE-Client-Pub-Key: {session_public_key_hex}
//	X-Venice-TEE-Model-Pub-Key:  {model_signing_key_hex}
//	X-Venice-TEE-Signing-Algo:   ecdsa
//	Authorization:               Bearer {api_key}
package venice

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/jsonstrict"
)

// attestationPath is the Venice API path for TEE attestation.
const attestationPath = "/api/v1/tee/attestation"

// eventLogEntry is one entry in Venice's event_log array — a TDX RTMR
// measurement extend event.
type eventLogEntry struct {
	Digest       string `json:"digest"`
	Event        string `json:"event"`
	EventPayload string `json:"event_payload"`
	EventType    int    `json:"event_type"`
	IMR          int    `json:"imr"`
}

// veniceInfo holds the nested "info" object from Venice's attestation
// response, containing dstack environment metadata.
type veniceInfo struct {
	AppCert      string          `json:"app_cert"`
	AppID        string          `json:"app_id"`
	AppName      string          `json:"app_name"`
	ComposeHash  string          `json:"compose_hash"`
	DeviceID     string          `json:"device_id"`
	InstanceID   string          `json:"instance_id"`
	KeyProvider  string          `json:"key_provider_info"`
	MRAggregated string          `json:"mr_aggregated"`
	OSImageHash  string          `json:"os_image_hash"`
	TCBInfo      json.RawMessage `json:"tcb_info"`
	VMConfig     string          `json:"vm_config"`
}

// attestationResponse is the JSON shape returned by Venice's attestation
// endpoint. All 20 fields are parsed to eliminate jsonstrict warnings.
type attestationResponse struct {
	// Core fields (original 8).
	Verified       bool   `json:"verified"`
	Nonce          string `json:"nonce"`
	Model          string `json:"model"`
	TEEProvider    string `json:"tee_provider"`
	SigningKey     string `json:"signing_key"`
	SigningAddress string `json:"signing_address"`
	IntelQuote     string `json:"intel_quote"`
	NvidiaPayload  string `json:"nvidia_payload"`

	// Extended fields (10 propagated to RawAttestation).
	EventLog           []eventLogEntry `json:"event_log"`
	Info               veniceInfo      `json:"info"`
	ServerVerification json.RawMessage `json:"server_verification"`
	ModelName          string          `json:"model_name"`
	UpstreamModel      string          `json:"upstream_model"`
	SigningAlgo        string          `json:"signing_algo"`
	TEEHardware        string          `json:"tee_hardware"`
	NonceSource        string          `json:"nonce_source"`
	CandidatesAvail    int             `json:"candidates_available"`
	CandidatesEval     int             `json:"candidates_evaluated"`

	// Duplicate fields (parsed to silence jsonstrict, not propagated).
	SigningPublicKey string `json:"signing_public_key"`
	RequestNonce     string `json:"request_nonce"`
}

// Attester fetches attestation data from Venice's /api/v1/tee/attestation
// endpoint. It sends the client-supplied nonce as a query parameter so Venice
// echoes it back in the response for nonce_match verification.
type Attester struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewAttester returns a Venice Attester configured with the given base URL and
// API key. It uses a 30-second HTTP timeout via config.NewAttestationClient.
func NewAttester(baseURL, apiKey string) *Attester {
	return &Attester{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  config.NewAttestationClient(),
	}
}

// FetchAttestation fetches TEE attestation for the given model from Venice.
// The nonce is sent to Venice as a hex string query parameter; Venice echoes it
// back in the response so callers can verify nonce_match.
func (a *Attester) FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	endpoint, err := url.Parse(a.baseURL + attestationPath)
	if err != nil {
		return nil, fmt.Errorf("venice: parse base URL %q: %w", a.baseURL, err)
	}

	q := endpoint.Query()
	q.Set("model", model)
	q.Set("nonce", nonce.Hex())
	endpoint.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("venice: build attestation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.apiKey)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("venice: GET %s: %w", endpoint.String(), err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB max
	if err != nil {
		return nil, fmt.Errorf("venice: read attestation response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := string(body)
		if len(msg) > 512 {
			msg = msg[:512] + "...[truncated]"
		}
		return nil, fmt.Errorf("venice: attestation endpoint returned HTTP %d: %s", resp.StatusCode, msg)
	}

	var ar attestationResponse
	if err := jsonstrict.UnmarshalWarn(body, &ar, "venice attestation response"); err != nil {
		return nil, fmt.Errorf("venice: unmarshal attestation response: %w", err)
	}

	slog.Debug("venice event log", "entries", len(ar.EventLog))
	for i, e := range ar.EventLog {
		digest := e.Digest
		if len(digest) > 16 {
			digest = digest[:16] + "..."
		}
		slog.Debug("event log entry", "index", i, "imr", e.IMR,
			"event", e.Event, "type", e.EventType, "digest", digest)
	}

	return &attestation.RawAttestation{
		Verified:       ar.Verified,
		Nonce:          ar.Nonce,
		Model:          ar.Model,
		TEEProvider:    ar.TEEProvider,
		SigningKey:     ar.SigningKey,
		SigningAddress: ar.SigningAddress,
		IntelQuote:     ar.IntelQuote,
		NvidiaPayload:  ar.NvidiaPayload,

		TEEHardware:        ar.TEEHardware,
		SigningAlgo:        ar.SigningAlgo,
		UpstreamModel:      ar.UpstreamModel,
		AppName:            ar.Info.AppName,
		ComposeHash:        ar.Info.ComposeHash,
		OSImageHash:        ar.Info.OSImageHash,
		DeviceID:           ar.Info.DeviceID,
		EventLogCount:      len(ar.EventLog),
		NonceSource:        ar.NonceSource,
		CandidatesAvail:    ar.CandidatesAvail,
		CandidatesEval:     ar.CandidatesEval,
		ServerVerification: ar.ServerVerification,

		RawBody: body,
	}, nil
}

// Preparer injects Venice E2EE headers into an outgoing chat completions
// request. The three required Venice E2EE headers identify the client's
// ephemeral public key, the model's attested signing key, and the algorithm.
type Preparer struct {
	apiKey string
}

// NewPreparer returns a Venice Preparer configured with the given API key.
func NewPreparer(apiKey string) *Preparer {
	return &Preparer{apiKey: apiKey}
}

// PrepareRequest injects the Venice E2EE headers into req. The session must
// have its ModelKeyHex set (via SetModelKey) before calling this function.
func (p *Preparer) PrepareRequest(req *http.Request, session *attestation.Session) error {
	if session.ModelKeyHex == "" {
		return fmt.Errorf("venice: PrepareRequest called with empty session.ModelKeyHex; call SetModelKey first")
	}
	if session.PublicKeyHex == "" {
		return fmt.Errorf("venice: PrepareRequest called with empty session.PublicKeyHex; session may not be initialised")
	}

	req.Header.Set("X-Venice-TEE-Client-Pub-Key", session.PublicKeyHex)
	req.Header.Set("X-Venice-TEE-Model-Pub-Key", session.ModelKeyHex)
	req.Header.Set("X-Venice-TEE-Signing-Algo", "ecdsa")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	return nil
}
