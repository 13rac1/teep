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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/jsonstrict"
)

// attestationPath is the NanoGPT API path for TEE attestation.
const attestationPath = "/v1/tee/attestation"

// eventLogEntry is one entry in NanoGPT's event_log array — a TDX RTMR
// measurement extend event. Mirrors attestation.EventLogEntry but with
// NanoGPT's field order for strict JSON parsing.
type eventLogEntry struct {
	Digest       string `json:"digest"`
	Event        string `json:"event"`
	EventPayload string `json:"event_payload"`
	EventType    int    `json:"event_type"`
	IMR          int    `json:"imr"`
}

// tcbInfo holds the parsed info.tcb_info object from NanoGPT's attestation
// response. Contains dstack measurements and the docker-compose manifest.
type tcbInfo struct {
	AppCompose  string          `json:"app_compose"`
	ComposeHash string          `json:"compose_hash"`
	DeviceID    string          `json:"device_id"`
	EventLog    []eventLogEntry `json:"event_log"`
	MRTD        string          `json:"mrtd"`
	OSImageHash string          `json:"os_image_hash"`
	RTMR0       string          `json:"rtmr0"`
	RTMR1       string          `json:"rtmr1"`
	RTMR2       string          `json:"rtmr2"`
	RTMR3       string          `json:"rtmr3"`
}

// UnmarshalJSON handles tcb_info being either a direct JSON object or a
// JSON-encoded string containing JSON (double-encoded by some dstack versions).
func (t *tcbInfo) UnmarshalJSON(data []byte) error {
	var str string
	if json.Unmarshal(data, &str) == nil {
		data = []byte(str)
	}
	type alias tcbInfo // prevent recursion
	return json.Unmarshal(data, (*alias)(t))
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
type eventLogFlexible []eventLogEntry

func (e *eventLogFlexible) UnmarshalJSON(data []byte) error {
	// Try direct array first.
	var entries []eventLogEntry
	if json.Unmarshal(data, &entries) == nil {
		*e = entries
		return nil
	}
	// Try JSON-encoded string containing the array.
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("event_log: expected array or string, got: %.50s", data)
	}
	return json.Unmarshal([]byte(str), (*[]eventLogEntry)(e))
}

func toEventLogEntries(local []eventLogEntry) []attestation.EventLogEntry {
	out := make([]attestation.EventLogEntry, len(local))
	for i, e := range local {
		out[i] = attestation.EventLogEntry{
			IMR:          e.IMR,
			Digest:       e.Digest,
			EventType:    e.EventType,
			Event:        e.Event,
			EventPayload: e.EventPayload,
		}
	}
	return out
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("nanogpt: build attestation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.apiKey)

	resp, err := a.client.Do(req)
	if err != nil {
		// Use host+path only — never include query parameters (may leak nonce).
		return nil, fmt.Errorf("nanogpt: GET %s%s: %w", endpoint.Host, endpoint.Path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB max
	if err != nil {
		return nil, fmt.Errorf("nanogpt: read attestation response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := string(body)
		if len(msg) > 512 {
			msg = msg[:512] + "...[truncated]"
		}
		return nil, fmt.Errorf("nanogpt: attestation endpoint returned HTTP %d: %s", resp.StatusCode, msg)
	}

	return ParseAttestationResponse(body)
}

// ParseAttestationResponse unmarshals a NanoGPT attestation JSON response body
// into a RawAttestation. Exported so integration tests can parse fixture files
// without making HTTP calls.
func ParseAttestationResponse(body []byte) (*attestation.RawAttestation, error) {
	var ar attestationResponse
	if err := jsonstrict.UnmarshalWarn(body, &ar, "nanogpt attestation response"); err != nil {
		return nil, fmt.Errorf("nanogpt: unmarshal attestation response: %w", err)
	}

	entries := []eventLogEntry(ar.EventLog)
	slog.Debug("nanogpt event log", "entries", len(entries))
	for i, e := range entries {
		digest := e.Digest
		if len(digest) > 16 {
			digest = digest[:16] + "..."
		}
		slog.Debug("event log entry", "index", i, "imr", e.IMR,
			"event", e.Event, "type", e.EventType, "digest", digest)
	}

	appCompose := ar.Info.TCBInfo.AppCompose

	// NanoGPT returns the raw secp256k1 x||y point (64 bytes = 128 hex)
	// without the 04 uncompressed-point prefix. Prepend it so downstream
	// code (reportdata verifier, E2EE session) works unchanged.
	signingKey := ar.SigningPublicKey
	if len(signingKey) == 128 {
		signingKey = "04" + signingKey
	}

	return &attestation.RawAttestation{
		Nonce:          ar.RequestNonce,
		SigningKey:     signingKey,
		SigningAddress: ar.SigningAddress,
		IntelQuote:     ar.IntelQuote,
		NvidiaPayload:  ar.NvidiaPayload,

		SigningAlgo:   ar.SigningAlgo,
		AppName:       ar.Info.AppName,
		ComposeHash:   ar.Info.ComposeHash,
		OSImageHash:   ar.Info.OSImageHash,
		DeviceID:      ar.Info.DeviceID,
		AppCompose:    appCompose,
		EventLog:      toEventLogEntries(entries),
		EventLogCount: len(entries),

		RawBody: body,
	}, nil
}
