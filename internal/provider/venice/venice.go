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
	"log/slog"
	"maps"
	"net/http"
	"net/url"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
)

// attestationPath is the Venice API path for TEE attestation.
const attestationPath = "/api/v1/tee/attestation"

// eventLogFlexible handles event_log being either a JSON array of objects or a
// JSON-encoded string containing the array.
type eventLogFlexible []attestation.EventLogEntry

func (e *eventLogFlexible) UnmarshalJSON(data []byte) error {
	// Try direct array first. Error intentionally discarded — fall through to string parse.
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

// tcbInfo holds the parsed info.tcb_info object from Venice's attestation
// response. Contains dstack measurements and the docker-compose manifest.
type tcbInfo struct {
	AppCompose  string           `json:"app_compose"`  // JSON-encoded dstack manifest
	ComposeHash string           `json:"compose_hash"` // hex SHA-256
	DeviceID    string           `json:"device_id"`    // hex TDX device ID
	EventLog    eventLogFlexible `json:"event_log"`    // TDX RTMR extend events
	MRTD        string           `json:"mrtd"`         // hex SHA-384
	OSImageHash string           `json:"os_image_hash"`
	RTMR0       string           `json:"rtmr0"` // hex SHA-384
	RTMR1       string           `json:"rtmr1"`
	RTMR2       string           `json:"rtmr2"`
	RTMR3       string           `json:"rtmr3"`
}

// UnmarshalJSON handles tcb_info being either a direct JSON object or a
// JSON-encoded string containing JSON (double-encoded by some dstack versions).
func (t *tcbInfo) UnmarshalJSON(data []byte) error {
	type alias tcbInfo
	return json.Unmarshal(provider.UnwrapDoubleEncoded(data), (*alias)(t))
}

// ServerVerification holds Venice's gateway-level verification result.
// The gateway re-verifies the TDX quote and reports its findings; this is
// an untrusted claim (the gateway is not hardware-attested itself).
type ServerVerification struct {
	TDX struct {
		Valid                 bool   `json:"valid"`
		SignatureValid        bool   `json:"signatureValid"`
		CertificateChainValid bool   `json:"certificateChainValid"`
		RootCAPinned          bool   `json:"rootCaPinned"`
		AttestationKeyMatch   bool   `json:"attestationKeyMatch"`
		ReportData            string `json:"reportData"`
		Measurements          struct {
			MRTD          string `json:"mrtd"`
			MRConfigID    string `json:"mrconfigid"`
			MROwner       string `json:"mrowner"`
			MROwnerConfig string `json:"mrownerconfig"`
			RTMR0         string `json:"rtmr0"`
			RTMR1         string `json:"rtmr1"`
			RTMR2         string `json:"rtmr2"`
			RTMR3         string `json:"rtmr3"`
			TDAttributes  string `json:"tdAttributes"`
			XFAM          string `json:"xfam"`
		} `json:"measurements"`
		CRLCheck struct {
			Checked bool `json:"checked"`
			Revoked bool `json:"revoked"`
		} `json:"crlCheck"`
	} `json:"tdx"`
	Nvidia struct {
		Valid             bool `json:"valid"`
		SignatureVerified bool `json:"signatureVerified"`
		CertificateChain  struct {
			Valid              bool   `json:"valid"`
			IntermediatePinned bool   `json:"intermediatePinned"`
			LeafCertExpiry     string `json:"leafCertExpiry"`
		} `json:"certificateChainStatus"`
	} `json:"nvidia"`
	SigningAddressBinding struct {
		Bound             bool   `json:"bound"`
		ReportDataAddress string `json:"reportDataAddress"`
	} `json:"signingAddressBinding"`
	NonceBinding struct {
		Bound  bool   `json:"bound"`
		Method string `json:"method"`
	} `json:"nonceBinding"`
	NvidiaNonceBinding struct {
		Bound  bool   `json:"bound"`
		Method string `json:"method"`
	} `json:"nvidiaNonceBinding"`
	VerifiedAt             string `json:"verifiedAt"`
	VerificationDurationMs int    `json:"verificationDurationMs"`
}

// veniceInfo holds the nested "info" object from Venice's attestation
// response, containing dstack environment metadata.
type veniceInfo struct {
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

// attestationResponse is the JSON shape returned by Venice's attestation
// endpoint. All 20 fields are parsed to eliminate jsonstrict warnings.
type attestationResponse struct {
	// Core fields (original 8).
	Verified       bool   `json:"verified"`
	Nonce          string `json:"nonce"`
	Model          string `json:"model"`
	TEEProvider    string `json:"tee_provider"`
	SigningKey     string `json:"signing_public_key"`
	SigningAddress string `json:"signing_address"`
	IntelQuote     string `json:"intel_quote"`
	NvidiaPayload  string `json:"nvidia_payload"`

	// Extended fields (10 propagated to RawAttestation).
	EventLog           eventLogFlexible    `json:"event_log"`
	Info               veniceInfo          `json:"info"`
	ServerVerification *ServerVerification `json:"server_verification"`
	ModelName          string              `json:"model_name"`
	UpstreamModel      string              `json:"upstream_model"`
	SigningAlgo        string              `json:"signing_algo"`
	TEEHardware        string              `json:"tee_hardware"`
	NonceSource        string              `json:"nonce_source"`
	CandidatesAvail    int                 `json:"candidates_available"`
	CandidatesEval     int                 `json:"candidates_evaluated"`

	// Duplicate top-level fields (parsed to silence jsonstrict, not propagated).
	// quote == intel_quote; vm_config == info.vm_config. Venice flattens these.
	// signing_key is an alternate name for signing_public_key used by some backends.
	RequestNonce  string `json:"request_nonce"`
	Quote         string `json:"quote"`
	VMConfig      string `json:"vm_config"`
	DupSigningKey string `json:"signing_key"`
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
func NewAttester(baseURL, apiKey string, offline ...bool) *Attester {
	return &Attester{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  config.NewAttestationClient(offline...),
	}
}

// SetClient replaces the HTTP client used for attestation fetches.
func (a *Attester) SetClient(c *http.Client) { a.client = c }

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

	body, err := provider.FetchAttestationJSON(ctx, a.client, endpoint.String(), a.apiKey, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("venice: %w", err)
	}
	return ParseAttestationResponse(ctx, body)
}

// ParseAttestationResponse unmarshals a Venice attestation JSON response body
// into a RawAttestation. Extracted from FetchAttestation so integration tests
// can parse fixture files without making HTTP calls.
func ParseAttestationResponse(ctx context.Context, body []byte) (*attestation.RawAttestation, error) {
	var ar attestationResponse
	unknown, err := jsonstrict.Unmarshal(body, &ar)
	if err != nil {
		return nil, fmt.Errorf("venice: unmarshal attestation response: %w", err)
	}

	slog.DebugContext(ctx, "venice event log", "entries", len(ar.EventLog))
	for i, e := range ar.EventLog {
		digest := e.Digest
		if len(digest) > 16 {
			digest = digest[:16] + "..."
		}
		slog.DebugContext(ctx, "event log entry", "index", i, "imr", e.IMR,
			"event", e.Event, "type", e.EventType, "digest", digest)
	}

	return &attestation.RawAttestation{
		BackendFormat:  attestation.FormatDstack,
		Verified:       ar.Verified,
		Nonce:          ar.Nonce,
		Model:          ar.Model,
		TEEProvider:    ar.TEEProvider,
		SigningKey:     ar.SigningKey,
		SigningAddress: ar.SigningAddress,
		IntelQuote:     ar.IntelQuote,
		NvidiaPayload:  ar.NvidiaPayload,

		TEEHardware:     ar.TEEHardware,
		SigningAlgo:     ar.SigningAlgo,
		UpstreamModel:   ar.UpstreamModel,
		AppName:         ar.Info.AppName,
		ComposeHash:     ar.Info.ComposeHash,
		OSImageHash:     ar.Info.OSImageHash,
		DeviceID:        ar.Info.DeviceID,
		AppCompose:      ar.Info.TCBInfo.AppCompose,
		EventLog:        ar.EventLog,
		EventLogCount:   len(ar.EventLog),
		NonceSource:     ar.NonceSource,
		CandidatesAvail: ar.CandidatesAvail,
		CandidatesEval:  ar.CandidatesEval,

		UnknownFields: unknown,
		RawBody:       body,
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

// PrepareRequest merges pre-built E2EE headers into req and sets Authorization.
func (p *Preparer) PrepareRequest(req *http.Request, e2eeHeaders http.Header, _ *e2ee.ChutesE2EE, _ bool, _ string) error {
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	maps.Copy(req.Header, e2eeHeaders)
	return nil
}
