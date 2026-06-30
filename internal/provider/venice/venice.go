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

// aciResponse is the JSON shape returned by Venice's ACI/1 attestation format.
// The api_version field discriminates this from the dstack format. ACI/1
// includes both the new nested "attestation" block and dstack-compatible
// top-level fields (nonce, model, verified, etc.).
type aciResponse struct {
	// ACI/1-specific fields.
	APIVersion           string         `json:"api_version"`
	WorkloadID           string         `json:"workload_id"`
	WorkloadKeysetDigest string         `json:"workload_keyset_digest"`
	Attestation          aciAttestation `json:"attestation"`
	ServiceCapabilities  aciServiceCaps `json:"service_capabilities"`

	// dstack-compatible top-level fields.
	Verified           bool                `json:"verified"`
	Nonce              string              `json:"nonce"`
	Model              string              `json:"model"`
	TEEProvider        string              `json:"tee_provider"`
	SigningKey         string              `json:"signing_public_key"`
	SigningAddress     string              `json:"signing_address"`
	IntelQuote         string              `json:"intel_quote"`
	NvidiaPayload      string              `json:"nvidia_payload"`
	ServerVerification *ServerVerification `json:"server_verification"`
	UpstreamModel      string              `json:"upstream_model"`
	SigningAlgo        string              `json:"signing_algo"`
	TEEHardware        string              `json:"tee_hardware"`
	NonceSource        string              `json:"nonce_source"`
	CandidatesAvail    int                 `json:"candidates_available"`
	CandidatesEval     int                 `json:"candidates_evaluated"`
}

// aciServiceCaps holds service capability declarations.
type aciServiceCaps struct {
	SupportedE2EEVersions []string `json:"supported_e2ee_versions"`
}

// aciAttestation holds the nested "attestation" object in ACI/1 responses.
type aciAttestation struct {
	Vendor            string               `json:"vendor"`
	TEEType           string               `json:"tee_type"`
	WorkloadKeyset    aciWorkloadKeyset    `json:"workload_keyset"`
	ReportData        string               `json:"report_data"`
	KeysetEndorsement aciKeysetEndorsement `json:"keyset_endorsement"`
	SourceProvenance  aciSourceProvenance  `json:"source_provenance"`
	Freshness         aciFreshness         `json:"freshness"`
	Evidence          aciEvidence          `json:"evidence"`
}

// aciWorkloadKeyset holds the workload_keyset object in ACI/1 responses.
type aciWorkloadKeyset struct {
	WorkloadIdentity   aciWorkloadIdentity `json:"workload_identity"`
	KeysetEpoch        aciKeysetEpoch      `json:"keyset_epoch"`
	ReceiptSigningKeys []aciKey            `json:"receipt_signing_keys"`
	E2EEPublicKeys     []aciKey            `json:"e2ee_public_keys"`
	TLSPublicKeys      []aciTLSBinding     `json:"tls_public_keys"`
}

// aciWorkloadIdentity holds the workload_identity object.
type aciWorkloadIdentity struct {
	PublicKey aciPublicKey `json:"public_key"`
	Subject   *string      `json:"subject"` // nullable
}

// aciPublicKey holds an algorithm + public key pair.
type aciPublicKey struct {
	Algo      string `json:"algo"`
	PublicKey string `json:"public_key"`
}

// aciKeysetEpoch holds keyset epoch metadata. NotAfter uses json.Number
// because the wire value may be a float64-rounded representation of u64::MAX
// (e.g. 18446744073709552000) which exceeds uint64 range. The raw JSON number
// is preserved as-is for JCS canonicalization.
type aciKeysetEpoch struct {
	Version  int         `json:"version"`
	NotAfter json.Number `json:"not_after"`
}

// aciKey holds a named cryptographic key entry.
type aciKey struct {
	KeyID     string `json:"key_id"`
	Algo      string `json:"algo"`
	PublicKey string `json:"public_key"`
}

// aciKeysetEndorsement holds the keyset endorsement signature.
type aciKeysetEndorsement struct {
	Algo  string `json:"algo"`
	Value string `json:"value"`
}

// aciFreshness holds attestation freshness timestamps.
type aciFreshness struct {
	FetchedAt  int64 `json:"fetched_at"`
	StaleAfter int64 `json:"stale_after"`
}

// aciSourceProvenance holds the source_provenance object in ACI/1 responses.
type aciSourceProvenance struct {
	RepoURL         string  `json:"repo_url"`
	RepoCommit      string  `json:"repo_commit"`
	ImageDigest     *string `json:"image_digest"`     // nullable
	ImageProvenance *string `json:"image_provenance"` // nullable
}

// aciKeyCustody holds the key_custody object in ACI/1 responses.
type aciKeyCustody struct {
	Provider string          `json:"provider"`
	Keys     []aciCustodyKey `json:"keys"`
}

// aciCustodyKey holds one entry in the key_custody.keys array.
type aciCustodyKey struct {
	Role           string   `json:"role"`
	Path           string   `json:"path"`
	Purpose        string   `json:"purpose"`
	Algo           string   `json:"algo"`
	PublicKey      string   `json:"public_key"`
	SignatureChain []string `json:"signature_chain"`
}

// aciTLSBinding holds a domain + SPKI hash pair (used in both
// downstream_tls_binding and workload_keyset.tls_public_keys).
type aciTLSBinding struct {
	Domain     string `json:"domain"`
	SPKISHA256 string `json:"spki_sha256"`
}

// aciEvidence holds the evidence object in ACI/1 responses.
type aciEvidence struct {
	Quote                string           `json:"quote"`
	QuoteReportData      string           `json:"quote_report_data"`
	EventLog             eventLogFlexible `json:"event_log"`
	VMConfig             string           `json:"vm_config"`
	KeyCustody           aciKeyCustody    `json:"key_custody"`
	DownstreamTLSBinding aciTLSBinding    `json:"downstream_tls_binding"`
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
		client:  config.NewAttestationClient(len(offline) > 0 && offline[0]),
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
// into a RawAttestation. Detects ACI/1 format via the api_version field;
// responses without api_version are treated as dstack. Extracted from
// FetchAttestation so integration tests can parse fixture files without making
// HTTP calls.
func ParseAttestationResponse(ctx context.Context, body []byte) (*attestation.RawAttestation, error) {
	var probe struct {
		APIVersion string `json:"api_version"`
	}
	// Intentionally ignore error — missing api_version means dstack.
	_ = json.Unmarshal(body, &probe)

	if probe.APIVersion == "aci/1" {
		var ar aciResponse
		unknown, missing, err := jsonstrict.UnmarshalWarn(body, &ar, "venice aci/1 attestation")
		if err != nil {
			return nil, fmt.Errorf("venice aci/1: unmarshal: %w", err)
		}
		return aciToRaw(ctx, &ar, unknown, missing, body), nil
	}

	var ar attestationResponse
	unknown, missing, err := jsonstrict.UnmarshalWarn(body, &ar, "venice dstack attestation")
	if err != nil {
		return nil, fmt.Errorf("venice dstack: unmarshal: %w", err)
	}
	return dstackToRaw(ctx, &ar, unknown, missing, body), nil
}

// dstackToRaw converts a parsed dstack attestation response to RawAttestation.
func dstackToRaw(ctx context.Context, ar *attestationResponse, unknown, missing []string, body []byte) *attestation.RawAttestation {
	logEventLog(ctx, ar.EventLog)
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
		MissingFields: missing,
		RawBody:       body,
	}
}

// aciToRaw converts a parsed ACI/1 attestation response to RawAttestation.
// ACI/1 includes dstack-compatible top-level fields (nonce, model, verified,
// etc.) alongside the new nested "attestation" block. Event logs come from the
// nested evidence object rather than the top level.
func aciToRaw(ctx context.Context, ar *aciResponse, unknown, missing []string, body []byte) *attestation.RawAttestation {
	logEventLog(ctx, ar.Attestation.Evidence.EventLog)
	return &attestation.RawAttestation{
		BackendFormat:   attestation.FormatACI1,
		Verified:        ar.Verified,
		Nonce:           ar.Nonce,
		Model:           ar.Model,
		TEEProvider:     ar.TEEProvider,
		SigningKey:      ar.SigningKey,
		SigningAddress:  ar.SigningAddress,
		IntelQuote:      ar.IntelQuote,
		NvidiaPayload:   ar.NvidiaPayload,
		TEEHardware:     ar.TEEHardware,
		SigningAlgo:     ar.SigningAlgo,
		UpstreamModel:   ar.UpstreamModel,
		NonceSource:     ar.NonceSource,
		CandidatesAvail: ar.CandidatesAvail,
		CandidatesEval:  ar.CandidatesEval,
		EventLog:        ar.Attestation.Evidence.EventLog,
		EventLogCount:   len(ar.Attestation.Evidence.EventLog),

		ACISourceRepoURL:        ar.Attestation.SourceProvenance.RepoURL,
		ACIWorkloadID:           ar.WorkloadID,
		ACIWorkloadKeysetDigest: ar.WorkloadKeysetDigest,
		ACIKeysetEndorsementSig: ar.Attestation.KeysetEndorsement.Value,
		ACIIdentityKeyHex:       ar.Attestation.WorkloadKeyset.WorkloadIdentity.PublicKey.PublicKey,
		ACIWorkloadKeyset:       &ar.Attestation.WorkloadKeyset,

		UnknownFields: unknown,
		MissingFields: missing,
		RawBody:       body,
	}
}

// logEventLog logs event log entries at debug level.
func logEventLog(ctx context.Context, entries []attestation.EventLogEntry) {
	slog.DebugContext(ctx, "venice event log", "entries", len(entries))
	for i, e := range entries {
		digest := e.Digest
		if len(digest) > 16 {
			digest = digest[:16] + "..."
		}
		slog.DebugContext(ctx, "event log entry", "index", i, "imr", e.IMR,
			"event", e.Event, "type", e.EventType, "digest", digest)
	}
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
