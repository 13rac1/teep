// Package chutes implements the Attester and RequestPreparer interfaces for
// the Chutes direct TEE attestation API.
//
// The Chutes API uses a two-step attestation protocol:
//  1. GET /e2e/instances/{chute} → discover instances with ML-KEM-768 public keys
//  2. GET /chutes/{chute}/evidence?nonce={hex} → fetch TDX quotes and GPU evidence
//
// REPORTDATA binding: SHA256(nonce + e2e_pubkey).
// Model aliases: "default", "default:latency", "default:throughput".
//
// Chutes attestation endpoint:
//
//	GET {base_url}/chutes/{chute}/evidence?nonce={hex}
//	Authorization: Bearer {api_key}
package chutes

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
)

// DefaultLLMBaseURL is the Chutes OpenAI-compatible LLM inference gateway.
// This is distinct from the platform API (api.chutes.ai) which handles
// attestation, E2EE invoke, and management endpoints.
const DefaultLLMBaseURL = "https://llm.chutes.ai"

const (
	// attestationPath is the Chutes API path for TEE evidence (with chute ID placeholder).
	attestationPath = "/chutes/%s/evidence"

	// instancesPath is the Chutes API path for discovering e2e instances.
	instancesPath = "/e2e/instances/"

	// maxInstances bounds the number of e2e instance entries we parse.
	maxInstances = 256

	// maxEvidence bounds the number of evidence entries we parse.
	maxEvidence = 256

	// maxGPUEvidence bounds the number of GPU evidence entries per instance.
	maxGPUEvidence = 64

	// maxBodySize is the maximum response body size (2 MiB).
	maxBodySize = 2 << 20
)

// e2eInstancesResponse is the JSON response from GET /e2e/instances/{chute}.
type e2eInstancesResponse struct {
	Instances  []e2eInstance `json:"instances"`
	NonceExpIn int           `json:"nonce_expires_in"`
	NonceExpAt float64       `json:"nonce_expires_at"`
}

// e2eInstance is one instance entry with its ML-KEM-768 public key.
type e2eInstance struct {
	InstanceID string   `json:"instance_id"`
	E2EPubKey  string   `json:"e2e_pubkey"`
	Nonces     []string `json:"nonces"`
}

// attestationResponse is the JSON response from GET /chutes/{chute}/evidence.
type attestationResponse struct {
	Evidence          []instanceEvidence `json:"evidence"`
	FailedInstanceIDs []string           `json:"failed_instance_ids"`
}

// instanceEvidence is one instance's attestation evidence.
type instanceEvidence struct {
	Quote       string                    `json:"quote"` // base64-encoded TDX quote
	GPUEvidence []attestation.GPUEvidence `json:"gpu_evidence"`
	InstanceID  string                    `json:"instance_id"`
	Certificate string                    `json:"certificate"` // base64 DER TLS cert
}

// Attester fetches attestation data from the Chutes direct API.
type Attester struct {
	baseURL  string
	apiKey   string
	client   *http.Client
	resolver *ModelResolver
}

// NewAttester returns a Chutes Attester configured with the given base URL
// and API key. modelsBase is the URL for /v1/models model-name resolution
// (defaults to https://llm.chutes.ai if empty).
func NewAttester(baseURL, apiKey string, offline ...bool) *Attester {
	client := config.NewAttestationClient(offline...)
	return &Attester{
		baseURL:  baseURL,
		apiKey:   apiKey,
		client:   client,
		resolver: NewModelResolver("", apiKey, client),
	}
}

// SetModelsBase overrides the URL used for /v1/models model-name resolution.
// Primarily for testing.
func (a *Attester) SetModelsBase(modelsBase string) {
	a.resolver = NewModelResolver(modelsBase, a.apiKey, a.client)
}

// Resolver returns the Attester's ModelResolver for sharing with NoncePool.
func (a *Attester) Resolver() *ModelResolver {
	return a.resolver
}

// FetchAttestation fetches TEE attestation from Chutes using the two-step
// protocol: discover instances, then fetch evidence. The model parameter
// can be a human-readable name (e.g. "deepseek-ai/DeepSeek-V3-0324-TEE")
// or a chute UUID; names are resolved via /v1/models automatically.
func (a *Attester) FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	// Resolve human-readable model name to chute UUID.
	chuteID, err := a.resolver.Resolve(ctx, model)
	if err != nil {
		return nil, fmt.Errorf("chutes: resolve model: %w", err)
	}
	if chuteID != model {
		slog.InfoContext(ctx, "chutes: resolved model name to chute UUID", "model", model, "chute_id", chuteID)
	}

	// Step 1: Discover instances with e2e public keys.
	instancesURL, err := url.Parse(a.baseURL + instancesPath + url.PathEscape(chuteID))
	if err != nil {
		return nil, fmt.Errorf("chutes: parse instances URL: %w", err)
	}

	slog.DebugContext(ctx, "chutes: fetching e2e instances", "url_path", instancesURL.Path)
	instancesBody, err := provider.FetchAttestationJSON(ctx, a.client, instancesURL.String(), a.apiKey, maxBodySize)
	if err != nil {
		return nil, fmt.Errorf("chutes: fetch instances: %w", err)
	}

	// Step 2: Fetch evidence with our nonce.
	evidencePath := fmt.Sprintf(attestationPath, url.PathEscape(chuteID))
	evidenceURL, err := url.Parse(a.baseURL + evidencePath)
	if err != nil {
		return nil, fmt.Errorf("chutes: parse evidence URL: %w", err)
	}
	q := evidenceURL.Query()
	q.Set("nonce", nonce.Hex())
	evidenceURL.RawQuery = q.Encode()

	slog.DebugContext(ctx, "chutes: fetching evidence", "url_path", evidenceURL.Path)
	evidenceBody, err := provider.FetchAttestationJSON(ctx, a.client, evidenceURL.String(), a.apiKey, maxBodySize)
	if err != nil {
		return nil, fmt.Errorf("chutes: fetch evidence: %w", err)
	}

	raw, err := ParseAttestationResponse(instancesBody, evidenceBody, nonce)
	if err != nil {
		return nil, err
	}
	raw.ChuteID = chuteID
	return raw, nil
}

// ParseAttestationResponse parses the two Chutes API response bodies (instances
// and evidence) into a RawAttestation. Evidence entries are matched against the
// instances list; the first evidence entry whose instance ID appears in the
// instances list and whose matched instance has complete E2EE material
// (non-empty e2e_pubkey and at least one nonce) is used. This tolerates fleet
// changes between the two API calls (instances fetched first, then evidence),
// where an evidence entry may reference an instance that joined or left the
// fleet in between.
func ParseAttestationResponse(instancesBody, evidenceBody []byte, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	var instances e2eInstancesResponse
	if err := jsonstrict.UnmarshalWarn(instancesBody, &instances, "chutes e2e instances response"); err != nil {
		return nil, fmt.Errorf("chutes: unmarshal instances response: %w", err)
	}
	if len(instances.Instances) == 0 {
		return nil, errors.New("chutes: no instances available")
	}
	if len(instances.Instances) > maxInstances {
		return nil, fmt.Errorf("chutes: instances has %d entries, max %d",
			len(instances.Instances), maxInstances)
	}

	var ar attestationResponse
	if err := jsonstrict.UnmarshalWarn(evidenceBody, &ar, "chutes evidence response"); err != nil {
		return nil, fmt.Errorf("chutes: unmarshal evidence response: %w", err)
	}
	if len(ar.Evidence) == 0 {
		return nil, errors.New("chutes: no evidence entries returned")
	}
	if len(ar.Evidence) > maxEvidence {
		return nil, fmt.Errorf("chutes: evidence has %d entries, max %d",
			len(ar.Evidence), maxEvidence)
	}

	// Build instance lookup map for O(1) matching. Keyed by instance ID.
	instanceMap := make(map[string]*e2eInstance, len(instances.Instances))
	for i := range instances.Instances {
		instanceMap[instances.Instances[i].InstanceID] = &instances.Instances[i]
	}

	slog.Debug("chutes: attestation received",
		"instances", len(instances.Instances),
		"evidence", len(ar.Evidence),
		"failed", len(ar.FailedInstanceIDs),
	)

	// Find the first evidence entry whose instance exists in the instances
	// list AND has the E2EE material needed for a complete attestation
	// (public key + at least one nonce). The Chutes fleet is dynamic: the
	// /evidence response may include instances that were not (or no longer)
	// in the /e2e/instances response, or whose E2EE material is incomplete.
	var matched *instanceEvidence
	var matchedInst *e2eInstance
	skipped := 0
	for i := range ar.Evidence {
		inst, ok := instanceMap[ar.Evidence[i].InstanceID]
		if !ok {
			skipped++
			continue
		}
		if inst.E2EPubKey == "" {
			slog.Info("chutes: skipping instance with empty e2e_pubkey",
				"instance_id", ar.Evidence[i].InstanceID)
			skipped++
			continue
		}
		if len(inst.Nonces) == 0 {
			slog.Info("chutes: skipping instance with no nonces",
				"instance_id", ar.Evidence[i].InstanceID)
			skipped++
			continue
		}
		matched = &ar.Evidence[i]
		matchedInst = inst
		break
	}
	if matched == nil {
		return nil, fmt.Errorf("chutes: none of %d evidence entries match a known instance with valid E2EE material (%d instances available)",
			len(ar.Evidence), len(instances.Instances))
	}
	if skipped > 0 {
		slog.Info("chutes: skipped evidence entries",
			"skipped", skipped, "used_instance", matched.InstanceID)
	}

	if len(matched.GPUEvidence) > maxGPUEvidence {
		return nil, fmt.Errorf("chutes: instance %s has %d GPU evidence entries, max %d",
			matched.InstanceID, len(matched.GPUEvidence), maxGPUEvidence)
	}

	// Convert base64-encoded quote to hex for TDX verification pipeline.
	var intelQuoteHex string
	if matched.Quote != "" {
		quoteBytes, err := base64.StdEncoding.DecodeString(matched.Quote)
		if err != nil {
			return nil, fmt.Errorf("chutes: base64-decode quote: %w", err)
		}
		intelQuoteHex = hex.EncodeToString(quoteBytes)
	}

	slog.Debug("chutes: attestation parsed",
		"instance_id", matched.InstanceID,
		"gpus", len(matched.GPUEvidence),
		"has_quote", matched.Quote != "",
		"has_e2e_pubkey", matchedInst.E2EPubKey != "",
	)

	return &attestation.RawAttestation{
		BackendFormat: attestation.FormatChutes,
		Nonce:         nonce.Hex(),
		TEEProvider:   "TDX+NVIDIA",
		SigningKey:    matchedInst.E2EPubKey,
		SigningAlgo:   "ml-kem-768",
		IntelQuote:    intelQuoteHex,
		GPUEvidence:   matched.GPUEvidence,

		TEEHardware: "intel-tdx",
		NonceSource: "client",

		CandidatesAvail: len(ar.Evidence),
		CandidatesEval:  1,

		InstanceID: matched.InstanceID,
		E2ENonce:   matchedInst.Nonces[0],

		RawBody: evidenceBody,
	}, nil
}

// Preparer injects the Chutes Authorization header and E2EE headers into
// outgoing requests. For E2EE, it rewrites the full URL to the platform API
// /e2e/invoke endpoint and sets the required headers.
type Preparer struct {
	apiKey     string
	chatPath   string
	apiBaseURL string // platform API base (e.g. https://api.chutes.ai)
}

// NewPreparer returns a Chutes Preparer configured with the given API key,
// chat path, and platform API base URL. The apiBaseURL is used for E2EE
// invoke URL rewriting (the LLM inference and platform APIs use different hosts).
func NewPreparer(apiKey, chatPath, apiBaseURL string) *Preparer {
	return &Preparer{apiKey: apiKey, chatPath: chatPath, apiBaseURL: apiBaseURL}
}

// PrepareRequest injects the Authorization header into req. For Chutes E2EE
// sessions, it also sets the E2EE headers and rewrites the full URL to the
// platform API's /e2e/invoke endpoint.
func (p *Preparer) PrepareRequest(req *http.Request, _ http.Header, meta *e2ee.ChutesE2EE, stream bool) error {
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	if meta != nil {
		req.Header.Set("X-Chute-Id", meta.ChuteID)
		req.Header.Set("X-Instance-Id", meta.InstanceID)
		req.Header["X-E2E-Nonce"] = []string{meta.E2ENonce}
		req.Header["X-E2E-Stream"] = []string{strconv.FormatBool(stream)}
		req.Header["X-E2E-Path"] = []string{p.chatPath}
		req.Header.Set("Content-Type", "application/octet-stream")
		// E2EE invoke is on the platform API (api.chutes.ai), not the
		// LLM inference gateway (llm.chutes.ai). We must also set
		// req.Host to match the rewritten URL host; http.NewRequestWithContext
		// snapshots the original host into req.Host, which would otherwise
		// override the URL host.
		e2eURL, err := url.Parse(p.apiBaseURL + "/e2e/invoke")
		if err != nil {
			return fmt.Errorf("parse e2e invoke URL: %w", err)
		}
		if e2eURL.Scheme == "" || e2eURL.Host == "" {
			return fmt.Errorf("invalid Chutes API base URL %q: must include scheme and host", p.apiBaseURL)
		}
		req.URL = e2eURL
		req.Host = e2eURL.Host
	}
	return nil
}
