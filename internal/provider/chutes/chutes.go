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
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
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

	// maxBodySize is the maximum response body size (2 MiB) of the instance list.
	maxBodySize = 2 << 20

	// maxEvidenceBodySize is the maximum evidence response body size (16 MiB).
	// One evidence response carries the TDX quote and GPU evidence of every
	// instance of the chute, so it exceeds 2 MiB for a chute with many instances.
	maxEvidenceBodySize = 16 << 20
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
// ExcludedInstanceIDs and the TEEType, AttestedBody and Signature members of
// an entry are newer members of the response; older responses lack them, so
// they are optional here and the session path requires them.
type attestationResponse struct {
	Evidence            []instanceEvidence `json:"evidence"`
	FailedInstanceIDs   []string           `json:"failed_instance_ids"`
	ExcludedInstanceIDs *[]string          `json:"excluded_instance_ids,omitempty"`
}

// instanceEvidence is one instance's attestation evidence.
type instanceEvidence struct {
	Quote       string                    `json:"quote"` // base64-encoded TDX quote
	GPUEvidence []attestation.GPUEvidence `json:"gpu_evidence"`
	InstanceID  string                    `json:"instance_id"`
	Certificate string                    `json:"certificate"` // base64 DER TLS cert
	TEEType     string                    `json:"tee_type,omitempty"`
	// AttestedBody is base64 JSON of the evidence that Chutes signed;
	// Signature is that signature. Chutes publishes no key for it, so teep
	// does not verify Signature (SEE: checkAttestedBody).
	AttestedBody string `json:"attested_body,omitempty"`
	Signature    string `json:"signature,omitempty"`
}

// attestedBody is the decoded AttestedBody of an evidence entry. The quote
// is under tdx_quote or, in other entries of the same response, quote.
type attestedBody struct {
	Evidence struct {
		TDXQuote        *string `json:"tdx_quote,omitempty"`
		Quote           *string `json:"quote,omitempty"`
		NvtrustEvidence string  `json:"nvtrust_evidence"`
	} `json:"evidence"`
	Nonce string `json:"nonce"`
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
	client := config.NewAttestationClient(len(offline) > 0 && offline[0])
	return &Attester{
		baseURL:  baseURL,
		apiKey:   apiKey,
		client:   client,
		resolver: NewModelResolver("", apiKey, client),
	}
}

// SetClient replaces the HTTP client used for attestation fetches and for
// model-name resolution, so that capture records the /v1/models exchange and
// replay serves it. The resolver stays the same object, because the nonce
// pool shares it.
func (a *Attester) SetClient(c *http.Client) {
	a.client = c
	a.resolver.SetClient(c)
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
	evidenceBody, err := provider.FetchAttestationJSON(ctx, a.client, evidenceURL.String(), a.apiKey, maxEvidenceBodySize)
	if err != nil {
		return nil, fmt.Errorf("chutes: fetch evidence: %w", err)
	}

	raw, err := ParseAttestationResponse(ctx, instancesBody, evidenceBody, nonce)
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
func ParseAttestationResponse(ctx context.Context, instancesBody, evidenceBody []byte, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	instances := &e2eInstancesResponse{}
	unknownInst, missingInst, err := jsonstrict.UnmarshalWarn(instancesBody, instances, "chutes instances")
	if err != nil {
		return nil, fmt.Errorf("chutes: unmarshal instances response: %w", err)
	}
	if err := checkInstances(instances); err != nil {
		return nil, err
	}
	ar := &attestationResponse{}
	unknownEvid, missingEvid, err := jsonstrict.UnmarshalWarn(evidenceBody, ar, "chutes evidence")
	if err != nil {
		return nil, fmt.Errorf("chutes: unmarshal evidence response: %w", err)
	}
	if err := checkEvidence(ar); err != nil {
		return nil, err
	}

	// Build instance lookup map for O(1) matching. Keyed by instance ID.
	instanceMap := make(map[string]*e2eInstance, len(instances.Instances))
	for i := range instances.Instances {
		instanceMap[instances.Instances[i].InstanceID] = &instances.Instances[i]
	}

	slog.DebugContext(ctx, "chutes: attestation received",
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
			slog.DebugContext(ctx, "chutes: skipping instance with empty e2e_pubkey",
				"instance_id", ar.Evidence[i].InstanceID)
			skipped++
			continue
		}
		if len(inst.Nonces) == 0 {
			slog.DebugContext(ctx, "chutes: skipping instance with no nonces",
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
		slog.InfoContext(ctx, "chutes: skipped evidence entries",
			"skipped", skipped, "used_instance", matched.InstanceID)
	}

	raw, err := instanceRaw(ctx, matched, matchedInst.E2EPubKey)
	if err != nil {
		return nil, err
	}
	raw.CandidatesAvail = len(ar.Evidence)
	raw.CandidatesEval = skipped + 1
	raw.E2ENonce = matchedInst.Nonces[0]
	raw.UnknownFields = slices.Concat(unknownInst, unknownEvid)
	raw.MissingFields = slices.Concat(missingInst, missingEvid)
	raw.RawBody = evidenceBody
	return raw, nil
}

// ParseInstanceAttestation returns the attestation of the instance
// instanceID from an evidence response and one or more instance lists, as
// the evidence of an attested session of the private-ai-gateway records
// them. Every instance list that names the instance must give it the same
// E2EE public key. nonce is the nonce of the evidence request. The result
// carries no E2EE request nonce: the attestation is not used to encrypt.
// Undefined and absent members of the bodies are returned in UnknownFields
// and MissingFields without logging; the caller decides.
func ParseInstanceAttestation(ctx context.Context, instancesBodies [][]byte, evidenceBody []byte, instanceID string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	var pubKey string
	var unknown, missing []string
	for i, body := range instancesBodies {
		instances := &e2eInstancesResponse{}
		u, m, err := jsonstrict.Unmarshal(body, instances)
		if err != nil {
			return nil, fmt.Errorf("chutes: unmarshal instance list %d: %w", i, err)
		}
		if err := checkInstances(instances); err != nil {
			return nil, fmt.Errorf("instance list %d: %w", i, err)
		}
		unknown, missing = append(unknown, u...), append(missing, m...)
		for j := range instances.Instances {
			inst := &instances.Instances[j]
			if inst.InstanceID != instanceID {
				continue
			}
			if inst.E2EPubKey == "" {
				return nil, fmt.Errorf("chutes: instance %s has no e2e_pubkey", instanceID)
			}
			if pubKey != "" && subtle.ConstantTimeCompare([]byte(pubKey), []byte(inst.E2EPubKey)) != 1 {
				return nil, fmt.Errorf("chutes: instance lists give instance %s different e2e_pubkey values", instanceID)
			}
			pubKey = inst.E2EPubKey
		}
	}
	if pubKey == "" {
		return nil, fmt.Errorf("chutes: no instance list names instance %s", instanceID)
	}
	ar := &attestationResponse{}
	u, m, err := jsonstrict.Unmarshal(evidenceBody, ar)
	if err != nil {
		return nil, fmt.Errorf("chutes: unmarshal evidence response: %w", err)
	}
	if err := checkEvidence(ar); err != nil {
		return nil, err
	}
	var matched *instanceEvidence
	for i := range ar.Evidence {
		if ar.Evidence[i].InstanceID != instanceID {
			continue
		}
		if matched != nil {
			return nil, fmt.Errorf("chutes: evidence lists instance %s twice", instanceID)
		}
		matched = &ar.Evidence[i]
	}
	if matched == nil {
		return nil, fmt.Errorf("chutes: evidence has no entry for instance %s", instanceID)
	}
	if ar.ExcludedInstanceIDs == nil {
		return nil, errors.New("chutes: evidence has no excluded_instance_ids")
	}
	if err := checkAttestedBody(matched, nonce); err != nil {
		return nil, fmt.Errorf("chutes: instance %s: %w", instanceID, err)
	}
	raw, err := instanceRaw(ctx, matched, pubKey)
	if err != nil {
		return nil, err
	}
	raw.CandidatesAvail = len(ar.Evidence)
	raw.CandidatesEval = 1
	raw.UnknownFields = slices.Concat(unknown, u)
	raw.MissingFields = slices.Concat(missing, m)
	raw.RawBody = evidenceBody
	return raw, nil
}

// ParseEvidence returns the attestation of the first entry of an evidence
// response that is relayed without an instance list, as NanoGPT relays it.
// The response may have at most maxEntries entries, and its
// failed_instance_ids and excluded_instance_ids together at most maxEntries
// ids. Every entry must pass
// the attested-body checks of the session path (checkAttestedBody), and the
// instance ids must pass checkInstanceIDs, so one malformed entry refuses
// the response. The response names no E2EE public key, so the result has no
// SigningKey and no quote in it can be shown to bind nonce; nothing names
// the instance that serves a request either. nonce is the nonce of the
// evidence request; the result marks it NonceSourceAttestedBody, because
// only the unverified attested_body states it. Unknown and missing
// members are returned in UnknownFields and MissingFields without logging;
// the caller decides.
//
// Instances in failed_instance_ids and excluded_instance_ids have no
// evidence in the response. The meaning of the two lists is assumed from
// their names: Chutes does not document it. A non-empty list is logged at
// warn level, not refused.
func ParseEvidence(ctx context.Context, evidenceBody []byte, nonce attestation.Nonce, maxEntries int) (*attestation.RawAttestation, error) {
	ar := &attestationResponse{}
	unknown, missing, err := jsonstrict.Unmarshal(evidenceBody, ar)
	if err != nil {
		return nil, fmt.Errorf("chutes: unmarshal evidence response: %w", err)
	}
	if err := checkEvidence(ar); err != nil {
		return nil, err
	}
	if len(ar.Evidence) > maxEntries {
		return nil, fmt.Errorf("chutes: evidence has %d entries, max %d", len(ar.Evidence), maxEntries)
	}
	// A listed instance id names an instance of the same chute without
	// evidence, so the two lists together have the same bound as the
	// entries. checkInstanceIDs sizes a map from their lengths.
	if n := len(ar.FailedInstanceIDs) + listLen(ar.ExcludedInstanceIDs); n > maxEntries {
		return nil, fmt.Errorf("chutes: failed_instance_ids and excluded_instance_ids list %d instances, max %d", n, maxEntries)
	}
	if err := checkInstanceIDs(ar); err != nil {
		return nil, err
	}
	for i := range ar.Evidence {
		if err := checkAttestedBody(&ar.Evidence[i], nonce); err != nil {
			return nil, fmt.Errorf("chutes: instance %s: %w", ar.Evidence[i].InstanceID, err)
		}
	}
	if n, m := len(ar.FailedInstanceIDs), len(*ar.ExcludedInstanceIDs); n > 0 || m > 0 {
		slog.WarnContext(ctx, "chutes: evidence response lists instances without evidence",
			"failed_instances", n, "excluded_instances", m, "evidence_instances", len(ar.Evidence))
	}
	raw, err := instanceRaw(ctx, &ar.Evidence[0], "")
	if err != nil {
		return nil, err
	}
	raw.SigningAlgo = "" // no E2EE key is named
	raw.NonceSource = attestation.NonceSourceAttestedBody
	raw.CandidatesAvail = len(ar.Evidence)
	raw.CandidatesEval = 1
	raw.UnknownFields = unknown
	raw.MissingFields = missing
	raw.RawBody = evidenceBody
	return raw, nil
}

// checkInstanceIDs checks the instance ids of an evidence response that
// ParseEvidence parses: excluded_instance_ids and failed_instance_ids are
// present, each id is non-empty, and no id is in two places (two entries, a
// list twice, or an entry and a list). The two nil checks refuse a missing
// list. The missing-member report of jsonstrict does not: it goes to the
// response_schema factor, which a provider may allow to fail. The member
// types stay as they are because the direct path, where an older response
// has no excluded_instance_ids, shares attestationResponse.
func checkInstanceIDs(ar *attestationResponse) error {
	if ar.ExcludedInstanceIDs == nil {
		return errors.New("chutes: evidence has no excluded_instance_ids")
	}
	if ar.FailedInstanceIDs == nil {
		return errors.New("chutes: evidence has no failed_instance_ids")
	}
	seen := make(map[string]string, len(ar.Evidence)+len(ar.FailedInstanceIDs)+len(*ar.ExcludedInstanceIDs))
	add := func(id, where string) error {
		if id == "" {
			return fmt.Errorf("chutes: %s has an empty instance id", where)
		}
		if prev, ok := seen[id]; ok {
			return fmt.Errorf("chutes: instance %s is in %s and in %s", id, prev, where)
		}
		seen[id] = where
		return nil
	}
	for i := range ar.Evidence {
		if err := add(ar.Evidence[i].InstanceID, "evidence"); err != nil {
			return err
		}
	}
	for _, id := range ar.FailedInstanceIDs {
		if err := add(id, "failed_instance_ids"); err != nil {
			return err
		}
	}
	for _, id := range *ar.ExcludedInstanceIDs {
		if err := add(id, "excluded_instance_ids"); err != nil {
			return err
		}
	}
	return nil
}

// listLen returns the length of a list member that may be absent.
func listLen(ids *[]string) int {
	if ids == nil {
		return 0
	}
	return len(*ids)
}

// checkAttestedBody checks the newer members of an evidence entry: tee_type
// is tdx, and attested_body is base64 JSON with exactly the members of
// attestedBody whose quote is the entry's quote and whose nonce is the nonce
// of the evidence request. teep does not verify Signature, which Chutes
// signs under a key that it does not publish, and does not use
// nvtrust_evidence; the quote and the GPU evidence are verified on their own.
func checkAttestedBody(e *instanceEvidence, nonce attestation.Nonce) error {
	if e.TEEType != "tdx" {
		return fmt.Errorf("tee_type is %q, want tdx", e.TEEType)
	}
	if e.Signature == "" {
		return errors.New("evidence entry has no signature")
	}
	data, err := base64.StdEncoding.DecodeString(e.AttestedBody)
	if err != nil || len(data) == 0 {
		return errors.New("attested_body is not base64")
	}
	var body attestedBody
	unknown, missing, err := jsonstrict.Unmarshal(data, &body)
	if err != nil {
		return fmt.Errorf("attested_body: %w", err)
	}
	if len(unknown) > 0 || len(missing) > 0 {
		return fmt.Errorf("attested_body: undefined members %q, missing members %q", unknown, missing)
	}
	quote := body.Evidence.TDXQuote
	if (quote == nil) == (body.Evidence.Quote == nil) {
		return errors.New("attested_body needs exactly one of evidence.tdx_quote and evidence.quote")
	}
	if quote == nil {
		quote = body.Evidence.Quote
	}
	if subtle.ConstantTimeCompare([]byte(*quote), []byte(e.Quote)) != 1 {
		return errors.New("attested_body quote is not the quote of the entry")
	}
	if subtle.ConstantTimeCompare([]byte(body.Nonce), []byte(nonce.Hex())) != 1 {
		return errors.New("attested_body nonce is not the nonce of the evidence request")
	}
	return nil
}

func checkInstances(instances *e2eInstancesResponse) error {
	if len(instances.Instances) == 0 {
		return errors.New("chutes: no instances available")
	}
	if len(instances.Instances) > maxInstances {
		return fmt.Errorf("chutes: instances has %d entries, max %d",
			len(instances.Instances), maxInstances)
	}
	return nil
}

func checkEvidence(ar *attestationResponse) error {
	if len(ar.Evidence) == 0 {
		return errors.New("chutes: no evidence entries returned")
	}
	if len(ar.Evidence) > maxEvidence {
		return fmt.Errorf("chutes: evidence has %d entries, max %d",
			len(ar.Evidence), maxEvidence)
	}
	return nil
}

// instanceRaw converts the evidence of one instance and its E2EE public key.
func instanceRaw(ctx context.Context, matched *instanceEvidence, pubKey string) (*attestation.RawAttestation, error) {
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

	slog.DebugContext(ctx, "chutes: attestation parsed",
		"instance_id", matched.InstanceID,
		"gpus", len(matched.GPUEvidence),
		"has_quote", matched.Quote != "",
		"has_e2e_pubkey", pubKey != "",
	)

	// The evidence response echoes no nonce: Nonce stays empty, and the
	// client nonce is checked by the REPORTDATA binding and the GPU
	// requester nonce.
	return &attestation.RawAttestation{
		BackendFormat: attestation.FormatChutes,
		TEEProvider:   "TDX+NVIDIA",
		SigningKey:    pubKey,
		SigningAlgo:   "ml-kem-768",
		IntelQuote:    intelQuoteHex,
		GPUEvidence:   matched.GPUEvidence,

		TEEHardware: "intel-tdx",
		NonceSource: attestation.NonceSourceNotEchoed,

		InstanceID: matched.InstanceID,
	}, nil
}

// Preparer injects the Chutes Authorization header and E2EE headers into
// outgoing requests. For E2EE, it rewrites the full URL to the platform API
// /e2e/invoke endpoint and sets the required headers.
type Preparer struct {
	apiKey     string
	apiBaseURL string // platform API base (e.g. https://api.chutes.ai)
}

// NewPreparer returns a Chutes Preparer configured with the given API key
// and platform API base URL. The apiBaseURL is used for E2EE invoke URL
// rewriting (the LLM inference and platform APIs use different hosts).
// Endpoint paths are passed dynamically per-request via PrepareRequest.
func NewPreparer(apiKey, apiBaseURL string) *Preparer {
	return &Preparer{apiKey: apiKey, apiBaseURL: apiBaseURL}
}

// PrepareRequest injects the Authorization header into req. For Chutes E2EE
// sessions, it also sets the E2EE headers and rewrites the full URL to the
// platform API's /e2e/invoke endpoint. The path parameter specifies the
// TEE-internal endpoint path for X-E2E-Path (e.g. "/v1/embeddings").
func (p *Preparer) PrepareRequest(req *http.Request, _ http.Header, meta *e2ee.ChutesE2EE, stream bool, path string, _ provider.PreparationData) error {
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	if meta != nil {
		if path == "" {
			return errors.New("chutes E2EE: endpoint path is required but empty")
		}
		req.Header.Set("X-Chute-Id", meta.ChuteID)
		req.Header.Set("X-Instance-Id", meta.InstanceID)
		req.Header["X-E2E-Nonce"] = []string{meta.E2ENonce}
		req.Header["X-E2E-Stream"] = []string{strconv.FormatBool(stream)}
		req.Header["X-E2E-Path"] = []string{path}
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

// CloseIdleConnections releases idle attestation and discovery connections.
// Call SetClient only before concurrent use or cleanup.
func (a *Attester) CloseIdleConnections() {
	a.client.CloseIdleConnections()
	a.resolver.CloseIdleConnections()
}
