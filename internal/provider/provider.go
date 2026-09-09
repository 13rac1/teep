// Package provider defines the Provider struct and the Attester and
// RequestPreparer interfaces used by all TEE-capable AI backends.
//
// Dependency flow: attestation → e2ee → provider → proxy → cmd
// Provider uses attestation types but is not imported by attestation.
package provider

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
)

// Attester fetches raw attestation data from a TEE provider.
// Implementations are in the provider-specific sub-packages.
type Attester interface {
	FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error)
}

// E2EEMaterial holds the minimum information needed to encrypt a single
// Chutes E2EE request without full re-attestation: instance ID, ML-KEM
// public key, single-use nonce, and resolved chute UUID.
type E2EEMaterial struct {
	InstanceID string
	E2EPubKey  string // base64-encoded ML-KEM-768 public key
	E2ENonce   string // single-use nonce from /e2e/instances
	ChuteID    string // resolved chute UUID
}

// E2EEMaterialFetcher provides lightweight E2EE key material from a nonce
// pool without full re-attestation. Used by Chutes to avoid the expensive
// /chutes/{id}/evidence + TDX verification roundtrip on every request.
// MarkFailed records that an instance produced an error so the pool can
// prefer other instances. Invalidate discards all cached material for a
// chute, forcing a fresh fetch on the next request.
type E2EEMaterialFetcher interface {
	FetchE2EEMaterial(ctx context.Context, model string) (*E2EEMaterial, error)
	MarkFailed(chuteID, instanceID string)
	Invalidate(chuteID string)
}

// RequestPreparer injects provider-specific headers into an outgoing upstream
// request. e2eeHeaders contains pre-built E2EE protocol headers (may be nil
// for plaintext or Chutes paths). meta is non-nil for Chutes requests.
// path is the endpoint path for this request (e.g. "/v1/embeddings"); used by
// Chutes to set X-E2E-Path dynamically per endpoint type.
type RequestPreparer interface {
	PrepareRequest(req *http.Request, e2eeHeaders http.Header, meta *e2ee.ChutesE2EE, stream bool, path string) error
}

// RequestEncryptor encrypts an outgoing request body for a provider's E2EE
// protocol. The endpoint identifies the canonical route kind (chat,
// embeddings, images, etc.) used to select field-encryption policy.
//
// Exactly one of EncryptResult.Session, .Chutes, or .EHBP is non-nil:
//   - Venice/NearCloud: Session (field-level Decryptor)
//   - Chutes: Chutes (full-body relay state)
//   - Tinfoil/EHBP: EHBP (full-body state, decrypted before relay)
type RequestEncryptor interface {
	EncryptRequest(body []byte, raw *attestation.RawAttestation, endpoint e2ee.EndpointType) (e2ee.EncryptResult, error)
}

// ModelLister fetches the list of available models from a provider.
// Each entry is a json.RawMessage conforming to the OpenAI model object schema.
// Implementations may cache results internally.
type ModelLister interface {
	ListModels(ctx context.Context) ([]json.RawMessage, error)
}

// ReportDataVerifier validates that TDX REPORTDATA binds the expected identity.
// Each provider implements its own binding scheme (e.g. Venice uses
// keccak256-derived address, NEAR uses sha256(signing_address + tls_fingerprint)).
type ReportDataVerifier interface {
	VerifyReportData(reportData [64]byte, raw *attestation.RawAttestation, nonce attestation.Nonce) (detail string, err error)
}

// Provider is a fully constructed TEE-capable AI backend. It combines the data from
// config.Provider with the behavioral interfaces Attester and Preparer.
//
// The zero value is not useful; construct with New or fill fields directly.
type Provider struct {
	// Name is the canonical provider identifier (e.g. "venice", "neardirect").
	Name string

	// BaseURL is the upstream API root (e.g. "https://api.venice.ai").
	BaseURL string

	// APIKey is the resolved API key. Never log this directly; use
	// config.RedactKey.
	APIKey string

	// ChatPath is the API path for chat completions (e.g. "/api/v1/chat/completions").
	ChatPath string

	// EmbeddingsPath is the upstream API path for embeddings (e.g. "/v1/embeddings").
	// Empty means the provider does not support embeddings via this proxy.
	EmbeddingsPath string

	// AudioPath is the upstream API path for audio transcriptions
	// (e.g. "/v1/audio/transcriptions"). Empty means unsupported.
	AudioPath string

	// ImagesPath is the upstream API path for image generations
	// (e.g. "/v1/images/generations"). Empty means unsupported.
	ImagesPath string

	// RerankPath is the upstream API path for reranking
	// (e.g. "/v1/rerank"). Empty means unsupported.
	RerankPath string

	// ScorePath is the upstream API path for score requests
	// (e.g. "/v1/score"). Empty means unsupported.
	ScorePath string

	// ResponsesPath is the upstream API path for responses
	// (e.g. "/v1/responses"). Empty means unsupported.
	ResponsesPath string

	// SpeechPath is the upstream API path for text-to-speech
	// (e.g. "/v1/audio/speech"). Empty means unsupported.
	SpeechPath string

	// E2EE indicates whether this provider supports end-to-end encryption.
	E2EE bool

	// Encryptor encrypts outgoing chat request bodies for the provider's
	// E2EE protocol. Non-nil when E2EE is true.
	Encryptor RequestEncryptor

	// SkipSigningKeyCache indicates the provider needs fresh attestation for
	// each E2EE request (e.g. Chutes requires per-request instance/nonce data).
	SkipSigningKeyCache bool

	// E2EEMaterialFetcher provides lightweight E2EE material from a nonce
	// pool for providers that separate attestation from E2EE key exchange
	// (Chutes). When set, buildUpstreamBody uses this instead of full
	// re-attestation for cache-hit E2EE requests.
	E2EEMaterialFetcher E2EEMaterialFetcher

	// Attester fetches raw attestation from the provider's attestation endpoint.
	// May be nil if the provider does not support attestation.
	Attester Attester

	// StaticRoute is the validated origin for a static TLS-binding provider.
	StaticRoute ResolvedRoute

	// ResolveRoute selects one immutable route before authorization access.
	ResolveRoute func(context.Context, string) (ResolvedRoute, error)

	// Preparer injects provider-specific headers into outgoing requests.
	// May be nil if no special headers are needed.
	Preparer RequestPreparer

	// ReportDataVerifier validates REPORTDATA binding for this provider.
	// May be nil if the provider does not support REPORTDATA verification.
	ReportDataVerifier ReportDataVerifier

	// UsesTLSBinding requires atomic authorization and a transport authenticated
	// against the attested SPKI before request transmission. Pools are scoped
	// to the provider, authority, and attested key. The derived live-peer
	// identity must be present in the verification report.
	UsesTLSBinding bool

	// E2EEKeyBoundByGateway declares that the gateway attestation, not the
	// model endpoint's, binds the key clients encrypt to. The proxy gates
	// E2EE on that factor instead of the core one.
	// SEE: attestation.ReportInput.E2EEKeyBoundByGateway.
	E2EEKeyBoundByGateway bool

	// SupplyChainPolicy defines the allowed container image repos for this
	// provider. Never nil on a constructed Provider: set a real policy, or
	// attestation.NoSupplyChainPolicy() for a provider with no supply chain
	// surface. SEE: proxy.fromConfig, which calls Validate and rejects nil.
	SupplyChainPolicy *attestation.SupplyChainPolicy

	// MeasurementPolicy is the merged TDX measurement allowlist for this
	// provider's model backend CVM (Go defaults + global TOML + per-provider TOML).
	MeasurementPolicy attestation.MeasurementPolicy

	// GatewayMeasurementPolicy is the merged TDX measurement allowlist for
	// this provider's gateway CVM. Zero value for non-gateway providers.
	GatewayMeasurementPolicy attestation.MeasurementPolicy

	// ModelLister fetches available models from the provider's discovery API.
	// May be nil if the provider does not support model listing.
	ModelLister ModelLister
}
