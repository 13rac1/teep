// Package provider defines the Provider struct and the Attester and
// RequestPreparer interfaces used by all TEE-capable AI backends.
//
// Dependency flow: attestation → e2ee → provider → proxy → cmd
// Provider uses attestation types but is not imported by attestation.
package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
)

// Attester fetches raw attestation data from a TEE provider.
// Implementations are in the provider-specific sub-packages.
type Attester interface {
	FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error)
}

// RequestPreparer injects provider-specific headers into an outgoing upstream
// request. It is called once per request after the E2EE session is established.
type RequestPreparer interface {
	PrepareRequest(req *http.Request, session *e2ee.Session) error
}

// RequestEncryptor encrypts an outgoing chat request body for a provider's
// E2EE protocol. Returns the encrypted body, session for response decryption,
// and any error.
type RequestEncryptor interface {
	EncryptRequest(body []byte, raw *attestation.RawAttestation) ([]byte, *e2ee.Session, error)
}

// PinnedHandler handles chat requests on a connection-pinned TLS connection
// where attestation and inference share the same TCP connection. Used by
// providers like NEAR AI where the TLS cert is verified via attestation
// rather than a traditional CA chain.
type PinnedHandler interface {
	HandlePinned(ctx context.Context, req *PinnedRequest) (*PinnedResponse, error)
}

// PinnedRequest is the input to a pinned chat handler.
type PinnedRequest struct {
	Method  string
	Path    string      // e.g. "/v1/chat/completions"
	Headers http.Header // forwarded headers (Authorization, Content-Type, etc.)
	Body    []byte      // raw request body
	Model   string      // upstream model name (for endpoint resolution)
	E2EE    bool        // encrypt message contents for the model backend

	// SigningKey is the model's attested public key, provided by the caller
	// from its signing key cache. Used on SPKI cache hits when E2EE is
	// active and no fresh attestation provides a signing key.
	SigningKey string
}

// PinnedResponse is a raw HTTP response from a pinned connection.
type PinnedResponse struct {
	StatusCode int
	Header     http.Header
	Body       io.ReadCloser

	// Report is the verification report from attestation, if attestation was
	// performed on this connection. Nil on SPKI cache hits.
	Report *attestation.VerificationReport

	// SigningKey is the attested model key returned on cache misses. It allows
	// callers to refresh signing-key caches without a second attestation fetch.
	SigningKey string

	// Session is the E2EE session established during the pinned request.
	// Non-nil when E2EE was active; callers use it for response decryption.
	Session *e2ee.Session
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

// Provider is a fully wired TEE-capable AI backend. It combines the data from
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

	// E2EE indicates whether this provider supports end-to-end encryption.
	E2EE bool

	// Encryptor encrypts outgoing chat request bodies for the provider's
	// E2EE protocol. Non-nil when E2EE is true.
	Encryptor RequestEncryptor

	// SkipSigningKeyCache indicates the provider needs fresh attestation for
	// each E2EE request (e.g. Chutes requires per-request instance/nonce data).
	SkipSigningKeyCache bool

	// Attester fetches raw attestation from the provider's attestation endpoint.
	// May be nil if the provider does not support attestation.
	Attester Attester

	// Preparer injects provider-specific headers into outgoing requests.
	// May be nil if no special headers are needed.
	Preparer RequestPreparer

	// ReportDataVerifier validates REPORTDATA binding for this provider.
	// May be nil if the provider does not support REPORTDATA verification.
	ReportDataVerifier ReportDataVerifier

	// PinnedHandler handles chat requests on a connection-pinned TLS
	// connection. Set for providers that require same-connection attestation
	// (e.g. NEAR AI). When non-nil, the proxy uses this instead of the
	// standard http.Client path.
	PinnedHandler PinnedHandler

	// SupplyChainPolicy defines the allowed container image repos for this
	// provider. May be nil if the provider has no policy.
	SupplyChainPolicy *attestation.SupplyChainPolicy

	// ModelLister fetches available models from the provider's discovery API.
	// May be nil if the provider does not support model listing.
	ModelLister ModelLister
}
