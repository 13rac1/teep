// Package provider defines the Provider struct and the Attester and
// RequestPreparer interfaces used by all TEE-capable AI backends.
//
// Dependency flow: attestation → provider → proxy → cmd
// Provider uses attestation types but is not imported by attestation.
package provider

import (
	"context"
	"io"
	"net/http"

	"github.com/13rac1/teep/internal/attestation"
)

// Attester fetches raw attestation data from a TEE provider.
// Implementations are in the provider-specific sub-packages.
type Attester interface {
	FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error)
}

// RequestPreparer injects provider-specific headers into an outgoing upstream
// request. It is called once per request after the E2EE session is established.
type RequestPreparer interface {
	PrepareRequest(req *http.Request, session *attestation.Session) error
}

// PinnedHandler handles chat requests on a connection-pinned TLS connection
// where attestation and inference share the same TCP connection. Used by
// providers like NEAR AI where the TLS cert is verified via attestation
// rather than a traditional CA chain.
type PinnedHandler interface {
	HandlePinned(ctx context.Context, req PinnedRequest) (*PinnedResponse, error)
}

// PinnedRequest is the input to a pinned chat handler.
type PinnedRequest struct {
	Method  string
	Path    string      // e.g. "/v1/chat/completions"
	Headers http.Header // forwarded headers (Authorization, Content-Type, etc.)
	Body    []byte      // raw request body
	Model   string      // upstream model name (for endpoint resolution)
}

// PinnedResponse is a raw HTTP response from a pinned connection.
type PinnedResponse struct {
	StatusCode int
	Header     http.Header
	Body       io.ReadCloser

	// Report is the verification report from attestation, if attestation was
	// performed on this connection. Nil on SPKI cache hits.
	Report *attestation.VerificationReport
}

// ReportDataVerifier validates that TDX REPORTDATA binds the expected identity.
// Each provider implements its own binding scheme (e.g. Venice uses Ethereum
// address derivation, NEAR uses sha256(signing_address + tls_fingerprint)).
type ReportDataVerifier interface {
	VerifyReportData(reportData [64]byte, raw *attestation.RawAttestation, nonce attestation.Nonce) (detail string, err error)
}

// Provider is a fully wired TEE-capable AI backend. It combines the data from
// config.Provider with the behavioral interfaces Attester and Preparer.
//
// The zero value is not useful; construct with New or fill fields directly.
type Provider struct {
	// Name is the canonical provider identifier (e.g. "venice", "nearai").
	Name string

	// BaseURL is the upstream API root (e.g. "https://api.venice.ai").
	BaseURL string

	// APIKey is the resolved API key. Never log this directly; use
	// config.RedactKey.
	APIKey string

	// ModelMap translates client-facing model names to upstream model names.
	// If a model name is absent, MapModel returns it unchanged.
	ModelMap map[string]string

	// ChatPath is the API path for chat completions (e.g. "/api/v1/chat/completions").
	ChatPath string

	// E2EE indicates whether this provider supports end-to-end encryption.
	E2EE bool

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
}

// MapModel translates a client-facing model name to the upstream model name.
// Returns the input unchanged if no mapping exists.
func (p *Provider) MapModel(clientModel string) string {
	if mapped, ok := p.ModelMap[clientModel]; ok {
		return mapped
	}
	return clientModel
}
