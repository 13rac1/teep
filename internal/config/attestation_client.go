package config

import (
	"net/http"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/tlsct"
)

// AttestationClientFactory creates independent pools with shared socket admission.
// Configure it before concurrent use. Each returned client owns its pools.
type AttestationClientFactory struct {
	offline bool
	budget  *tlsct.SocketBudget
	wrap    func(http.RoundTripper) http.RoundTripper
}

// NewAttestationClientFactory retains the explicit budget and optional decorator.
// The decorator must be safe for concurrent calls and preserve pool cleanup.
func NewAttestationClientFactory(offline bool, budget *tlsct.SocketBudget, wrap func(http.RoundTripper) http.RoundTripper) *AttestationClientFactory {
	if budget == nil {
		panic("attestation socket budget is required")
	}
	return &AttestationClientFactory{offline: offline, budget: budget, wrap: wrap}
}

// NewClient preserves production trust, redirects, retries, and timeout policy.
func (f *AttestationClientFactory) NewClient() *http.Client {
	client := tlsct.NewHTTPClientWithTransport(AttestationTimeout, tlsct.NewPooledTransportWithBudget(f.budget), !f.offline)
	client.Transport = tlsct.NewTLS12FallbackTransportWithBudget(client.Transport, f.budget, attestation.AMDKDSHost)
	client.Transport = tlsct.WrapLogging(client.Transport)
	client.Transport = &RetryTransport{Base: client.Transport}
	if f.wrap != nil {
		client.Transport = f.wrap(client.Transport)
	}
	return client
}
