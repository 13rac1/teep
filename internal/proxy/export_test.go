package proxy

import (
	"net/http"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
)

// ProviderByName returns the named provider from the server's provider map.
// Exported for use in external tests only.
func (s *Server) ProviderByName(name string) *provider.Provider {
	return s.providers[name]
}

// SetNegativeCache replaces the server's negative cache.
// Exported for use in external tests that need a short TTL.
func (s *Server) SetNegativeCache(nc *attestation.NegativeCache) {
	s.negCache = nc
}

// PrepareUpstreamHeaders exposes prepareUpstreamHeaders for external tests.
func PrepareUpstreamHeaders(req *http.Request, prov *provider.Provider, session e2ee.Decryptor, meta *e2ee.ChutesE2EE, stream bool) error {
	return prepareUpstreamHeaders(req, prov, session, meta, stream)
}

// PutAttestationCache injects a report into the attestation cache.
// Exported for use in external tests that need to simulate cache hits.
func (s *Server) PutAttestationCache(providerName, model string, report *attestation.VerificationReport) {
	s.cache.Put(providerName, model, report)
}

// PutSigningKeyCache injects a signing key into the signing key cache.
// Exported for use in external tests that need to simulate key cache hits.
func (s *Server) PutSigningKeyCache(providerName, model, key string) {
	s.signingKeyCache.Put(providerName, model, key)
}
