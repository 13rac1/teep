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
