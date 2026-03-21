package proxy

import (
	"io"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
)

// ProviderByName returns the named provider from the server's provider map.
// Exported for use in external tests only.
func (s *Server) ProviderByName(name string) *provider.Provider {
	return s.providers[name]
}

// ReassembleNonStream exposes reassembleNonStream for external tests.
func ReassembleNonStream(body io.Reader, session *attestation.Session) ([]byte, error) {
	return reassembleNonStream(body, session)
}
