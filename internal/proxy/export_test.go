package proxy

import (
	"context"
	"net/http"
	"time"

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
func PrepareUpstreamHeaders(req *http.Request, prov *provider.Provider, session e2ee.Decryptor, meta *e2ee.ChutesE2EE, stream bool, endpointPath string) error {
	return provider.PrepareInferenceHeaders(req, prov, session, meta, stream, endpointPath)
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

// ChutesRetryableError exposes chutesRetryableError for external tests.
func ChutesRetryableError(err error, resp *http.Response) bool {
	return chutesRetryableError(err, resp)
}

// RespStatusCode exposes respStatusCode for external tests.
func RespStatusCode(resp *http.Response) int {
	return respStatusCode(resp)
}

// PutAuthorizationForTest installs a complete authorization through the production
// constructor. Tests of cache/transport behavior supply their explicit factor policy.
func (s *Server) PutAuthorizationForTest(ctx context.Context, name, model string, route provider.ResolvedRoute, report *attestation.VerificationReport, signingKey string) error {
	key, err := route.AuthorizationKey(name, model)
	if err != nil {
		return err
	}
	expires, present := report.Validity.Expiry()
	value, err := newAuthorization(key, report, signingKey, s.providers[name].E2EE, false, expires, present, time.Now())
	if err != nil {
		return err
	}
	_, _, err = s.authorizations.load(ctx, key, nil, nil, func(context.Context) (authorizationVerification, error) {
		return authorizationVerification{candidate: value}, nil
	})
	return err
}
