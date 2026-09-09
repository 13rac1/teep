// Package neardirect implements the Attester and RequestPreparer interfaces for
// NEAR AI's direct TEE attestation API.
//
// NEAR AI attestation endpoint:
//
//	GET {base_url}/v1/attestation/report?nonce={nonce}&include_tls_fingerprint=true&signing_algo=ed25519
//	Authorization: Bearer {api_key}
//
// The response contains a model_attestations array, where each element holds
// TDX and NVIDIA attestation payloads for one inference node, plus
// signing_address, tls_cert_fingerprint, and the echoed nonce.
//
// When E2EE is enabled, the request encryptor encrypts the request body using the
// Ed25519/X25519/XChaCha20-Poly1305 protocol (same as nearcloud).
package neardirect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearparse"
	"github.com/13rac1/teep/internal/provider/nearroute"
	"github.com/13rac1/teep/internal/tlsct"
)

const (
	// attestationPath is the NEAR AI API path for TEE attestation reports.
	attestationPath = "/v1/attestation/report"

	maxComposeManagerActions = 10_000
)

// Attester fetches attestation data from NEAR AI's /v1/attestation/report
// endpoint. The nonce is sent as a query parameter and echoed back.
type Attester struct {
	origin    nearroute.Origin
	apiKey    string
	newClient func() *http.Client
	resolver  DomainResolver
}

// NewAttester returns a NEAR AI Attester configured with the given base URL
// and API key. It uses a 30-second HTTP timeout via config.NewAttestationClient.
func NewAttester(baseURL, apiKey string, offline ...bool) *Attester {
	return NewAttesterWithResolver(baseURL, apiKey, NewEndpointResolver(offline...), offline...)
}

// NewAttesterWithResolver returns a NEAR AI Attester configured with the given
// validated base URL, API key, and model resolver. An invalid origin is a
// construction error and panics; configuration loaders return it before construction.
func NewAttesterWithResolver(baseURL, apiKey string, resolver DomainResolver, offline ...bool) *Attester {
	origin, err := nearroute.ParseOrigin(baseURL)
	if err != nil {
		panic(fmt.Sprintf("invalid NEAR configured origin: %v", err))
	}
	factory := config.NewAttestationClientFactory(len(offline) > 0 && offline[0], tlsct.NewAttestationSocketBudget(tlsct.MaxConnectionsPerHost), nil)
	return &Attester{origin: origin, apiKey: apiKey, newClient: factory.NewFreshClient, resolver: resolver}
}

// CloseIdleConnections releases idle attestation and discovery connections.
// Configure client factories only before concurrent use or cleanup.
func (a *Attester) CloseIdleConnections() {
	if closer, ok := a.resolver.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// SetClientFactory supplies an independently owned pool for every full fetch.
// Replay factories may return clients backed by an explicit replay transport.
func (a *Attester) SetClientFactory(factory func() *http.Client) {
	if factory == nil {
		panic("attestation client factory is required")
	}
	a.newClient = factory
}

// SetMetadataClient assigns the discovery client before concurrent use.
func (a *Attester) SetMetadataClient(c *http.Client) {
	if setter, ok := a.resolver.(interface{ SetClient(*http.Client) }); ok {
		setter.SetClient(c)
	}
}

// FetchAttestation fetches TEE attestation from NEAR AI. The nonce is sent as
// a query parameter; NEAR AI echoes it back in the response. Query parameters
// include_tls_fingerprint=true and signing_algo=ed25519 are also sent so the
// response includes TLS certificate binding data and an Ed25519 signing key
// for E2EE key exchange. The model parameter selects which attestation to use
// when the response contains multiple entries.
func (a *Attester) FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	route, err := a.ResolveRoute(ctx, model)
	if err != nil {
		return nil, err
	}
	return fetchAttestationForRoute(ctx, a, route, model, nonce)
}

// FetchAttestationForRoute uses the supplied route without another resolution.
func (a *Attester) FetchAttestationForRoute(ctx context.Context, route provider.ResolvedRoute, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	return fetchAttestationForRoute(ctx, a, route, model, nonce)
}

func fetchAttestationForRoute(ctx context.Context, a *Attester, route provider.ResolvedRoute, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	if route.Authority() == "" {
		return nil, errors.New("nearai: attestation requires a resolved route")
	}
	baseURL := route.BaseURL()

	endpoint, err := url.Parse(baseURL + attestationPath)
	if err != nil {
		return nil, fmt.Errorf("nearai: parse endpoint base URL %q: %w", baseURL, err)
	}
	q := endpoint.Query()
	q.Set("nonce", nonce.Hex())
	q.Set("include_tls_fingerprint", "true")
	q.Set("signing_algo", "ed25519")
	endpoint.RawQuery = q.Encode()

	client := a.newClient()
	defer client.CloseIdleConnections()
	body, peerSPKI, err := provider.FetchAttestationWithTLS(ctx, client, endpoint.String(), a.apiKey, nearparse.MaxEvidenceBytes)
	if err != nil {
		return nil, fmt.Errorf("nearai: %w", err)
	}

	raw, err := ParseAttestationResponse(ctx, body, model)
	if err != nil {
		return nil, err
	}
	if err := tlsct.CompareSPKIFingerprints(peerSPKI, raw.TLSFingerprint); err != nil {
		return nil, fmt.Errorf("nearai: attestation TLS binding: %w", err)
	}
	raw.TransportTLSFingerprint = raw.TLSFingerprint
	raw.TransportTLSAuthority = route.Authority()
	return raw, nil
}

// Preparer injects the NEAR AI Authorization header into an outgoing request.
// NEAR AI's E2EE protocol headers are not yet publicly specified; this
// implementation sets the Authorization header only. Additional headers will
// be added when the protocol is documented.
type Preparer struct {
	apiKey string
}

// NewPreparer returns a NEAR AI Preparer configured with the given API key.
func NewPreparer(apiKey string) *Preparer {
	return &Preparer{apiKey: apiKey}
}

// PrepareRequest injects the NEAR AI Authorization header into req.
func (p *Preparer) PrepareRequest(req *http.Request, headers http.Header, _ *e2ee.ChutesE2EE, _ bool, _ string) error {
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	if len(headers) == 0 {
		return nil
	}
	names := []string{"X-Signing-Algo", "X-Client-Pub-Key", "X-Encryption-Version", "X-Encrypt-All-Fields"}
	for _, name := range names {
		if len(headers.Values(name)) != 1 || headers.Get(name) == "" {
			return fmt.Errorf("incomplete NEAR E2EE headers: %s", name)
		}
	}
	if headers.Get("X-Signing-Algo") != "ed25519" || headers.Get("X-Encryption-Version") != "2" || headers.Get("X-Encrypt-All-Fields") != "true" {
		return errors.New("invalid NEAR E2EE protocol headers")
	}
	for _, name := range names {
		req.Header.Set(name, headers.Get(name))
	}
	return nil
}

// ResolveRoute selects the same origin that a standalone attestation will use.
func (a *Attester) ResolveRoute(ctx context.Context, model string) (provider.ResolvedRoute, error) {
	if err := nearroute.ValidateModel(model); err != nil {
		return provider.ResolvedRoute{}, err
	}
	if err := ctx.Err(); err != nil {
		return provider.ResolvedRoute{}, err
	}
	configured := a.origin
	if configured.Static {
		return provider.NewResolvedRoute("https://"+configured.Authority, "")
	}
	if a.resolver == nil {
		return provider.ResolvedRoute{}, errors.New("missing NEAR route resolver")
	}
	return a.resolver.ResolveConfigured(ctx, model, configured)
}

// DomainResolver maps a model name to a backend authority.
type DomainResolver interface {
	ResolveConfigured(context.Context, string, nearroute.Origin) (provider.ResolvedRoute, error)
}

// StopResolution cancels and joins metadata/selection work without closing injected clients.
func (a *Attester) StopResolution() {
	if owner, ok := a.resolver.(interface{ Stop() }); ok {
		owner.Stop()
	}
}

// LookupRoute reads a static or established route without initial selection.
func (a *Attester) LookupRoute(model string) (provider.ResolvedRoute, bool) {
	if nearroute.ValidateModel(model) != nil {
		return provider.ResolvedRoute{}, false
	}
	origin := a.origin
	if origin.Static || origin.Indexed {
		route, err := provider.NewResolvedRoute("https://"+origin.Authority, "")
		return route, err == nil
	}
	if resolver, ok := a.resolver.(interface {
		LookupSelection(string) (Selection, bool)
	}); ok {
		selection, found := resolver.LookupSelection(model)
		if found {
			route, err := provider.NewResolvedRoute("https://"+selection.Authority, "")
			return route, err == nil
		}
	}
	return provider.ResolvedRoute{}, false
}
