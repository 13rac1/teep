package tinfoil

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
)

const attestationPath = "/.well-known/tinfoil-attestation"

// Attester fetches attestation data from the Tinfoil attestation endpoint.
type Attester struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewAttester returns a Tinfoil Attester configured with the given base URL
// and API key.
func NewAttester(baseURL, apiKey string, offline ...bool) *Attester {
	client := config.NewAttestationClient(len(offline) > 0 && offline[0])
	return &Attester{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  client,
	}
}

// SetClient replaces the HTTP client used for attestation fetches.
func (a *Attester) SetClient(c *http.Client) { a.client = c }

// FetchAttestation fetches a v3 attestation document from the static base URL.
//
// The document comes from the Tinfoil router, which is not the endpoint that
// runs the model: the router terminates the client TLS session, decrypts the
// request, chooses a backend, and opens a second connection to it. Its quote
// is therefore gateway evidence, and teep reports it as such.
func (a *Attester) FetchAttestation(ctx context.Context, _ string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	raw, err := fetchAndVerifyAttestation(ctx, a.client, a.baseURL, a.apiKey, nonce)
	if err != nil {
		return nil, err
	}
	if err := asGatewayEvidence(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// asGatewayEvidence moves the router's quote out of the core attestation
// fields and into the gateway fields.
//
// The core fields mean "the TEE that will process this request". Leaving the
// router there reports an intermediary as though it were the model endpoint,
// which overstates what the document proves. Emptying them makes the core
// factors fail closed, which is the true state: the router carries no evidence
// about the backend.
func asGatewayEvidence(raw *attestation.RawAttestation) error {
	if raw.IntelQuote != "" {
		return errors.New("tinfoil: the router served a TDX quote; teep reports the router as a SEV-SNP gateway and has no TDX gateway path for it")
	}
	raw.GatewaySEVReportBytes = raw.SEVReportBytes
	raw.SEVReportBytes = nil

	// TEEHardware names the hardware of the endpoint the report describes. The
	// report header prints it, so leaving it set states the model endpoint's
	// platform is known while the core tier says no evidence exists.
	raw.TEEHardware = ""

	// The router echoes the client nonce in the document it signs, so the
	// gateway nonce factor compares the same value the quote binds.
	raw.GatewayNonceHex = raw.TinfoilNonce
	return nil
}

// DirectAttester fetches attestation from per-model inference enclaves,
// resolving each model to its dedicated domain via the DirectResolver.
type DirectAttester struct {
	resolver *DirectResolver
	apiKey   string
	client   *http.Client
}

// NewDirectAttester returns an attester that resolves per-model domains via
// the DirectResolver and fetches attestation from the resolved enclave.
func NewDirectAttester(resolver *DirectResolver, apiKey string, offline ...bool) *DirectAttester {
	return &DirectAttester{
		resolver: resolver,
		apiKey:   apiKey,
		client:   config.NewAttestationClient(len(offline) > 0 && offline[0]),
	}
}

// SetClient replaces the HTTP client used for attestation fetches and
// propagates it to the resolver for model discovery.
func (a *DirectAttester) SetClient(c *http.Client) {
	a.client = c
	a.resolver.SetClient(c)
}

// FetchAttestation resolves the model to a per-model domain and fetches
// attestation from that enclave's well-known endpoint. When a
// prompt_cache_key is present in the context, the resolver uses
// hash-based sticky routing for cache-aware backend selection.
func (a *DirectAttester) FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	m, err := a.resolver.ResolveMapping(ctx, model)
	if err != nil {
		return nil, fmt.Errorf("tinfoil direct: resolve model %q: %w", model, err)
	}
	promptCacheKey := PromptCacheKeyFromContext(ctx)
	domain := m.SelectDomain(promptCacheKey)
	baseURL := "https://" + domain
	slog.DebugContext(ctx, "tinfoil direct: resolved model domain", "model", model, "domain", domain, "repo", m.Repo)
	raw, err := fetchAndVerifyAttestation(ctx, a.client, baseURL, a.apiKey, nonce)
	if err != nil {
		return nil, err
	}
	raw.TinfoilRepo = m.Repo
	return raw, nil
}

// fetchAndVerifyAttestation fetches a v3 attestation document from the given
// base URL, parses it, and checks the nonce and the TLS channel binding.
//
// The document carries no signature of its own. Its only authentication is the
// CPU quote over REPORT_DATA, which VerifyReportData checks later. The checks
// here reject a document that cannot possibly verify, before teep spends the
// work; they do not authenticate it.
func fetchAndVerifyAttestation(ctx context.Context, client *http.Client, baseURL, apiKey string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	u, err := url.Parse(baseURL + attestationPath)
	if err != nil {
		return nil, fmt.Errorf("tinfoil: parse attestation URL: %w", err)
	}
	q := u.Query()
	q.Set("nonce", nonce.Hex())
	u.RawQuery = q.Encode()

	// Log host+path only; the query string carries the client nonce and must
	// not be written to logs (matches tlsct.WrapLogging nonce-safety policy).
	slog.DebugContext(ctx, "tinfoil: fetching attestation", "host", u.Host, "path", u.Path)
	body, peerSPKI, err := provider.FetchAttestationWithTLS(ctx, client, u.String(), apiKey, maxBodySize)
	if err != nil {
		return nil, fmt.Errorf("tinfoil: fetch attestation: %w", err)
	}

	raw, err := parseV3Document(body)
	if err != nil {
		return nil, err
	}

	// Verify nonce matches (constant-time, decoded bytes per spec).
	responseNonce, err := hex.DecodeString(raw.Nonce)
	if err != nil {
		return nil, fmt.Errorf("tinfoil: decode response nonce hex: %w", err)
	}
	if subtle.ConstantTimeCompare(responseNonce, nonce[:]) != 1 {
		return nil, fmt.Errorf("tinfoil: nonce mismatch: response nonce %q does not match client nonce",
			attestation.NoncePrefix(raw.Nonce))
	}

	// TLS channel binding: the live TLS peer must present the key the enclave
	// endorsed. parseV3Document requires the tls item, so an absent
	// fingerprint here is an internal invariant violation, not provider input.
	if peerSPKI == "" {
		return nil, errors.New("tinfoil: TLS channel binding failed: no TLS peer state (plain HTTP is not allowed for attestation endpoints)")
	}
	if err := tlsct.CompareSPKIFingerprints(peerSPKI, raw.TinfoilTLSKeyFP); err != nil {
		return nil, fmt.Errorf("tinfoil: TLS channel binding failed: %w", err)
	}
	authority, err := tlsct.HTTPSOriginAuthority(baseURL)
	if err != nil {
		return nil, fmt.Errorf("tinfoil: attestation authority: %w", err)
	}
	raw.TransportTLSFingerprint = raw.TinfoilTLSKeyFP
	raw.TransportTLSAuthority = authority

	return raw, nil
}
