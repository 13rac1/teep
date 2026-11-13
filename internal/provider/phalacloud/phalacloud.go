// Package phalacloud implements the Attester and RequestPreparer interfaces for
// Phala Cloud, which serves its TEE models through the dstack
// private-ai-gateway.
//
// teep verifies the gateway's ACI/1 report, whose quote binds the whole
// workload keyset (ACI/1 §3.2):
//
//	GET {base_url}/v1/aci/attestation?nonce={nonce}
//	Authorization: Bearer {api_key}
package phalacloud

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/formatdetect"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/13rac1/teep/internal/tlsct"
)

const (
	// attestationPath is the ACI/1 report route that teep verifies.
	attestationPath = aci.CanonicalPath

	// attestationTimeout is longer than the default because Phala Cloud's
	// multi-instance attestation endpoint is slow (typically 30-60s).
	attestationTimeout = 120 * time.Second
)

// Attester fetches attestation data from Phala Cloud's attestation endpoint.
// The nonce is sent as a query parameter; the server may generate its own.
type Attester struct {
	baseURL string
	apiKey  string
	client  *http.Client
	// sessionClient returns the client of the session requests, pinned to
	// the TLS key that the report binds (SEE: SetSessionClientFactory).
	sessionClient func(tlsct.TransportIdentity) (*http.Client, error)
}

// NewAttester returns a Phala Cloud Attester configured with the given base URL
// and API key. Uses an extended timeout because Phala Cloud's multi-instance
// attestation endpoint is slow.
func NewAttester(baseURL, apiKey string, offline ...bool) *Attester {
	ctEnabled := len(offline) == 0 || !offline[0]
	client := tlsct.NewHTTPClientWithTransport(attestationTimeout, &http.Transport{
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}, ctEnabled)
	client.Transport = tlsct.WrapLogging(client.Transport)
	return &Attester{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  client,
		sessionClient: func(identity tlsct.TransportIdentity) (*http.Client, error) {
			pinned, err := tlsct.NewSPKIPinnedHTTPClientWithTransport(attestationTimeout, tlsct.NewPooledTransport(), identity, ctEnabled)
			if err != nil {
				return nil, err
			}
			pinned.Transport = tlsct.WrapLogging(pinned.Transport)
			return pinned, nil
		},
	}
}

// SetClient replaces the HTTP client used for attestation fetches.
func (a *Attester) SetClient(c *http.Client) { a.client = c }

// SetSessionClientFactory replaces the factory of the session client. A
// live client must be pinned to the identity before it sends; a replay
// client returns the recorded responses, whose TLS key fetchSessions checks.
func (a *Attester) SetSessionClientFactory(f func(tlsct.TransportIdentity) (*http.Client, error)) {
	a.sessionClient = f
}

// FetchAttestation fetches the ACI/1 report of the private-ai-gateway from
// /v1/aci/attestation with the client nonce, and the attested sessions
// behind model (fetchSessions). The report is service-scoped (ACI/1 §4), so
// its request does not send the model; the sessions describe the upstreams
// that serve the model, and the proxy and teep verify audit them
// (AuditSessions).
func (a *Attester) FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	ctx, cancel := context.WithTimeout(ctx, attestationTimeout)
	defer cancel()

	endpoint, err := url.Parse(a.baseURL + attestationPath)
	if err != nil {
		return nil, fmt.Errorf("phalacloud: parse endpoint URL %q: %w", a.baseURL+attestationPath, err)
	}
	q := endpoint.Query()
	q.Set("nonce", nonce.Hex())
	endpoint.RawQuery = q.Encode()

	body, peerSPKI, err := provider.FetchAttestationWithTLS(ctx, a.client, endpoint.String(), a.apiKey, 2<<20)
	if err != nil {
		return nil, fmt.Errorf("phalacloud: %w", err)
	}
	raw, err := ParseAttestationResponse(ctx, body)
	if err != nil {
		return nil, err
	}
	// The report binds the keyset, and the keyset lists the TLS key of the
	// host; the connection that carried the report must use that key.
	spki, err := aci.TLSKeyForDomain(raw, endpoint.Hostname())
	if err != nil {
		return nil, fmt.Errorf("phalacloud: %w", err)
	}
	if err := tlsct.CompareSPKIFingerprints(peerSPKI, spki); err != nil {
		return nil, fmt.Errorf("phalacloud: attestation TLS binding: %w", err)
	}
	raw.TransportTLSFingerprint = spki
	raw.TransportTLSAuthority = endpoint.Host
	identity, err := tlsct.NewTransportIdentity(endpoint.Host, spki)
	if err != nil {
		return nil, fmt.Errorf("phalacloud: %w", err)
	}
	raw.ACISessions = a.fetchSessions(ctx, model, identity)
	return raw, nil
}

// ParseAttestationResponse parses the ACI/1 report of /v1/aci/attestation.
// Any other format fails: ACI/1 verifiers use the /v1/aci/* routes, and only
// that report binds the whole workload keyset in the gateway quote.
func ParseAttestationResponse(ctx context.Context, body []byte) (*attestation.RawAttestation, error) {
	if format := formatdetect.Detect(body); format != attestation.FormatACI1 {
		return nil, fmt.Errorf("phalacloud: the report of %s must be ACI/1, got format %q", aci.CanonicalPath, format)
	}
	return aci.ParseCanonical(ctx, body, "phalacloud")
}

// Preparer injects the Phala Cloud Authorization header into outgoing requests.
type Preparer struct {
	apiKey string
}

// NewPreparer returns a Phala Cloud Preparer configured with the given API key.
func NewPreparer(apiKey string) *Preparer {
	return &Preparer{apiKey: apiKey}
}

// PrepareRequest injects the Authorization header and the E2EE v2 headers
// into req.
func (p *Preparer) PrepareRequest(req *http.Request, e2eeHeaders http.Header, _ *e2ee.ChutesE2EE, _ bool, _ string, _ provider.PreparationData) error {
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	maps.Copy(req.Header, e2eeHeaders)
	return nil
}

// CloseIdleConnections releases idle connections owned by this component.
func (a *Attester) CloseIdleConnections() { a.client.CloseIdleConnections() }
