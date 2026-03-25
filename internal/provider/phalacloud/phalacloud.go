// Package phalacloud implements the Attester and RequestPreparer interfaces for
// Phala Cloud's TEE attestation API.
//
// Phala Cloud attestation endpoint:
//
//	GET {base_url}/attestation/report?model={model}&nonce={nonce}
//	Authorization: Bearer {api_key}
//
// The response format is compatible with NEAR AI's attestation response (Phala
// forked the private-ml-sdk), containing model_attestations / all_attestations
// arrays with TDX and NVIDIA attestation payloads, signing_address, and the
// echoed nonce.
//
// Phala Cloud's REPORTDATA binding differs from NEAR AI:
//
//	[0:32]  = signing_address_bytes left-padded with zeros to 32 bytes
//	[32:64] = nonce (raw 32 bytes)
//
// Phala publishes known-good MRTD and MRSEAM values for their dstack-based
// infrastructure and supports proof-of-cloud verification.
package phalacloud

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

const (
	// attestationPath is the Phala Cloud API path for TEE attestation reports.
	attestationPath = "/attestation/report"
)

// Attester fetches attestation data from Phala Cloud's attestation endpoint.
// The nonce is sent as a query parameter and echoed back.
type Attester struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewAttester returns a Phala Cloud Attester configured with the given base URL
// and API key.
func NewAttester(baseURL, apiKey string, offline ...bool) *Attester {
	return &Attester{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  config.NewAttestationClient(offline...),
	}
}

// FetchAttestation fetches TEE attestation from Phala Cloud. The nonce is sent
// as a query parameter; Phala echoes it back in the response. The response
// format is compatible with NEAR AI's format and is parsed using the shared
// neardirect parser.
func (a *Attester) FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	endpoint, err := url.Parse(a.baseURL + attestationPath)
	if err != nil {
		return nil, fmt.Errorf("phalacloud: parse endpoint URL %q: %w", a.baseURL+attestationPath, err)
	}

	q := endpoint.Query()
	q.Set("model", model)
	q.Set("nonce", nonce.Hex())
	endpoint.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("phalacloud: build attestation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.apiKey)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("phalacloud: GET %s%s: %w", endpoint.Host, endpoint.Path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2 MiB max
	if err != nil {
		return nil, fmt.Errorf("phalacloud: read attestation response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := string(body)
		if len(msg) > 512 {
			msg = msg[:512] + "...[truncated]"
		}
		return nil, fmt.Errorf("phalacloud: attestation endpoint returned HTTP %d: %s", resp.StatusCode, msg)
	}

	// The Phala Cloud attestation response is compatible with NEAR AI's format.
	return neardirect.ParseAttestationResponse(body, model)
}

// Preparer injects the Phala Cloud Authorization header into outgoing requests.
type Preparer struct {
	apiKey string
}

// NewPreparer returns a Phala Cloud Preparer configured with the given API key.
func NewPreparer(apiKey string) *Preparer {
	return &Preparer{apiKey: apiKey}
}

// PrepareRequest injects the Authorization header into req.
func (p *Preparer) PrepareRequest(req *http.Request, _ *attestation.Session) error {
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	return nil
}

// ModelLister fetches available models from the Phala Cloud /v1/models endpoint.
// The response format is the standard OpenAI models list.
type ModelLister = neardirect.ModelLister

// NewModelLister returns a ModelLister that fetches from baseURL/v1/models.
// Reuses the neardirect implementation since the endpoint format is identical.
var NewModelLister = neardirect.NewModelLister
