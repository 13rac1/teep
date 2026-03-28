// Package phalacloud implements the Attester and RequestPreparer interfaces for
// Phala Cloud's TEE attestation API (RedPill gateway).
//
// RedPill is a multi-backend gateway that returns attestation in different
// formats depending on the backend model. Supported formats:
//
//   - chutes:  "attestation_type" key present → delegates to chutes.ParseAttestationResponse
//   - dstack:  "intel_quote" key present → delegates to nanogpt.ParseAttestationResponse
//   - tinfoil: "format" key present → not yet supported
//   - gateway: "gateway_attestation" key present → not yet supported
//
// Phala Cloud attestation endpoint:
//
//	GET {base_url}/attestation/report?model={model}&nonce={nonce}
//	Authorization: Bearer {api_key}
package phalacloud

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/formatdetect"
	"github.com/13rac1/teep/internal/provider/chutes"
	"github.com/13rac1/teep/internal/provider/nanogpt"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/tlsct"
)

const (
	// attestationPath is the Phala Cloud API path for TEE attestation reports.
	attestationPath = "/attestation/report"

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
	return &Attester{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  client,
	}
}

// FetchAttestation fetches TEE attestation from Phala Cloud. The nonce is sent
// as a query parameter. Format detection is performed on the response body to
// delegate to the correct backend parser.
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

	return ParseAttestationResponse(body)
}

// ParseAttestationResponse detects the attestation format from the JSON body
// and delegates to the appropriate backend parser.
func ParseAttestationResponse(body []byte) (*attestation.RawAttestation, error) {
	format := formatdetect.Detect(body)
	slog.Debug("phalacloud format detected", "format", format)

	switch format {
	case attestation.FormatChutes:
		return chutes.ParseAttestationResponse(body)
	case attestation.FormatDstack:
		return nanogpt.ParseAttestationResponse(body)
	case attestation.FormatTinfoil:
		return nil, fmt.Errorf("phalacloud: tinfoil attestation format not yet supported")
	case attestation.FormatGateway:
		return nil, fmt.Errorf("phalacloud: gateway attestation format not yet supported")
	default:
		return nil, fmt.Errorf("phalacloud: unrecognized attestation format (no known format keys found)")
	}
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
