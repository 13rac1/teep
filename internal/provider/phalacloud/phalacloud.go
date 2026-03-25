// Package phalacloud implements the Attester and RequestPreparer interfaces for
// Phala Cloud's TEE attestation API (RedPill / Chutes infrastructure).
//
// Phala Cloud attestation endpoint:
//
//	GET {base_url}/attestation/report?model={model}&nonce={nonce}
//	Authorization: Bearer {api_key}
//
// The "chutes" attestation format returns:
//
//	{
//	  "attestation_type": "chutes",
//	  "nonce": "<server-generated 64-hex>",
//	  "all_attestations": [
//	    {
//	      "instance_id": "...",
//	      "nonce": "...",
//	      "e2e_pubkey": "<base64 certificate>",
//	      "intel_quote": "<base64 TDX quote>",
//	      "gpu_evidence": [{"certificate":"...","evidence":"...","arch":"HOPPER"}]
//	    }
//	  ]
//	}
//
// Key differences from NEAR AI / Venice formats:
//   - intel_quote is base64-encoded (not hex)
//   - No signing_address field; uses e2e_pubkey instead
//   - GPU attestation is per-GPU evidence, not a single nvidia_payload JWT
//   - The server generates its own nonce (does not echo the client nonce)
package phalacloud

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/tlsct"
)

const (
	// attestationPath is the Phala Cloud API path for TEE attestation reports.
	attestationPath = "/attestation/report"

	// attestationTimeout is longer than the default because Phala Cloud's
	// multi-instance attestation endpoint is slow (typically 30-60s).
	attestationTimeout = 120 * time.Second

	// maxAttestationEntries bounds the number of attestation entries we parse.
	maxAttestationEntries = 256

	// maxGPUEvidence bounds the number of GPU evidence entries per attestation.
	maxGPUEvidence = 64
)

// gpuEvidence is a single GPU attestation entry from the chutes format.
type gpuEvidence struct {
	Certificate string `json:"certificate"`
	Evidence    string `json:"evidence"`
	Arch        string `json:"arch"`
}

// phalaAttestation is one entry in the chutes "all_attestations" array.
type phalaAttestation struct {
	InstanceID  string        `json:"instance_id"`
	Nonce       string        `json:"nonce"`
	E2EPubKey   string        `json:"e2e_pubkey"`
	IntelQuote  string        `json:"intel_quote"` // base64-encoded TDX quote
	GPUEvidence []gpuEvidence `json:"gpu_evidence"`
}

// attestationResponse is the top-level JSON shape returned by Phala Cloud's
// "chutes" attestation format.
type attestationResponse struct {
	AttestationType string             `json:"attestation_type"`
	Nonce           string             `json:"nonce"`
	AllAttestations []phalaAttestation `json:"all_attestations"`
}

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
// as a query parameter. In the chutes format, the server generates its own
// nonce (does not echo the client nonce).
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

// ParseAttestationResponse unmarshals a Phala Cloud "chutes" attestation JSON
// response body into a RawAttestation. The first attestation entry is used for
// TDX quote verification. The base64-encoded intel_quote is converted to hex
// for compatibility with the TDX verification pipeline.
func ParseAttestationResponse(body []byte) (*attestation.RawAttestation, error) {
	var ar attestationResponse
	if err := jsonstrict.UnmarshalWarn(body, &ar, "phalacloud attestation response"); err != nil {
		return nil, fmt.Errorf("phalacloud: unmarshal attestation response: %w", err)
	}

	if len(ar.AllAttestations) == 0 {
		return nil, errors.New("phalacloud: all_attestations is empty")
	}
	if len(ar.AllAttestations) > maxAttestationEntries {
		return nil, fmt.Errorf("phalacloud: all_attestations has %d entries, max %d",
			len(ar.AllAttestations), maxAttestationEntries)
	}

	// Use the first attestation entry for verification.
	first := ar.AllAttestations[0]

	for i, a := range ar.AllAttestations {
		if len(a.GPUEvidence) > maxGPUEvidence {
			return nil, fmt.Errorf("phalacloud: attestation[%d] has %d GPU evidence entries, max %d",
				i, len(a.GPUEvidence), maxGPUEvidence)
		}
	}

	// Convert base64-encoded intel_quote to hex for TDX verification pipeline.
	var intelQuoteHex string
	if first.IntelQuote != "" {
		quoteBytes, err := base64.StdEncoding.DecodeString(first.IntelQuote)
		if err != nil {
			return nil, fmt.Errorf("phalacloud: base64-decode intel_quote: %w", err)
		}
		intelQuoteHex = hex.EncodeToString(quoteBytes)
	}

	slog.Debug("phalacloud attestation parsed",
		"type", ar.AttestationType,
		"instances", len(ar.AllAttestations),
		"instance_id", first.InstanceID,
		"gpus", len(first.GPUEvidence),
		"nonce_prefix", attestation.NoncePrefix(ar.Nonce),
	)

	return &attestation.RawAttestation{
		Nonce:       ar.Nonce,
		TEEProvider: "TDX+NVIDIA",
		SigningKey:  first.E2EPubKey,
		IntelQuote:  intelQuoteHex,

		TEEHardware: "intel-tdx",
		NonceSource: "server",

		CandidatesAvail: len(ar.AllAttestations),

		RawBody: body,
	}, nil
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
