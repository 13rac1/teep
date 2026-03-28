// Package chutes implements the Attester for the Chutes TEE attestation format.
//
// Chutes attestation responses use a distinct format from dstack/Venice:
//   - intel_quote is base64-encoded (not hex)
//   - No signing_address field; uses e2e_pubkey instead
//   - GPU attestation is per-GPU evidence, not a single nvidia_payload JWT
//   - The server generates its own nonce (does not echo the client nonce)
//
// Chutes attestation endpoint:
//
//	GET {base_url}/attestation/report?model={model}&nonce={nonce}
//	Authorization: Bearer {api_key}
//
// This package is used both directly (for the chutes provider) and by gateway
// providers (nanogpt, phalacloud/RedPill) that detect chutes format and delegate.
package chutes

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
)

// attestationPath is the Chutes API path for TEE attestation reports.
const attestationPath = "/attestation/report"

const (
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

// chutesAttestation is one entry in the chutes "all_attestations" array.
type chutesAttestation struct {
	InstanceID  string        `json:"instance_id"`
	Nonce       string        `json:"nonce"`
	E2EPubKey   string        `json:"e2e_pubkey"`
	IntelQuote  string        `json:"intel_quote"` // base64-encoded TDX quote
	GPUEvidence []gpuEvidence `json:"gpu_evidence"`
}

// attestationResponse is the top-level JSON shape returned by the chutes
// attestation format.
type attestationResponse struct {
	AttestationType string              `json:"attestation_type"`
	Nonce           string              `json:"nonce"`
	AllAttestations []chutesAttestation `json:"all_attestations"`
}

// Attester fetches attestation data from a Chutes-compatible attestation
// endpoint. The nonce is sent as a query parameter; the server generates
// its own nonce (does not echo the client nonce).
type Attester struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewAttester returns a Chutes Attester configured with the given base URL
// and API key.
func NewAttester(baseURL, apiKey string, offline ...bool) *Attester {
	return &Attester{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  config.NewAttestationClient(offline...),
	}
}

// FetchAttestation fetches TEE attestation from Chutes. The nonce is sent
// as a query parameter. The server generates its own nonce.
func (a *Attester) FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	endpoint, err := url.Parse(a.baseURL + attestationPath)
	if err != nil {
		return nil, fmt.Errorf("chutes: parse endpoint URL %q: %w", a.baseURL+attestationPath, err)
	}
	q := endpoint.Query()
	q.Set("model", model)
	q.Set("nonce", nonce.Hex())
	endpoint.RawQuery = q.Encode()

	body, err := provider.FetchAttestationJSON(ctx, a.client, endpoint.String(), a.apiKey, 2<<20)
	if err != nil {
		return nil, fmt.Errorf("chutes: %w", err)
	}
	return ParseAttestationResponse(body)
}

// ParseAttestationResponse unmarshals a chutes-format attestation JSON response
// body into a RawAttestation. The first attestation entry is used for TDX quote
// verification. The base64-encoded intel_quote is converted to hex for
// compatibility with the TDX verification pipeline.
func ParseAttestationResponse(body []byte) (*attestation.RawAttestation, error) {
	var ar attestationResponse
	if err := jsonstrict.UnmarshalWarn(body, &ar, "chutes attestation response"); err != nil {
		return nil, fmt.Errorf("chutes: unmarshal attestation response: %w", err)
	}

	if len(ar.AllAttestations) == 0 {
		return nil, errors.New("chutes: all_attestations is empty")
	}
	if len(ar.AllAttestations) > maxAttestationEntries {
		return nil, fmt.Errorf("chutes: all_attestations has %d entries, max %d",
			len(ar.AllAttestations), maxAttestationEntries)
	}

	// Use the first attestation entry for verification.
	first := ar.AllAttestations[0]

	for i, a := range ar.AllAttestations {
		if len(a.GPUEvidence) > maxGPUEvidence {
			return nil, fmt.Errorf("chutes: attestation[%d] has %d GPU evidence entries, max %d",
				i, len(a.GPUEvidence), maxGPUEvidence)
		}
	}

	// Convert base64-encoded intel_quote to hex for TDX verification pipeline.
	var intelQuoteHex string
	if first.IntelQuote != "" {
		quoteBytes, err := base64.StdEncoding.DecodeString(first.IntelQuote)
		if err != nil {
			return nil, fmt.Errorf("chutes: base64-decode intel_quote: %w", err)
		}
		intelQuoteHex = hex.EncodeToString(quoteBytes)
	}

	slog.Debug("chutes attestation parsed",
		"type", ar.AttestationType,
		"instances", len(ar.AllAttestations),
		"instance_id", first.InstanceID,
		"gpus", len(first.GPUEvidence),
		"nonce_prefix", attestation.NoncePrefix(ar.Nonce),
	)

	return &attestation.RawAttestation{
		BackendFormat: attestation.FormatChutes,
		Nonce:         ar.Nonce,
		TEEProvider:   "TDX+NVIDIA",
		SigningKey:    first.E2EPubKey,
		IntelQuote:    intelQuoteHex,

		TEEHardware: "intel-tdx",
		NonceSource: "server",

		CandidatesAvail: len(ar.AllAttestations),

		RawBody: body,
	}, nil
}

// Preparer injects the Chutes Authorization header into outgoing requests.
type Preparer struct {
	apiKey string
}

// NewPreparer returns a Chutes Preparer configured with the given API key.
func NewPreparer(apiKey string) *Preparer {
	return &Preparer{apiKey: apiKey}
}

// PrepareRequest injects the Authorization header into req.
func (p *Preparer) PrepareRequest(req *http.Request, _ *attestation.Session) error {
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	return nil
}
