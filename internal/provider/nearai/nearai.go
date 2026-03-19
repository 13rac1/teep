// Package nearai implements the Attester and RequestPreparer interfaces for
// NEAR AI's TEE attestation API.
//
// NEAR AI attestation endpoint (based on nearai/verified-proxy research):
//
//	GET {base_url}/attestation/report
//	Authorization: Bearer {api_key}
//
// The response contains a model_attestations array, where each element holds
// TDX and NVIDIA attestation payloads for one inference node.
//
// NEAR AI E2EE is less documented than Venice. PrepareRequest injects the
// Authorization header; additional E2EE headers will be added when the NEAR AI
// E2EE protocol is fully specified.
package nearai

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/jsonstrict"
)

// attestationPath is the NEAR AI API path for TEE attestation reports.
const attestationPath = "/attestation/report"

// modelAttestation represents one element of the model_attestations array
// returned by NEAR AI's attestation endpoint.
type modelAttestation struct {
	Model         string `json:"model"`
	IntelQuote    string `json:"intel_quote"`
	NvidiaPayload string `json:"nvidia_payload"`
	SigningKey    string `json:"signing_key"`
	Nonce         string `json:"nonce"`
}

// attestationResponse is the JSON shape returned by NEAR AI's attestation
// endpoint. The server may return a single attestation or an array under
// model_attestations. Both forms are handled.
type attestationResponse struct {
	// ModelAttestations is the primary response field: an array of per-node
	// attestation records.
	ModelAttestations []modelAttestation `json:"model_attestations"`

	// Top-level fields are present when the server returns a flat response
	// rather than the array form. Both forms are tolerated.
	Model         string `json:"model"`
	IntelQuote    string `json:"intel_quote"`
	NvidiaPayload string `json:"nvidia_payload"`
	SigningKey    string `json:"signing_key"`
	Nonce         string `json:"nonce"`
	Verified      bool   `json:"verified"`
}

// Attester fetches attestation data from NEAR AI's /attestation/report
// endpoint. NEAR AI's attestation protocol does not currently echo a
// client-supplied nonce, so nonce_match will Skip for NEAR AI.
type Attester struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewAttester returns a NEAR AI Attester configured with the given base URL
// and API key. It uses a 30-second HTTP timeout via config.NewAttestationClient.
func NewAttester(baseURL, apiKey string) *Attester {
	return &Attester{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  config.NewAttestationClient(),
	}
}

// FetchAttestation fetches TEE attestation from NEAR AI. The model parameter
// selects which attestation to use when the response contains multiple
// model_attestations entries. The nonce is stored as-is in the returned
// RawAttestation.Nonce only when NEAR AI echoes it; if absent, the Nonce
// field is left empty (which causes nonce_match to Fail in the report).
func (a *Attester) FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	endpoint := a.baseURL + attestationPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("nearai: build attestation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.apiKey)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nearai: GET %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB max
	if err != nil {
		return nil, fmt.Errorf("nearai: read attestation response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := string(body)
		if len(msg) > 512 {
			msg = msg[:512] + "...[truncated]"
		}
		return nil, fmt.Errorf("nearai: attestation endpoint returned HTTP %d: %s", resp.StatusCode, msg)
	}

	var ar attestationResponse
	if err := jsonstrict.UnmarshalWarn(body, &ar, "nearai attestation response"); err != nil {
		return nil, fmt.Errorf("nearai: unmarshal attestation response: %w", err)
	}

	// If the response contains model_attestations, pick the best match for the
	// requested model. Fall back to the first entry if no exact match.
	if len(ar.ModelAttestations) > 0 {
		selected := ar.ModelAttestations[0]
		for _, ma := range ar.ModelAttestations {
			if ma.Model == model {
				selected = ma
				break
			}
		}
		return &attestation.RawAttestation{
			Verified:      ar.Verified,
			Nonce:         selected.Nonce,
			Model:         selected.Model,
			TEEProvider:   "TDX+NVIDIA",
			SigningKey:    selected.SigningKey,
			IntelQuote:    selected.IntelQuote,
			NvidiaPayload: selected.NvidiaPayload,
			RawBody:       body,
		}, nil
	}

	// Flat response form: use top-level fields directly.
	return &attestation.RawAttestation{
		Verified:      ar.Verified,
		Nonce:         ar.Nonce,
		Model:         ar.Model,
		TEEProvider:   "TDX+NVIDIA",
		SigningKey:    ar.SigningKey,
		IntelQuote:    ar.IntelQuote,
		NvidiaPayload: ar.NvidiaPayload,
		RawBody:       body,
	}, nil
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

// PrepareRequest injects the NEAR AI Authorization header into req. The session
// parameter is accepted for interface compatibility but is not used until NEAR
// AI's E2EE header protocol is specified.
func (p *Preparer) PrepareRequest(req *http.Request, session *attestation.Session) error {
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	return nil
}
