// Package venice implements the Attester and RequestPreparer interfaces for
// Venice AI's TEE attestation and E2EE API.
//
// Venice attestation endpoint:
//
//	GET {base_url}/api/v1/tee/attestation?model={model}&nonce={nonce}
//	Authorization: Bearer {api_key}
//
// Venice E2EE request headers (PrepareRequest):
//
//	X-Venice-TEE-Client-Pub-Key: {session_public_key_hex}
//	X-Venice-TEE-Model-Pub-Key:  {model_signing_key_hex}
//	X-Venice-TEE-Signing-Algo:   ecdsa
//	Authorization:               Bearer {api_key}
package venice

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/jsonstrict"
)

// attestationPath is the Venice API path for TEE attestation.
const attestationPath = "/api/v1/tee/attestation"

// attestationResponse is the JSON shape returned by Venice's attestation
// endpoint. Fields are unmarshalled directly from the API response.
type attestationResponse struct {
	Verified       bool   `json:"verified"`
	Nonce          string `json:"nonce"`
	Model          string `json:"model"`
	TEEProvider    string `json:"tee_provider"`
	SigningKey     string `json:"signing_key"`
	SigningAddress string `json:"signing_address"`
	IntelQuote     string `json:"intel_quote"`
	NvidiaPayload  string `json:"nvidia_payload"`
}

// Attester fetches attestation data from Venice's /api/v1/tee/attestation
// endpoint. It sends the client-supplied nonce as a query parameter so Venice
// echoes it back in the response for nonce_match verification.
type Attester struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewAttester returns a Venice Attester configured with the given base URL and
// API key. It uses a 30-second HTTP timeout via config.NewAttestationClient.
func NewAttester(baseURL, apiKey string) *Attester {
	return &Attester{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  config.NewAttestationClient(),
	}
}

// FetchAttestation fetches TEE attestation for the given model from Venice.
// The nonce is sent to Venice as a hex string query parameter; Venice echoes it
// back in the response so callers can verify nonce_match.
func (a *Attester) FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	endpoint, err := url.Parse(a.baseURL + attestationPath)
	if err != nil {
		return nil, fmt.Errorf("venice: parse base URL %q: %w", a.baseURL, err)
	}

	q := endpoint.Query()
	q.Set("model", model)
	q.Set("nonce", nonce.Hex())
	endpoint.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("venice: build attestation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.apiKey)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("venice: GET %s: %w", endpoint.String(), err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB max
	if err != nil {
		return nil, fmt.Errorf("venice: read attestation response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := string(body)
		if len(msg) > 512 {
			msg = msg[:512] + "...[truncated]"
		}
		return nil, fmt.Errorf("venice: attestation endpoint returned HTTP %d: %s", resp.StatusCode, msg)
	}

	var ar attestationResponse
	if err := jsonstrict.UnmarshalWarn(body, &ar, "venice attestation response"); err != nil {
		return nil, fmt.Errorf("venice: unmarshal attestation response: %w", err)
	}

	return &attestation.RawAttestation{
		Verified:       ar.Verified,
		Nonce:          ar.Nonce,
		Model:          ar.Model,
		TEEProvider:    ar.TEEProvider,
		SigningKey:     ar.SigningKey,
		SigningAddress: ar.SigningAddress,
		IntelQuote:     ar.IntelQuote,
		NvidiaPayload:  ar.NvidiaPayload,
		RawBody:        body,
	}, nil
}

// Preparer injects Venice E2EE headers into an outgoing chat completions
// request. The three required Venice E2EE headers identify the client's
// ephemeral public key, the model's attested signing key, and the algorithm.
type Preparer struct {
	apiKey string
}

// NewPreparer returns a Venice Preparer configured with the given API key.
func NewPreparer(apiKey string) *Preparer {
	return &Preparer{apiKey: apiKey}
}

// PrepareRequest injects the Venice E2EE headers into req. The session must
// have its ModelKeyHex set (via SetModelKey) before calling this function.
func (p *Preparer) PrepareRequest(req *http.Request, session *attestation.Session) error {
	if session.ModelKeyHex == "" {
		return fmt.Errorf("venice: PrepareRequest called with empty session.ModelKeyHex; call SetModelKey first")
	}
	if session.PublicKeyHex == "" {
		return fmt.Errorf("venice: PrepareRequest called with empty session.PublicKeyHex; session may not be initialised")
	}

	req.Header.Set("X-Venice-TEE-Client-Pub-Key", session.PublicKeyHex)
	req.Header.Set("X-Venice-TEE-Model-Pub-Key", session.ModelKeyHex)
	req.Header.Set("X-Venice-TEE-Signing-Algo", "ecdsa")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	return nil
}
