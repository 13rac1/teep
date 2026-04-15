package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/13rac1/teep/internal/jsonstrict"
)

// modelsPath is the standard OpenAI-compatible models API path.
const modelsPath = "/v1/models"

// modelsResponse is the top-level JSON shape returned by /v1/models endpoints.
type modelsResponse struct {
	Object string            `json:"object"`
	Data   []json.RawMessage `json:"data"`
}

// genericModelLister fetches available models from a /v1/models endpoint.
type genericModelLister struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewModelLister returns a ModelLister that fetches from baseURL/v1/models.
func NewModelLister(baseURL, apiKey string, client *http.Client) ModelLister {
	return &genericModelLister{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  client,
	}
}

// ListModels fetches models from the API and returns all entries as raw JSON,
// preserving all upstream fields (pricing, context_length, etc.).
func (l *genericModelLister) ListModels(ctx context.Context) ([]json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.baseURL+modelsPath, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("models: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+l.apiKey)

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("models: GET %s: %w", l.baseURL+modelsPath, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("models: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("models: endpoint returned HTTP %d: %s", resp.StatusCode, Truncate(string(body), 256))
	}

	var mr modelsResponse
	if unknown, err := jsonstrict.Unmarshal(body, &mr); err != nil {
		return nil, fmt.Errorf("models: unmarshal response: %w", err)
	} else if len(unknown) > 0 {
		slog.Warn("unexpected JSON fields", "fields", unknown, "context", "models response")
	}

	return mr.Data, nil
}
