package neardirect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// modelsPath is the NEAR AI models API path.
const modelsPath = "/v1/models"

// modelsResponse is the top-level JSON shape returned by NEAR AI's models endpoint.
type modelsResponse struct {
	Data []json.RawMessage `json:"data"`
}

// ModelLister fetches available models from the NEAR AI /v1/models endpoint.
type ModelLister struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewModelLister returns a ModelLister that fetches from baseURL/v1/models.
func NewModelLister(baseURL, apiKey string, client *http.Client) *ModelLister {
	return &ModelLister{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  client,
	}
}

// ListModels fetches models from the NEAR AI API and returns all entries as
// raw JSON, preserving all upstream fields (pricing, context_length, etc.).
func (l *ModelLister) ListModels(ctx context.Context) ([]json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.baseURL+modelsPath, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("nearai: build models request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+l.apiKey)

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nearai: GET %s: %w", l.baseURL+modelsPath, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("nearai: read models response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nearai: models endpoint returned HTTP %d: %s", resp.StatusCode, truncate(string(body), 256))
	}

	var mr modelsResponse
	if err := json.Unmarshal(body, &mr); err != nil {
		return nil, fmt.Errorf("nearai: unmarshal models response: %w", err)
	}

	return mr.Data, nil
}
