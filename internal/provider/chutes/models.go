package chutes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/13rac1/teep/internal/provider"
)

// rawModelsResponse is the top-level /v1/models response with raw JSON entries,
// kept separate from modelsListResponse (used by ModelResolver) to preserve all
// upstream fields for client-facing model listing.
type rawModelsResponse struct {
	Data []json.RawMessage `json:"data"`
}

// modelFilter extracts just enough from a model entry to decide whether to include it.
type modelFilter struct {
	ConfidentialCompute bool `json:"confidential_compute"`
}

// ModelLister fetches TEE-enabled models from the Chutes /v1/models endpoint.
type ModelLister struct {
	modelsBase string
	apiKey     string
	client     *http.Client
}

// NewModelLister returns a ModelLister that fetches from modelsBase/v1/models
// and filters for TEE-enabled models. If modelsBase is empty,
// DefaultModelsBaseURL is used.
func NewModelLister(modelsBase, apiKey string, client *http.Client) *ModelLister {
	if modelsBase == "" {
		modelsBase = DefaultModelsBaseURL
	}
	return &ModelLister{
		modelsBase: strings.TrimRight(modelsBase, "/"),
		apiKey:     apiKey,
		client:     client,
	}
}

// ListModels fetches models from the Chutes LLM gateway and returns raw JSON
// entries for those with confidential_compute enabled (running in Intel TDX
// TEE). All upstream fields (pricing, context_length, etc.) are preserved.
func (l *ModelLister) ListModels(ctx context.Context) ([]json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.modelsBase+modelsPath, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("chutes: build models request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+l.apiKey)

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("chutes: GET %s: %w", l.modelsBase+modelsPath, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, modelsMaxBody))
	if err != nil {
		return nil, fmt.Errorf("chutes: read models response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("chutes: models endpoint returned HTTP %d: %s", resp.StatusCode, provider.Truncate(string(body), 256))
	}

	var mr rawModelsResponse
	if err := json.Unmarshal(body, &mr); err != nil {
		return nil, fmt.Errorf("chutes: unmarshal models response: %w", err)
	}

	var models []json.RawMessage
	for _, raw := range mr.Data {
		var f modelFilter
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("chutes: unmarshal model entry: %w", err)
		}
		if f.ConfidentialCompute {
			models = append(models, raw)
		}
	}
	return models, nil
}
