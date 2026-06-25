package provider

import (
	"context"
	"encoding/json"
	"errors"
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
	SetUserAgent(req)

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
	if _, _, err := jsonstrict.UnmarshalWarn(body, &mr, "models response"); err != nil {
		return nil, fmt.Errorf("models: unmarshal response: %w", err)
	}

	return mr.Data, nil
}

// modelEntry covers commonly used OpenAI-compatible model object fields plus
// known provider extensions (NEAR AI, Tinfoil). This avoids jsonstrict.Unmarshal
// false positives for fields this code intentionally accepts; it is not an
// exhaustive schema for all standard OpenAI model fields.
//
// Common OpenAI-compatible fields here: id, object, created, owned_by
// NEAR AI extensions:                 pricing, context_length, architecture.
// Tinfoil extensions:                 context_window, endpoints, multimodal,
//
//	reasoning, tool_calling, type.
type modelEntry struct {
	ID            string          `json:"id"`
	Object        string          `json:"object"`
	Created       int64           `json:"created"`
	OwnedBy       string          `json:"owned_by"`
	Pricing       json.RawMessage `json:"pricing"`
	ContextLength json.RawMessage `json:"context_length"`
	Architecture  json.RawMessage `json:"architecture"`

	// Tinfoil extensions.
	ContextWindow json.RawMessage `json:"context_window"`
	Endpoints     json.RawMessage `json:"endpoints"`
	Multimodal    json.RawMessage `json:"multimodal"`
	Reasoning     json.RawMessage `json:"reasoning"`
	ToolCalling   json.RawMessage `json:"tool_calling"`
	Type          string          `json:"type"`
}

// ownedByModelLister wraps a genericModelLister and keeps only models whose
// owned_by field matches a configured owner string exactly.
type ownedByModelLister struct {
	inner   *genericModelLister
	ownedBy string
}

// NewOwnedByModelLister returns a ModelLister that fetches baseURL/v1/models
// and returns only entries whose owned_by field matches ownedBy exactly.
func NewOwnedByModelLister(baseURL, apiKey string, client *http.Client, ownedBy string) ModelLister {
	return &ownedByModelLister{
		inner: &genericModelLister{
			baseURL: baseURL,
			apiKey:  apiKey,
			client:  client,
		},
		ownedBy: ownedBy,
	}
}

// ListModels fetches the full catalog and filters by owned_by.
func (l *ownedByModelLister) ListModels(ctx context.Context) ([]json.RawMessage, error) {
	all, err := l.inner.ListModels(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]json.RawMessage, 0, len(all))
	for _, raw := range all {
		var m modelEntry
		if _, _, err := jsonstrict.UnmarshalWarn(raw, &m, "model entry"); err != nil {
			return nil, fmt.Errorf("models: unmarshal entry to extract owned_by: %w", err)
		}
		if m.ID == "" {
			return nil, errors.New("models: model entry missing required id")
		}
		if m.OwnedBy == l.ownedBy {
			out = append(out, raw)
		}
	}
	return out, nil
}
