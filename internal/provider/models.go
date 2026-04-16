package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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

// modelID extracts the "id" field from a raw model JSON entry.
type modelID struct {
	ID string `json:"id"`
}

// ModelFilter returns the set of model names that should be included in a
// filtered model listing. Implementations must be safe for concurrent use.
type ModelFilter interface {
	Models(ctx context.Context) (map[string]struct{}, error)
}

// filteredModelLister wraps a genericModelLister and filters its results
// against a ModelFilter. Only models whose "id" appears in the filter set
// are returned. All upstream metadata (pricing, context_length, etc.) is
// preserved for included models.
type filteredModelLister struct {
	inner  *genericModelLister
	filter ModelFilter
}

// NewFilteredModelLister returns a ModelLister that fetches the full model
// catalog from baseURL/v1/models (with apiKey auth) and then filters to
// only include models present in the filter set.
func NewFilteredModelLister(baseURL, apiKey string, client *http.Client, filter ModelFilter) ModelLister {
	return &filteredModelLister{
		inner: &genericModelLister{
			baseURL: baseURL,
			apiKey:  apiKey,
			client:  client,
		},
		filter: filter,
	}
}

// ListModels fetches the full catalog, fetches the filter set, and returns
// only the intersection. If the filter fetch fails, the full catalog is
// returned rather than failing closed (model listing is not a security
// boundary — it's a UX improvement).
func (f *filteredModelLister) ListModels(ctx context.Context) ([]json.RawMessage, error) {
	all, err := f.inner.ListModels(ctx)
	if err != nil {
		return nil, err
	}

	allowed, filterErr := f.filter.Models(ctx)
	if filterErr != nil {
		slog.WarnContext(ctx, "models: endpoint filter failed, returning unfiltered catalog", "err", filterErr)
		return all, nil
	}

	out := make([]json.RawMessage, 0, len(all))
	for _, raw := range all {
		var m modelID
		if err := json.Unmarshal(raw, &m); err != nil {
			continue // skip entries with no parseable id
		}
		if _, ok := allowed[m.ID]; ok {
			out = append(out, raw)
		}
	}
	return out, nil
}
