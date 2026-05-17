package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/13rac1/teep/internal/httpclient"
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

	resp, err := httpclient.Do(l.client, req)
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

// modelEntry covers commonly used OpenAI-compatible model object fields plus
// known provider extensions (NEAR AI). This avoids jsonstrict.Unmarshal
// false positives for fields this code intentionally accepts; it is not an
// exhaustive schema for all standard OpenAI model fields.
//
// Common OpenAI-compatible fields here: id, object, created, owned_by
// NEAR AI extensions:                 pricing, context_length, architecture.
type modelEntry struct {
	ID            string          `json:"id"`
	Object        string          `json:"object"`
	Created       int64           `json:"created"`
	OwnedBy       string          `json:"owned_by"`
	Pricing       json.RawMessage `json:"pricing"`
	ContextLength json.RawMessage `json:"context_length"`
	Architecture  json.RawMessage `json:"architecture"`
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

// ListModels fetches the filter set, then the full catalog, and returns
// only the intersection. The filter is fetched first to avoid a wasted
// upstream call if the filter fails.
func (f *filteredModelLister) ListModels(ctx context.Context) ([]json.RawMessage, error) {
	allowed, filterErr := f.filter.Models(ctx)
	if filterErr != nil {
		return nil, fmt.Errorf("models: endpoint filter: %w", filterErr)
	}

	all, err := f.inner.ListModels(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]json.RawMessage, 0, len(all))
	for _, raw := range all {
		var m modelEntry
		if unknown, err := jsonstrict.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("models: unmarshal entry to extract id: %w", err)
		} else if len(unknown) > 0 {
			slog.Warn("unexpected JSON fields", "fields", unknown, "context", "model entry")
		}
		if m.ID == "" {
			return nil, errors.New("models: model entry missing required id")
		}
		if _, ok := allowed[m.ID]; ok {
			out = append(out, raw)
		}
	}
	return out, nil
}
