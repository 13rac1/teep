package neardirect

import (
	"context"
	"encoding/json"
	"fmt"
)

// ModelLister fetches available models from the NEAR AI endpoint discovery API.
type ModelLister struct {
	resolver *EndpointResolver
	ownedBy  string
}

// NewModelLister returns a ModelLister backed by the given EndpointResolver.
func NewModelLister(resolver *EndpointResolver, ownedBy string) *ModelLister {
	return &ModelLister{resolver: resolver, ownedBy: ownedBy}
}

// ListModels returns all models from the NEAR AI endpoint discovery API as
// OpenAI-compatible model objects.
func (l *ModelLister) ListModels(ctx context.Context) ([]json.RawMessage, error) {
	names, err := l.resolver.Models(ctx)
	if err != nil {
		return nil, err
	}
	models := make([]json.RawMessage, 0, len(names))
	for _, name := range names {
		entry, err := json.Marshal(struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			OwnedBy string `json:"owned_by"`
		}{
			ID:      name,
			Object:  "model",
			OwnedBy: l.ownedBy,
		})
		if err != nil {
			return nil, fmt.Errorf("marshal model %q: %w", name, err)
		}
		models = append(models, entry)
	}
	return models, nil
}
