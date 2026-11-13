package neardirect

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/13rac1/teep/internal/provider"
)

// extraModels returns the models that teep lists for neardirect although
// the NEAR AI catalog (cloud-api.near.ai/v1/models) does not list them with
// owned_by "nearai". Teep lists each one only while the endpoint list of
// completions.near.ai serves it.
//
// z-ai/glm-5.3-flash-long, 2026-11-13: the endpoint list serves it on a NEAR
// AI TEE endpoint and it passed verification with no enforced failure, but
// the catalog does not list it.
func extraModels() []string {
	return []string{"z-ai/glm-5.3-flash-long"}
}

// modelLister adds the extra models that the endpoint list serves to the
// catalog models of owned_by "nearai".
type modelLister struct {
	inner  provider.ModelLister
	served func(ctx context.Context, model string) bool
	extra  []string
}

// NewModelLister returns the neardirect model lister: the models of inner,
// and each extra model that the attester's endpoint list serves.
func NewModelLister(inner provider.ModelLister, attester *Attester) provider.ModelLister {
	return &modelLister{inner: inner, served: attester.servesModel, extra: extraModels()}
}

// ListModels returns the inner models and the served extra models that the
// inner models do not hold.
func (l *modelLister) ListModels(ctx context.Context) ([]json.RawMessage, error) {
	models, err := l.inner.ListModels(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(models))
	for _, raw := range models {
		var entry struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			return nil, fmt.Errorf("models: read model id: %w", err)
		}
		ids = append(ids, entry.ID)
	}
	for _, model := range l.extra {
		if slices.Contains(ids, model) || !l.served(ctx, model) {
			continue
		}
		raw, err := json.Marshal(map[string]string{"id": model, "object": "model"})
		if err != nil {
			return nil, fmt.Errorf("models: encode %s: %w", model, err)
		}
		models = append(models, raw)
	}
	return models, nil
}

// CloseIdleConnections forwards cleanup to the wrapped lister.
func (l *modelLister) CloseIdleConnections() {
	if closer, ok := l.inner.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// servesModel reports whether the endpoint list serves model. A configured
// static origin has no endpoint list, so it serves no extra model.
func (a *Attester) servesModel(ctx context.Context, model string) bool {
	if a.origin.Static {
		return false
	}
	resolver, ok := a.resolver.(*EndpointResolver)
	if !ok {
		return false
	}
	_, err := resolver.mappingForModel(ctx, model)
	return err == nil
}
