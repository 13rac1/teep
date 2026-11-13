package neardirect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearroute"
)

// extraModels holds the models that teep lists for neardirect although
// the NEAR AI catalog (cloud-api.near.ai/v1/models) does not list them with
// owned_by "nearai". Teep lists each one only while the endpoint list of
// completions.near.ai serves it.
//
// z-ai/glm-5.3-flash-long, 2026-11-13: the endpoint list serves it on a NEAR
// AI TEE endpoint and it passed verification with no enforced failure, but
// the catalog does not list it.
var extraModels = []string{"z-ai/glm-5.3-flash-long"}

// modelLister adds the extra models that the endpoint list serves to the
// catalog models of owned_by "nearai".
type modelLister struct {
	inner    provider.ModelLister
	attester *Attester
}

// NewModelLister returns the neardirect model lister: the models of inner,
// and each extra model that the attester's endpoint list serves.
func NewModelLister(inner provider.ModelLister, attester *Attester) provider.ModelLister {
	return &modelLister{inner: inner, attester: attester}
}

// ListModels returns the inner models and the served extra models that the
// inner models do not hold. The inner lister decodes each entry and
// requires its id, so every entry here is a JSON object with an id; an
// entry that does not decode is an error of that guarantee.
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
	for _, model := range extraModels {
		if slices.Contains(ids, model) || !l.attester.servesModel(ctx, model) {
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
// static origin has no endpoint list, so it serves no extra model. An error
// other than an unknown model, such as an endpoint list outage, is logged
// at debug level and reads as not served.
func (a *Attester) servesModel(ctx context.Context, model string) bool {
	if a.origin.Static {
		return false
	}
	resolver, ok := a.resolver.(*EndpointResolver)
	if !ok {
		return false
	}
	_, err := resolver.mappingForModel(ctx, model)
	var routeErr *nearroute.Error
	if err != nil && (!errors.As(err, &routeErr) || routeErr.Kind != nearroute.UnknownModel) {
		slog.DebugContext(ctx, "endpoint list lookup failed; extra model not listed", "model", model, "err", err)
	}
	return err == nil
}
