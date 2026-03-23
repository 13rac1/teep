package nearcloud

import (
	"context"
	"encoding/json"

	"github.com/13rac1/teep/internal/provider/neardirect"
)

// ModelLister fetches available models from the NEAR AI endpoint discovery API.
// Nearcloud serves the same model universe as neardirect.
type ModelLister struct {
	lister *neardirect.ModelLister
}

// NewModelLister returns a ModelLister for the nearcloud provider.
func NewModelLister(offline ...bool) *ModelLister {
	return &ModelLister{
		lister: neardirect.NewModelLister(neardirect.NewEndpointResolver(offline...), "nearcloud"),
	}
}

// ListModels returns all models from the NEAR AI endpoint discovery API.
func (l *ModelLister) ListModels(ctx context.Context) ([]json.RawMessage, error) {
	return l.lister.ListModels(ctx)
}
