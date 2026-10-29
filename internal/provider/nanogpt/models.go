package nanogpt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
)

// teeModelPrefix starts the ID of every NanoGPT model that runs in a TEE and
// serves attestation. Other NanoGPT models have no attestation, so teep does
// not list them.
const teeModelPrefix = "TEE/"

// modelEntry is one entry of NanoGPT's /v1/models response.
type modelEntry struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

// ModelLister lists the TEE models of NanoGPT's /v1/models endpoint.
type ModelLister struct {
	inner provider.ModelLister
}

// NewModelLister returns a ModelLister that fetches baseURL/v1/models and
// keeps only TEE models.
func NewModelLister(baseURL, apiKey string, client *http.Client) *ModelLister {
	return &ModelLister{inner: provider.NewModelLister(baseURL, apiKey, client)}
}

// ListModels returns the raw entries of the TEE models. An entry that does
// not parse, or has no id, fails the listing.
func (l *ModelLister) ListModels(ctx context.Context) ([]json.RawMessage, error) {
	all, err := l.inner.ListModels(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]json.RawMessage, 0, len(all))
	for _, raw := range all {
		var e modelEntry
		if _, _, err := jsonstrict.UnmarshalWarn(raw, &e, "nanogpt model entry"); err != nil {
			return nil, fmt.Errorf("nanogpt models: unmarshal entry: %w", err)
		}
		if e.ID == "" {
			return nil, errors.New("nanogpt models: model entry missing required id")
		}
		if strings.HasPrefix(e.ID, teeModelPrefix) {
			out = append(out, raw)
		}
	}
	return out, nil
}

// CloseIdleConnections releases idle model discovery connections.
func (l *ModelLister) CloseIdleConnections() {
	if closer, ok := l.inner.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
