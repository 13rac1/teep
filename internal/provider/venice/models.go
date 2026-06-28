package venice

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
)

// modelsPath is the Venice API path for listing models.
const modelsPath = "/api/v1/models"

// modelsResponse is the top-level JSON shape returned by Venice's models endpoint.
type modelsResponse struct {
	Data []json.RawMessage `json:"data"`
}

// veniceModelEntry matches the Venice /api/v1/models entry schema. Used for
// jsonstrict schema drift detection and TEE/E2EE capability filtering.
type veniceModelEntry struct {
	ID            string `json:"id"`
	Object        string `json:"object"`
	Created       int64  `json:"created"`
	OwnedBy       string `json:"owned_by"`
	Type          string `json:"type"`
	ContextLength int    `json:"context_length"`
	ModelSpec     struct {
		AvailableContextTokens int    `json:"availableContextTokens"`
		Description            string `json:"description"`
		Name                   string `json:"name"`
		Capabilities           struct {
			SupportsTeeAttestation bool `json:"supportsTeeAttestation"`
			SupportsE2EE           bool `json:"supportsE2EE"`
		} `json:"capabilities"`
	} `json:"model_spec"`
}

// ModelLister fetches TEE/E2EE models from Venice's /api/v1/models endpoint.
type ModelLister struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewModelLister returns a ModelLister for Venice.
func NewModelLister(baseURL, apiKey string, client *http.Client) *ModelLister {
	return &ModelLister{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  client,
	}
}

// ListModels fetches models from Venice and returns raw JSON entries for those
// with TEE or E2EE support. All upstream fields are preserved.
func (l *ModelLister) ListModels(ctx context.Context) ([]json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.baseURL+modelsPath, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("venice: build models request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+l.apiKey)
	provider.SetUserAgent(req)

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("venice: GET %s: %w", l.baseURL+modelsPath, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("venice: read models response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("venice: models endpoint returned HTTP %d: %s", resp.StatusCode, provider.Truncate(string(body), 256))
	}

	var mr modelsResponse
	if err := json.Unmarshal(body, &mr); err != nil {
		return nil, fmt.Errorf("venice: unmarshal models response: %w", err)
	}

	var models []json.RawMessage
	for _, raw := range mr.Data {
		var entry veniceModelEntry
		if _, _, err := jsonstrict.UnmarshalWarn(raw, &entry, "venice model entry"); err != nil {
			slog.WarnContext(ctx, "venice: skipping model entry", "err", err)
			continue
		}
		if entry.ModelSpec.Capabilities.SupportsTeeAttestation || entry.ModelSpec.Capabilities.SupportsE2EE {
			models = append(models, raw)
		}
	}
	return models, nil
}
