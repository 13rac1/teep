package provider

import (
	"context"
	"encoding/json"
	"errors"
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
	Object string            `json:"object,omitempty"`
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

// nearModelEntry matches the NEAR AI /v1/models entry schema. Used by
// ownedByModelLister for jsonstrict schema drift detection.
type nearModelEntry struct {
	ID                          string          `json:"id"`
	Object                      string          `json:"object"`
	Created                     int64           `json:"created"`
	OwnedBy                     string          `json:"owned_by"`
	Name                        string          `json:"name"`
	Description                 string          `json:"description"`
	ContextLength               int             `json:"context_length"`
	InputModalities             []string        `json:"input_modalities"`
	OutputModalities            []string        `json:"output_modalities"`
	SupportedFeatures           []string        `json:"supported_features"`
	SupportedSamplingParameters []string        `json:"supported_sampling_parameters"`
	Pricing                     json.RawMessage `json:"pricing"`
	Architecture                json.RawMessage `json:"architecture"`
	TopProvider                 json.RawMessage `json:"top_provider"`

	// Optional — not present on all NEAR model entries (e.g. image/embedding
	// models may omit these). Tagged omitempty so jsonstrict does not report
	// them as missing.
	MaxOutputLength int             `json:"max_output_length,omitempty"`
	Quantization    string          `json:"quantization,omitempty"`
	HuggingFaceID   string          `json:"hugging_face_id,omitempty"`
	IsReady         bool            `json:"is_ready,omitempty"`
	Datacenters     json.RawMessage `json:"datacenters,omitempty"`
	Openrouter      json.RawMessage `json:"openrouter,omitempty"`
}

// tinfoilModelEntry matches the Tinfoil /v1/models entry schema. Used by
// validatingModelLister for jsonstrict schema drift detection.
type tinfoilModelEntry struct {
	ID            string          `json:"id"`
	Object        string          `json:"object"`
	Created       int64           `json:"created"`
	OwnedBy       string          `json:"owned_by"`
	Type          string          `json:"type"`
	ContextWindow int             `json:"context_window,omitempty"`
	Multimodal    bool            `json:"multimodal"`
	ToolCalling   bool            `json:"tool_calling"`
	Reasoning     bool            `json:"reasoning"`
	Endpoints     []string        `json:"endpoints"`
	Pricing       json.RawMessage `json:"pricing"`
}

// phalaModelEntry matches the Phalacloud /v1/models entry schema. Used by
// validatingModelLister for jsonstrict schema drift detection.
type phalaModelEntry struct {
	ID                  string          `json:"id"`
	Created             int64           `json:"created"`
	Name                string          `json:"name"`
	Description         string          `json:"description"`
	IsTee               bool            `json:"is_tee"`
	ContextLength       int             `json:"context_length"`
	MaxOutputLength     int             `json:"max_output_length"`
	InputModalities     []string        `json:"input_modalities"`
	OutputModalities    []string        `json:"output_modalities"`
	Providers           []string        `json:"providers"`
	SupportedParameters []string        `json:"supported_parameters"`
	Pricing             json.RawMessage `json:"pricing"`
	Metadata            json.RawMessage `json:"metadata"`
}

// ValidateTinfoilEntry validates a single model entry against the Tinfoil schema.
func ValidateTinfoilEntry(raw json.RawMessage) {
	var e tinfoilModelEntry
	if _, _, err := jsonstrict.UnmarshalWarn(raw, &e, "tinfoil model entry"); err != nil {
		slog.Warn("tinfoil model entry parse failed", "err", err)
	}
}

// ValidatePhalaEntry validates a single model entry against the Phalacloud schema.
func ValidatePhalaEntry(raw json.RawMessage) {
	var e phalaModelEntry
	if _, _, err := jsonstrict.UnmarshalWarn(raw, &e, "phalacloud model entry"); err != nil {
		slog.Warn("phalacloud model entry parse failed", "err", err)
	}
}

// validatingModelLister wraps a ModelLister and runs a validation function on
// each returned entry. Used to apply jsonstrict schema checks to providers
// that use genericModelLister (which returns raw JSON without parsing entries).
type validatingModelLister struct {
	inner    ModelLister
	validate func(json.RawMessage)
}

// NewValidatingModelLister wraps inner and calls validate on each entry
// returned by ListModels. The validate function should log warnings (e.g.
// via jsonstrict.UnmarshalWarn) but not fail the listing.
func NewValidatingModelLister(inner ModelLister, validate func(json.RawMessage)) ModelLister {
	return &validatingModelLister{inner: inner, validate: validate}
}

// ListModels fetches models from the inner lister and validates each entry.
func (l *validatingModelLister) ListModels(ctx context.Context) ([]json.RawMessage, error) {
	models, err := l.inner.ListModels(ctx)
	if err != nil {
		return nil, err
	}
	for _, raw := range models {
		l.validate(raw)
	}
	return models, nil
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
		var m nearModelEntry
		if _, _, err := jsonstrict.UnmarshalWarn(raw, &m, "near model entry"); err != nil {
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
