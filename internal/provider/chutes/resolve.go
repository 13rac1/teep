package chutes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/13rac1/teep/internal/httpclient"
)

const (
	// modelsPath is the OpenAI-compatible models listing endpoint.
	modelsPath = "/v1/models"

	// modelMapTTL controls how long cached model→chute_id mappings are used.
	modelMapTTL = 5 * time.Minute

	// modelsMaxBody bounds the /v1/models response body (1 MiB).
	modelsMaxBody = 1 << 20

	// DefaultModelsBaseURL is the Chutes MegaLLM gateway that serves /v1/models.
	DefaultModelsBaseURL = "https://llm.chutes.ai"
)

// modelEntry is a single entry from the /v1/models response.
type modelEntry struct {
	ID      string `json:"id"`
	ChuteID string `json:"chute_id"`
}

// modelsListResponse is the top-level /v1/models response.
type modelsListResponse struct {
	Data []modelEntry `json:"data"`
}

// ModelResolver maps human-readable model names (e.g. "deepseek-ai/DeepSeek-V3-0324-TEE")
// to chute UUIDs required by the Chutes E2EE API. UUIDs pass through unchanged.
type ModelResolver struct {
	modelsBase string
	apiKey     string
	client     *http.Client

	mu       sync.Mutex
	cache    map[string]string // model name → chute_id
	loadedAt time.Time
}

// NewModelResolver returns a resolver that fetches model mappings from
// modelsBase/v1/models. If modelsBase is empty, DefaultModelsBaseURL is used.
func NewModelResolver(modelsBase, apiKey string, client *http.Client) *ModelResolver {
	if modelsBase == "" {
		modelsBase = DefaultModelsBaseURL
	}
	return &ModelResolver{
		modelsBase: strings.TrimRight(modelsBase, "/"),
		apiKey:     apiKey,
		client:     client,
	}
}

// Resolve maps a model identifier to a chute UUID. If model is already a UUID
// it is returned unchanged. Otherwise the /v1/models listing is consulted
// (with caching). Returns an error if the model cannot be resolved.
func (r *ModelResolver) Resolve(ctx context.Context, model string) (string, error) {
	if looksLikeUUID(model) {
		return model, nil
	}

	if err := r.maybeRefresh(ctx); err != nil {
		return "", err
	}

	r.mu.Lock()
	id, ok := r.cache[model]
	r.mu.Unlock()
	if ok {
		return id, nil
	}

	// Force refresh in case the map was stale.
	r.mu.Lock()
	r.loadedAt = time.Time{}
	r.mu.Unlock()

	if err := r.maybeRefresh(ctx); err != nil {
		return "", err
	}

	r.mu.Lock()
	id, ok = r.cache[model]
	r.mu.Unlock()
	if ok {
		return id, nil
	}

	return "", fmt.Errorf("chutes: model %q not found in /v1/models listing; use a chute UUID or check available models", model)
}

// maybeRefresh fetches /v1/models if the cache has expired.
func (r *ModelResolver) maybeRefresh(ctx context.Context) error {
	r.mu.Lock()
	if time.Since(r.loadedAt) < modelMapTTL {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()

	newMap, err := r.fetchModels(ctx)
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.cache = newMap
	r.loadedAt = time.Now()
	r.mu.Unlock()
	return nil
}

// fetchModels calls GET modelsBase/v1/models and returns a name→chute_id map.
func (r *ModelResolver) fetchModels(ctx context.Context) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.modelsBase+modelsPath, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("chutes: build models request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+r.apiKey)

	resp, err := httpclient.Do(r.client, req)
	if err != nil {
		return nil, fmt.Errorf("chutes: GET %s: %w", r.modelsBase+modelsPath, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("chutes: GET %s: HTTP %d", r.modelsBase+modelsPath, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, modelsMaxBody))
	if err != nil {
		return nil, fmt.Errorf("chutes: read models response: %w", err)
	}

	var list modelsListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("chutes: unmarshal models response: %w", err)
	}

	result := make(map[string]string, len(list.Data))
	for _, entry := range list.Data {
		if entry.ID != "" && entry.ChuteID != "" {
			result[entry.ID] = entry.ChuteID
		}
	}

	slog.DebugContext(ctx, "chutes: model map refreshed", "models", len(result))
	return result, nil
}

// looksLikeUUID returns true if s has the format of a UUID (8-4-4-4-12 hex).
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return false
	}
	for _, c := range strings.ReplaceAll(s, "-", "") {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
