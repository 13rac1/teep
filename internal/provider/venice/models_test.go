package venice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const testModelsJSON = `{
	"data": [
		{
			"created": 1727966436,
			"id": "e2ee-qwen3",
			"model_spec": {
				"availableContextTokens": 131072,
				"capabilities": {"supportsE2EE": true, "supportsTeeAttestation": true},
				"description": "E2EE model",
				"name": "Qwen3"
			},
			"object": "model",
			"owned_by": "venice.ai",
			"type": "text"
		},
		{
			"created": 1727966436,
			"id": "tee-llama",
			"model_spec": {
				"capabilities": {"supportsE2EE": false, "supportsTeeAttestation": true},
				"name": "Llama TEE"
			},
			"object": "model",
			"owned_by": "venice.ai",
			"type": "text"
		},
		{
			"created": 1727966436,
			"id": "plain-gpt",
			"model_spec": {
				"capabilities": {"supportsE2EE": false, "supportsTeeAttestation": false},
				"name": "Plain GPT"
			},
			"object": "model",
			"owned_by": "venice.ai",
			"type": "text"
		}
	]
}`

func TestModelLister_ListModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("request: %s %s", r.Method, r.URL.Path)
		if r.URL.Path != "/api/v1/models" {
			http.NotFound(w, r)
			return
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-key" {
			t.Errorf("Authorization = %q, want %q", auth, "Bearer test-key")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(testModelsJSON))
	}))
	defer srv.Close()

	lister := NewModelLister(srv.URL, "test-key", srv.Client())
	models, err := lister.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}

	t.Logf("got %d models (plain-gpt should be filtered)", len(models))
	if len(models) != 2 {
		t.Fatalf("got %d models, want 2", len(models))
	}

	// Verify full upstream fields are preserved.
	for _, raw := range models {
		var entry struct {
			ID      string `json:"id"`
			Created int64  `json:"created"`
			Object  string `json:"object"`
			OwnedBy string `json:"owned_by"`
			Type    string `json:"type"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			t.Fatalf("unmarshal model entry: %v", err)
		}
		t.Logf("  id=%q created=%d object=%q owned_by=%q type=%q", entry.ID, entry.Created, entry.Object, entry.OwnedBy, entry.Type)

		if entry.Object != "model" {
			t.Errorf("model %q: object = %q, want %q", entry.ID, entry.Object, "model")
		}
		if entry.OwnedBy != "venice.ai" {
			t.Errorf("model %q: owned_by = %q, want %q", entry.ID, entry.OwnedBy, "venice.ai")
		}
		if entry.Created != 1727966436 {
			t.Errorf("model %q: created = %d, want 1727966436", entry.ID, entry.Created)
		}
	}

	// Verify model_spec is preserved in raw JSON.
	var first struct {
		ModelSpec struct {
			AvailableContextTokens int `json:"availableContextTokens"`
		} `json:"model_spec"`
	}
	if err := json.Unmarshal(models[0], &first); err != nil {
		t.Fatalf("unmarshal first model_spec: %v", err)
	}
	t.Logf("  first model availableContextTokens=%d", first.ModelSpec.AvailableContextTokens)
	if first.ModelSpec.AvailableContextTokens != 131072 {
		t.Errorf("availableContextTokens = %d, want 131072", first.ModelSpec.AvailableContextTokens)
	}
}

func TestModelLister_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data": []}`))
	}))
	defer srv.Close()

	lister := NewModelLister(srv.URL, "test-key", srv.Client())
	models, err := lister.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	t.Logf("got %d models", len(models))
	if len(models) != 0 {
		t.Errorf("got %d models, want 0", len(models))
	}
}

func TestModelLister_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	lister := NewModelLister(srv.URL, "test-key", srv.Client())
	_, err := lister.ListModels(context.Background())
	t.Logf("error: %v", err)
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}
