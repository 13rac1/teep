package provider_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/provider"
)

const testModelsJSON = `{
	"object": "list",
	"data": [
		{
			"id": "qwen2p5-72b-instruct",
			"object": "model",
			"created": 1727389200,
			"owned_by": "near-ai",
			"name": "Qwen 2.5 72B Instruct",
			"description": "A large language model",
			"quantization": "fp16",
			"hugging_face_id": "Qwen/Qwen2.5-72B-Instruct",
			"is_ready": true,
			"context_length": 32768,
			"max_output_length": 4096,
			"input_modalities": ["text"],
			"output_modalities": ["text"],
			"supported_features": ["chat"],
			"supported_sampling_parameters": ["temperature", "top_p"],
			"pricing": {"prompt": "0.00059", "completion": "0.00079"},
			"architecture": {"tokenizer": "Qwen/Qwen2.5-72B-Instruct", "instruct_type": "chatml"},
			"datacenters": [{"name": "us-east"}],
			"openrouter": null,
			"top_provider": {"max_completion_tokens": 4096}
		},
		{
			"id": "llama-3.3-70b-instruct",
			"object": "model",
			"created": 1733961600,
			"owned_by": "near-ai",
			"name": "Llama 3.3 70B Instruct",
			"description": "Meta Llama model",
			"quantization": "fp16",
			"hugging_face_id": "meta-llama/Llama-3.3-70B-Instruct",
			"is_ready": true,
			"context_length": 131072,
			"max_output_length": 8192,
			"input_modalities": ["text"],
			"output_modalities": ["text"],
			"supported_features": ["chat"],
			"supported_sampling_parameters": ["temperature"],
			"pricing": {"prompt": "0.00035", "completion": "0.0004"},
			"architecture": {"tokenizer": "meta-llama/Llama-3.3-70B-Instruct", "instruct_type": "llama3"},
			"datacenters": [{"name": "us-west"}],
			"openrouter": null,
			"top_provider": {"max_completion_tokens": 8192}
		}
	]
}`

func TestModelLister_ListModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("request: %s %s", r.Method, r.URL.Path)
		if r.URL.Path != "/v1/models" {
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

	lister := provider.NewModelLister(srv.URL, "test-key", srv.Client())
	models, err := lister.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}

	t.Logf("got %d models", len(models))
	if len(models) != 2 {
		t.Fatalf("got %d models, want 2", len(models))
	}

	// Verify full upstream fields are preserved.
	for _, raw := range models {
		var entry struct {
			ID            string `json:"id"`
			Object        string `json:"object"`
			Created       int64  `json:"created"`
			OwnedBy       string `json:"owned_by"`
			ContextLength int    `json:"context_length"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			t.Fatalf("unmarshal model entry: %v", err)
		}
		t.Logf("  id=%q object=%q created=%d owned_by=%q context_length=%d",
			entry.ID, entry.Object, entry.Created, entry.OwnedBy, entry.ContextLength)

		if entry.Object != "model" {
			t.Errorf("model %q: object = %q, want %q", entry.ID, entry.Object, "model")
		}
		if entry.OwnedBy != "near-ai" {
			t.Errorf("model %q: owned_by = %q, want %q", entry.ID, entry.OwnedBy, "near-ai")
		}
	}

	// Verify pricing is preserved in raw JSON.
	var first struct {
		Pricing struct {
			Prompt     string `json:"prompt"`
			Completion string `json:"completion"`
		} `json:"pricing"`
	}
	if err := json.Unmarshal(models[0], &first); err != nil {
		t.Fatalf("unmarshal first pricing: %v", err)
	}
	t.Logf("  first model pricing: prompt=%s completion=%s", first.Pricing.Prompt, first.Pricing.Completion)
	if first.Pricing.Prompt != "0.00059" {
		t.Errorf("pricing.prompt = %q, want %q", first.Pricing.Prompt, "0.00059")
	}
}

func TestModelLister_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object": "list", "data": []}`))
	}))
	defer srv.Close()

	lister := provider.NewModelLister(srv.URL, "test-key", srv.Client())
	models, err := lister.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	t.Logf("got %d models", len(models))
	if len(models) != 0 {
		t.Errorf("got %d models, want 0", len(models))
	}
}

func TestModelLister_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	lister := provider.NewModelLister(srv.URL, "test-key", srv.Client())
	_, err := lister.ListModels(context.Background())
	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("error %q does not mention unmarshal", err)
	}
}

func TestModelLister_CancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	lister := provider.NewModelLister(srv.URL, "test-key", srv.Client())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := lister.ListModels(ctx)
	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestModelLister_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer srv.Close()

	lister := provider.NewModelLister(srv.URL, "test-key", srv.Client())
	_, err := lister.ListModels(context.Background())
	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not mention status code", err)
	}
	if !strings.Contains(err.Error(), "internal server error") {
		t.Errorf("error %q does not include response body", err)
	}
}

func TestOwnedByModelLister_FiltersModels(t *testing.T) {
	const modelsJSON = `{
		"object": "list",
		"data": [
			{
				"id": "near-model", "object": "model", "created": 1700000000, "owned_by": "nearai",
				"name": "Near Model", "description": "test", "quantization": "fp16",
				"hugging_face_id": "org/near-model", "is_ready": true, "context_length": 8192,
				"max_output_length": 4096, "input_modalities": ["text"], "output_modalities": ["text"],
				"supported_features": ["chat"], "supported_sampling_parameters": ["temperature"],
				"pricing": {}, "architecture": {}, "datacenters": [], "openrouter": null, "top_provider": {}
			},
			{
				"id": "third-party", "object": "model", "created": 1700000000, "owned_by": "openai",
				"name": "Third Party", "description": "test", "quantization": "",
				"hugging_face_id": "", "is_ready": true, "context_length": 4096,
				"max_output_length": 2048, "input_modalities": ["text"], "output_modalities": ["text"],
				"supported_features": [], "supported_sampling_parameters": [],
				"pricing": {}, "architecture": {}, "datacenters": [], "openrouter": null, "top_provider": {}
			},
			{
				"id": "legacy-near", "object": "model", "created": 1700000000, "owned_by": "near-ai",
				"name": "Legacy Near", "description": "test", "quantization": "",
				"hugging_face_id": "", "is_ready": true, "context_length": 2048,
				"max_output_length": 1024, "input_modalities": ["text"], "output_modalities": ["text"],
				"supported_features": [], "supported_sampling_parameters": [],
				"pricing": {}, "architecture": {}, "datacenters": [], "openrouter": null, "top_provider": {}
			}
		]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(modelsJSON))
	}))
	defer srv.Close()

	lister := provider.NewOwnedByModelLister(srv.URL, "test-key", srv.Client(), "nearai")
	models, err := lister.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	if len(models) != 1 {
		t.Fatalf("got %d models, want 1", len(models))
	}

	var entry struct {
		ID            string `json:"id"`
		OwnedBy       string `json:"owned_by"`
		ContextLength int    `json:"context_length"`
	}
	if err := json.Unmarshal(models[0], &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if entry.ID != "near-model" {
		t.Errorf("id = %q, want %q", entry.ID, "near-model")
	}
	if entry.OwnedBy != "nearai" {
		t.Errorf("owned_by = %q, want %q", entry.OwnedBy, "nearai")
	}
	if entry.ContextLength != 8192 {
		t.Errorf("context_length = %d, want 8192", entry.ContextLength)
	}
}

func TestOwnedByModelLister_EmptyID(t *testing.T) {
	const modelsWithEmptyID = `{
		"object": "list",
		"data": [
			{
				"id": "", "object": "model", "created": 0, "owned_by": "nearai",
				"name": "", "description": "", "quantization": "",
				"hugging_face_id": "", "is_ready": false, "context_length": 0,
				"max_output_length": 0, "input_modalities": [], "output_modalities": [],
				"supported_features": [], "supported_sampling_parameters": [],
				"pricing": {}, "architecture": {}, "datacenters": [], "openrouter": null, "top_provider": {}
			}
		]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(modelsWithEmptyID))
	}))
	defer srv.Close()

	lister := provider.NewOwnedByModelLister(srv.URL, "test-key", srv.Client(), "nearai")
	_, err := lister.ListModels(context.Background())
	if err == nil {
		t.Fatal("expected error for model entry with empty id")
	}
	if !strings.Contains(err.Error(), "missing required id") {
		t.Errorf("error %q does not mention missing required id", err)
	}
}

func TestValidatingModelLister(t *testing.T) {
	const tinfoilModelsJSON = `{
		"object": "list",
		"data": [
			{
				"id": "meta-llama/Llama-4-Scout-17B-16E-Instruct",
				"object": "model",
				"created": 1749000000,
				"owned_by": "tinfoil",
				"type": "chat",
				"context_window": 131072,
				"multimodal": true,
				"tool_calling": true,
				"reasoning": false,
				"endpoints": ["/v1/chat/completions"],
				"pricing": {"prompt": "0.0001", "completion": "0.0003"}
			}
		]
	}`

	validated := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(tinfoilModelsJSON))
	}))
	defer srv.Close()

	inner := provider.NewModelLister(srv.URL, "test-key", srv.Client())
	lister := provider.NewValidatingModelLister(inner, func(_ json.RawMessage) {
		validated = true
	})

	models, err := lister.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	if len(models) != 1 {
		t.Fatalf("got %d models, want 1", len(models))
	}
	if !validated {
		t.Error("validate function was not called")
	}
}
