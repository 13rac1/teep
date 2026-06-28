package chutes_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/provider/chutes"
)

const testChutesModelsJSON = `{
	"object": "list",
	"data": [
		{
			"id": "deepseek-ai/DeepSeek-V3-0324-TEE",
			"object": "model",
			"created": 1749000000,
			"owned_by": "sglang",
			"chute_id": "aaaa-bbbb-cccc",
			"confidential_compute": true,
			"quantization": "fp16",
			"root": "deepseek-ai/DeepSeek-V3-0324",
			"context_length": 65536,
			"max_model_len": 65536,
			"max_output_length": 8192,
			"input_modalities": ["text"],
			"output_modalities": ["text"],
			"supported_features": ["chat"],
			"supported_sampling_parameters": ["temperature", "top_p"],
			"pricing": {"prompt": "0.0009", "completion": "0.0009"},
			"price": {"input": 0.0009, "output": 0.0009},
			"parent": null,
			"permission": []
		},
		{
			"id": "meta-llama/Llama-3.3-70B-Instruct",
			"object": "model",
			"created": 1749000000,
			"owned_by": "vllm",
			"chute_id": "dddd-eeee-ffff",
			"confidential_compute": false,
			"quantization": "fp16",
			"root": "meta-llama/Llama-3.3-70B-Instruct",
			"context_length": 131072,
			"max_model_len": 131072,
			"max_output_length": 4096,
			"input_modalities": ["text"],
			"output_modalities": ["text"],
			"supported_features": ["chat"],
			"supported_sampling_parameters": ["temperature"],
			"pricing": {"prompt": "0.0003", "completion": "0.0004"},
			"price": {"input": 0.0003, "output": 0.0004},
			"parent": null,
			"permission": []
		},
		{
			"id": "Qwen/Qwen3-235B-A22B-TEE",
			"object": "model",
			"created": 1749000000,
			"owned_by": "vllm",
			"chute_id": "1111-2222-3333",
			"confidential_compute": true,
			"quantization": "fp8",
			"root": "Qwen/Qwen3-235B-A22B",
			"context_length": 32768,
			"max_model_len": 32768,
			"max_output_length": 4096,
			"input_modalities": ["text"],
			"output_modalities": ["text"],
			"supported_features": ["chat"],
			"supported_sampling_parameters": ["temperature", "top_p"],
			"pricing": {"prompt": "0.0005", "completion": "0.0005"},
			"price": {"input": 0.0005, "output": 0.0005},
			"parent": null,
			"permission": []
		}
	]
}`

func TestModelLister_FiltersTEEModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-key" {
			t.Errorf("Authorization = %q, want %q", auth, "Bearer test-key")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(testChutesModelsJSON))
	}))
	defer srv.Close()

	lister := chutes.NewModelLister(srv.URL, "test-key", srv.Client())
	models, err := lister.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}

	if len(models) != 2 {
		t.Fatalf("got %d models, want 2 (only confidential_compute: true)", len(models))
	}

	// Verify correct models were kept.
	ids := make([]string, 0, len(models))
	for _, raw := range models {
		var entry struct {
			ID                  string `json:"id"`
			ConfidentialCompute bool   `json:"confidential_compute"`
			ContextLength       int    `json:"context_length"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			t.Fatalf("unmarshal model entry: %v", err)
		}
		if !entry.ConfidentialCompute {
			t.Errorf("model %q: confidential_compute = false, should have been filtered out", entry.ID)
		}
		ids = append(ids, entry.ID)
	}

	if ids[0] != "deepseek-ai/DeepSeek-V3-0324-TEE" {
		t.Errorf("first model = %q, want %q", ids[0], "deepseek-ai/DeepSeek-V3-0324-TEE")
	}
	if ids[1] != "Qwen/Qwen3-235B-A22B-TEE" {
		t.Errorf("second model = %q, want %q", ids[1], "Qwen/Qwen3-235B-A22B-TEE")
	}

	// Verify upstream fields are preserved (pricing, context_length).
	var first struct {
		Pricing struct {
			Prompt     string `json:"prompt"`
			Completion string `json:"completion"`
		} `json:"pricing"`
		ChuteID string `json:"chute_id"`
		OwnedBy string `json:"owned_by"`
	}
	if err := json.Unmarshal(models[0], &first); err != nil {
		t.Fatalf("unmarshal first pricing: %v", err)
	}
	if first.Pricing.Prompt != "0.0009" {
		t.Errorf("pricing.prompt = %q, want %q", first.Pricing.Prompt, "0.0009")
	}
	if first.ChuteID != "aaaa-bbbb-cccc" {
		t.Errorf("chute_id = %q, want %q", first.ChuteID, "aaaa-bbbb-cccc")
	}
	if first.OwnedBy != "sglang" {
		t.Errorf("owned_by = %q, want %q", first.OwnedBy, "sglang")
	}
}

func TestModelLister_AllNonTEE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[
			{"id":"plain-model","confidential_compute":false}
		]}`))
	}))
	defer srv.Close()

	lister := chutes.NewModelLister(srv.URL, "test-key", srv.Client())
	models, err := lister.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	if len(models) != 0 {
		t.Errorf("got %d models, want 0 (no TEE models)", len(models))
	}
}

func TestModelLister_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
	}))
	defer srv.Close()

	lister := chutes.NewModelLister(srv.URL, "test-key", srv.Client())
	models, err := lister.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	if len(models) != 0 {
		t.Errorf("got %d models, want 0", len(models))
	}
}

func TestModelLister_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"detail":"unauthorized"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	lister := chutes.NewModelLister(srv.URL, "bad-key", srv.Client())
	_, err := lister.ListModels(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP 401")
	}
	if !strings.Contains(err.Error(), "HTTP 401") {
		t.Errorf("error %q does not mention HTTP 401", err)
	}
}

func TestModelLister_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	lister := chutes.NewModelLister(srv.URL, "test-key", srv.Client())
	_, err := lister.ListModels(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("error %q does not mention unmarshal", err)
	}
}

func TestModelLister_MalformedEntry(t *testing.T) {
	// Per fail-closed policy: malformed entries must fail the entire response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[
			{"id":"good-model","confidential_compute":true},
			"not-an-object"
		]}`))
	}))
	defer srv.Close()

	lister := chutes.NewModelLister(srv.URL, "test-key", srv.Client())
	_, err := lister.ListModels(context.Background())
	if err == nil {
		t.Fatal("expected error for malformed model entry")
	}
	if !strings.Contains(err.Error(), "unmarshal model entry") {
		t.Errorf("error %q does not mention unmarshal model entry", err)
	}
}

func TestModelLister_CancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(testChutesModelsJSON))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	lister := chutes.NewModelLister(srv.URL, "test-key", srv.Client())
	_, err := lister.ListModels(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}
