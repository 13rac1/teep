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
			"pricing": {"prompt": "0.00059", "completion": "0.00079"},
			"context_length": 32768,
			"architecture": {"tokenizer": "Qwen/Qwen2.5-72B-Instruct", "instruct_type": "chatml"}
		},
		{
			"id": "llama-3.3-70b-instruct",
			"object": "model",
			"created": 1733961600,
			"owned_by": "near-ai",
			"pricing": {"prompt": "0.00035", "completion": "0.0004"},
			"context_length": 131072,
			"architecture": {"tokenizer": "meta-llama/Llama-3.3-70B-Instruct", "instruct_type": "llama3"}
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
