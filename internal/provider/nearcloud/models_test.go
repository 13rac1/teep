package nearcloud_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

func TestModelLister_Delegation(t *testing.T) {
	const mockResponse = `{
		"object": "list",
		"data": [
			{"id": "test-model", "object": "model", "created": 1700000000, "owned_by": "near-ai", "context_length": 32768}
		]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("request: %s %s", r.Method, r.URL.Path)
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(mockResponse))
	}))
	defer srv.Close()

	inner := neardirect.NewModelLister(srv.URL, "test-key", srv.Client())
	lister := nearcloud.NewModelLister(inner)

	models, err := lister.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}

	t.Logf("got %d models", len(models))
	if len(models) != 1 {
		t.Fatalf("got %d models, want 1", len(models))
	}

	var entry struct {
		ID            string `json:"id"`
		Object        string `json:"object"`
		OwnedBy       string `json:"owned_by"`
		ContextLength int    `json:"context_length"`
	}
	if err := json.Unmarshal(models[0], &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	t.Logf("  id=%q object=%q owned_by=%q context_length=%d", entry.ID, entry.Object, entry.OwnedBy, entry.ContextLength)
	if entry.ID != "test-model" {
		t.Errorf("id = %q, want %q", entry.ID, "test-model")
	}
	if entry.ContextLength != 32768 {
		t.Errorf("context_length = %d, want 32768", entry.ContextLength)
	}
}
