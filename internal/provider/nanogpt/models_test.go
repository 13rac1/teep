package nanogpt_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/provider/nanogpt"
)

// modelsServer serves body as NanoGPT's /api/v1/models response and records
// the request path and Authorization header.
func modelsServer(t *testing.T, status int, body string) (srv *httptest.Server, path, auth *string) {
	t.Helper()
	var gotPath, gotAuth string
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &gotPath, &gotAuth
}

func TestModelLister_ListsOnlyTEEModels(t *testing.T) {
	body := `{"object":"list","data":[
		{"id":"TEE/qwen3.8-27b","object":"model","created":1787529600,"owned_by":"qwen"},
		{"id":"openai/gpt-5","object":"model","created":1787529600,"owned_by":"openai"},
		{"id":"Steelskull/L3.3-Electra-R1-70b","object":"model","created":1,"owned_by":"steelskull"},
		{"id":"TEE/gemma-4-26b-a4b-uncensored","object":"model","created":1787529601,"owned_by":"google"}
	]}`
	srv, path, auth := modelsServer(t, http.StatusOK, body)
	l := nanogpt.NewModelLister(srv.URL+"/api", "test-key", srv.Client())
	defer l.CloseIdleConnections()

	models, err := l.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	if *path != "/api/v1/models" || *auth != "Bearer test-key" {
		t.Fatalf("request path=%q auth=%q, want /api/v1/models with the bearer key", *path, *auth)
	}
	ids := make([]string, 0, len(models))
	for _, raw := range models {
		var e struct {
			ID      string `json:"id"`
			OwnedBy string `json:"owned_by"`
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.ID+"/"+e.OwnedBy)
	}
	if got := strings.Join(ids, ","); got != "TEE/qwen3.8-27b/qwen,TEE/gemma-4-26b-a4b-uncensored/google" {
		t.Fatalf("listed %q, want the two TEE models with their entries unchanged", got)
	}
}

func TestModelLister_FailsOnBadEntry(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"missing id", `{"data":[{"id":"","object":"model","created":1,"owned_by":"x"}]}`, "missing required id"},
		{"wrong type", `{"data":[{"id":7,"object":"model","created":1,"owned_by":"x"}]}`, "unmarshal entry"},
		{"not an object", `{"data":["TEE/qwen"]}`, "unmarshal entry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := modelsServer(t, http.StatusOK, tc.body)
			_, err := nanogpt.NewModelLister(srv.URL+"/api", "k", srv.Client()).ListModels(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestModelLister_HTTPError(t *testing.T) {
	srv, _, _ := modelsServer(t, http.StatusUnauthorized, `{"error":"bad key"}`)
	_, err := nanogpt.NewModelLister(srv.URL+"/api", "k", srv.Client()).ListModels(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("err = %v, want the HTTP 401 error", err)
	}
}
