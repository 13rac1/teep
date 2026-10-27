package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"testing"

	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// The proxy-aggregated model list includes NanoGPT's TEE models, with the
// provider prefix, and no other NanoGPT models.
func TestFetchModelsListsNanoGPTTEEModels(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/models" {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, `{"object":"list","data":[
				{"id":"TEE/qwen3.8-27b","object":"model","created":1,"owned_by":"qwen"},
				{"id":"openai/gpt-5","object":"model","created":1,"owned_by":"openai"}
			]}`)
		}))
		server, err := New(&config.Config{Providers: map[string]*config.Provider{
			"nanogpt": {Name: "nanogpt", BaseURL: upstream.URL + "/api", APIKey: "test-key"},
		}})
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()

		models := server.fetchModels()
		ids := make([]string, 0, len(models))
		for _, raw := range models {
			var e struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(raw, &e); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, e.ID)
		}
		if !slices.Equal(ids, []string{"nanogpt:TEE/qwen3.8-27b"}) {
			t.Fatalf("model ids = %v, want only the NanoGPT TEE model", ids)
		}
	})
}
