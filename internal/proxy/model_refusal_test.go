package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/config"
)

func TestInvalidNearModelsLogRefusal(t *testing.T) {
	for _, name := range []string{"nearcloud", "neardirect"} {
		t.Run(name, func(t *testing.T) {
			server, err := New(&config.Config{Providers: map[string]*config.Provider{
				name: {Name: name, BaseURL: "https://completions.near.ai", APIKey: "private-test-key", E2EE: true},
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			for _, path := range []string{"/v1/chat/completions", "/explore/infer", "/explore/attest"} {
				body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"private-test-content"}]}`, name+":invalid\nmodel")
				if strings.HasPrefix(path, "/explore/") {
					body = fmt.Sprintf(`{"model":%q}`, name+":invalid\nmodel")
				}
				request := httptest.NewRequest(http.MethodPost, "https://proxy.test"+path, strings.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				logs := captureSlogWithLevel(t, slog.LevelWarn, func() { server.ServeHTTP(response, request) })
				wantStatus := http.StatusBadRequest
				if path == "/explore/infer" {
					wantStatus = http.StatusOK
				}
				if response.Code != wantStatus || !strings.Contains(response.Body.String(), "invalid_model") {
					t.Fatalf("%s: status=%d body=%s", path, response.Code, response.Body.String())
				}
				for _, want := range []string{"level=WARN", "inference blocked", "action=validate_model", "provider=" + name, "status=400"} {
					if !strings.Contains(logs, want) {
						t.Fatalf("%s: missing %q in %s", path, want, logs)
					}
				}
				if strings.Contains(logs, "private-test") || strings.Contains(logs, "invalid\\nmodel") {
					t.Fatal("refusal logged private content or the malformed model")
				}
			}
		})
	}
}
