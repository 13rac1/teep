package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
)

// Cold requests must share verification within a scope while independent
// providers and model scopes can verify concurrently. Warm requests reuse it.
func TestIntegration_ConcurrentProviders(t *testing.T) {
	if testing.Short() || os.Getenv("NEARAI_API_KEY") == "" || os.Getenv("TINFOIL_API_KEY") == "" {
		t.Skip("live concurrent providers require NEAR and Tinfoil credentials")
	}
	cfg := &config.Config{Providers: map[string]*config.Provider{
		"nearcloud":        {Name: "nearcloud", BaseURL: "https://cloud-api.near.ai", APIKey: os.Getenv("NEARAI_API_KEY"), E2EE: true},
		"neardirect":       {Name: "neardirect", BaseURL: "https://completions.near.ai", APIKey: os.Getenv("NEARAI_API_KEY"), E2EE: true},
		"tinfoil_v3_cloud": {Name: "tinfoil_v3_cloud", BaseURL: "https://inference.tinfoil.sh", APIKey: os.Getenv("TINFOIL_API_KEY"), E2EE: true},
	}}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	var started atomic.Int32
	release := make(chan struct{})
	beforeFetch := func(ctx context.Context) error {
		if started.Add(1) == 5 {
			close(release)
		}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	counts := make(map[string]*recoveryAttester)
	var routes []concurrentLiveRoute
	for _, name := range []string{"nearcloud", "neardirect", "tinfoil_v3_cloud"} {
		prov := s.providers[name]
		for _, model := range concurrentLiveModels(ctx, t, prov) {
			_, key, err := resolveRequestRoute(ctx, prov, model)
			if err != nil {
				t.Fatal(err)
			}
			routes = append(routes, concurrentLiveRoute{name: name, model: model, key: key})
		}
		counted := &recoveryAttester{Attester: prov.Attester, beforeFetch: beforeFetch}
		counts[name] = counted
		if routed, ok := prov.Attester.(provider.RouteAttester); ok {
			prov.Attester = &recoveryRouteAttester{recoveryAttester: counted, routed: routed}
		} else {
			prov.Attester = counted
		}
	}
	upstream := httptest.NewTLSServer(s)
	defer upstream.Close()
	for wave := range 2 {
		concurrentLiveWave(ctx, t, upstream, routes)
		for i := range routes {
			route := &routes[i]
			value, ok := s.authorizations.acquire(route.key)
			if !ok {
				t.Fatalf("%s model has no current authorization", route.name)
			}
			if value.report.Provider != route.name || value.report.Model != route.model || value.report.Blocked() {
				t.Fatal("concurrent client received an incorrect authorization report")
			}
			if wave == 0 {
				route.generation = value.generation
			} else if route.generation != value.generation {
				t.Errorf("%s unnecessarily replaced valid authorization", route.name)
			}
		}
		for name, count := range counts {
			want := int32(2)
			if name == "tinfoil_v3_cloud" {
				want = 1
			}
			if count.calls.Load() != want {
				t.Errorf("%s attestations=%d; want %d", name, count.calls.Load(), want)
			}
		}
	}
}

type concurrentLiveRoute struct {
	name, model string
	key         provider.AuthorizationKey
	generation  authorizationGeneration
}

func concurrentLiveModels(ctx context.Context, t *testing.T, prov *provider.Provider) []string {
	t.Helper()
	rawModels, err := prov.ModelLister.ListModels(ctx)
	if err != nil {
		t.Fatal("live model discovery failed")
	}
	var models []string
	for _, raw := range rawModels {
		var model struct {
			ID               string   `json:"id"`
			OutputModalities []string `json:"output_modalities"`
			Endpoints        []string `json:"endpoints"`
		}
		// Catalog metadata outside these selection fields is not used by this test.
		if _, _, err := jsonstrict.Unmarshal(raw, &model); err != nil {
			t.Fatal("invalid model metadata")
		}
		if model.ID != "" && (slices.Contains(model.OutputModalities, "text") || slices.Contains(model.Endpoints, "/v1/chat/completions")) {
			models = append(models, model.ID)
		}
	}
	if len(models) < 2 {
		t.Fatal("concurrent coverage requires two chat models per provider")
	}
	return models[:2]
}

func concurrentLiveWave(ctx context.Context, t *testing.T, server *httptest.Server, routes []concurrentLiveRoute) {
	t.Helper()
	var wg sync.WaitGroup
	for _, route := range routes {
		for _, stream := range []bool{false, true} {
			wg.Go(func() {
				transport := server.Client().Transport.(*http.Transport).Clone()
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport}
				if err := concurrentLiveChat(ctx, client, server.URL, &route, stream); err != nil {
					t.Error(err)
				}
			})
		}
	}
	wg.Wait()
}

func concurrentLiveChat(ctx context.Context, client *http.Client, origin string, route *concurrentLiveRoute, stream bool) error {
	body, err := json.Marshal(map[string]any{"model": route.name + ":" + route.model, "messages": []map[string]string{{"role": "user", "content": "Say hello"}}, "stream": stream, "max_tokens": 64})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s concurrent inference: %w", route.name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	response, err := io.ReadAll(io.LimitReader(resp.Body, (10<<20)+1))
	if err != nil {
		return fmt.Errorf("%s concurrent response read: %w", route.name, err)
	}
	if len(response) > 10<<20 || resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s concurrent inference failed: status=%d bytes=%d", route.name, resp.StatusCode, len(response))
	}
	return validateConcurrentLiveResponse(response, stream)
}

// Do not treat HTTP 200 with an SSE error or an incomplete stream as success.
func validateConcurrentLiveResponse(body []byte, stream bool) error {
	if !stream {
		_, err := validateConcurrentLiveChoices(body, true)
		return err
	}
	complete, choices := false, false
	for line := range bytes.SplitSeq(body, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		data := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if string(data) == "[DONE]" {
			complete = true
			continue
		}
		if complete {
			return errors.New("live stream has data after completion")
		}
		hasChoices, err := validateConcurrentLiveChoices(data, false)
		if err != nil {
			return err
		}
		choices = choices || hasChoices
	}
	if !complete || !choices {
		return errors.New("live stream did not complete")
	}
	return nil
}

func validateConcurrentLiveChoices(data []byte, required bool) (bool, error) {
	var response struct {
		Choices []json.RawMessage `json:"choices"`
		Error   json.RawMessage   `json:"error"`
	}
	// Ignore unrelated completion metadata, but reject errors and empty output.
	if _, _, err := jsonstrict.Unmarshal(data, &response); err != nil || (required && len(response.Choices) == 0) || (len(response.Error) != 0 && string(response.Error) != "null") {
		return false, errors.New("invalid live chat response; response content is not logged")
	}
	return len(response.Choices) != 0, nil
}
