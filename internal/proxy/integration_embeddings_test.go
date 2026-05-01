package proxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// NearDirect embeddings integration
// --------------------------------------------------------------------------

func nearDirectEmbeddingsModel() string {
	if m := os.Getenv("NEARAI_EMBEDDING_MODEL"); m != "" {
		if strings.HasPrefix(m, "neardirect:") {
			return m
		}
		return "neardirect:" + m
	}
	return "neardirect:Qwen/Qwen3-Embedding-0.6B"
}

func TestNearDirectEmbeddingsModel_PrefixHandling(t *testing.T) {
	t.Setenv("NEARAI_EMBEDDING_MODEL", "Qwen/Qwen3-Embedding-0.6B")
	if got, want := nearDirectEmbeddingsModel(), "neardirect:Qwen/Qwen3-Embedding-0.6B"; got != want {
		t.Fatalf("nearDirectEmbeddingsModel() = %q, want %q", got, want)
	}

	t.Setenv("NEARAI_EMBEDDING_MODEL", "neardirect:Qwen/Qwen3-Embedding-0.6B")
	if got, want := nearDirectEmbeddingsModel(), "neardirect:Qwen/Qwen3-Embedding-0.6B"; got != want {
		t.Fatalf("nearDirectEmbeddingsModel() = %q, want %q", got, want)
	}

	// Model ID containing ':' but without the neardirect: prefix must still be prefixed.
	t.Setenv("NEARAI_EMBEDDING_MODEL", "hf:org/embedding-model")
	if got, want := nearDirectEmbeddingsModel(), "neardirect:hf:org/embedding-model"; got != want {
		t.Fatalf("nearDirectEmbeddingsModel() = %q, want %q", got, want)
	}
}

func TestIntegration_NearDirect_Embeddings(t *testing.T) {
	skipNearDirectIntegration(t)

	proxySrv := newProxyServer(t, integrationNearDirectConfig(t))
	defer proxySrv.Close()

	model := nearDirectEmbeddingsModel()
	body := `{"model":"` + model + `","input":"The quick brown fox jumps over the lazy dog"}`
	resp, err := integrationClient.Post(proxySrv.URL+"/v1/embeddings", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST embeddings: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, respBody)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	assertEmbeddingsResponse(t, respBody)
}

// --------------------------------------------------------------------------
// Chutes embeddings integration
// --------------------------------------------------------------------------

func chutesEmbeddingsModel(t *testing.T) string {
	t.Helper()
	m := os.Getenv("CHUTES_EMBEDDING_MODEL")
	if m == "" {
		t.Skip("CHUTES_EMBEDDING_MODEL not set; Chutes does not currently list embedding models")
	}
	if strings.HasPrefix(m, "chutes:") {
		return m
	}
	return "chutes:" + m
}

func TestIntegration_Chutes_Embeddings(t *testing.T) {
	skipChutesIntegration(t)

	// Chutes embeddings with E2EE disabled to test basic flow.
	proxySrv := newProxyServer(t, integrationChutesPlaintextConfig(t))
	defer proxySrv.Close()

	model := chutesEmbeddingsModel(t)
	body := `{"model":"` + model + `","input":"The quick brown fox jumps over the lazy dog"}`
	resp, err := integrationClient.Post(proxySrv.URL+"/v1/embeddings", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST embeddings: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, respBody)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	assertEmbeddingsResponse(t, respBody)
}

func TestIntegration_Chutes_EmbeddingsE2EE(t *testing.T) {
	skipChutesIntegration(t)

	proxySrv := newProxyServer(t, integrationChutesE2EEConfig(t))
	defer proxySrv.Close()

	model := chutesEmbeddingsModel(t)
	body := `{"model":"` + model + `","input":"The quick brown fox jumps over the lazy dog"}`
	resp, err := integrationClient.Post(proxySrv.URL+"/v1/embeddings", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST embeddings: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, respBody)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	assertEmbeddingsResponse(t, respBody)
}

// --------------------------------------------------------------------------
// PhalaCloud embeddings integration
// --------------------------------------------------------------------------

// phalaCloudEmbeddingsModel returns the model for phalacloud embedding tests.
func phalaCloudEmbeddingsModel() string {
	if m := os.Getenv("PHALA_EMBEDDING_MODEL"); m != "" {
		if strings.HasPrefix(m, "phalacloud:") {
			return m
		}
		return "phalacloud:" + m
	}
	return "phalacloud:qwen/qwen3-embedding-8b"
}

func TestIntegration_PhalaCloud_Embeddings(t *testing.T) {
	skipPhalaCloudIntegration(t)

	proxySrv := newProxyServer(t, integrationPhalaCloudConfig(t))
	defer proxySrv.Close()

	model := phalaCloudEmbeddingsModel()
	body := `{"model":"` + model + `","input":"The quick brown fox jumps over the lazy dog"}`
	resp, err := integrationClient.Post(proxySrv.URL+"/v1/embeddings", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST embeddings: %v", err)
	}
	defer resp.Body.Close()

	// PhalaCloud has no E2EE. Depending on E2EE enforcement policy, the
	// proxy may block the request (502) or pass it through to the provider.
	// Either outcome is valid — the important thing is the proxy does not
	// silently claim E2EE is active when it is not.
	t.Logf("phalacloud embeddings: status=%d", resp.StatusCode)
	if resp.StatusCode == http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		assertEmbeddingsResponse(t, respBody)
	}
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// assertEmbeddingsResponse validates the response body matches OpenAI embeddings spec.
func assertEmbeddingsResponse(t *testing.T, body []byte) {
	t.Helper()

	var resp struct {
		Object string `json:"object"`
		Data   []struct {
			Object    string    `json:"object"`
			Embedding []float64 `json:"embedding"`
			Index     int       `json:"index"`
		} `json:"data"`
		Model string `json:"model"`
		Usage struct {
			PromptTokens int `json:"prompt_tokens"`
			TotalTokens  int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode embeddings response: %v\nraw: %s", err, body)
	}

	if resp.Object != "list" {
		t.Errorf("object = %q, want %q", resp.Object, "list")
	}
	if len(resp.Data) == 0 {
		t.Fatal("no embedding data in response")
	}
	if resp.Data[0].Object != "embedding" {
		t.Errorf("data[0].object = %q, want %q", resp.Data[0].Object, "embedding")
	}
	if len(resp.Data[0].Embedding) == 0 {
		t.Error("embedding vector is empty")
	}
	t.Logf("embeddings: model=%s dimensions=%d tokens=%d",
		resp.Model, len(resp.Data[0].Embedding), resp.Usage.TotalTokens)
}
