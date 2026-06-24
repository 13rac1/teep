package proxy_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	tinfoilProvider "github.com/13rac1/teep/internal/provider/tinfoil"
)

const (
	tinfoilDefaultChatModel       = "gemma4-31b"
	tinfoilDefaultVisionModel     = "kimi-k2-6"
	tinfoilDefaultEmbeddingsModel = "nomic-embed-text"
	tinfoilDefaultAudioModel      = "whisper-large-v3-turbo"
	tinfoilDefaultSpeechModel     = "qwen3-tts"
)

type tinfoilModelEntry struct {
	ID          string   `json:"id"`
	Object      string   `json:"object"`
	OwnedBy     string   `json:"owned_by"`
	Type        string   `json:"type"`
	Endpoints   []string `json:"endpoints"`
	Multimodal  bool     `json:"multimodal"`
	ToolCalling bool     `json:"tool_calling"`
	Reasoning   bool     `json:"reasoning"`
}

type tinfoilCatalog struct {
	provider string
	models   map[string]tinfoilModelEntry
}

type tinfoilPromptCacheRoute struct {
	key    string
	domain string
}

// skipTinfoilIntegration skips the test if TINFOIL_API_KEY is unset or if
// running under go test -short.
func skipTinfoilIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("TINFOIL_API_KEY") == "" {
		t.Skip("TINFOIL_API_KEY not set")
	}
}

// tinfoilIntegrationModel returns the cloud chat model to use, defaulting to
// gemma4-31b as listed by Tinfoil's live /v1/models catalog.
func tinfoilIntegrationModel() string {
	return tinfoilChatModel("tinfoil_v3_cloud")
}

// tinfoilDirectIntegrationModel returns the direct chat model to use,
// defaulting to gemma4-31b as listed by Tinfoil's live /v1/models catalog.
func tinfoilDirectIntegrationModel() string {
	return tinfoilChatModel("tinfoil_v3_direct")
}

func tinfoilChatModel(providerName string) string {
	if m := os.Getenv("TINFOIL_CHAT_MODEL"); m != "" {
		return tinfoilPrefixModel(providerName, m)
	}
	if providerName == "tinfoil_v3_direct" {
		if m := os.Getenv("TINFOIL_DIRECT_MODEL"); m != "" {
			return tinfoilPrefixModel(providerName, m)
		}
	}
	if m := os.Getenv("TINFOIL_E2EE_MODEL"); m != "" {
		return tinfoilPrefixModel(providerName, m)
	}
	return tinfoilPrefixModel(providerName, tinfoilDefaultChatModel)
}

func tinfoilVisionModel(providerName string) string {
	if m := os.Getenv("TINFOIL_VISION_MODEL"); m != "" {
		return tinfoilPrefixModel(providerName, m)
	}
	return tinfoilPrefixModel(providerName, tinfoilDefaultVisionModel)
}

func tinfoilEmbeddingsModel(providerName string) string {
	if m := os.Getenv("TINFOIL_EMBEDDINGS_MODEL"); m != "" {
		return tinfoilPrefixModel(providerName, m)
	}
	return tinfoilPrefixModel(providerName, tinfoilDefaultEmbeddingsModel)
}

func tinfoilAudioModel(providerName string) string {
	if m := os.Getenv("TINFOIL_AUDIO_MODEL"); m != "" {
		return tinfoilPrefixModel(providerName, m)
	}
	return tinfoilPrefixModel(providerName, tinfoilDefaultAudioModel)
}

func tinfoilSpeechModel(providerName string) string {
	if m := os.Getenv("TINFOIL_SPEECH_MODEL"); m != "" {
		return tinfoilPrefixModel(providerName, m)
	}
	return tinfoilPrefixModel(providerName, tinfoilDefaultSpeechModel)
}

func tinfoilPrefixModel(providerName, model string) string {
	for _, prefix := range []string{"tinfoil_v3_cloud:", "tinfoil_v3_direct:"} {
		model = strings.TrimPrefix(model, prefix)
	}
	return providerName + ":" + model
}

func tinfoilUpstreamModel(t *testing.T, providerName, model string) string {
	t.Helper()
	prefix := providerName + ":"
	if !strings.HasPrefix(model, prefix) {
		t.Fatalf("model %q does not have provider prefix %q", model, prefix)
	}
	return strings.TrimPrefix(model, prefix)
}

// integrationTinfoilPlaintextConfig returns a config pointing at the live
// Tinfoil API with E2EE disabled and Offline true.
func integrationTinfoilPlaintextConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Offline:    true,
		Providers: map[string]*config.Provider{
			"tinfoil_v3_cloud": {
				Name:    "tinfoil_v3_cloud",
				BaseURL: "https://inference.tinfoil.sh",
				APIKey:  os.Getenv("TINFOIL_API_KEY"),
				E2EE:    false,
			},
		},
		AllowFail: attestation.KnownFactors,
	}
}

// integrationTinfoilE2EEConfig returns a config pointing at the live Tinfoil
// API with E2EE enabled and Offline true.
func integrationTinfoilE2EEConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Offline:    true,
		Providers: map[string]*config.Provider{
			"tinfoil_v3_cloud": {
				Name:    "tinfoil_v3_cloud",
				BaseURL: "https://inference.tinfoil.sh",
				APIKey:  os.Getenv("TINFOIL_API_KEY"),
				E2EE:    true,
			},
		},
		AllowFail: attestation.KnownFactors,
	}
}

func integrationTinfoilDirectPlaintextConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Offline:    true,
		Providers: map[string]*config.Provider{
			"tinfoil_v3_direct": {
				Name:   "tinfoil_v3_direct",
				APIKey: os.Getenv("TINFOIL_API_KEY"),
				E2EE:   false,
			},
		},
		AllowFail: attestation.KnownFactors,
	}
}

func integrationTinfoilDirectE2EEConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Offline:    true,
		Providers: map[string]*config.Provider{
			"tinfoil_v3_direct": {
				Name:   "tinfoil_v3_direct",
				APIKey: os.Getenv("TINFOIL_API_KEY"),
				E2EE:   true,
			},
		},
		AllowFail: attestation.KnownFactors,
	}
}

func TestIntegration_Tinfoil(t *testing.T) {
	skipTinfoilIntegration(t)

	plainSrv := newProxyServer(t, integrationTinfoilPlaintextConfig(t))
	defer plainSrv.Close()
	e2eeSrv := newProxyServer(t, integrationTinfoilE2EEConfig(t))
	defer e2eeSrv.Close()

	catalog := fetchTinfoilCatalog(t, plainSrv.URL, "tinfoil_v3_cloud")
	runTinfoilAPISurface(t, "tinfoil_v3_cloud", catalog, plainSrv.URL, e2eeSrv.URL)

	t.Run("AttestationReport", func(t *testing.T) {
		assertTinfoilAttestationReport(t, integrationTinfoilE2EEConfig(t), tinfoilIntegrationModel(), "tinfoil_v3_cloud")
	})
}

func TestIntegration_TinfoilDirect(t *testing.T) {
	skipTinfoilIntegration(t)

	plainSrv := newProxyServer(t, integrationTinfoilDirectPlaintextConfig(t))
	defer plainSrv.Close()
	e2eeSrv := newProxyServer(t, integrationTinfoilDirectE2EEConfig(t))
	defer e2eeSrv.Close()

	catalog := fetchTinfoilCatalog(t, plainSrv.URL, "tinfoil_v3_direct")
	runTinfoilAPISurface(t, "tinfoil_v3_direct", catalog, plainSrv.URL, e2eeSrv.URL)

	t.Run("AttestationReport", func(t *testing.T) {
		assertTinfoilAttestationReport(t, integrationTinfoilDirectE2EEConfig(t), tinfoilDirectIntegrationModel(), "tinfoil_v3_direct")
	})
	t.Run("PromptCacheKeyRouting", func(t *testing.T) {
		model := requireTinfoilModelEndpoint(t, catalog, tinfoilDirectIntegrationModel(), "/v1/chat/completions")
		assertTinfoilDirectPromptCacheKeyRouting(t, e2eeSrv.URL, model)
	})
}

func runTinfoilAPISurface(t *testing.T, providerName string, catalog tinfoilCatalog, plainURL, e2eeURL string) {
	t.Helper()

	chatModel := requireTinfoilModelEndpoint(t, catalog, tinfoilChatModel(providerName), "/v1/chat/completions")
	visionModel := requireTinfoilMultimodalModel(t, catalog, tinfoilVisionModel(providerName), "/v1/chat/completions")
	responsesModel := requireTinfoilModelEndpoint(t, catalog, tinfoilChatModel(providerName), "/v1/responses")
	embeddingsModel := requireTinfoilModelEndpoint(t, catalog, tinfoilEmbeddingsModel(providerName), "/v1/embeddings")
	audioModel := requireTinfoilModelEndpoint(t, catalog, tinfoilAudioModel(providerName), "/v1/audio/transcriptions")
	speechModel := requireTinfoilModelEndpoint(t, catalog, tinfoilSpeechModel(providerName), "/v1/audio/speech")

	t.Run("Models", func(t *testing.T) {
		assertTinfoilCatalog(t, catalog, []string{
			tinfoilDefaultChatModel,
			tinfoilDefaultVisionModel,
			tinfoilDefaultEmbeddingsModel,
			tinfoilDefaultAudioModel,
			tinfoilDefaultSpeechModel,
		})
	})
	t.Run("ChatNonStream", func(t *testing.T) {
		resp := postChatIntegration(t, plainURL, chatModel, false)
		defer resp.Body.Close()
		assertNonStreamResponse(t, resp)
	})
	t.Run("ChatStreaming", func(t *testing.T) {
		resp := postChatIntegration(t, plainURL, chatModel, true)
		defer resp.Body.Close()
		assertStreamResponse(t, resp)
	})
	t.Run("ChatE2EENonStream", func(t *testing.T) {
		resp := postChatIntegration(t, e2eeURL, chatModel, false)
		defer resp.Body.Close()
		assertNonStreamResponse(t, resp)
	})
	t.Run("ChatE2EEStreaming", func(t *testing.T) {
		resp := postChatIntegration(t, e2eeURL, chatModel, true)
		defer resp.Body.Close()
		assertStreamResponse(t, resp)
	})
	t.Run("ChatE2EENonStreamWithTools", func(t *testing.T) {
		resp := postChatWithTools(t, e2eeURL, chatModel, false)
		defer resp.Body.Close()
		if !assertNonStreamToolCallLeaves(t, resp, providerName) {
			t.Fatal("expected at least one tool call in Tinfoil tools integration test")
		}
	})
	t.Run("VisionKimi", func(t *testing.T) {
		resp := postTinfoilVisionChat(t, plainURL, visionModel, false)
		defer resp.Body.Close()
		assertChatShapeResponse(t, resp, false)
	})
	t.Run("VisionKimiE2EE", func(t *testing.T) {
		resp := postTinfoilVisionChat(t, e2eeURL, visionModel, true)
		defer resp.Body.Close()
		assertChatShapeResponse(t, resp, true)
	})
	t.Run("ResponsesNonStream", func(t *testing.T) {
		resp := postTinfoilResponses(t, plainURL, responsesModel, false)
		defer resp.Body.Close()
		assertResponsesResponse(t, resp, false)
	})
	t.Run("ResponsesStreaming", func(t *testing.T) {
		resp := postTinfoilResponses(t, plainURL, responsesModel, true)
		defer resp.Body.Close()
		assertResponsesResponse(t, resp, true)
	})
	t.Run("ResponsesE2EENonStream", func(t *testing.T) {
		resp := postTinfoilResponses(t, e2eeURL, responsesModel, false)
		defer resp.Body.Close()
		assertResponsesResponse(t, resp, false)
	})
	t.Run("ResponsesE2EEStreaming", func(t *testing.T) {
		resp := postTinfoilResponses(t, e2eeURL, responsesModel, true)
		defer resp.Body.Close()
		assertResponsesResponse(t, resp, true)
	})
	t.Run("Embeddings", func(t *testing.T) {
		resp := postTinfoilEmbeddings(t, plainURL, embeddingsModel)
		defer resp.Body.Close()
		assertTinfoilEmbeddingsResponse(t, resp)
	})
	t.Run("EmbeddingsE2EE", func(t *testing.T) {
		resp := postTinfoilEmbeddings(t, e2eeURL, embeddingsModel)
		defer resp.Body.Close()
		assertTinfoilEmbeddingsResponse(t, resp)
	})
	t.Run("AudioTranscriptions", func(t *testing.T) {
		resp := postTinfoilAudioTranscription(t, plainURL, audioModel)
		defer resp.Body.Close()
		assertAudioHTTPResponse(t, resp)
	})
	t.Run("AudioTranscriptionsE2EEFailClosed", func(t *testing.T) {
		resp := postTinfoilAudioTranscription(t, e2eeURL, audioModel)
		defer resp.Body.Close()
		assertAudioE2EEFailClosed(t, resp)
	})
	t.Run("Speech", func(t *testing.T) {
		resp := postTinfoilSpeech(t, plainURL, speechModel)
		defer resp.Body.Close()
		assertSpeechResponse(t, resp)
	})
	t.Run("SpeechE2EE", func(t *testing.T) {
		resp := postTinfoilSpeech(t, e2eeURL, speechModel)
		defer resp.Body.Close()
		assertSpeechResponse(t, resp)
	})
	t.Run("UnsupportedEndpointsFailClosed", func(t *testing.T) {
		assertTinfoilUnsupportedEndpoints(t, plainURL, chatModel)
	})
}

func fetchTinfoilCatalog(t *testing.T, proxyURL, providerName string) tinfoilCatalog {
	t.Helper()
	resp, err := integrationClient.Get(proxyURL + "/v1/models")
	if err != nil {
		t.Fatalf("GET /v1/models: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	var result struct {
		Object string              `json:"object"`
		Data   []tinfoilModelEntry `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode /v1/models: %v", err)
	}
	if result.Object != "list" {
		t.Fatalf("object = %q, want list", result.Object)
	}
	if len(result.Data) == 0 {
		t.Fatal("/v1/models returned no Tinfoil models")
	}

	prefix := providerName + ":"
	catalog := tinfoilCatalog{provider: providerName, models: make(map[string]tinfoilModelEntry, len(result.Data))}
	for _, m := range result.Data {
		if !strings.HasPrefix(m.ID, prefix) {
			t.Fatalf("model id = %q, want %s prefix", m.ID, prefix)
		}
		if m.OwnedBy != "tinfoil" {
			t.Fatalf("model %q owned_by = %q, want tinfoil", m.ID, m.OwnedBy)
		}
		upstreamID := strings.TrimPrefix(m.ID, prefix)
		m.ID = upstreamID
		catalog.models[upstreamID] = m
	}
	return catalog
}

func assertTinfoilCatalog(t *testing.T, catalog tinfoilCatalog, required []string) {
	t.Helper()
	for _, id := range required {
		if _, ok := catalog.models[id]; !ok {
			t.Fatalf("Tinfoil /v1/models missing required model %q", id)
		}
	}
	for id, m := range catalog.models {
		if id == "" {
			t.Fatal("Tinfoil /v1/models returned empty model id")
		}
		if m.Object != "" && m.Object != "model" {
			t.Fatalf("model %q object = %q, want model", id, m.Object)
		}
		if len(m.Endpoints) == 0 {
			t.Fatalf("model %q has no endpoints", id)
		}
	}
	t.Logf("Tinfoil %s catalog contains %d models", catalog.provider, len(catalog.models))
}

func requireTinfoilModelEndpoint(t *testing.T, catalog tinfoilCatalog, model, endpoint string) string {
	t.Helper()
	upstream := tinfoilUpstreamModel(t, catalog.provider, model)
	entry, ok := catalog.models[upstream]
	if !ok {
		t.Fatalf("model %q not found in Tinfoil /v1/models catalog", upstream)
	}
	if !stringInSlice(endpoint, entry.Endpoints) {
		t.Fatalf("model %q endpoints = %v, want %s", upstream, entry.Endpoints, endpoint)
	}
	return model
}

func requireTinfoilMultimodalModel(t *testing.T, catalog tinfoilCatalog, model, endpoint string) string {
	t.Helper()
	model = requireTinfoilModelEndpoint(t, catalog, model, endpoint)
	upstream := tinfoilUpstreamModel(t, catalog.provider, model)
	if !catalog.models[upstream].Multimodal {
		t.Fatalf("model %q is not marked multimodal in Tinfoil /v1/models", upstream)
	}
	return model
}

func stringInSlice(needle string, haystack []string) bool {
	return slices.Contains(haystack, needle)
}

func postTinfoilVisionChat(t *testing.T, proxyURL, model string, stream bool) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{
		"model": %q,
		"messages": [{
			"role": "user",
			"content": [
				{"type": "text", "text": "What color is this image? Answer in one word."},
				{"type": "image_url", "image_url": {"url": "data:image/png;base64,%s"}}
			]
		}],
		"stream": %v,
		"max_tokens": 50
	}`, model, testPNG(), stream)
	resp, err := integrationPostJSON(t, proxyURL+"/v1/chat/completions", body)
	if err != nil {
		t.Fatalf("POST vision chat: %v", err)
	}
	return resp
}

func postTinfoilChatWithPromptCacheKey(t *testing.T, proxyURL, model, promptCacheKey string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{
		"model": %q,
		"messages": [{"role": "user", "content": %q}],
		"prompt_cache_key": %q,
		"stream": false,
		"max_tokens": 16
	}`, model, integrationPrompt, promptCacheKey)
	resp, err := integrationPostJSON(t, proxyURL+"/v1/chat/completions", body)
	if err != nil {
		t.Fatalf("POST chat with prompt_cache_key: %v", err)
	}
	return resp
}

func postTinfoilResponses(t *testing.T, proxyURL, model string, stream bool) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"model":%q,"input":%q,"stream":%v,"max_output_tokens":32}`, model, integrationPrompt, stream)
	resp, err := integrationPostJSON(t, proxyURL+"/v1/responses", body)
	if err != nil {
		t.Fatalf("POST responses: %v", err)
	}
	return resp
}

func postTinfoilEmbeddings(t *testing.T, proxyURL, model string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"model":%q,"input":"hello world"}`, model)
	resp, err := integrationPostJSON(t, proxyURL+"/v1/embeddings", body)
	if err != nil {
		t.Fatalf("POST embeddings: %v", err)
	}
	return resp
}

func postTinfoilAudioTranscription(t *testing.T, proxyURL, model string) *http.Response {
	t.Helper()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("model", model); err != nil {
		t.Fatalf("write model field: %v", err)
	}
	fw, err := mw.CreateFormFile("file", "test.wav")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write(makeMinimalWAV()); err != nil {
		t.Fatalf("write wav data: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	resp, err := integrationClient.Post(proxyURL+"/v1/audio/transcriptions", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatalf("POST audio transcription: %v", err)
	}
	return resp
}

func postTinfoilSpeech(t *testing.T, proxyURL, model string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"model":%q,"input":"Hello from Teep.","voice":"serena","response_format":"mp3"}`, model)
	resp, err := integrationPostJSON(t, proxyURL+"/v1/audio/speech", body)
	if err != nil {
		t.Fatalf("POST speech: %v", err)
	}
	return resp
}

func assertChatShapeResponse(t *testing.T, resp *http.Response, stream bool) {
	t.Helper()
	if stream {
		assertChatShapeStreamResponse(t, resp)
		return
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read chat body: %v", err)
	}
	var parsed struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Choices []struct {
			Index   int `json:"index"`
			Message any `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("decode chat body: %v; body=%s", err, body)
	}
	if len(parsed.Choices) == 0 {
		t.Fatalf("chat response has no choices: %s", body)
	}
	t.Logf("chat response id=%q object=%q choices=%d", parsed.ID, parsed.Object, len(parsed.Choices))
}

func assertChatShapeStreamResponse(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	chunks := readSSEChunks(t, resp.Body)
	if len(chunks) == 0 {
		t.Fatal("no chat SSE chunks received")
	}
	for _, chunk := range chunks {
		var parsed struct {
			Choices []struct {
				Index int `json:"index"`
				Delta any `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(chunk), &parsed); err != nil {
			t.Fatalf("decode chat SSE chunk: %v; chunk=%s", err, chunk)
		}
	}
	t.Logf("chat stream chunks: %d", len(chunks))
}

func assertResponsesResponse(t *testing.T, resp *http.Response, stream bool) {
	t.Helper()
	if stream {
		assertResponsesStreamResponse(t, resp)
		return
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read responses body: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("decode responses body: %v; body=%s", err, body)
	}
	if parsed["id"] == "" && parsed["output"] == nil && parsed["output_text"] == nil {
		t.Fatalf("responses body missing id/output fields: %s", body)
	}
	t.Logf("responses body: %s", diagnosticBodySnippet(body))
}

func assertResponsesStreamResponse(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	chunks := readSSEChunks(t, resp.Body)
	if len(chunks) == 0 {
		t.Fatal("no responses SSE chunks received")
	}
	for _, chunk := range chunks {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(chunk), &parsed); err != nil {
			t.Fatalf("decode responses SSE chunk: %v; chunk=%s", err, chunk)
		}
	}
	t.Logf("responses stream chunks: %d", len(chunks))
}

func assertTinfoilEmbeddingsResponse(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read embeddings body: %v", err)
	}
	var parsed struct {
		Object string `json:"object"`
		Data   []struct {
			Object    string    `json:"object"`
			Embedding []float64 `json:"embedding"`
			Index     int       `json:"index"`
		} `json:"data"`
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("decode embeddings body: %v; body=%s", err, body)
	}
	if len(parsed.Data) == 0 {
		t.Fatal("embeddings response has no data")
	}
	if len(parsed.Data[0].Embedding) == 0 {
		t.Fatal("embeddings response first vector is empty")
	}
	t.Logf("embedding model=%s dims=%d", parsed.Model, len(parsed.Data[0].Embedding))
}

func assertAudioHTTPResponse(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read audio body: %v", err)
	}
	assertAudioResponse(t, body)
}

func assertAudioE2EEFailClosed(t *testing.T, resp *http.Response) {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read audio E2EE body: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "audio transcription requires TLS-level E2EE") {
		t.Fatalf("body = %q, want fail-closed E2EE diagnostic", diagnosticBodySnippet(body))
	}
}

func assertSpeechResponse(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read speech body: %v", err)
	}
	if len(body) < 32 {
		t.Fatalf("speech response too short: %d bytes", len(body))
	}
	t.Logf("speech response content-type=%q bytes=%d", resp.Header.Get("Content-Type"), len(body))
}

func assertTinfoilUnsupportedEndpoints(t *testing.T, proxyURL, model string) {
	t.Helper()
	assertUnsupportedEndpoint(t, proxyURL+"/v1/images/generations", fmt.Sprintf(`{"model":%q,"prompt":"a red square"}`, model), "image generation")
	assertUnsupportedEndpoint(t, proxyURL+"/v1/rerank", fmt.Sprintf(`{"model":%q,"query":"x","documents":["x"]}`, model), "reranking")
	assertUnsupportedEndpoint(t, proxyURL+"/v1/score", fmt.Sprintf(`{"model":%q,"text_1":"x","text_2":"y"}`, model), "score")
}

func assertUnsupportedEndpoint(t *testing.T, endpointURL, body, want string) {
	t.Helper()
	resp, err := integrationPostJSON(t, endpointURL, body)
	if err != nil {
		t.Fatalf("POST unsupported endpoint: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read unsupported endpoint body: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, respBody)
	}
	if !strings.Contains(string(respBody), want) {
		t.Fatalf("body = %q, want diagnostic containing %q", diagnosticBodySnippet(respBody), want)
	}
}

func assertTinfoilDirectPromptCacheKeyRouting(t *testing.T, proxyURL, model string) {
	t.Helper()

	upstreamModel := tinfoilUpstreamModel(t, "tinfoil_v3_direct", model)
	domains := fetchTinfoilDirectReportDomains(t, upstreamModel)
	firstRoute, secondRoute := tinfoilDistinctPromptCacheRoutes(t, domains)

	assertTinfoilPromptCacheKeyRequest(t, proxyURL, model, upstreamModel, firstRoute.key, firstRoute.domain)
	assertTinfoilPromptCacheKeyRequest(t, proxyURL, model, upstreamModel, secondRoute.key, secondRoute.domain)
	t.Logf("prompt_cache_key routing exercised %q -> %s and %q -> %s",
		firstRoute.key, firstRoute.domain, secondRoute.key, secondRoute.domain)
}

func assertTinfoilPromptCacheKeyRequest(t *testing.T, proxyURL, model, upstreamModel, promptCacheKey, domain string) {
	t.Helper()

	resp := postTinfoilChatWithPromptCacheKey(t, proxyURL, model, promptCacheKey)
	defer resp.Body.Close()
	assertChatShapeResponse(t, resp, false)

	assertTinfoilReportCached(t, proxyURL, "tinfoil_v3_direct", upstreamModel+"@"+domain)
}

func tinfoilDistinctPromptCacheRoutes(t *testing.T, domains []string) (firstRoute, secondRoute tinfoilPromptCacheRoute) {
	t.Helper()
	if len(domains) < 2 {
		t.Fatalf("direct prompt_cache_key integration requires at least two live domains, got %d: %v", len(domains), domains)
	}

	mapping := tinfoilProvider.ModelMapping{Domains: domains}
	firstKey := "teep-integration-prompt-cache-key-0"
	firstDomain := mapping.SelectDomain(firstKey)
	firstRoute = tinfoilPromptCacheRoute{key: firstKey, domain: firstDomain}
	for i := 1; i < 512; i++ {
		key := fmt.Sprintf("teep-integration-prompt-cache-key-%d", i)
		domain := mapping.SelectDomain(key)
		if domain != "" && domain != firstDomain {
			return firstRoute, tinfoilPromptCacheRoute{key: key, domain: domain}
		}
	}
	t.Fatalf("could not find two prompt_cache_key values selecting distinct domains from %v", domains)
	return tinfoilPromptCacheRoute{}, tinfoilPromptCacheRoute{}
}

func assertTinfoilReportCached(t *testing.T, proxyURL, providerName, reportModel string) {
	t.Helper()

	reportURL := fmt.Sprintf("%s/v1/tee/report?provider=%s&model=%s",
		proxyURL, url.QueryEscape(providerName), url.QueryEscape(reportModel))
	reportResp, err := integrationClient.Get(reportURL)
	if err != nil {
		t.Fatalf("GET cached report: %v", err)
	}
	defer reportResp.Body.Close()

	if reportResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(reportResp.Body)
		t.Fatalf("cached report status = %d, want 200 for model %q; body=%s", reportResp.StatusCode, reportModel, body)
	}
}

func tinfoilMustPassFactors() []string {
	return []string{
		"nonce_match",
		"tee_quote_present",
		"tee_quote_structure",
		"tee_cert_chain",
		"tee_quote_signature",
		"tee_debug_disabled",
		"tee_reportdata_binding",
		"tee_hardware_config",
		"tee_tcb_current",
		"tee_tcb_not_revoked",
		"signing_key_present",
		"e2ee_capable",
		"tls_key_binding",
		"e2ee_usable",
	}
}

func assertTinfoilAttestationReport(t *testing.T, cfg *config.Config, model, providerName string) {
	t.Helper()

	cfg.Offline = false
	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	_, upstreamModel, _ := strings.Cut(model, ":")
	reportModel := tinfoilReportCacheModel(t, providerName, upstreamModel)

	// First chat request triggers attestation and populates the report cache.
	chatResp := postChatIntegration(t, proxySrv.URL, model, true)
	io.Copy(io.Discard, chatResp.Body)
	chatResp.Body.Close()

	reportURL := fmt.Sprintf("%s/v1/tee/report?provider=%s&model=%s",
		proxySrv.URL, url.QueryEscape(providerName), url.QueryEscape(reportModel))
	reportResp, err := integrationClient.Get(reportURL)
	if err != nil {
		t.Fatalf("GET report: %v", err)
	}
	defer reportResp.Body.Close()

	if reportResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(reportResp.Body)
		t.Fatalf("status = %d, want 200; body=%s", reportResp.StatusCode, body)
	}

	var report attestation.VerificationReport
	if err := json.NewDecoder(reportResp.Body).Decode(&report); err != nil {
		t.Fatalf("decode report: %v", err)
	}

	for _, name := range tinfoilMustPassFactors() {
		f, ok := findFactor(report.Factors, name)
		if !ok {
			t.Errorf("factor %q not found in report", name)
			continue
		}
		if f.Status != attestation.Pass {
			t.Errorf("factor %q: status = %v, want Pass; detail: %s", name, f.Status, f.Detail)
		}
	}
}

func tinfoilReportCacheModel(t *testing.T, providerName, upstreamModel string) string {
	t.Helper()
	if providerName != "tinfoil_v3_direct" {
		return upstreamModel
	}
	return upstreamModel + "@" + fetchTinfoilDirectReportDomain(t, upstreamModel)
}

func fetchTinfoilDirectReportDomain(t *testing.T, upstreamModel string) string {
	t.Helper()
	return fetchTinfoilDirectReportDomains(t, upstreamModel)[0]
}

func fetchTinfoilDirectReportDomains(t *testing.T, upstreamModel string) []string {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, "https://inference.tinfoil.sh/.well-known/tinfoil-proxy", http.NoBody)
	if err != nil {
		t.Fatalf("build Tinfoil proxy discovery request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("TINFOIL_API_KEY"))

	resp, err := integrationClient.Do(req)
	if err != nil {
		t.Fatalf("GET Tinfoil proxy discovery: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		t.Fatalf("read Tinfoil proxy discovery: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Tinfoil proxy discovery status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	var parsed struct {
		Models map[string]struct {
			Enclaves map[string]json.RawMessage `json:"enclaves"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("decode Tinfoil proxy discovery: %v", err)
	}
	entry, ok := parsed.Models[upstreamModel]
	if !ok {
		t.Fatalf("model %q not found in Tinfoil proxy discovery", upstreamModel)
	}
	domains := make([]string, 0, len(entry.Enclaves))
	for domain := range entry.Enclaves {
		if isTinfoilIntegrationBackendDomain(domain) {
			domains = append(domains, domain)
		}
	}
	sort.Strings(domains)
	if len(domains) == 0 {
		t.Fatalf("model %q has no valid Tinfoil proxy discovery domains", upstreamModel)
	}
	return domains
}

func isTinfoilIntegrationBackendDomain(domain string) bool {
	lower := strings.ToLower(domain)
	if !strings.HasSuffix(lower, ".tinfoil.sh") && !strings.HasSuffix(lower, ".tinfoil.containers.tinfoil.dev") {
		return false
	}
	for _, c := range domain {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}
