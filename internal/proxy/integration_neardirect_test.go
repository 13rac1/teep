package proxy_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
)

// skipNearDirectIntegration skips the test if NEARAI_API_KEY is unset or if
// running under go test -short.
func skipNearDirectIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("NEARAI_API_KEY") == "" {
		t.Skip("NEARAI_API_KEY not set")
	}
}

// nearDirectIntegrationModel returns the NEAR AI model to use, defaulting to a
// known-good model if NEARAI_E2EE_MODEL is unset.
func nearDirectIntegrationModel() string {
	if m := os.Getenv("NEARAI_E2EE_MODEL"); m != "" {
		if strings.HasPrefix(m, "neardirect:") {
			return m
		}
		return "neardirect:" + m
	}
	return "neardirect:Qwen/Qwen3.5-122B-A10B"
}

func TestNearDirectIntegrationModel_PrefixHandling(t *testing.T) {
	t.Setenv("NEARAI_E2EE_MODEL", "Qwen/Qwen3.5-122B-A10B")
	if got, want := nearDirectIntegrationModel(), "neardirect:Qwen/Qwen3.5-122B-A10B"; got != want {
		t.Fatalf("nearDirectIntegrationModel() = %q, want %q", got, want)
	}

	t.Setenv("NEARAI_E2EE_MODEL", "neardirect:Qwen/Qwen3.5-122B-A10B")
	if got, want := nearDirectIntegrationModel(), "neardirect:Qwen/Qwen3.5-122B-A10B"; got != want {
		t.Fatalf("nearDirectIntegrationModel() = %q, want %q", got, want)
	}

	// Model ID containing ':' but without the neardirect: prefix must still be prefixed.
	t.Setenv("NEARAI_E2EE_MODEL", "other-provider/model:v2")
	if got, want := nearDirectIntegrationModel(), "neardirect:other-provider/model:v2"; got != want {
		t.Fatalf("nearDirectIntegrationModel() = %q, want %q", got, want)
	}
}

// with Offline true (skips Intel PCS, NRAS, PoC network calls).
func integrationNearDirectConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Offline:    true,
		Providers: map[string]*config.Provider{
			"neardirect": {
				Name:    "neardirect",
				BaseURL: "https://completions.near.ai",
				APIKey:  os.Getenv("NEARAI_API_KEY"),
				E2EE:    false,
			},
		},
		AllowFail: attestation.KnownFactors,
	}
}

// integrationNearDirectE2EEConfig returns a config pointing at the live
// completions.near.ai endpoints with E2EE enabled and Offline true.
func integrationNearDirectE2EEConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Offline:    true,
		Providers: map[string]*config.Provider{
			"neardirect": {
				Name:    "neardirect",
				BaseURL: "https://completions.near.ai",
				APIKey:  os.Getenv("NEARAI_API_KEY"),
				E2EE:    true,
			},
		},
		AllowFail: attestation.KnownFactors,
	}
}

func TestIntegration_NearDirect(t *testing.T) {
	skipNearDirectIntegration(t)

	t.Run("NonStream", runNearDirectNonStream)
	t.Run("Streaming", runNearDirectStreaming)
	t.Run("Models", runNearDirectModels)
	t.Run("E2EEStreaming", runNearDirectE2EEStreaming)
	t.Run("E2EENonStream", runNearDirectE2EENonStream)
	t.Run("AttestationReport", runNearDirectAttestationReport)
	t.Run("E2EEStreamingWithTools", runNearDirectE2EEStreamingWithTools)
	t.Run("E2EENonStreamWithTools", runNearDirectE2EENonStreamWithTools)
	t.Run("E2EEStreamingMultimodalContentArray", runNearDirectE2EEStreamingMultimodalContentArray)
	t.Run("E2EENonStreamMultimodalContentArray", runNearDirectE2EENonStreamMultimodalContentArray)
}

func runNearDirectNonStream(t *testing.T) {
	proxySrv := newProxyServer(t, integrationNearDirectConfig(t))
	defer proxySrv.Close()

	resp := postChatIntegration(t, proxySrv.URL, nearDirectIntegrationModel(), false)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	content := extractMessageContent(t, body)
	if !isPrintableUTF8(content) {
		t.Errorf("content is not valid printable UTF-8: %q", content)
	}
	t.Logf("response: %q", content)
}

func runNearDirectStreaming(t *testing.T) {
	proxySrv := newProxyServer(t, integrationNearDirectConfig(t))
	defer proxySrv.Close()

	resp := postChatIntegration(t, proxySrv.URL, nearDirectIntegrationModel(), true)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	chunks := readSSEChunks(t, resp.Body)
	if len(chunks) == 0 {
		t.Fatal("no SSE chunks received")
	}

	var sb strings.Builder
	for _, c := range chunks {
		sb.WriteString(extractDeltaContent(t, c))
	}
	content := sb.String()
	if !isPrintableUTF8(content) {
		t.Errorf("aggregated content is not valid printable UTF-8: %q", content)
	}
	t.Logf("response (%d chunks): %q", len(chunks), content)
}

func runNearDirectModels(t *testing.T) {
	proxySrv := newProxyServer(t, integrationNearDirectConfig(t))
	defer proxySrv.Close()

	resp, err := integrationClient.Get(proxySrv.URL + "/v1/models")
	if err != nil {
		t.Fatalf("GET /v1/models: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	var result struct {
		Object string `json:"object"`
		Data   []struct {
			ID      string `json:"id"`
			OwnedBy string `json:"owned_by"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode /v1/models: %v", err)
	}

	if result.Object != "list" {
		t.Fatalf("object = %q, want %q", result.Object, "list")
	}
	if len(result.Data) == 0 {
		t.Fatal("/v1/models returned no models")
	}

	for _, m := range result.Data {
		if !strings.HasPrefix(m.ID, "neardirect:") {
			t.Errorf("model id = %q, want neardirect: prefix", m.ID)
		}
		if m.OwnedBy != "nearai" {
			t.Errorf("model %q owned_by = %q, want %q", m.ID, m.OwnedBy, "nearai")
		}
	}
}

func runNearDirectE2EEStreaming(t *testing.T) {
	proxySrv := newProxyServer(t, integrationNearDirectE2EEConfig(t))
	defer proxySrv.Close()

	resp := postChatIntegration(t, proxySrv.URL, nearDirectIntegrationModel(), true)
	defer resp.Body.Close()
	assertStreamResponse(t, resp)
}

func runNearDirectE2EENonStream(t *testing.T) {
	proxySrv := newProxyServer(t, integrationNearDirectE2EEConfig(t))
	defer proxySrv.Close()

	resp := postChatIntegration(t, proxySrv.URL, nearDirectIntegrationModel(), false)
	defer resp.Body.Close()
	assertNonStreamResponse(t, resp)
}

func runNearDirectAttestationReport(t *testing.T) {
	// Online mode so the report includes Intel PCS, NRAS, and PoC results.
	cfg := integrationNearDirectConfig(t)
	cfg.Offline = false
	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	model := nearDirectIntegrationModel()
	_, upstreamModel, _ := strings.Cut(model, ":")

	// A chat request populates the report cache. For NEAR AI (a pinned
	// provider), PinnedHandler.HandlePinned returns a non-nil Report only
	// on SPKI cache miss — i.e., when the first request to a new domain
	// triggers attestation. The proxy caches that report at proxy.go:431-432:
	//
	//   if pinnedResp.Report != nil {
	//       s.cache.Put(prov.Name, upstreamModel, pinnedResp.Report)
	//   }
	//
	// A fresh proxy instance starts with an empty SPKI cache, so the first
	// chat request always misses, triggers attestation, and populates the
	// report cache.
	chatResp := postChatIntegration(t, proxySrv.URL, model, true)
	io.Copy(io.Discard, chatResp.Body) // drain so the proxy's relayStream finishes cleanly
	chatResp.Body.Close()

	reportURL := fmt.Sprintf("%s/v1/tee/report?provider=neardirect&model=%s", proxySrv.URL, upstreamModel)
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

	// Verify Tier 1 factors all pass.
	tier1 := []string{
		"nonce_match",
		"tee_quote_present",
		"tee_quote_structure",
		"tee_cert_chain",
		"tee_quote_signature",
		"tee_debug_disabled",
		"signing_key_present",
	}
	for _, name := range tier1 {
		f, ok := findFactor(report.Factors, name)
		if !ok {
			t.Errorf("factor %q not found in report", name)
			continue
		}
		if f.Status != attestation.Pass {
			t.Errorf("factor %q: status = %v, want Pass; detail: %s", name, f.Status, f.Detail)
		}
	}

	// Verify REPORTDATA binding passes.
	f, ok := findFactor(report.Factors, "tee_reportdata_binding")
	if !ok {
		t.Error("factor tee_reportdata_binding not found")
	} else if f.Status != attestation.Pass {
		t.Errorf("tee_reportdata_binding: status = %v, want Pass; detail: %s", f.Status, f.Detail)
	}

	// Verify TLS key binding passes (NEAR AI-specific; Venice fails this).
	f, ok = findFactor(report.Factors, "tls_key_binding")
	if !ok {
		t.Error("factor tls_key_binding not found")
	} else if f.Status != attestation.Pass {
		t.Errorf("tls_key_binding: status = %v, want Pass; detail: %s", f.Status, f.Detail)
	}

	// Log every non-Pass factor so failures are visible in test output.
	for _, f := range report.Factors {
		if f.Status == attestation.Pass {
			continue
		}
		t.Logf("  %s %s: %s", f.Status, f.Name, f.Detail)
	}

	t.Logf("score: %d/%d passed, %d skipped, %d failed",
		report.Passed, report.Passed+report.Failed+report.Skipped, report.Skipped, report.Failed)
}

func runNearDirectE2EEStreamingWithTools(t *testing.T) {
	// Validate that tool-call function leaves are surfaced as plaintext after E2EE relay decryption.
	proxySrv := newProxyServer(t, integrationNearDirectE2EEConfig(t))
	defer proxySrv.Close()
	resp := postChatWithTools(t, proxySrv.URL, nearDirectIntegrationModel(), true)
	defer resp.Body.Close()
	if !assertStreamToolCallLeaves(t, resp, "neardirect") {
		t.Fatal("neardirect: expected at least one tool call in streaming tools integration test")
	}
}

func runNearDirectE2EENonStreamWithTools(t *testing.T) {
	proxySrv := newProxyServer(t, integrationNearDirectE2EEConfig(t))
	defer proxySrv.Close()

	resp := postChatWithTools(t, proxySrv.URL, nearDirectIntegrationModel(), false)
	defer resp.Body.Close()
	if !assertNonStreamToolCallLeaves(t, resp, "neardirect") {
		t.Fatal("neardirect: expected at least one tool call in non-stream tools integration test")
	}
}

func runNearDirectE2EEStreamingMultimodalContentArray(t *testing.T) {
	proxySrv := newProxyServer(t, integrationNearDirectE2EEConfig(t))
	defer proxySrv.Close()

	model := nearDirectVLModel()
	body := fmt.Sprintf(`{
		"model": %q,
		"messages": [{
			"role": "user",
			"content": [
				{"type": "text", "text": "What color is this image? Answer in one word."},
				{"type": "image_url", "image_url": {"url": "data:image/png;base64,%s"}}
			]
		}],
		"stream": true,
		"max_tokens": 50
	}`, model, testPNG())

	resp, err := integrationPostJSON(t, proxySrv.URL+"/v1/chat/completions", body)
	if err != nil {
		t.Fatalf("POST chat (multimodal stream E2EE): %v", err)
	}
	defer resp.Body.Close()

	assertStreamMultimodalResponse(t, resp, "neardirect")
}

func runNearDirectE2EENonStreamMultimodalContentArray(t *testing.T) {
	proxySrv := newProxyServer(t, integrationNearDirectE2EEConfig(t))
	defer proxySrv.Close()

	model := nearDirectVLModel()
	body := fmt.Sprintf(`{
		"model": %q,
		"messages": [{
			"role": "user",
			"content": [
				{"type": "text", "text": "What color is this image? Answer in one word."},
				{"type": "image_url", "image_url": {"url": "data:image/png;base64,%s"}}
			]
		}],
		"stream": false,
		"max_tokens": 50
	}`, model, testPNG())

	resp, err := integrationPostJSON(t, proxySrv.URL+"/v1/chat/completions", body)
	if err != nil {
		t.Fatalf("POST chat (multimodal non-stream E2EE): %v", err)
	}
	defer resp.Body.Close()

	assertNonStreamMultimodalResponse(t, resp, "neardirect")
}
