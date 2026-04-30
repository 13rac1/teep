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

// skipNearCloudIntegration skips the test if NEARAI_API_KEY is unset or if
// running under go test -short.
func skipNearCloudIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("NEARAI_API_KEY") == "" {
		t.Skip("NEARAI_API_KEY not set")
	}
}

// nearCloudIntegrationModel returns the model to use for nearcloud tests.
func nearCloudIntegrationModel() string {
	if m := os.Getenv("NEARAI_E2EE_MODEL"); m != "" {
		if strings.Contains(m, ":") {
			return m
		}
		return "nearcloud:" + m
	}
	return "nearcloud:Qwen/Qwen3.5-122B-A10B"
}

// integrationNearCloudConfig returns a config pointing at the live cloud-api.near.ai
// gateway with Offline true (skips Intel PCS, NRAS, PoC network calls).
func integrationNearCloudConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Offline:    true,
		Providers: map[string]*config.Provider{
			"nearcloud": {
				Name:    "nearcloud",
				BaseURL: "https://cloud-api.near.ai",
				APIKey:  os.Getenv("NEARAI_API_KEY"),
				E2EE:    false,
			},
		},
		AllowFail: attestation.KnownFactors,
	}
}

// integrationNearCloudE2EEConfig returns a config pointing at the live
// cloud-api.near.ai gateway with E2EE enabled and Offline true.
func integrationNearCloudE2EEConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Offline:    true,
		Providers: map[string]*config.Provider{
			"nearcloud": {
				Name:    "nearcloud",
				BaseURL: "https://cloud-api.near.ai",
				APIKey:  os.Getenv("NEARAI_API_KEY"),
				E2EE:    true,
			},
		},
		AllowFail: attestation.KnownFactors,
	}
}

func TestIntegration_NearCloud(t *testing.T) {
	skipNearCloudIntegration(t)

	t.Run("NonStream", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationNearCloudConfig(t))
		defer proxySrv.Close()

		resp := postChatIntegration(t, proxySrv.URL, nearCloudIntegrationModel(), false)
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
	})

	t.Run("Streaming", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationNearCloudConfig(t))
		defer proxySrv.Close()

		resp := postChatIntegration(t, proxySrv.URL, nearCloudIntegrationModel(), true)
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
	})

	t.Run("E2EEStreaming", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationNearCloudE2EEConfig(t))
		defer proxySrv.Close()
		resp := postChatIntegration(t, proxySrv.URL, nearCloudIntegrationModel(), true)
		defer resp.Body.Close()
		assertStreamResponse(t, resp)
	})

	t.Run("AttestationReport", func(t *testing.T) {
		// Online mode with E2EE so the report includes Intel PCS, NRAS, PoC,
		// gateway results, and e2ee_usable transitions to Pass after a live
		// E2EE roundtrip. Non-streaming avoids relay timeout issues while
		// still exercising the full E2EE path through the proxy.
		cfg := integrationNearCloudE2EEConfig(t)
		cfg.Offline = false
		proxySrv := newProxyServer(t, cfg)
		defer proxySrv.Close()

		model := nearCloudIntegrationModel()
		_, upstreamModel, _ := strings.Cut(model, ":")

		// First chat request triggers attestation + E2EE and populates the report cache.
		chatResp := postChatIntegration(t, proxySrv.URL, model, false)
		io.Copy(io.Discard, chatResp.Body)
		chatResp.Body.Close()

		reportURL := fmt.Sprintf("%s/v1/tee/report?provider=nearcloud&model=%s", proxySrv.URL, upstreamModel)
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

		// Verify critical model factors (Tier 1 core + Tier 2 binding) all pass.
		mustPass := []string{
			// Tier 1: Core TDX.
			"nonce_match",
			"tdx_quote_present",
			"tdx_quote_structure",
			"tdx_cert_chain",
			"tdx_quote_signature",
			"tdx_debug_disabled",
			"signing_key_present",
			// Tier 2: Binding & Crypto.
			"e2ee_capable",
			// e2ee_usable must be Pass after a live E2EE inference test.
			// This test issues a real encrypted request before fetching the
			// report, so the proxy should record that usability into the
			// cached report.
			"e2ee_usable",
		}
		for _, name := range mustPass {
			f, ok := findFactor(report.Factors, name)
			if !ok {
				t.Errorf("factor %q not found in report", name)
				continue
			}
			if f.Status != attestation.Pass {
				t.Errorf("factor %q: status = %v, want Pass; detail: %s", name, f.Status, f.Detail)
			}
		}

		// Verify gateway Tier 4 factors exist and critical ones pass.
		gatewayFactors := []string{
			"gateway_nonce_match",
			"gateway_tdx_quote_present",
			"gateway_tdx_quote_structure",
			"gateway_tdx_cert_chain",
			"gateway_tdx_quote_signature",
			"gateway_tdx_debug_disabled",
			"gateway_compose_binding",
		}
		for _, name := range gatewayFactors {
			f, ok := findFactor(report.Factors, name)
			if !ok {
				t.Errorf("gateway factor %q not found in report", name)
				continue
			}
			t.Logf("  %s %s: %s", f.Status, f.Name, f.Detail)
		}

		// Gateway TDX core factors should pass.
		for _, name := range []string{
			"gateway_tdx_quote_present",
			"gateway_tdx_quote_structure",
			"gateway_tdx_cert_chain",
			"gateway_tdx_quote_signature",
			"gateway_tdx_debug_disabled",
		} {
			f, ok := findFactor(report.Factors, name)
			if !ok {
				continue // already reported above
			}
			if f.Status != attestation.Pass {
				t.Errorf("gateway factor %q: status = %v, want Pass; detail: %s", name, f.Status, f.Detail)
			}
		}

		// Log every non-Pass factor.
		for _, f := range report.Factors {
			if f.Status == attestation.Pass {
				continue
			}
			t.Logf("  %s %s: %s", f.Status, f.Name, f.Detail)
		}

		t.Logf("score: %d/%d passed, %d skipped, %d failed",
			report.Passed, report.Passed+report.Failed+report.Skipped, report.Skipped, report.Failed)
	})
}

// --------------------------------------------------------------------------
// NearCloud Images E2EE integration (FLUX via gateway)
// --------------------------------------------------------------------------

// nearCloudImagesModel returns the model for nearcloud image generation tests.
// Reuses the NEARAI_IMAGES_MODEL env var shared with neardirect tests.
func nearCloudImagesModel() string {
	if m := os.Getenv("NEARAI_IMAGES_MODEL"); m != "" {
		return "nearcloud:" + m
	}
	return "nearcloud:black-forest-labs/FLUX.2-klein-4B"
}

func TestIntegration_NearCloud_Images(t *testing.T) {
	skipNearCloudIntegration(t)

	t.Run("E2EE", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationNearCloudE2EEConfig(t))
		defer proxySrv.Close()

		model := nearCloudImagesModel()
		body := fmt.Sprintf(`{"model":%q,"prompt":"a solid red square","n":1,"size":"256x256","response_format":"b64_json"}`, model)

		resp, err := integrationClient.Post(proxySrv.URL+"/v1/images/generations", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST images: %v", err)
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

		assertImagesResponse(t, respBody)
	})
}

// --------------------------------------------------------------------------
// NearCloud VL E2EE integration (serialize-and-encrypt via gateway)
// --------------------------------------------------------------------------

// nearCloudVLModel returns the model for nearcloud VL tests.
// Reuses the NEARAI_VL_MODEL env var shared with neardirect tests.
func nearCloudVLModel() string {
	if m := os.Getenv("NEARAI_VL_MODEL"); m != "" {
		return "nearcloud:" + m
	}
	return "nearcloud:Qwen/Qwen3-VL-30B-A3B-Instruct"
}

func TestIntegration_NearCloud_VL(t *testing.T) {
	skipNearCloudIntegration(t)

	t.Run("E2EE", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationNearCloudE2EEConfig(t))
		defer proxySrv.Close()

		model := nearCloudVLModel()
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

		resp, err := integrationClient.Post(proxySrv.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST chat (VL E2EE): %v", err)
		}
		defer resp.Body.Close()

		assertStreamResponse(t, resp)
	})
}
