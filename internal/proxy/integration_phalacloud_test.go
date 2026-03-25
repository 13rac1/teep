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

// skipPhalaCloudIntegration skips the test if PHALA_API_KEY is unset or if
// running under go test -short.
func skipPhalaCloudIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("PHALA_API_KEY") == "" {
		t.Skip("PHALA_API_KEY not set")
	}
}

// phalaCloudIntegrationModel returns the Phala Cloud model to use, defaulting
// to a known-good model if PHALA_MODEL is unset.
func phalaCloudIntegrationModel() string {
	if m := os.Getenv("PHALA_MODEL"); m != "" {
		return m
	}
	return "phala/deepseek-chat-v3-0324"
}

// integrationPhalaCloudConfig returns a config pointing at the live Phala Cloud
// API with Offline true (skips Intel PCS, NRAS, PoC network calls).
func integrationPhalaCloudConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Offline:    true,
		Providers: map[string]*config.Provider{
			"phalacloud": {
				Name:    "phalacloud",
				BaseURL: "https://api.phala.network/v1",
				APIKey:  os.Getenv("PHALA_API_KEY"),
				E2EE:    false,
			},
		},
		Enforced: []string{},
	}
}

func TestIntegration_PhalaCloud(t *testing.T) {
	skipPhalaCloudIntegration(t)

	t.Run("NonStream", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationPhalaCloudConfig(t))
		defer proxySrv.Close()

		resp := postChatIntegration(t, proxySrv.URL, phalaCloudIntegrationModel(), false)
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
		proxySrv := newProxyServer(t, integrationPhalaCloudConfig(t))
		defer proxySrv.Close()

		resp := postChatIntegration(t, proxySrv.URL, phalaCloudIntegrationModel(), true)
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

	t.Run("AttestationReport", func(t *testing.T) {
		// Online mode so the report includes Intel PCS, NRAS, and PoC results.
		cfg := integrationPhalaCloudConfig(t)
		cfg.Offline = false
		proxySrv := newProxyServer(t, cfg)
		defer proxySrv.Close()

		model := phalaCloudIntegrationModel()

		// First chat request triggers attestation and populates the report cache.
		chatResp := postChatIntegration(t, proxySrv.URL, model, true)
		io.Copy(io.Discard, chatResp.Body)
		chatResp.Body.Close()

		reportURL := fmt.Sprintf("%s/v1/tee/report?provider=phalacloud&model=%s", proxySrv.URL, model)
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
			"tdx_quote_present",
			"tdx_quote_structure",
			"tdx_cert_chain",
			"tdx_quote_signature",
			"tdx_debug_disabled",
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
		f, ok := findFactor(report.Factors, "tdx_reportdata_binding")
		if !ok {
			t.Error("factor tdx_reportdata_binding not found")
		} else if f.Status != attestation.Pass {
			t.Errorf("tdx_reportdata_binding: status = %v, want Pass; detail: %s", f.Status, f.Detail)
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
	})
}
