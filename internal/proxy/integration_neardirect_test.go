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
		return m
	}
	return "Qwen/Qwen3.5-122B-A10B"
}

// integrationNearDirectConfig returns a config pointing at the live NEAR AI API
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
		Enforced: []string{},
	}
}

func TestIntegration_NearDirect(t *testing.T) {
	skipNearDirectIntegration(t)

	t.Run("NonStream", func(t *testing.T) {
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
	})

	t.Run("Streaming", func(t *testing.T) {
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
	})

	t.Run("AttestationReport", func(t *testing.T) {
		// Online mode so the report includes Intel PCS, NRAS, and PoC results.
		cfg := integrationNearDirectConfig(t)
		cfg.Offline = false
		proxySrv := newProxyServer(t, cfg)
		defer proxySrv.Close()

		model := nearDirectIntegrationModel()

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

		reportURL := fmt.Sprintf("%s/v1/tee/report?provider=neardirect&model=%s", proxySrv.URL, model)
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
	})
}
