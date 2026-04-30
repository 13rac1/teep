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

// skipChutesIntegration skips the test if CHUTES_API_KEY is unset or if
// running under go test -short.
func skipChutesIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("CHUTES_API_KEY") == "" {
		t.Skip("CHUTES_API_KEY not set")
	}
}

// chutesIntegrationModel returns the model name or chute UUID to use,
// defaulting to a known-good TEE model if CHUTES_E2EE_MODEL is unset.
// Supports human-readable names (resolved via /v1/models) or UUIDs.
func chutesIntegrationModel() string {
	if m := os.Getenv("CHUTES_E2EE_MODEL"); m != "" {
		if strings.Contains(m, ":") {
			return m
		}
		return "chutes:" + m
	}
	return chutesVLModel()
}

// integrationChutesPlaintextConfig returns a config pointing at the live
// Chutes API with E2EE disabled and Offline true (skips Intel PCS, NRAS, PoC
// network calls). Used to diagnose 403s: if non-E2EE requests also fail,
// the issue is the API key or account rather than the E2EE path.
func integrationChutesPlaintextConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Offline:    true,
		Providers: map[string]*config.Provider{
			"chutes": {
				Name:    "chutes",
				BaseURL: "https://api.chutes.ai",
				APIKey:  os.Getenv("CHUTES_API_KEY"),
				E2EE:    false,
			},
		},
		AllowFail: attestation.KnownFactors,
	}
}

// integrationChutesE2EEConfig returns a config pointing at the live Chutes API
// with E2EE enabled and Offline true (skips Intel PCS, NRAS, PoC network
// calls in the initial fetchAndVerify; buildUpstreamBody always fetches fresh
// attestation for Chutes because SkipSigningKeyCache is true).
func integrationChutesE2EEConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Offline:    true,
		Providers: map[string]*config.Provider{
			"chutes": {
				Name:    "chutes",
				BaseURL: "https://api.chutes.ai",
				APIKey:  os.Getenv("CHUTES_API_KEY"),
				E2EE:    true,
			},
		},
		AllowFail: attestation.KnownFactors,
	}
}

func TestIntegration_Chutes(t *testing.T) {
	skipChutesIntegration(t)

	t.Run("NonStream", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationChutesPlaintextConfig(t))
		defer proxySrv.Close()
		resp := postChatIntegration(t, proxySrv.URL, chutesIntegrationModel(), false)
		defer resp.Body.Close()
		assertNonStreamResponse(t, resp)
	})

	t.Run("Streaming", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationChutesPlaintextConfig(t))
		defer proxySrv.Close()
		resp := postChatIntegration(t, proxySrv.URL, chutesIntegrationModel(), true)
		defer resp.Body.Close()
		assertStreamResponse(t, resp)
	})

	t.Run("E2EEStreaming", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationChutesE2EEConfig(t))
		defer proxySrv.Close()

		resp := postChatIntegration(t, proxySrv.URL, chutesIntegrationModel(), true)
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

	t.Run("E2EENonStream", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationChutesE2EEConfig(t))
		defer proxySrv.Close()

		resp := postChatIntegration(t, proxySrv.URL, chutesIntegrationModel(), false)
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

	t.Run("AttestationReport", func(t *testing.T) {
		// Online mode so the report includes Intel PCS verification.
		cfg := integrationChutesE2EEConfig(t)
		cfg.Offline = false
		proxySrv := newProxyServer(t, cfg)
		defer proxySrv.Close()

		model := chutesIntegrationModel()
		_, upstreamModel, _ := strings.Cut(model, ":")

		// First chat request triggers attestation and populates the report cache.
		chatResp := postChatIntegration(t, proxySrv.URL, model, true)
		io.Copy(io.Discard, chatResp.Body)
		chatResp.Body.Close()

		reportURL := fmt.Sprintf("%s/v1/tee/report?provider=chutes&model=%s", proxySrv.URL, upstreamModel)
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

		// Verify critical factors (Tier 1 core + Tier 2 binding) all pass.
		// Chutes uses direct TEE attestation (no gateway), so there are no
		// gateway_* factors to check.
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
			"tdx_reportdata_binding",
			"e2ee_capable",
			// e2ee_usable: after a successful E2EE roundtrip in proxy
			// mode the cached report is promoted from Skip to Pass.
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

		// Log every non-Pass factor for diagnostics (nonce expiry, API errors, etc.).
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
