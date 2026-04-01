package proxy_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
)

// integrationClient is an HTTP client with a 60-second timeout for integration
// tests. Attestation + chat can take 10-30s; 60s gives headroom without
// hanging forever on a stuck connection.
var integrationClient = &http.Client{Timeout: 60 * time.Second}

// skipIntegration skips the test if VENICE_API_KEY is unset or if running
// under go test -short.
func skipIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("VENICE_API_KEY") == "" {
		t.Skip("VENICE_API_KEY not set")
	}
}

// integrationModel returns the Venice E2EE model to use, defaulting to a
// known-good model if VENICE_E2EE_MODEL is unset.
func integrationModel() string {
	if m := os.Getenv("VENICE_E2EE_MODEL"); m != "" {
		return m
	}
	return "e2ee-qwen3-5-122b-a10b"
}

// integrationPlaintextConfig returns a config pointing at the live Venice API
// with E2EE disabled and Offline true (skips Intel PCS, NRAS, PoC network
// calls).
func integrationPlaintextConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Offline:    true,
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: "https://api.venice.ai",
				APIKey:  os.Getenv("VENICE_API_KEY"),
				E2EE:    false,
			},
		},
		AllowFail: attestation.KnownFactors,
	}
}

// integrationE2EEConfig returns a config pointing at the live Venice API with
// E2EE enabled and Offline true (skips Intel PCS, NRAS, PoC in the initial
// fetchAndVerify; buildUpstreamBody always uses offline=true for its own
// fresh TDX check).
func integrationE2EEConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Offline:    true,
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: "https://api.venice.ai",
				APIKey:  os.Getenv("VENICE_API_KEY"),
				E2EE:    true,
			},
		},
		AllowFail: attestation.KnownFactors,
	}
}

// integrationPrompt is a short prompt that minimizes cost and response time.
const integrationPrompt = "Say hello in exactly two words"

// postChatIntegration sends a POST /v1/chat/completions with the standard
// integration prompt. Uses integrationClient (60s timeout).
func postChatIntegration(t *testing.T, proxyURL, model string, stream bool) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":%q}],"stream":%v}`, model, integrationPrompt, stream)
	resp, err := integrationClient.Post(proxyURL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	return resp
}

// findFactor returns the named factor from a report's factor list.
func findFactor(factors []attestation.FactorResult, name string) (attestation.FactorResult, bool) {
	for _, f := range factors {
		if f.Name == name {
			return f, true
		}
	}
	return attestation.FactorResult{}, false
}

// isPrintableUTF8 returns true if s is valid UTF-8 and contains at least one
// printable, non-control character.
func isPrintableUTF8(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsPrint(r) && !unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// assertNonStreamResponse validates a non-streaming chat response has valid
// printable UTF-8 content.
func assertNonStreamResponse(t *testing.T, resp *http.Response) {
	t.Helper()

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

// assertStreamResponse validates a streaming chat response has valid printable
// UTF-8 content across all SSE chunks.
func assertStreamResponse(t *testing.T, resp *http.Response) {
	t.Helper()

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
		t.Errorf("content is not valid printable UTF-8: %q", content)
	}
	t.Logf("response (%d chunks): %q", len(chunks), content)
}

// assertReportFactors verifies tier-1 factors pass, REPORTDATA binding holds,
// and e2ee_usable is Pass (the test issues a chat request with E2EE before
// fetching the report).
func assertReportFactors(t *testing.T, report *attestation.VerificationReport) {
	t.Helper()

	mustPass := []string{
		"nonce_match",
		"tdx_quote_present",
		"tdx_quote_structure",
		"tdx_cert_chain",
		"tdx_quote_signature",
		"tdx_debug_disabled",
		"signing_key_present",
		"tdx_reportdata_binding",
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

	for _, f := range report.Factors {
		if f.Status != attestation.Pass {
			t.Logf("  %s %s: %s", f.Status, f.Name, f.Detail)
		}
	}

	t.Logf("score: %d/%d passed, %d skipped, %d failed",
		report.Passed, report.Passed+report.Failed+report.Skipped, report.Skipped, report.Failed)
}

func TestIntegration_Venice(t *testing.T) {
	skipIntegration(t)

	t.Run("NonStream", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationPlaintextConfig(t))
		defer proxySrv.Close()
		resp := postChatIntegration(t, proxySrv.URL, integrationModel(), false)
		defer resp.Body.Close()
		assertNonStreamResponse(t, resp)
	})

	t.Run("Streaming", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationPlaintextConfig(t))
		defer proxySrv.Close()
		resp := postChatIntegration(t, proxySrv.URL, integrationModel(), true)
		defer resp.Body.Close()
		assertStreamResponse(t, resp)
	})

	t.Run("E2EEStreaming", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationE2EEConfig(t))
		defer proxySrv.Close()
		resp := postChatIntegration(t, proxySrv.URL, integrationModel(), true)
		defer resp.Body.Close()
		assertStreamResponse(t, resp)
	})

	t.Run("AttestationReport", func(t *testing.T) {
		cfg := integrationE2EEConfig(t)
		cfg.Offline = false
		proxySrv := newProxyServer(t, cfg)
		defer proxySrv.Close()

		chatResp := postChatIntegration(t, proxySrv.URL, integrationModel(), true)
		io.Copy(io.Discard, chatResp.Body)
		chatResp.Body.Close()

		reportURL := fmt.Sprintf("%s/v1/tee/report?provider=venice&model=%s", proxySrv.URL, integrationModel())
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
		assertReportFactors(t, &report)
	})
}
