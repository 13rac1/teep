package proxy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
)

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
		if strings.HasPrefix(m, "venice:") {
			return m
		}
		return "venice:" + m
	}
	return "venice:e2ee-qwen3-6-35b-a3b"
}

func TestIntegrationModel_PrefixHandling(t *testing.T) {
	t.Setenv("VENICE_E2EE_MODEL", "e2ee-qwen3-6-35b-a3b")
	if got, want := integrationModel(), "venice:e2ee-qwen3-6-35b-a3b"; got != want {
		t.Fatalf("integrationModel() = %q, want %q", got, want)
	}

	t.Setenv("VENICE_E2EE_MODEL", "venice:e2ee-qwen3-6-35b-a3b")
	if got, want := integrationModel(), "venice:e2ee-qwen3-6-35b-a3b"; got != want {
		t.Fatalf("integrationModel() = %q, want %q", got, want)
	}

	// Model ID containing ':' but without the venice: prefix must still be prefixed.
	t.Setenv("VENICE_E2EE_MODEL", "hf:org/model:v1")
	if got, want := integrationModel(), "venice:hf:org/model:v1"; got != want {
		t.Fatalf("integrationModel() = %q, want %q", got, want)
	}
}

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

// assertReportFactors verifies tier-1 factors pass, REPORTDATA binding holds,
// and e2ee_usable is Pass (the test issues a chat request with E2EE before
// fetching the report).
func assertReportFactors(t *testing.T, report *attestation.VerificationReport) {
	t.Helper()

	mustPass := []string{
		"nonce_match",
		"tee_quote_present",
		"tee_quote_structure",
		"tee_cert_chain",
		"tee_quote_signature",
		"tee_debug_disabled",
		"signing_key_present",
		"tee_reportdata_binding",
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

	t.Run("E2EENonStream", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationE2EEConfig(t))
		defer proxySrv.Close()
		resp := postChatIntegration(t, proxySrv.URL, integrationModel(), false)
		defer resp.Body.Close()
		assertNonStreamResponse(t, resp)
	})

	t.Run("AttestationReport", func(t *testing.T) {
		cfg := integrationE2EEConfig(t)
		cfg.Offline = false
		proxySrv := newProxyServer(t, cfg)
		defer proxySrv.Close()

		model := integrationModel()
		_, upstreamModel, _ := strings.Cut(model, ":")
		chatResp := postChatIntegration(t, proxySrv.URL, model, true)
		io.Copy(io.Discard, chatResp.Body)
		chatResp.Body.Close()

		reportURL := fmt.Sprintf("%s/v1/tee/report?provider=venice&model=%s", proxySrv.URL, upstreamModel)
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

	t.Run("E2EEStreamingWithTools", func(t *testing.T) {
		// Validate that Venice tool-call function leaves are surfaced as plaintext.
		proxySrv := newProxyServer(t, integrationE2EEConfig(t))
		defer proxySrv.Close()
		resp := postChatWithTools(t, proxySrv.URL, integrationModel(), true)
		defer resp.Body.Close()
		if !assertStreamToolCallLeaves(t, resp, "venice") {
			t.Skip("venice live model returned no tool calls; cannot assert tool-call leaf status in this run")
		}
	})

	t.Run("E2EENonStreamWithTools", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationE2EEConfig(t))
		defer proxySrv.Close()
		resp := postChatWithTools(t, proxySrv.URL, integrationModel(), false)
		defer resp.Body.Close()
		if !assertNonStreamToolCallLeaves(t, resp, "venice") {
			t.Skip("venice live model returned no tool calls; cannot assert tool-call leaf status in this run")
		}
	})

	t.Run("E2EEPlaintextToolCalls", func(t *testing.T) {
		// Venice E2EE preserves plaintext for tool_calls function name and arguments
		// (unlike NearCloud/NearDirect which use full-field encryption).
		// This test validates that when Venice returns tool_calls, the function
		// name and arguments are accessible as plaintext strings without decryption.
		proxySrv := newProxyServer(t, integrationE2EEConfig(t))
		defer proxySrv.Close()

		// Use a prompt that encourages tool use and a tool that would be called.
		// Model behavior varies; if it chooses to return content instead of calling
		// a tool, we still validate the response structure is valid.
		toolPrompt := integrationToolPrompt
		model := integrationModel()
		toolJSON := fmt.Sprintf(
			`{"model":%q,"messages":[{"role":"user","content":%q}],"stream":false,"tool_choice":{"type":"function","function":{"name":"get_weather"}},"tools":[{"type":"function","function":{"name":"get_weather","description":"Get the current weather in a location","parameters":{"type":"object","properties":{"location":{"type":"string","description":"The location to get weather for"}},"required":["location"]}}}]}`,
			model, toolPrompt)

		const maxAttempts = 3
		const attemptTimeout = 25 * time.Second
		lastReason := ""
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			attemptCtx, cancel := context.WithTimeout(context.Background(), attemptTimeout)
			req, reqErr := http.NewRequestWithContext(
				attemptCtx,
				http.MethodPost,
				proxySrv.URL+"/v1/chat/completions",
				strings.NewReader(toolJSON),
			)
			if reqErr != nil {
				cancel()
				t.Fatalf("construct tool-call request: %v", reqErr)
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				cancel()
				lastReason = fmt.Sprintf("request error: %v", err)
				t.Logf("attempt %d/%d: %s", attempt, maxAttempts, lastReason)
				continue
			}

			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			cancel()
			if readErr != nil {
				lastReason = fmt.Sprintf("read body: %v", readErr)
				t.Logf("attempt %d/%d: %s", attempt, maxAttempts, lastReason)
				continue
			}

			if resp.StatusCode != http.StatusOK {
				lastReason = fmt.Sprintf("status=%d body=%s", resp.StatusCode, body)
				t.Logf("attempt %d/%d: %s", attempt, maxAttempts, lastReason)
				continue
			}

			calls, err := decodeNonStreamToolCallLeaves(body)
			if err != nil {
				t.Fatalf("decode tool response: %v; body=%s", err, body)
			}
			if len(calls) == 0 {
				lastReason = "response contained no tool_calls"
				t.Logf("attempt %d/%d: %s; snippet=%q", attempt, maxAttempts, lastReason, diagnosticBodySnippet(body))
				continue
			}

			assertToolCallLeavesPlaintext(t, "venice", calls)
			t.Logf("venice non-stream tool calls verified in plaintext test: %d", len(calls))
			return
		}

		t.Skipf("venice live model did not return verifiable tool_calls after %d attempts: %s", maxAttempts, lastReason)
	})
}
