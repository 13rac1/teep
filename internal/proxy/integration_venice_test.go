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
	"unicode"
	"unicode/utf8"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/tlsct"
)

// integrationClient is an HTTP client with a 5-minute timeout for integration
// tests. Chutes E2EE can take ~30s attestation + ~60s inference, and with
// instance failover retries the total may exceed 120s. 5 minutes gives
// generous headroom without hanging forever on a stuck connection.
var integrationClient = tlsct.NewHTTPClient(5 * time.Minute)

const (
	integrationRequestTimeoutDefault  = 2 * time.Minute
	integrationRequestTimeoutHeadroom = 10 * time.Second
	integrationRequestTimeoutMin      = 5 * time.Second
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
	return "venice:e2ee-qwen3-5-122b-a10b"
}

func TestIntegrationModel_PrefixHandling(t *testing.T) {
	t.Setenv("VENICE_E2EE_MODEL", "e2ee-qwen3-5-122b-a10b")
	if got, want := integrationModel(), "venice:e2ee-qwen3-5-122b-a10b"; got != want {
		t.Fatalf("integrationModel() = %q, want %q", got, want)
	}

	t.Setenv("VENICE_E2EE_MODEL", "venice:e2ee-qwen3-5-122b-a10b")
	if got, want := integrationModel(), "venice:e2ee-qwen3-5-122b-a10b"; got != want {
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

// integrationPrompt is a short prompt that minimizes cost and response time.
const integrationPrompt = "Say hello in exactly two words"

type cancelOnCloseReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (r *cancelOnCloseReadCloser) Close() error {
	err := r.ReadCloser.Close()
	r.cancel()
	return err
}

func integrationRequestTimeout(t *testing.T) time.Duration {
	t.Helper()

	timeout := integrationRequestTimeoutDefault
	if deadline, ok := t.Deadline(); ok {
		remaining := time.Until(deadline) - integrationRequestTimeoutHeadroom
		switch {
		case remaining <= integrationRequestTimeoutMin:
			return integrationRequestTimeoutMin
		case remaining < timeout:
			return remaining
		}
	}

	return timeout
}

func integrationPostJSON(t *testing.T, url, body string) (*http.Response, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), integrationRequestTimeout(t))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := integrationClient.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}

	resp.Body = &cancelOnCloseReadCloser{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// postChatIntegration sends a POST /v1/chat/completions with the standard
// integration prompt. Requests are bounded by integrationRequestTimeout(t),
// with integrationClient's 5-minute timeout as an additional upper bound.
func postChatIntegration(t *testing.T, proxyURL, model string, stream bool) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":%q}],"stream":%v}`, model, integrationPrompt, stream)
	resp, err := integrationPostJSON(t, proxyURL+"/v1/chat/completions", body)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	return resp
}

// postChatWithTools sends a POST /v1/chat/completions with a tool schema.
// This exercises the protocol-aware nested field decryption code paths for
// handling tool_calls, audio.data, and function_call fields in responses.
func postChatWithTools(t *testing.T, proxyURL, model string, stream bool) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":%q}],"stream":%v,"tools":[{"type":"function","function":{"name":"get_weather","description":"Get the weather","parameters":{"type":"object","properties":{"location":{"type":"string"}}}}}]}`, model, integrationPrompt, stream)
	resp, err := integrationPostJSON(t, proxyURL+"/v1/chat/completions", body)
	if err != nil {
		t.Fatalf("POST chat with tools: %v", err)
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

// assertNonStreamResponseOrToolCall validates a non-streaming chat response
// where models may either return text content or a tool call message.
func assertNonStreamResponseOrToolCall(t *testing.T, resp *http.Response) {
	t.Helper()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content   *string           `json:"content"`
				ToolCalls []json.RawMessage `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("decode non-stream response: %v; body=%s", err, body)
	}
	if len(parsed.Choices) == 0 {
		t.Fatalf("no choices in response: %s", body)
	}

	msg := parsed.Choices[0].Message
	if msg.Content != nil && *msg.Content != "" {
		if !isPrintableUTF8(*msg.Content) {
			t.Errorf("content is not valid printable UTF-8: %q", *msg.Content)
		}
		t.Logf("response content: %q", *msg.Content)
		return
	}
	if len(msg.ToolCalls) > 0 {
		t.Logf("response contains %d tool call(s)", len(msg.ToolCalls))
		return
	}

	t.Fatalf("expected printable content or tool_calls, got body=%s", body)
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
		// Test that requests with tool schemas don't break E2EE decryption.
		// This exercises protocol-aware nested field decryption for tool_calls.
		proxySrv := newProxyServer(t, integrationE2EEConfig(t))
		defer proxySrv.Close()
		resp := postChatWithTools(t, proxySrv.URL, integrationModel(), true)
		defer resp.Body.Close()
		assertStreamResponse(t, resp)
	})

	t.Run("E2EENonStreamWithTools", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationE2EEConfig(t))
		defer proxySrv.Close()
		resp := postChatWithTools(t, proxySrv.URL, integrationModel(), false)
		defer resp.Body.Close()
		assertNonStreamResponseOrToolCall(t, resp)
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
		toolPrompt := `Use the weather tool to get the current weather for San Francisco.`
		model := integrationModel()
		toolJSON := fmt.Sprintf(
			`{"model":%q,"messages":[{"role":"user","content":%q}],"stream":false,"tools":[{"type":"function","function":{"name":"get_weather","description":"Get the current weather in a location","parameters":{"type":"object","properties":{"location":{"type":"string","description":"The location to get weather for"}}}}}]}`,
			model, toolPrompt)

		resp, err := integrationPostJSON(t, proxySrv.URL+"/v1/chat/completions", toolJSON)
		if err != nil {
			t.Fatalf("POST chat with tool request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		var parsed struct {
			Choices []struct {
				Message struct {
					Content   *string `json:"content"`
					ToolCalls []struct {
						ID       string `json:"id"`
						Type     string `json:"type"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatalf("decode tool response: %v; body=%s", err, body)
		}
		if len(parsed.Choices) == 0 {
			t.Fatalf("no choices in response: %s", body)
		}

		msg := parsed.Choices[0].Message
		if msg.Content != nil && *msg.Content != "" {
			// Model returned text instead of tool call, which is valid.
			t.Logf("model returned content instead of tool call: %q", *msg.Content)
			return
		}

		if len(msg.ToolCalls) > 0 {
			// Validate that tool_calls are accessible (plaintext, not encrypted).
			// The key assertion here is that we can unmarshal the tool_calls structure
			// without errors, which proves that:
			// 1. decryptToolCallsField correctly skipped decryption for Venice
			// 2. The plaintext function name and arguments are preserved
			// 3. No encryption-related errors were raised during relay decryption
			toolCall := msg.ToolCalls[0]
			if toolCall.Function.Name == "" {
				t.Fatalf("tool_call function name is empty; structure: %+v", toolCall)
			}
			if toolCall.Function.Arguments == "" {
				t.Fatalf("tool_call function arguments are empty; structure: %+v", toolCall)
			}
			// Validate arguments are valid JSON (they should be plaintext JSON, not encrypted).
			var args map[string]any
			if err := json.Unmarshal([]byte(toolCall.Function.Arguments), &args); err != nil {
				t.Fatalf("tool_call arguments not valid JSON (expected plaintext): %v; args=%q", err, toolCall.Function.Arguments)
			}
			t.Logf("Venice E2EE tool_calls: function=%q, arguments=%q", toolCall.Function.Name, toolCall.Function.Arguments)
			return
		}

		// Model didn't use tools with this prompt, which is acceptable.
		t.Logf("model did not use tools with this prompt")
	})
}
