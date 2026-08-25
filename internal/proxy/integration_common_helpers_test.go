package proxy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
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
	integrationRequestTimeoutFloor    = 5 * time.Second
)

// integrationPrompt is a short prompt that minimizes cost and response time.
const integrationPrompt = "Say hello in exactly two words"

// integrationToolPrompt strongly nudges the model toward tool invocation so
// tool-call leaf decryption status is exercised by integration tests.
const integrationToolPrompt = "You must call the get_weather function for San Francisco. Do not provide prose. Return only the function call."

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
		case remaining <= integrationRequestTimeoutFloor:
			return integrationRequestTimeoutFloor
		case remaining < timeout:
			return remaining
		}
	}

	return timeout
}

func integrationPostJSON(t *testing.T, url, body string) (*http.Response, error) {
	t.Helper()
	return integrationPost(t, url, "application/json", strings.NewReader(body))
}

func integrationPost(t *testing.T, url, contentType string, body io.Reader) (*http.Response, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), integrationRequestTimeout(t))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)

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
	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":%q}],"stream":%v,"max_tokens":64}`, model, integrationPrompt, stream)
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
	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":%q}],"stream":%v,"max_tokens":128,"tool_choice":{"type":"function","function":{"name":"get_weather"}},"tools":[{"type":"function","function":{"name":"get_weather","description":"Get the weather","parameters":{"type":"object","properties":{"location":{"type":"string"}},"required":["location"]}}}]}`, model, integrationToolPrompt, stream)
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

func logReportScore(t *testing.T, report *attestation.VerificationReport) {
	t.Helper()

	total := report.Passed + report.Failed + report.Skipped
	msg := "score: %d/%d passed, %d skipped, %d failed"
	args := []any{report.Passed, total, report.Skipped, report.Failed}
	if report.Failed > 0 {
		msg += " (%d enforced, %d allowed)"
		args = append(args, report.EnforcedFailed, report.AllowedFailed)
	}
	if report.NotApplicableCount > 0 {
		msg += ", %d n/a"
		args = append(args, report.NotApplicableCount)
	}
	t.Logf(msg, args...)
	assertNoEnforcedFailures(t, report)
}

func assertNoEnforcedFailures(t *testing.T, report *attestation.VerificationReport) {
	t.Helper()

	blocked := report.BlockedFactors()
	if len(blocked) == 0 {
		return
	}
	for _, f := range blocked {
		t.Errorf("enforced factor failed: %s: %s", f.Name, f.Detail)
	}
}

func logReportFactor(t *testing.T, f attestation.FactorResult) {
	t.Helper()
	t.Logf("  %s %s: %s%s", f.Status, f.Name, f.Detail, factorPolicySuffix(f))
}

func factorPolicySuffix(f attestation.FactorResult) string {
	tag := factorPolicyTag(f)
	if tag == "" {
		return ""
	}
	return "  " + tag
}

func factorPolicyTag(f attestation.FactorResult) string {
	if f.Status == attestation.NotApplicable {
		return ""
	}
	if f.Enforced {
		return "[ENFORCED]"
	}
	return "[ALLOWED]"
}

func TestIntegrationConfigsUseServeAllowFailPolicy(t *testing.T) {
	tests := []struct {
		name         string
		providerName string
		build        func(*testing.T) *config.Config
	}{
		{"venice_plaintext", "venice", integrationPlaintextConfig},
		{"venice_e2ee", "venice", integrationE2EEConfig},
		{"neardirect_plaintext", "neardirect", integrationNearDirectConfig},
		{"neardirect_e2ee", "neardirect", integrationNearDirectE2EEConfig},
		{"nearcloud_plaintext", "nearcloud", integrationNearCloudConfig},
		{"nearcloud_e2ee", "nearcloud", integrationNearCloudE2EEConfig},
		{"nanogpt", "nanogpt", nanogptIntegrationConfig},
		{"phalacloud", "phalacloud", integrationPhalaCloudConfig},
		{"chutes_plaintext", "chutes", integrationChutesPlaintextConfig},
		{"chutes_e2ee", "chutes", integrationChutesE2EEConfig},
		{"tinfoil_cloud_plaintext", "tinfoil_v3_cloud", integrationTinfoilPlaintextConfig},
		{"tinfoil_cloud_e2ee", "tinfoil_v3_cloud", integrationTinfoilE2EEConfig},
		{"tinfoil_direct_plaintext", "tinfoil_v3_direct", integrationTinfoilDirectPlaintextConfig},
		{"tinfoil_direct_e2ee", "tinfoil_v3_direct", integrationTinfoilDirectE2EEConfig},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.build(t)
			if cfg.AllowFail != nil || cfg.GlobalAllowFailDefined {
				t.Fatalf("integration config must not set global allow_fail")
			}
			if len(cfg.ProviderAllowFail) != 0 {
				t.Fatalf("integration config must not set provider allow_fail: %+v", cfg.ProviderAllowFail)
			}
			if providerCfg := cfg.Providers[tt.providerName]; providerCfg == nil {
				t.Fatalf("missing provider %q", tt.providerName)
			}

			got := config.MergedAllowFail(tt.providerName, "", cfg, cfg.Offline)
			want := config.MergedAllowFail(tt.providerName, "", &config.Config{Offline: cfg.Offline}, cfg.Offline)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("effective allow_fail mismatch:\ngot  %v\nwant %v", got, want)
			}
		})
	}
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

func decodeMultimodalContentText(raw json.RawMessage) (content string, fromArray bool, err error) {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return "", false, nil
	}

	var collectText func(v any, sb *strings.Builder)
	collectText = func(v any, sb *strings.Builder) {
		switch x := v.(type) {
		case string:
			sb.WriteString(x)
		case []any:
			for _, child := range x {
				collectText(child, sb)
			}
		case map[string]any:
			if textVal, ok := x["text"]; ok {
				collectText(textVal, sb)
			}
			if contentVal, ok := x["content"]; ok {
				collectText(contentVal, sb)
			}
			if outputTextVal, ok := x["output_text"]; ok {
				collectText(outputTextVal, sb)
			}
		}
	}

	switch raw[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", false, err
		}
		return s, false, nil
	case '[':
		var arr []any
		if err := json.Unmarshal(raw, &arr); err != nil {
			return "", false, err
		}
		var sb strings.Builder
		collectText(arr, &sb)
		return sb.String(), true, nil
	case '{':
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			return "", false, err
		}
		var sb strings.Builder
		collectText(obj, &sb)
		return sb.String(), false, nil
	default:
		return "", false, fmt.Errorf("unexpected content JSON token %q", raw[0])
	}
}

func extractDeltaContentMultimodal(t *testing.T, chunkJSON string) (string, bool) {
	t.Helper()
	var chunk struct {
		Choices []struct {
			Delta struct {
				Content          json.RawMessage `json:"content"`
				ReasoningContent string          `json:"reasoning_content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(chunkJSON), &chunk); err != nil {
		t.Fatalf("unmarshal SSE chunk: %v", err)
	}
	if len(chunk.Choices) == 0 {
		return "", false
	}

	text, fromArray, err := decodeMultimodalContentText(chunk.Choices[0].Delta.Content)
	if err != nil {
		t.Fatalf("decode SSE chunk content: %v", err)
	}
	if text != "" {
		return text, fromArray
	}
	return chunk.Choices[0].Delta.ReasoningContent, false
}

func extractMessageContentMultimodal(t *testing.T, body []byte) (string, bool) {
	t.Helper()
	var resp struct {
		Choices []struct {
			Message struct {
				Content json.RawMessage `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(resp.Choices) == 0 {
		t.Fatal("no choices in response")
	}
	text, fromArray, err := decodeMultimodalContentText(resp.Choices[0].Message.Content)
	if err != nil {
		t.Fatalf("decode message content: %v", err)
	}
	return text, fromArray
}

func assertNonStreamMultimodalResponse(t *testing.T, resp *http.Response, provider string) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	content, fromArray := extractMessageContentMultimodal(t, body)
	if !isPrintableUTF8(content) {
		t.Errorf("content is not valid printable UTF-8: %q", content)
	}
	t.Logf("%s multimodal non-stream response (content array=%v): %q", provider, fromArray, content)
}

func assertStreamMultimodalResponse(t *testing.T, resp *http.Response, provider string) {
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
	sawArrayChunk := false
	for _, c := range chunks {
		text, fromArray := extractDeltaContentMultimodal(t, c)
		sb.WriteString(text)
		if fromArray {
			sawArrayChunk = true
		}
	}
	content := sb.String()
	if !isPrintableUTF8(content) {
		t.Errorf("content is not valid printable UTF-8: %q", content)
	}
	t.Logf("%s multimodal stream response (%d chunks, content array seen=%v): %q", provider, len(chunks), sawArrayChunk, content)
}

// --------------------------------------------------------------------------
// Tool-call integration helpers (provider-agnostic)
// --------------------------------------------------------------------------

// integrationToolCallLeaf captures tool-call leaf fields we validate after relay
// decryption in integration tests.
type integrationToolCallLeaf struct {
	Index     int
	ID        string
	Type      string
	Name      string
	Arguments string
}

func diagnosticBodySnippet(body []byte) string {
	const maxLen = 320
	s := strings.TrimSpace(string(body))
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func diagnosticChunkSnippet(chunks []string) string {
	if len(chunks) == 0 {
		return ""
	}
	const maxChunks = 3
	start := max(0, len(chunks)-maxChunks)
	combined := strings.Join(chunks[start:], "\n")
	return diagnosticBodySnippet([]byte(combined))
}

func assertToolCallLeavesPlaintext(t *testing.T, provider string, calls []integrationToolCallLeaf) {
	t.Helper()
	if len(calls) == 0 {
		t.Fatalf("%s: expected at least one tool call", provider)
	}
	for _, tc := range calls {
		if tc.ID == "" {
			t.Fatalf("%s: tool_call[%d].id is empty", provider, tc.Index)
		}
		if tc.Type != "function" {
			t.Fatalf("%s: tool_call[%d].type = %q, want function", provider, tc.Index, tc.Type)
		}
		if tc.Name == "" {
			t.Fatalf("%s: tool_call[%d].function.name is empty", provider, tc.Index)
		}
		if tc.Arguments == "" {
			t.Fatalf("%s: tool_call[%d].function.arguments is empty", provider, tc.Index)
		}
		if e2ee.IsEncryptedChunkXChaCha20(tc.Name) || e2ee.IsEncryptedChunkVenice(tc.Name) {
			t.Fatalf("%s: tool_call[%d].function.name still looks encrypted: %q", provider, tc.Index, tc.Name)
		}
		if e2ee.IsEncryptedChunkXChaCha20(tc.Arguments) || e2ee.IsEncryptedChunkVenice(tc.Arguments) {
			t.Fatalf("%s: tool_call[%d].function.arguments still looks encrypted", provider, tc.Index)
		}
		if tc.Name != "get_weather" {
			t.Fatalf("%s: tool_call[%d].function.name = %q, want get_weather", provider, tc.Index, tc.Name)
		}
		var args map[string]any
		if err := json.Unmarshal([]byte(tc.Arguments), &args); err != nil {
			t.Fatalf("%s: tool_call[%d].function.arguments not valid JSON: %v; got=%q", provider, tc.Index, err, tc.Arguments)
		}
		if _, ok := args["location"]; !ok {
			t.Fatalf("%s: tool_call[%d].function.arguments missing location key: %q", provider, tc.Index, tc.Arguments)
		}
	}
}

func decodeNonStreamToolCallLeaves(body []byte) ([]integrationToolCallLeaf, error) {
	var parsed struct {
		Choices []struct {
			Message struct {
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
		return nil, err
	}
	if len(parsed.Choices) == 0 {
		return nil, nil
	}
	out := make([]integrationToolCallLeaf, 0, len(parsed.Choices[0].Message.ToolCalls))
	for i, tc := range parsed.Choices[0].Message.ToolCalls {
		out = append(out, integrationToolCallLeaf{
			Index:     i,
			ID:        tc.ID,
			Type:      tc.Type,
			Name:      tc.Function.Name,
			Arguments: tc.Function.Arguments,
		})
	}
	return out, nil
}

func decodeStreamToolCallLeaves(chunks []string) ([]integrationToolCallLeaf, error) {
	type partialToolCall struct {
		ID        string
		Type      string
		Name      strings.Builder
		Arguments strings.Builder
	}
	partials := map[int]*partialToolCall{}

	for _, chunk := range chunks {
		var parsed struct {
			Choices []struct {
				Delta struct {
					ToolCalls []struct {
						ID       string `json:"id"`
						Type     string `json:"type"`
						Index    *int   `json:"index"`
						Function *struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(chunk), &parsed); err != nil {
			return nil, fmt.Errorf("decode stream chunk: %w", err)
		}
		if len(parsed.Choices) == 0 {
			continue
		}
		for j, tc := range parsed.Choices[0].Delta.ToolCalls {
			idx := j
			if tc.Index != nil {
				idx = *tc.Index
			}
			p, ok := partials[idx]
			if !ok {
				p = &partialToolCall{}
				partials[idx] = p
			}
			if tc.ID != "" {
				p.ID = tc.ID
			}
			if tc.Type != "" {
				p.Type = tc.Type
			}
			if tc.Function != nil {
				if tc.Function.Name != "" {
					p.Name.WriteString(tc.Function.Name)
				}
				if tc.Function.Arguments != "" {
					p.Arguments.WriteString(tc.Function.Arguments)
				}
			}
		}
	}

	indexes := make([]int, 0, len(partials))
	for idx := range partials {
		indexes = append(indexes, idx)
	}
	sort.Ints(indexes)
	out := make([]integrationToolCallLeaf, 0, len(indexes))
	for _, idx := range indexes {
		p := partials[idx]
		out = append(out, integrationToolCallLeaf{
			Index:     idx,
			ID:        p.ID,
			Type:      p.Type,
			Name:      p.Name.String(),
			Arguments: p.Arguments.String(),
		})
	}
	return out, nil
}

func assertNonStreamToolCallLeaves(t *testing.T, resp *http.Response, provider string) bool {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	calls, err := decodeNonStreamToolCallLeaves(body)
	if err != nil {
		t.Fatalf("decode non-stream tool calls: %v; body=%s", err, body)
	}
	if len(calls) == 0 {
		t.Logf("%s non-stream response did not include tool calls; snippet=%q", provider, diagnosticBodySnippet(body))
		return false
	}
	assertToolCallLeavesPlaintext(t, provider, calls)
	t.Logf("%s non-stream tool calls verified: %d", provider, len(calls))
	return true
}

func assertStreamToolCallLeaves(t *testing.T, resp *http.Response, provider string) bool {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	chunks := readSSEChunks(t, resp.Body)
	if len(chunks) == 0 {
		t.Fatal("no SSE chunks received")
	}
	calls, err := decodeStreamToolCallLeaves(chunks)
	if err != nil {
		t.Fatalf("decode stream tool calls: %v", err)
	}
	if len(calls) == 0 {
		t.Logf("%s stream response did not include tool calls; chunk_snippet=%q", provider, diagnosticChunkSnippet(chunks))
		return false
	}
	assertToolCallLeavesPlaintext(t, provider, calls)
	t.Logf("%s stream tool calls verified: %d", provider, len(calls))
	return true
}
