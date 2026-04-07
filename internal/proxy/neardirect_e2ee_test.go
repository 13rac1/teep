package proxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Reuses helpers from proxy_test.go:
//   readSSEChunks, extractDeltaContent, extractMessageContent, nonStreamResponse

// TestNeardirectE2EE_ChatStream verifies a streaming chat E2EE round-trip
// through the proxy with the mock neardirect handler.
func TestNeardirectE2EE_ChatStream(t *testing.T) {
	ts := newMockNeardirectE2EEServer(t, true)
	defer ts.Close()

	body := `{"model":"test-model","messages":[{"role":"user","content":"hello world"}],"stream":true}`
	resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, respBody)
	}

	chunks := readSSEChunks(t, resp.Body)
	t.Logf("received %d SSE chunks", len(chunks))
	if len(chunks) == 0 {
		t.Fatal("expected at least one SSE chunk")
	}

	content := extractDeltaContent(t, chunks[0])
	t.Logf("decrypted content: %q", content)
	if !strings.Contains(content, "echo: hello world") {
		t.Errorf("expected echo of input, got %q", content)
	}
}

// TestNeardirectE2EE_ChatNonStream verifies a non-streaming chat E2EE
// round-trip: the mock returns an SSE stream (E2EE always forces streaming)
// and the proxy reassembles it into a single JSON response.
func TestNeardirectE2EE_ChatNonStream(t *testing.T) {
	ts := newMockNeardirectE2EEServer(t, true)
	defer ts.Close()

	body := `{"model":"test-model","messages":[{"role":"user","content":"hello non-stream"}],"stream":false}`
	resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, respBody)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	t.Logf("response body: %s", respBody)

	content := extractMessageContent(t, respBody)
	t.Logf("decrypted content: %q", content)
	if !strings.Contains(content, "echo: hello non-stream") {
		t.Errorf("expected echo of input, got %q", content)
	}
}

// TestNeardirectE2EE_ToolCallNullContent verifies that messages with null
// content (e.g. assistant tool-call messages) pass through encryption
// without error, and that tool_calls fields are preserved.
func TestNeardirectE2EE_ToolCallNullContent(t *testing.T) {
	ts := newMockNeardirectE2EEServer(t, true)
	defer ts.Close()

	body := `{
		"model": "test-model",
		"messages": [
			{"role": "user", "content": "What's the weather?"},
			{"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"}}]},
			{"role": "tool", "tool_call_id": "call_1", "content": "72°F sunny"},
			{"role": "user", "content": "Thanks!"}
		],
		"stream": true
	}`
	resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, respBody)
	}

	chunks := readSSEChunks(t, resp.Body)
	t.Logf("received %d SSE chunks", len(chunks))
	if len(chunks) == 0 {
		t.Fatal("expected at least one SSE chunk")
	}

	content := extractDeltaContent(t, chunks[0])
	t.Logf("decrypted content: %q", content)
	if !strings.Contains(content, "echo: Thanks!") {
		t.Errorf("expected echo of last user message, got %q", content)
	}
}

// TestNeardirectE2EE_ImageGeneration verifies E2EE round-trip for the
// /v1/images/generations endpoint through the neardirect provider.
func TestNeardirectE2EE_ImageGeneration(t *testing.T) {
	ts := newMockNeardirectE2EEServer(t, true)
	defer ts.Close()

	body := `{"model":"test-model","prompt":"a cat sitting on a laptop","n":1,"size":"1024x1024"}`
	resp, err := http.Post(ts.URL+"/v1/images/generations", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, respBody)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	t.Logf("response body: %s", respBody)

	var result struct {
		Created int `json:"created"`
		Data    []struct {
			B64JSON       string `json:"b64_json"`
			RevisedPrompt string `json:"revised_prompt"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(result.Data) == 0 {
		t.Fatal("expected at least one data entry")
	}
	t.Logf("b64_json length: %d", len(result.Data[0].B64JSON))
	t.Logf("revised_prompt: %q", result.Data[0].RevisedPrompt)
	if result.Data[0].B64JSON == "" {
		t.Error("expected non-empty b64_json")
	}
	if result.Data[0].RevisedPrompt != "a cat sitting on a laptop" {
		t.Errorf("expected original prompt in revised_prompt, got %q", result.Data[0].RevisedPrompt)
	}
}

// TestNeardirectE2EE_PlaintextFallback verifies that non-E2EE requests
// still work through the neardirect pinned handler.
func TestNeardirectE2EE_PlaintextFallback(t *testing.T) {
	ts := newMockNeardirectE2EEServer(t, false)
	defer ts.Close()

	body := `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":false}`
	resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, respBody)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	t.Logf("response: %s", respBody)

	content := extractMessageContent(t, respBody)
	if content != "ok" {
		t.Errorf("expected 'ok', got %q", content)
	}
}

// TestNeardirectE2EE_UnsupportedEndpoint verifies that E2EE requests to
// endpoints not supported by nearcloud.NewE2EE (embeddings, audio, rerank)
// fail closed — the encryptor returns an error rather than sending plaintext.
func TestNeardirectE2EE_UnsupportedEndpoint(t *testing.T) {
	ts := newMockNeardirectE2EEServer(t, true)
	defer ts.Close()

	unsupported := []struct {
		path string
		body string
	}{
		{"/v1/embeddings", `{"model":"test-model","input":"hello"}`},
		{"/v1/audio/transcriptions", `{"model":"test-model","file":"data"}`},
		{"/v1/rerank", `{"model":"test-model","query":"hello","documents":["a","b"]}`},
	}

	for _, tc := range unsupported {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := http.Post(ts.URL+tc.path, "application/json", strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("POST %s: %v", tc.path, err)
			}
			defer resp.Body.Close()

			respBody, _ := io.ReadAll(resp.Body)
			t.Logf("status %d: %s", resp.StatusCode, respBody)

			// E2EE should fail for unsupported endpoints — either the proxy
			// rejects before dispatch or the encryptor returns an error.
			if resp.StatusCode == http.StatusOK {
				t.Errorf("expected non-200 for unsupported E2EE endpoint %s, got %d", tc.path, resp.StatusCode)
			}
		})
	}
}
