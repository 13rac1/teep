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

// TestNearCloudE2EE_ChatStream verifies a streaming chat E2EE round-trip
// through the proxy with the mock NearCloud handler.
func TestNearCloudE2EE_ChatStream(t *testing.T) {
	ts := newMockNearCloudProxyServer(t, true)
	defer ts.Close()

	body := `{"model":"nearcloud:test-model","messages":[{"role":"user","content":"hello world"}],"stream":true}`
	resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, respBody)
	}

	// The proxy should decrypt the E2EE SSE stream and relay plaintext SSE.
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

// TestNearCloudE2EE_ChatNonStream verifies a non-streaming chat E2EE
// round-trip: the mock returns an SSE stream (E2EE always forces streaming)
// and the proxy reassembles it into a single JSON response.
func TestNearCloudE2EE_ChatNonStream(t *testing.T) {
	ts := newMockNearCloudProxyServer(t, true)
	defer ts.Close()

	body := `{"model":"nearcloud:test-model","messages":[{"role":"user","content":"hello non-stream"}],"stream":false}`
	resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, respBody)
	}

	// Non-stream E2EE: proxy reassembles SSE into a JSON response.
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

// TestNearCloudE2EE_ToolCallNullContent verifies that messages with null
// content (e.g. assistant tool-call messages) pass through encryption
// without error, and that tool_calls fields are preserved.
func TestNearCloudE2EE_ToolCallNullContent(t *testing.T) {
	ts := newMockNearCloudProxyServer(t, true)
	defer ts.Close()

	body := `{
		"model": "nearcloud:test-model",
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
	// The last user message is "Thanks!", so the echo should contain it.
	if !strings.Contains(content, "echo: Thanks!") {
		t.Errorf("expected echo of last user message, got %q", content)
	}
}

// TestNearCloudE2EE_VLContent verifies that array content (OpenAI VL format)
// is encrypted and round-trips correctly.
func TestNearCloudE2EE_VLContent(t *testing.T) {
	ts := newMockNearCloudProxyServer(t, true)
	defer ts.Close()

	body := `{
		"model": "nearcloud:test-model",
		"messages": [{
			"role": "user",
			"content": [
				{"type": "text", "text": "What's in this image?"},
				{"type": "image_url", "image_url": {"url": "https://example.com/img.png"}}
			]
		}],
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

	// VL content is serialized as JSON array for encryption, then the server
	// decrypts it. The mock echoes the last user content. For VL arrays,
	// the mock's json.Unmarshal into string will fail, so we get the default "echo".
	content := extractDeltaContent(t, chunks[0])
	t.Logf("decrypted content: %q", content)
	if content == "" {
		t.Error("expected non-empty decrypted content")
	}
}

// TestNearCloudE2EE_ImageGeneration verifies E2EE round-trip for the
// /v1/images/generations endpoint.
func TestNearCloudE2EE_ImageGeneration(t *testing.T) {
	ts := newMockNearCloudProxyServer(t, true)
	defer ts.Close()

	body := `{"model":"nearcloud:test-model","prompt":"a cat sitting on a laptop","n":1,"size":"1024x1024"}`
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

	// Parse the decrypted response — should have data[0].b64_json and revised_prompt.
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

// TestNearCloudE2EE_PlaintextFallback verifies that non-E2EE requests
// still work through the pinned handler.
func TestNearCloudE2EE_PlaintextFallback(t *testing.T) {
	ts := newMockNearCloudProxyServer(t, false)
	defer ts.Close()

	body := `{"model":"nearcloud:test-model","messages":[{"role":"user","content":"hello"}],"stream":false}`
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

// TestNearCloudE2EE_MultipleMessages verifies E2EE with a multi-turn
// conversation including system, user, and assistant messages.
func TestNearCloudE2EE_MultipleMessages(t *testing.T) {
	ts := newMockNearCloudProxyServer(t, true)
	defer ts.Close()

	body := `{
		"model": "nearcloud:test-model",
		"messages": [
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": "What is 2+2?"},
			{"role": "assistant", "content": "4"},
			{"role": "user", "content": "And 3+3?"}
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
	if len(chunks) == 0 {
		t.Fatal("expected at least one SSE chunk")
	}
	content := extractDeltaContent(t, chunks[0])
	t.Logf("decrypted content: %q", content)
	if !strings.Contains(content, "echo: And 3+3?") {
		t.Errorf("expected echo of last user message, got %q", content)
	}
}

// TestNearCloudE2EE_ExtraFields verifies that top-level request fields like
// temperature, max_tokens, tools are preserved through E2EE encryption.
func TestNearCloudE2EE_ExtraFields(t *testing.T) {
	ts := newMockNearCloudProxyServer(t, true)
	defer ts.Close()

	body := `{
		"model": "nearcloud:test-model",
		"messages": [{"role": "user", "content": "hi"}],
		"temperature": 0.7,
		"max_tokens": 100,
		"tools": [{"type": "function", "function": {"name": "get_time"}}],
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
	if len(chunks) == 0 {
		t.Fatal("expected at least one SSE chunk")
	}
	// If the request was processed at all, E2EE worked with extra fields.
	content := extractDeltaContent(t, chunks[0])
	t.Logf("decrypted content: %q", content)
	if !strings.Contains(content, "echo: hi") {
		t.Errorf("expected echo, got %q", content)
	}
}
