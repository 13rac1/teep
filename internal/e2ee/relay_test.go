package e2ee

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testVeniceSession creates a Venice session and returns it. The caller
// simulates server-side encryption using EncryptVenice(plaintext, session.ClientPubKey()).
func testVeniceSession(t *testing.T) *VeniceSession {
	t.Helper()
	session, err := NewVeniceSession()
	if err != nil {
		t.Fatalf("NewVeniceSession: %v", err)
	}
	return session
}

// fullFieldVeniceSession wraps a Venice session for tests that need strict
// full-field encryption behavior irrespective of provider protocol defaults.
type fullFieldVeniceSession struct {
	*VeniceSession
}

func (s *fullFieldVeniceSession) IsResponseFieldEncrypted(fieldPath string, endpoint EndpointType) bool {
	// Simulate full-field mode: encrypt everything except metadata
	switch fieldPath {
	case "role", "finish_reason", "index", "object", "created", "id", "system_fingerprint":
		return false
	default:
		return true
	}
}

func testFullFieldVeniceSession(t *testing.T) *fullFieldVeniceSession {
	t.Helper()
	return &fullFieldVeniceSession{VeniceSession: testVeniceSession(t)}
}

// encryptForClient simulates server-side encryption: encrypts plaintext for
// the client's public key so the client's session can decrypt it.
func encryptForClient(t *testing.T, plaintext string, session *VeniceSession) string {
	t.Helper()
	ct, err := EncryptVenice([]byte(plaintext), session.ClientPubKey())
	if err != nil {
		t.Fatalf("EncryptVenice: %v", err)
	}
	return ct
}

func TestIsNonEncryptedField_KnownMetadataAllowed(t *testing.T) {
	for _, key := range []string{"role", "tool_call_id", "type", "finish_reason", "id"} {
		if !IsNonEncryptedField(key) {
			t.Fatalf("IsNonEncryptedField(%q) = false, want true", key)
		}
	}
}

func TestIsNonEncryptedField_IntentionalEncryptedOmissions(t *testing.T) {
	for _, key := range []string{"refusal", "name", "function_call"} {
		if IsNonEncryptedField(key) {
			t.Fatalf("IsNonEncryptedField(%q) = true, want false", key)
		}
	}
}

// sseChunkJSON builds a single SSE data JSON with encrypted content in the delta.
func sseChunkJSON(t *testing.T, encrypted string) string {
	t.Helper()
	chunk := map[string]any{
		"id":    "chatcmpl-1",
		"model": "test-model",
		"choices": []map[string]any{
			{
				"index": 0,
				"delta": map[string]string{
					"role":    "assistant",
					"content": encrypted,
				},
			},
		},
	}
	b, err := json.Marshal(chunk)
	if err != nil {
		t.Fatalf("marshal SSE chunk: %v", err)
	}
	return string(b)
}

// nonStreamJSON builds a non-streaming response with encrypted content in message.
func nonStreamJSON(t *testing.T, encrypted string) []byte {
	t.Helper()
	resp := map[string]any{
		"id":      "chatcmpl-1",
		"model":   "test-model",
		"created": 1234567890,
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": encrypted,
				},
				"finish_reason": "stop",
			},
		},
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal non-stream response: %v", err)
	}
	return b
}

func TestDecryptSSEChunk(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	encrypted := encryptForClient(t, "Hello", session)
	chunkJSON := sseChunkJSON(t, encrypted)
	t.Logf("input chunk: %s", chunkJSON[:80]+"...")

	decrypted, err := DecryptSSEChunk(chunkJSON, session, EndpointChat)
	if err != nil {
		t.Fatalf("DecryptSSEChunk: %v", err)
	}
	t.Logf("decrypted chunk: %s", decrypted)

	// Verify content was decrypted.
	var result struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
				Role    string `json:"role"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(decrypted), &result); err != nil {
		t.Fatalf("unmarshal decrypted: %v", err)
	}
	if len(result.Choices) == 0 {
		t.Fatal("no choices in decrypted output")
	}
	if result.Choices[0].Delta.Content != "Hello" {
		t.Errorf("content = %q, want Hello", result.Choices[0].Delta.Content)
	}
	if result.Choices[0].Delta.Role != "assistant" {
		t.Errorf("role = %q, want assistant", result.Choices[0].Delta.Role)
	}
}

func TestDecryptSSEChunk_NoChoices(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	input := `{"id":"chatcmpl-1","model":"m"}`
	result, err := DecryptSSEChunk(input, session, EndpointChat)
	if err != nil {
		t.Fatalf("DecryptSSEChunk: %v", err)
	}
	if result != input {
		t.Errorf("expected unchanged input, got %q", result)
	}
	t.Logf("no-choices passthrough: %s", result)
}

func TestDecryptSSEChunk_EmptyChoices(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	input := `{"id":"chatcmpl-1","choices":[]}`
	result, err := DecryptSSEChunk(input, session, EndpointChat)
	if err != nil {
		t.Fatalf("DecryptSSEChunk: %v", err)
	}
	if result != input {
		t.Errorf("expected unchanged input, got %q", result)
	}
	t.Logf("empty-choices passthrough: %s", result)
}

func TestDecryptSSEChunk_NoDelta(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	input := `{"id":"chatcmpl-1","choices":[{"index":0}]}`
	result, err := DecryptSSEChunk(input, session, EndpointChat)
	if err != nil {
		t.Fatalf("DecryptSSEChunk: %v", err)
	}
	if result != input {
		t.Errorf("expected unchanged input, got %q", result)
	}
	t.Logf("no-delta passthrough: %s", result)
}

func TestDecryptNonStreamResponse(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	encrypted := encryptForClient(t, "World", session)
	body := nonStreamJSON(t, encrypted)
	t.Logf("encrypted non-stream body: %s", body[:80])

	decrypted, err := DecryptNonStreamResponseForEndpoint(body, session, EndpointImages)
	if err != nil {
		t.Fatalf("DecryptNonStreamResponse: %v", err)
	}
	t.Logf("decrypted: %s", decrypted)

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
				Role    string `json:"role"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(decrypted, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.Choices[0].Message.Content != "World" {
		t.Errorf("content = %q, want World", result.Choices[0].Message.Content)
	}
}

func TestDecryptNonStreamResponse_ContentArrayText(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	encText := encryptForClient(t, "World", session.VeniceSession)
	body := map[string]any{
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]any{
					"role": "assistant",
					"content": []map[string]any{
						{"type": "output_text", "text": encText},
						{"type": "image_url", "image_url": map[string]any{"url": "https://example.invalid/image.png"}},
					},
				},
				"finish_reason": "stop",
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	out, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointChat)
	if err != nil {
		t.Fatalf("DecryptNonStreamResponseForEndpoint: %v", err)
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content []struct {
					Type     string `json:"type"`
					Text     string `json:"text"`
					ImageURL struct {
						URL string `json:"url"`
					} `json:"image_url"`
				} `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(parsed.Choices) != 1 || len(parsed.Choices[0].Message.Content) != 2 {
		t.Fatalf("unexpected content output: %s", out)
	}
	if parsed.Choices[0].Message.Content[0].Text != "World" {
		t.Fatalf("content[0].text = %q, want World", parsed.Choices[0].Message.Content[0].Text)
	}
	if parsed.Choices[0].Message.Content[1].ImageURL.URL != "https://example.invalid/image.png" {
		t.Fatalf("content[1].image_url.url = %q, want preserved URL", parsed.Choices[0].Message.Content[1].ImageURL.URL)
	}
}

func TestDecryptNonStreamResponse_ImageData(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	encB64JSON := encryptForClient(t, "iVBORw0KGgo=", session.VeniceSession)
	encPrompt := encryptForClient(t, "a solid red square", session.VeniceSession)

	resp := map[string]any{
		"created": 1234567890,
		"data": []map[string]any{
			{
				"b64_json":       encB64JSON,
				"revised_prompt": encPrompt,
			},
		},
	}
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	decrypted, err := DecryptNonStreamResponseForEndpoint(body, session, EndpointImages)
	if err != nil {
		t.Fatalf("DecryptNonStreamResponse: %v", err)
	}
	t.Logf("decrypted: %s", decrypted)

	var result struct {
		Data []struct {
			B64JSON       string `json:"b64_json"`
			RevisedPrompt string `json:"revised_prompt"`
		} `json:"data"`
	}
	if err := json.Unmarshal(decrypted, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(result.Data) != 1 {
		t.Fatalf("data length = %d, want 1", len(result.Data))
	}
	if result.Data[0].B64JSON != "iVBORw0KGgo=" {
		t.Errorf("b64_json = %q, want iVBORw0KGgo=", result.Data[0].B64JSON)
	}
	if result.Data[0].RevisedPrompt != "a solid red square" {
		t.Errorf("revised_prompt = %q, want 'a solid red square'", result.Data[0].RevisedPrompt)
	}
}

func TestDecryptNonStreamResponse_NoChoicesNoData(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	body := []byte(`{"object":"list","model":"test"}`)
	result, err := DecryptNonStreamResponseForEndpoint(body, session, EndpointChat)
	if err != nil {
		t.Fatalf("DecryptNonStreamResponse: %v", err)
	}
	if !bytes.Equal(result, body) {
		t.Errorf("expected unchanged body, got %s", result)
	}
}

func TestReassembleNonStream(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	// Build a 3-chunk SSE stream that reassembles to "Hello world!"
	chunks := []string{"Hello", " world", "!"}
	var sb strings.Builder
	for _, chunk := range chunks {
		encrypted := encryptForClient(t, chunk, session)
		data := sseChunkJSON(t, encrypted)
		fmt.Fprintf(&sb, "data: %s\n\n", data)
	}
	sb.WriteString("data: [DONE]\n\n")

	result, ss, err := ReassembleNonStream(strings.NewReader(sb.String()), session, EndpointChat)
	if err != nil {
		t.Fatalf("ReassembleNonStream: %v", err)
	}
	t.Logf("reassembled: %s (chunks=%d, tokens=%d, duration=%s)", result, ss.Chunks, ss.Tokens, ss.Duration)
	if ss.Chunks != len(chunks) {
		t.Errorf("StreamStats.Chunks = %d, want %d", ss.Chunks, len(chunks))
	}
	if ss.Tokens != 0 {
		t.Errorf("StreamStats.Tokens = %d, want 0 (no usage event in fixture)", ss.Tokens)
	}

	var resp struct {
		Object  string `json:"object"`
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		t.Fatalf("unmarshal reassembled: %v", err)
	}
	if resp.Object != "chat.completion" {
		t.Errorf("object = %q, want chat.completion", resp.Object)
	}
	if len(resp.Choices) == 0 {
		t.Fatal("no choices")
	}
	if resp.Choices[0].Message.Content != "Hello world!" {
		t.Errorf("content = %q, want Hello world!", resp.Choices[0].Message.Content)
	}
	if resp.Choices[0].Message.Role != "assistant" {
		t.Errorf("role = %q, want assistant", resp.Choices[0].Message.Role)
	}
	if resp.Choices[0].FinishReason != "stop" {
		t.Errorf("finish_reason = %q, want stop", resp.Choices[0].FinishReason)
	}
}

func TestReassembleNonStream_ToolCalls(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()
	argsPart1 := `{"location"`
	argsPart2 := `: "SF"}`

	// Build SSE stream with reasoning (encrypted) then tool_calls (plaintext).
	reasoning := encryptForClient(t, "Use the weather tool.", session)

	var sb strings.Builder

	// Chunk 1: reasoning content (encrypted).
	chunk1 := map[string]any{
		"id": "chatcmpl-1", "model": "test-model", "created": 1234567890,
		"choices": []map[string]any{{
			"index": 0,
			"delta": map[string]any{
				"reasoning":         reasoning,
				"reasoning_content": reasoning,
			},
		}},
	}
	b1, _ := json.Marshal(chunk1)
	fmt.Fprintf(&sb, "data: %s\n\n", b1)

	// Chunk 2: first tool_call delta with id, type, name.
	chunk2 := map[string]any{
		"id": "chatcmpl-1", "model": "test-model", "created": 1234567890,
		"choices": []map[string]any{{
			"index": 0,
			"delta": map[string]any{
				"tool_calls": []map[string]any{{
					"id": "call-abc", "type": "function", "index": 0,
					"function": map[string]string{"name": "get_weather", "arguments": ""},
				}},
			},
		}},
	}
	b2, _ := json.Marshal(chunk2)
	fmt.Fprintf(&sb, "data: %s\n\n", b2)

	// Chunk 3: tool_call arguments fragment.
	chunk3 := map[string]any{
		"id": "chatcmpl-1", "model": "test-model", "created": 1234567890,
		"choices": []map[string]any{{
			"index": 0,
			"delta": map[string]any{
				"tool_calls": []map[string]any{{
					"index":    0,
					"function": map[string]string{"arguments": argsPart1},
				}},
			},
		}},
	}
	b3, _ := json.Marshal(chunk3)
	fmt.Fprintf(&sb, "data: %s\n\n", b3)

	// Chunk 4: tool_call arguments fragment.
	chunk4 := map[string]any{
		"id": "chatcmpl-1", "model": "test-model", "created": 1234567890,
		"choices": []map[string]any{{
			"index": 0,
			"delta": map[string]any{
				"tool_calls": []map[string]any{{
					"index":    0,
					"function": map[string]string{"arguments": argsPart2},
				}},
			},
		}},
	}
	b4, _ := json.Marshal(chunk4)
	fmt.Fprintf(&sb, "data: %s\n\n", b4)

	// Chunk 5: finish_reason = "tool_calls".
	chunk5 := map[string]any{
		"id": "chatcmpl-1", "model": "test-model", "created": 1234567890,
		"choices": []map[string]any{{
			"index":         0,
			"delta":         map[string]any{},
			"finish_reason": "tool_calls",
		}},
	}
	b5, _ := json.Marshal(chunk5)
	fmt.Fprintf(&sb, "data: %s\n\n", b5)

	sb.WriteString("data: [DONE]\n\n")

	result, _, err := ReassembleNonStream(strings.NewReader(sb.String()), session, EndpointChat)
	if err != nil {
		t.Fatalf("ReassembleNonStream: %v", err)
	}
	t.Logf("reassembled: %s", result)

	var resp struct {
		Choices []struct {
			Message struct {
				Role      string `json:"role"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Choices) == 0 {
		t.Fatal("no choices")
	}
	if resp.Choices[0].FinishReason != "tool_calls" {
		t.Errorf("finish_reason = %q, want tool_calls", resp.Choices[0].FinishReason)
	}
	if len(resp.Choices[0].Message.ToolCalls) != 1 {
		t.Fatalf("tool_calls len = %d, want 1", len(resp.Choices[0].Message.ToolCalls))
	}
	tc := resp.Choices[0].Message.ToolCalls[0]
	if tc.ID != "call-abc" {
		t.Errorf("tool_call.id = %q, want call-abc", tc.ID)
	}
	if tc.Type != "function" {
		t.Errorf("tool_call.type = %q, want function", tc.Type)
	}
	if tc.Function.Name != "get_weather" {
		t.Errorf("tool_call.function.name = %q, want get_weather", tc.Function.Name)
	}
	wantArgs := `{"location": "SF"}`
	if tc.Function.Arguments != wantArgs {
		t.Errorf("tool_call.function.arguments = %q, want %q", tc.Function.Arguments, wantArgs)
	}
}

func TestReassembleNonStream_MultipleToolCalls(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()
	argsA := `{"x":1}`
	argsB := `{"y":2}`

	var sb strings.Builder

	// Two tool calls in parallel (different indices).
	chunk1 := map[string]any{
		"id": "chatcmpl-1", "model": "test-model", "created": 1234567890,
		"choices": []map[string]any{{
			"index": 0,
			"delta": map[string]any{
				"tool_calls": []map[string]any{
					{"id": "call-1", "type": "function", "index": 0, "function": map[string]string{"name": "fn_a", "arguments": ""}},
					{"id": "call-2", "type": "function", "index": 1, "function": map[string]string{"name": "fn_b", "arguments": ""}},
				},
			},
		}},
	}
	b1, _ := json.Marshal(chunk1)
	fmt.Fprintf(&sb, "data: %s\n\n", b1)

	// Arguments for both calls.
	chunk2 := map[string]any{
		"id": "chatcmpl-1", "model": "test-model", "created": 1234567890,
		"choices": []map[string]any{{
			"index": 0,
			"delta": map[string]any{
				"tool_calls": []map[string]any{
					{"index": 0, "function": map[string]string{"arguments": argsA}},
					{"index": 1, "function": map[string]string{"arguments": argsB}},
				},
			},
		}},
	}
	b2, _ := json.Marshal(chunk2)
	fmt.Fprintf(&sb, "data: %s\n\n", b2)

	// Final chunk.
	chunk3 := map[string]any{
		"id": "chatcmpl-1", "model": "test-model", "created": 1234567890,
		"choices": []map[string]any{{
			"index":         0,
			"delta":         map[string]any{},
			"finish_reason": "tool_calls",
		}},
	}
	b3, _ := json.Marshal(chunk3)
	fmt.Fprintf(&sb, "data: %s\n\n", b3)
	sb.WriteString("data: [DONE]\n\n")

	result, _, err := ReassembleNonStream(strings.NewReader(sb.String()), session, EndpointChat)
	if err != nil {
		t.Fatalf("ReassembleNonStream: %v", err)
	}
	t.Logf("reassembled: %s", result)

	var resp struct {
		Choices []struct {
			Message struct {
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Choices[0].Message.ToolCalls) != 2 {
		t.Fatalf("tool_calls len = %d, want 2", len(resp.Choices[0].Message.ToolCalls))
	}
	if resp.Choices[0].Message.ToolCalls[0].Function.Name != "fn_a" {
		t.Errorf("first tool call name = %q, want fn_a", resp.Choices[0].Message.ToolCalls[0].Function.Name)
	}
	if resp.Choices[0].Message.ToolCalls[1].Function.Name != "fn_b" {
		t.Errorf("second tool call name = %q, want fn_b", resp.Choices[0].Message.ToolCalls[1].Function.Name)
	}
	if resp.Choices[0].FinishReason != "tool_calls" {
		t.Errorf("finish_reason = %q, want tool_calls", resp.Choices[0].FinishReason)
	}
}

func TestRelayStream(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	encrypted := encryptForClient(t, "streamed", session)
	data := sseChunkJSON(t, encrypted)
	input := fmt.Sprintf("data: %s\n\ndata: [DONE]\n\n", data)

	rec := httptest.NewRecorder()
	_, err := RelayStream(context.Background(), rec, strings.NewReader(input), session, EndpointChat)
	if err != nil {
		t.Fatalf("RelayStream: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}

	body := rec.Body.String()
	t.Logf("relay output:\n%s", body)

	if !strings.Contains(body, `"content":"streamed"`) {
		t.Error("decrypted content not found in relay output")
	}
	if !strings.Contains(body, "data: [DONE]") {
		t.Error("[DONE] marker not found in relay output")
	}
}

func TestRelayStream_NilSession(t *testing.T) {
	input := "data: {\"choices\":[{\"delta\":{\"content\":\"plain\"}}]}\n\ndata: [DONE]\n\n"
	rec := httptest.NewRecorder()
	_, err := RelayStream(context.Background(), rec, strings.NewReader(input), nil, EndpointChat)
	if err != nil {
		t.Fatalf("RelayStream: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	t.Logf("plaintext relay:\n%s", body)
	if !strings.Contains(body, `"content":"plain"`) {
		t.Error("plaintext content not found")
	}
}

func TestRelayNonStream_NilSession(t *testing.T) {
	input := `{"choices":[{"message":{"content":"hello"}}]}`
	rec := httptest.NewRecorder()
	_, err := RelayNonStreamForEndpoint(context.Background(), rec, strings.NewReader(input), nil, EndpointChat)
	if err != nil {
		t.Fatalf("RelayNonStream: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	t.Logf("plaintext non-stream: %s", body)
	if body != input {
		t.Errorf("body mismatch: got %q, want %q", body, input)
	}
}

func TestRelayNonStream_Encrypted(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	encrypted := encryptForClient(t, "decrypted-content", session)
	body := nonStreamJSON(t, encrypted)

	rec := httptest.NewRecorder()
	_, err := RelayNonStreamForEndpoint(context.Background(), rec, strings.NewReader(string(body)), session, EndpointChat)
	if err != nil {
		t.Fatalf("RelayNonStream: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	output := rec.Body.String()
	t.Logf("decrypted non-stream: %s", output)
	if !strings.Contains(output, `"content":"decrypted-content"`) {
		t.Error("decrypted content not found")
	}
}

func TestRelayReassembledNonStream(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	encrypted := encryptForClient(t, "reassembled", session)
	data := sseChunkJSON(t, encrypted)
	input := fmt.Sprintf("data: %s\n\ndata: [DONE]\n\n", data)

	rec := httptest.NewRecorder()
	_, err := RelayReassembledNonStream(context.Background(), rec, strings.NewReader(input), session, EndpointChat)
	if err != nil {
		t.Fatalf("RelayReassembledNonStream: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	output := rec.Body.String()
	t.Logf("reassembled non-stream: %s", output)
	if !strings.Contains(output, `"content":"reassembled"`) {
		t.Error("reassembled content not found")
	}
	if !strings.Contains(output, `"object":"chat.completion"`) {
		t.Error("expected chat.completion object")
	}
}

func TestRelayReassembledNonStream_DecryptError(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	// Provide a chunk with unencrypted content — will trigger IsEncryptedChunk failure.
	chunk := `{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"role":"assistant","content":"plaintext-not-encrypted"}}]}`
	body := fmt.Sprintf("data: %s\n\ndata: [DONE]\n\n", chunk)
	rec := httptest.NewRecorder()
	_, err := RelayReassembledNonStream(context.Background(), rec, strings.NewReader(body), session, EndpointChat)
	if err == nil {
		t.Fatal("expected error for unencrypted content")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("error should wrap ErrDecryptionFailed, got: %v", err)
	}
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	t.Logf("relay reassembled decrypt error: %v", err)
}

func TestRelayStream_EmptyBody(t *testing.T) {
	rec := httptest.NewRecorder()
	_, err := RelayStream(context.Background(), rec, strings.NewReader(""), nil, EndpointChat)
	if err == nil {
		t.Fatal("RelayStream with empty body should return non-nil error")
	}
	if !errors.Is(err, ErrRelayFailed) {
		t.Errorf("error should wrap ErrRelayFailed, got: %v", err)
	}

	// Empty body should produce a bad gateway error.
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	t.Logf("empty body response: %d %s", rec.Code, rec.Body.String())
}

// sseChunkJSONMultiField builds an SSE chunk with multiple encrypted fields in delta.
func sseChunkJSONMultiField(t *testing.T, fields map[string]string) string {
	t.Helper()
	delta := map[string]string{"role": "assistant"}
	maps.Copy(delta, fields)
	chunk := map[string]any{
		"id":    "chatcmpl-1",
		"model": "test-model",
		"choices": []map[string]any{
			{
				"index": 0,
				"delta": delta,
			},
		},
	}
	b, err := json.Marshal(chunk)
	if err != nil {
		t.Fatalf("marshal SSE chunk: %v", err)
	}
	return string(b)
}

func TestDecryptSSEChunk_MultipleEncryptedFields(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	encContent := encryptForClient(t, "Hello", session)
	encReasoning := encryptForClient(t, "thinking...", session)

	chunkJSON := sseChunkJSONMultiField(t, map[string]string{
		"content":           encContent,
		"reasoning_content": encReasoning,
	})
	t.Logf("input chunk size: %d bytes", len(chunkJSON))

	decrypted, err := DecryptSSEChunk(chunkJSON, session, EndpointChat)
	if err != nil {
		t.Fatalf("DecryptSSEChunk: %v", err)
	}
	t.Logf("decrypted: %s", decrypted)

	var result struct {
		Choices []struct {
			Delta struct {
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
				Role             string `json:"role"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(decrypted), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.Choices[0].Delta.Content != "Hello" {
		t.Errorf("content = %q, want Hello", result.Choices[0].Delta.Content)
	}
	if result.Choices[0].Delta.ReasoningContent != "thinking..." {
		t.Errorf("reasoning_content = %q, want thinking...", result.Choices[0].Delta.ReasoningContent)
	}
	if result.Choices[0].Delta.Role != "assistant" {
		t.Errorf("role = %q, want assistant", result.Choices[0].Delta.Role)
	}
}

func TestDecryptSSEChunk_SpecialCharsInPlaintext(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	plaintext := "He said \"hello\" and\nnewline\ttab<html>&amp;"
	encrypted := encryptForClient(t, plaintext, session)
	chunkJSON := sseChunkJSON(t, encrypted)

	decrypted, err := DecryptSSEChunk(chunkJSON, session, EndpointChat)
	if err != nil {
		t.Fatalf("DecryptSSEChunk: %v", err)
	}
	t.Logf("decrypted: %s", decrypted)

	var result struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(decrypted), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.Choices[0].Delta.Content != plaintext {
		t.Errorf("content = %q, want %q", result.Choices[0].Delta.Content, plaintext)
	}
}

func TestDecryptSSEChunk_LargeContent(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	// Generate 100KB+ plaintext.
	large := strings.Repeat("Hello, this is a large token. ", 4000)
	t.Logf("plaintext size: %d bytes", len(large))

	encrypted := encryptForClient(t, large, session)
	chunkJSON := sseChunkJSON(t, encrypted)
	t.Logf("encrypted chunk size: %d bytes", len(chunkJSON))

	decrypted, err := DecryptSSEChunk(chunkJSON, session, EndpointChat)
	if err != nil {
		t.Fatalf("DecryptSSEChunk: %v", err)
	}

	var result struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(decrypted), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.Choices[0].Delta.Content != large {
		t.Errorf("content length = %d, want %d", len(result.Choices[0].Delta.Content), len(large))
	}
	t.Logf("large content decrypted correctly (%d bytes)", len(result.Choices[0].Delta.Content))
}

func TestDecryptSSEChunk_PreservesNonDeltaFields(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	encrypted := encryptForClient(t, "test", session)
	// Build a chunk with extra top-level and choice-level fields.
	// Build JSON with encrypted content embedded directly (encrypted is hex, no escaping needed).
	chunk := `{"id":"chatcmpl-99","object":"chat.completion.chunk","created":12345,"model":"gpt-4","system_fingerprint":"fp_abc","choices":[{"index":0,"delta":{"role":"assistant","content":"` + encrypted + `"},"logprobs":null,"finish_reason":null}]}`

	decrypted, err := DecryptSSEChunk(chunk, session, EndpointChat)
	if err != nil {
		t.Fatalf("DecryptSSEChunk: %v", err)
	}
	t.Logf("decrypted: %s", decrypted)

	// Verify non-delta fields are preserved.
	var result map[string]json.RawMessage
	if err := json.Unmarshal([]byte(decrypted), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"id", "object", "created", "model", "system_fingerprint"} {
		if _, ok := result[key]; !ok {
			t.Errorf("missing top-level key %q", key)
		}
	}

	// Verify content was decrypted.
	if !strings.Contains(decrypted, `"content":"test"`) {
		t.Error("decrypted content not found")
	}
	// Verify non-delta choice fields preserved.
	if !strings.Contains(decrypted, `"logprobs":null`) {
		t.Error("logprobs not preserved")
	}
}

func TestDecryptSSEChunk_EncryptedExtendedDeltaFields(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	encContent := encryptForClient(t, "hello", session)
	encRefusal := encryptForClient(t, "not allowed", session)
	encFnName := encryptForClient(t, "get_weather", session)
	encFnArgs := encryptForClient(t, `{"city":"SF"}`, session)
	encAudio := encryptForClient(t, "BASE64AUDIO", session)
	encFCName := encryptForClient(t, "legacy_fn", session)
	encFCArgs := encryptForClient(t, `{"k":1}`, session)

	chunk := map[string]any{
		"id":    "chatcmpl-1",
		"model": "test-model",
		"choices": []map[string]any{
			{
				"index": 0,
				"delta": map[string]any{
					"role":    "assistant",
					"content": encContent,
					"refusal": encRefusal,
					"audio": map[string]any{
						"data": encAudio,
					},
					"tool_calls": []map[string]any{
						{
							"index": 0,
							"function": map[string]any{
								"name":      encFnName,
								"arguments": encFnArgs,
							},
						},
					},
					"function_call": map[string]any{
						"name":      encFCName,
						"arguments": encFCArgs,
					},
				},
			},
		},
	}
	b, err := json.Marshal(chunk)
	if err != nil {
		t.Fatalf("marshal chunk: %v", err)
	}

	decrypted, err := DecryptSSEChunk(string(b), session, EndpointChat)
	if err != nil {
		t.Fatalf("DecryptSSEChunk: %v", err)
	}

	var out struct {
		Choices []struct {
			Delta struct {
				Content      string `json:"content"`
				Refusal      string `json:"refusal"`
				FunctionCall struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function_call"`
				Audio struct {
					Data string `json:"data"`
				} `json:"audio"`
				ToolCalls []struct {
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(decrypted), &out); err != nil {
		t.Fatalf("unmarshal decrypted chunk: %v", err)
	}
	if out.Choices[0].Delta.Content != "hello" {
		t.Errorf("content = %q, want hello", out.Choices[0].Delta.Content)
	}
	if out.Choices[0].Delta.Refusal != "not allowed" {
		t.Errorf("refusal = %q, want not allowed", out.Choices[0].Delta.Refusal)
	}
	// Venice only requires content to be encrypted in production. The refusal field
	// was also encrypted in this fixture to exercise the optional-field decryption path.
	// Other fields (audio.data, tool_calls, function_call) arrive encrypted here but
	// are not decrypted by Venice — verify they remain as ciphertext.
	if out.Choices[0].Delta.Audio.Data == "BASE64AUDIO" {
		t.Errorf("audio.data should remain encrypted for Venice, got plaintext: %q", out.Choices[0].Delta.Audio.Data)
	}
	if out.Choices[0].Delta.FunctionCall.Name == "legacy_fn" {
		t.Errorf("function_call.name should remain encrypted for Venice, got plaintext: %q", out.Choices[0].Delta.FunctionCall.Name)
	}
	if out.Choices[0].Delta.FunctionCall.Arguments == `{"k":1}` {
		t.Errorf("function_call.arguments should remain encrypted for Venice, got plaintext: %q", out.Choices[0].Delta.FunctionCall.Arguments)
	}
	if len(out.Choices[0].Delta.ToolCalls) > 0 {
		if out.Choices[0].Delta.ToolCalls[0].Function.Name == "get_weather" {
			t.Errorf("tool_calls[0].function.name should remain encrypted for Venice, got plaintext: %q", out.Choices[0].Delta.ToolCalls[0].Function.Name)
		}
		if out.Choices[0].Delta.ToolCalls[0].Function.Arguments == `{"city":"SF"}` {
			t.Errorf("tool_calls[0].function.arguments should remain encrypted for Venice, got plaintext: %q", out.Choices[0].Delta.ToolCalls[0].Function.Arguments)
		}
	}
}

func TestDecryptNonStreamResponse_EncryptedLogprobs(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	encContent := encryptForClient(t, "ok", session.VeniceSession)
	encToken := encryptForClient(t, "hello", session.VeniceSession)
	encBytes := encryptForClient(t, "[104,101,108,108,111]", session.VeniceSession)
	encTopToken := encryptForClient(t, "world", session.VeniceSession)
	encTopBytes := encryptForClient(t, "[119,111,114,108,100]", session.VeniceSession)

	body := map[string]any{
		"id":    "chatcmpl-1",
		"model": "test-model",
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]any{
					"role":    "assistant",
					"content": encContent,
				},
				"logprobs": map[string]any{
					"content": []map[string]any{
						{
							"token": encToken,
							"bytes": encBytes,
							"top_logprobs": []map[string]any{
								{
									"token": encTopToken,
									"bytes": encTopBytes,
								},
							},
						},
					},
				},
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	decrypted, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointChat)
	if err != nil {
		t.Fatalf("DecryptNonStreamResponse: %v", err)
	}

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Logprobs struct {
				Content []struct {
					Token       string `json:"token"`
					Bytes       []int  `json:"bytes"`
					TopLogprobs []struct {
						Token string `json:"token"`
						Bytes []int  `json:"bytes"`
					} `json:"top_logprobs"`
				} `json:"content"`
			} `json:"logprobs"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(decrypted, &out); err != nil {
		t.Fatalf("unmarshal decrypted response: %v", err)
	}
	if out.Choices[0].Message.Content != "ok" {
		t.Errorf("content = %q, want ok", out.Choices[0].Message.Content)
	}
	if out.Choices[0].Logprobs.Content[0].Token != "hello" {
		t.Errorf("token = %q, want hello", out.Choices[0].Logprobs.Content[0].Token)
	}
	if len(out.Choices[0].Logprobs.Content[0].Bytes) != 5 || out.Choices[0].Logprobs.Content[0].Bytes[0] != 104 {
		t.Errorf("bytes = %v, want [104 101 108 108 111]", out.Choices[0].Logprobs.Content[0].Bytes)
	}
	if out.Choices[0].Logprobs.Content[0].TopLogprobs[0].Token != "world" {
		t.Errorf("top token = %q, want world", out.Choices[0].Logprobs.Content[0].TopLogprobs[0].Token)
	}
}

func TestDecryptChoiceLogprobs_DoesNotRewriteUntouchedBranch(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	encRefusalToken := encryptForClient(t, "blocked", session.VeniceSession)
	choice := map[string]json.RawMessage{
		// content contains duplicate keys. If this branch is unnecessarily re-marshaled,
		// duplicate keys collapse and this exact token sequence disappears.
		"logprobs": json.RawMessage(`{"content":[{"dup":1,"dup":2}],"refusal":[{"token":"` + encRefusalToken + `"}]}`),
	}

	changed, err := decryptChoiceLogprobs(choice, session, "choice[0]", EndpointChat)
	if err != nil {
		t.Fatalf("decryptChoiceLogprobs: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true when refusal token is decrypted")
	}

	var logprobs map[string]json.RawMessage
	if err := json.Unmarshal(choice["logprobs"], &logprobs); err != nil {
		t.Fatalf("unmarshal logprobs: %v", err)
	}

	contentRaw := string(logprobs["content"])
	if !strings.Contains(contentRaw, `"dup":1,"dup":2`) {
		t.Fatalf("content branch was rewritten unexpectedly: %s", contentRaw)
	}

	var refusal []struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(logprobs["refusal"], &refusal); err != nil {
		t.Fatalf("unmarshal refusal: %v", err)
	}
	if len(refusal) != 1 || refusal[0].Token != "blocked" {
		t.Fatalf("unexpected refusal token output: %s", logprobs["refusal"])
	}
}

func TestDecryptDeltaFields_PlaintextRefusalRejected(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	fields := map[string]json.RawMessage{
		"role":    json.RawMessage(`"assistant"`),
		"refusal": json.RawMessage(`"none"`),
	}

	changed, err := decryptChatObject(fields, session, "test", EndpointChat)
	if err == nil {
		t.Fatal("expected error for plaintext refusal")
	}
	if !strings.Contains(err.Error(), "test.refusal: expected encrypted") {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Error("changed = true, want false on rejection")
	}
}

func TestDecryptDeltaFields_PlaintextNameRejected(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	fields := map[string]json.RawMessage{
		"role": json.RawMessage(`"assistant"`),
		"name": json.RawMessage(`"bot"`),
	}

	changed, err := decryptChatObject(fields, session, "test", EndpointChat)
	if err == nil {
		t.Fatal("expected error for plaintext name")
	}
	if !strings.Contains(err.Error(), "test.name: expected encrypted") {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Error("changed = true, want false on rejection")
	}
}

func TestDecryptDeltaFields_VeniceAllowsPlaintextRefusalAndName(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	fields := map[string]json.RawMessage{
		"role":    json.RawMessage(`"assistant"`),
		"name":    json.RawMessage(`"bot"`),
		"refusal": json.RawMessage(`"none"`),
	}

	changed, err := decryptChatObject(fields, session, "test", EndpointChat)
	if err != nil {
		t.Fatalf("unexpected error for Venice plaintext fields: %v", err)
	}
	if changed {
		t.Error("changed = true, want false for plaintext passthrough")
	}
}

func TestDecryptDeltaFields_RequiredNonStringRejectedInFullFieldMode(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	tests := []struct {
		name    string
		raw     json.RawMessage
		wantTyp string
	}{
		{name: "object", raw: json.RawMessage(`{"nested":"value"}`), wantTyp: "object"},
		{name: "array", raw: json.RawMessage(`["value"]`), wantTyp: "array"},
		{name: "number", raw: json.RawMessage(`123`), wantTyp: "number"},
		{name: "boolean", raw: json.RawMessage(`true`), wantTyp: "boolean"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fields := map[string]json.RawMessage{
				"role":    json.RawMessage(`"assistant"`),
				"content": tc.raw,
			}

			changed, err := decryptChatObject(fields, session, "test", EndpointChat)
			if err == nil {
				t.Fatal("expected error for non-string required field")
			}
			wantErr := "test.content: expected encrypted string or content-part array, got " + tc.wantTyp
			if tc.name == "array" {
				wantErr = "test.content[0]: expected object, got string"
			}
			if !strings.Contains(err.Error(), wantErr) {
				t.Fatalf("unexpected error: %v", err)
			}
			if changed {
				t.Error("changed = true, want false on rejection")
			}
		})
	}
}

func TestDecryptDeltaFields_VeniceContentStillRejectsNonString(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	fields := map[string]json.RawMessage{
		"role":    json.RawMessage(`"assistant"`),
		"content": json.RawMessage(`123`),
	}

	changed, err := decryptChatObject(fields, session, "test", EndpointChat)
	if err == nil {
		t.Fatal("expected error for non-string Venice content")
	}
	if !strings.Contains(err.Error(), "test.content: expected encrypted string or content-part array, got number") {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Error("changed = true, want false on rejection")
	}
}

func TestDecryptDeltaFields_FullFieldContentArrayRejectsNonObjectPart(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	fields := map[string]json.RawMessage{
		"role":    json.RawMessage(`"assistant"`),
		"content": json.RawMessage(`["value"]`),
	}

	changed, err := decryptChatObject(fields, session, "test", EndpointChat)
	if err == nil {
		t.Fatal("expected error for invalid content-part array")
	}
	if !strings.Contains(err.Error(), "test.content[0]: expected object, got string") {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Error("changed = true, want false on rejection")
	}
}

func TestDecryptDeltaFields_VeniceRejectsContentArray(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	fields := map[string]json.RawMessage{
		"role":    json.RawMessage(`"assistant"`),
		"content": json.RawMessage(`[{"type":"output_text","text":"plaintext"}]`),
	}

	changed, err := decryptChatObject(fields, session, "test", EndpointChat)
	if err == nil {
		t.Fatal("expected error for array content in Venice mode")
	}
	if !strings.Contains(err.Error(), "test.content: expected encrypted string but got array") {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Error("changed = true, want false on rejection")
	}
}

func TestDecryptDeltaFields_NullContentAllowedInFullFieldMode(t *testing.T) {
	// OpenAI spec: choices[].message.content and choices[].delta.content are
	// string|null. The NearCloud/NearDirect server explicitly does NOT encrypt
	// null — it skips null the same way it skips absent fields. Teep must treat
	// null as absent and not fail closed on a perfectly valid tool-call response.
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	for _, field := range []string{"content", "refusal", "reasoning_content"} {
		t.Run(field, func(t *testing.T) {
			fields := map[string]json.RawMessage{
				"role": json.RawMessage(`"assistant"`),
				field:  json.RawMessage(`null`),
			}

			changed, err := decryptChatObject(fields, session, "test", EndpointChat)
			if err != nil {
				t.Fatalf("unexpected error for null %s in full-field mode: %v", field, err)
			}
			if changed {
				t.Error("changed = true, want false for null passthrough")
			}
			// Null value must be preserved unchanged.
			if string(fields[field]) != "null" {
				t.Errorf("fields[%q] = %s, want null", field, fields[field])
			}
		})
	}
}

func TestDecryptDeltaFields_VeniceOptionalNonStringPassthrough(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	fields := map[string]json.RawMessage{
		"role":    json.RawMessage(`"assistant"`),
		"refusal": json.RawMessage(`123`),
	}

	changed, err := decryptChatObject(fields, session, "test", EndpointChat)
	if err != nil {
		t.Fatalf("unexpected error for optional non-string Venice field: %v", err)
	}
	if changed {
		t.Error("changed = true, want false for passthrough")
	}
	if string(fields["refusal"]) != `123` {
		t.Fatalf("refusal was rewritten unexpectedly: %s", string(fields["refusal"]))
	}
}

func TestDecryptSSEChunk_FunctionCallPlaintextAcceptedForVenice(t *testing.T) {
	// This test verifies that for protocols supporting full-field encryption,
	// plaintext nested fields are rejected. For Venice, which doesn't encrypt
	// these fields, plaintext is allowed and accepted without error.
	session := testVeniceSession(t)
	defer session.Zero()

	encArgs := encryptForClient(t, `{"k":1}`, session)
	chunk := map[string]any{
		"choices": []map[string]any{
			{
				"delta": map[string]any{
					"function_call": map[string]any{
						"name":      "legacy_fn",
						"arguments": encArgs,
					},
				},
			},
		},
	}
	b, err := json.Marshal(chunk)
	if err != nil {
		t.Fatalf("marshal chunk: %v", err)
	}

	// For Venice, plaintext nested fields don't cause an error; they're just left as-is
	_, err = DecryptSSEChunk(string(b), session, EndpointChat)
	if err != nil {
		t.Fatalf("unexpected error for Venice with plaintext nested field: %v", err)
	}
}

func TestDecryptSSEChunk_ToolCallPlaintextArgumentsAcceptedForVenice(t *testing.T) {
	// This test verifies that for protocols supporting full-field encryption,
	// plaintext nested fields are rejected. For Venice, which doesn't encrypt
	// these fields, plaintext is allowed and accepted without error.
	session := testVeniceSession(t)
	defer session.Zero()

	encName := encryptForClient(t, "get_weather", session)
	chunk := map[string]any{
		"choices": []map[string]any{
			{
				"delta": map[string]any{
					"tool_calls": []map[string]any{
						{
							"function": map[string]any{
								"name":      encName,
								"arguments": `{"city":"SF"}`,
							},
						},
					},
				},
			},
		},
	}
	b, err := json.Marshal(chunk)
	if err != nil {
		t.Fatalf("marshal chunk: %v", err)
	}

	// For Venice, plaintext nested fields don't cause an error; they're just left as-is
	_, err = DecryptSSEChunk(string(b), session, EndpointChat)
	if err != nil {
		t.Fatalf("unexpected error for Venice with plaintext nested field: %v", err)
	}
}

func TestDecryptNonStreamResponse_LogprobsPlaintextTokenRejected(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	encContent := encryptForClient(t, "ok", session.VeniceSession)
	body := map[string]any{
		"choices": []map[string]any{
			{
				"message": map[string]any{"content": encContent},
				"logprobs": map[string]any{
					"content": []map[string]any{
						{
							"token": "plaintext-token",
							"bytes": []int{112, 116},
						},
					},
				},
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	_, err = DecryptNonStreamResponseForEndpoint(b, session, EndpointChat)
	if err == nil {
		t.Fatal("expected error for plaintext logprobs token")
	}
	if !strings.Contains(err.Error(), "logprobs.content[0].token: expected encrypted") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptNonStreamResponse_LogprobsNonStringTokenRejected(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	encContent := encryptForClient(t, "ok", session.VeniceSession)
	body := map[string]any{
		"choices": []map[string]any{
			{
				"message": map[string]any{"content": encContent},
				"logprobs": map[string]any{
					"content": []map[string]any{
						{
							"token": map[string]any{"unexpected": true},
							"bytes": []int{112, 116},
						},
					},
				},
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	_, err = DecryptNonStreamResponseForEndpoint(b, session, EndpointChat)
	if err == nil {
		t.Fatal("expected error for non-string logprobs token")
	}
	if !strings.Contains(err.Error(), "logprobs.content[0].token: expected encrypted string") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptNonStreamResponse_LogprobsPlaintextBytesStringRejected(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	encContent := encryptForClient(t, "ok", session.VeniceSession)
	encToken := encryptForClient(t, "hello", session.VeniceSession)
	body := map[string]any{
		"choices": []map[string]any{
			{
				"message": map[string]any{"content": encContent},
				"logprobs": map[string]any{
					"content": []map[string]any{
						{
							"token": encToken,
							"bytes": "plaintext-bytes",
						},
					},
				},
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	_, err = DecryptNonStreamResponseForEndpoint(b, session, EndpointChat)
	if err == nil {
		t.Fatal("expected error for plaintext logprobs bytes string")
	}
	if !strings.Contains(err.Error(), "logprobs.content[0].bytes: expected encrypted string") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDecryptNonStreamResponse_LogprobsPlaintextBytesArrayRejected verifies that
// plaintext JSON arrays in logprobs.*.bytes are rejected in full-field E2EE mode,
// rather than silently passed through as they were before the fix.
func TestDecryptNonStreamResponse_LogprobsPlaintextBytesArrayRejected(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	encContent := encryptForClient(t, "ok", session.VeniceSession)
	encToken := encryptForClient(t, "hello", session.VeniceSession)
	body := map[string]any{
		"choices": []map[string]any{
			{
				"message": map[string]any{"content": encContent},
				"logprobs": map[string]any{
					"content": []map[string]any{
						{
							"token": encToken,
							// bytes is a plaintext JSON array, not an encrypted string
							"bytes": []int{72, 101, 108, 108, 111}, // ["H", "e", "l", "l", "o"] in UTF-8
						},
					},
				},
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	_, err = DecryptNonStreamResponseForEndpoint(b, session, EndpointChat)
	if err == nil {
		t.Fatal("expected error for plaintext logprobs bytes array in full-field mode")
	}
	if !strings.Contains(err.Error(), "logprobs.content[0].bytes: expected encrypted string") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDecryptNonStreamResponse_LogprobsPlaintextBytesStringPassthrough verifies that
// a Venice session (no logprobs bytes encryption) passes through a plaintext string bytes
// value without error, consistent with policy-driven fail-closed behaviour.
func TestDecryptNonStreamResponse_LogprobsPlaintextBytesStringPassthrough(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	encContent := encryptForClient(t, "ok", session)
	body := map[string]any{
		"choices": []map[string]any{
			{
				"message": map[string]any{"content": encContent},
				"logprobs": map[string]any{
					"content": []map[string]any{
						{
							"token": "hello",
							"bytes": "plaintext-bytes-string",
						},
					},
				},
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	_, err = DecryptNonStreamResponseForEndpoint(b, session, EndpointChat)
	if err != nil {
		t.Fatalf("expected passthrough for plaintext bytes string in Venice session, got: %v", err)
	}
}

// TestDecryptNonStreamResponse_LogprobsBytesDecryptedWrongTypePassthrough verifies that
// after a successful MAC-validated decrypt, a non-array-of-numbers payload is accepted
// without error (the type assertion was incorrect after MAC auth).
func TestDecryptNonStreamResponse_LogprobsBytesDecryptedWrongTypePassthrough(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	encContent := encryptForClient(t, "ok", session.VeniceSession)
	encToken := encryptForClient(t, "hello", session.VeniceSession)
	// Encrypt a string payload (not an array of numbers) for the bytes field.
	encBytes := encryptForClient(t, `"unexpected-string"`, session.VeniceSession)
	body := map[string]any{
		"choices": []map[string]any{
			{
				"message": map[string]any{"content": encContent},
				"logprobs": map[string]any{
					"content": []map[string]any{
						{
							"token": encToken,
							"bytes": encBytes,
						},
					},
				},
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	_, err = DecryptNonStreamResponseForEndpoint(b, session, EndpointChat)
	if err != nil {
		t.Fatalf("expected passthrough for wrong-type decrypted bytes, got: %v", err)
	}
}

func TestDecryptNonStreamResponse_EmbeddingsPlaintextPassthrough(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	body := map[string]any{
		"data": []map[string]any{
			{
				"embedding": []float64{0.1, 0.2, 0.3},
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	out, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointEmbeddings)
	if err != nil {
		t.Fatalf("unexpected error for plaintext embeddings response: %v", err)
	}

	var parsed struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(parsed.Data) != 1 || len(parsed.Data[0].Embedding) != 3 || parsed.Data[0].Embedding[0] != 0.1 {
		t.Fatalf("unexpected embeddings output: %s", out)
	}
}

func TestDecryptNonStreamResponse_EmbeddingsBase64StringPassthrough(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	body := map[string]any{
		"data": []map[string]any{
			{
				"embedding": "AQIDBA==",
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	out, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointEmbeddings)
	if err != nil {
		t.Fatalf("unexpected error for base64 embeddings response: %v", err)
	}

	var parsed struct {
		Data []struct {
			Embedding string `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(parsed.Data) != 1 || parsed.Data[0].Embedding != "AQIDBA==" {
		t.Fatalf("unexpected embeddings output: %s", out)
	}
}

func TestDecryptNonStreamResponse_EmbeddingsNullPassthrough(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	body := map[string]any{
		"data": []map[string]any{
			{
				"embedding": nil,
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	out, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointEmbeddings)
	if err != nil {
		t.Fatalf("unexpected error for null embeddings field: %v", err)
	}

	var parsed struct {
		Data []struct {
			Embedding any `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(parsed.Data) != 1 || parsed.Data[0].Embedding != nil {
		t.Fatalf("unexpected embeddings output: %s", out)
	}
}

func TestDecryptNonStreamResponse_RerankPlaintextPassthrough(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	body := map[string]any{
		"results": []map[string]any{
			{
				"document": map[string]any{
					"text": "plaintext-rerank-text",
				},
				"index":           0,
				"relevance_score": 0.9,
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	out, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointRerank)
	if err != nil {
		t.Fatalf("unexpected error for plaintext rerank document text: %v", err)
	}

	var parsed struct {
		Results []struct {
			Document struct {
				Text string `json:"text"`
			} `json:"document"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(parsed.Results) != 1 || parsed.Results[0].Document.Text != "plaintext-rerank-text" {
		t.Fatalf("unexpected rerank output: %s", out)
	}
}

func TestDecryptNonStreamResponse_RerankDocumentStringPassthrough(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	body := map[string]any{
		"results": []map[string]any{
			{
				"document":        "plain-document",
				"index":           0,
				"relevance_score": 0.9,
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	out, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointRerank)
	if err != nil {
		t.Fatalf("unexpected error for string rerank document: %v", err)
	}

	var parsed struct {
		Results []struct {
			Document string `json:"document"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(parsed.Results) != 1 || parsed.Results[0].Document != "plain-document" {
		t.Fatalf("unexpected rerank output: %s", out)
	}
}

func TestDecryptNonStreamResponse_EmbeddingsPlaintextRejectedForFullFieldSession(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	body := map[string]any{
		"data": []map[string]any{
			{
				"embedding": []float64{0.1, 0.2, 0.3},
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	_, err = DecryptNonStreamResponseForEndpoint(b, session, EndpointEmbeddings)
	if err == nil {
		t.Fatal("expected error for plaintext embedding in full-field session")
	}
	if !strings.Contains(err.Error(), "data[0].embedding: expected encrypted string") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptNonStreamResponse_RerankPlaintextRejectedForFullFieldSession(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	body := map[string]any{
		"results": []map[string]any{
			{
				"document": map[string]any{
					"text": "plaintext-rerank-text",
				},
				"index":           0,
				"relevance_score": 0.9,
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	_, err = DecryptNonStreamResponseForEndpoint(b, session, EndpointRerank)
	if err == nil {
		t.Fatal("expected error for plaintext rerank text in full-field session")
	}
	if !strings.Contains(err.Error(), "results[0].document.text: expected encrypted string") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptNonStreamResponse_RerankNullTextPassthrough(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	body := map[string]any{
		"results": []map[string]any{
			{
				"document": map[string]any{
					"text": nil,
				},
				"index":           0,
				"relevance_score": 0.9,
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	out, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointRerank)
	if err != nil {
		t.Fatalf("unexpected error for null rerank document text: %v", err)
	}

	var parsed struct {
		Results []struct {
			Document struct {
				Text *string `json:"text"`
			} `json:"document"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(parsed.Results) != 1 || parsed.Results[0].Document.Text != nil {
		t.Fatalf("unexpected rerank output: %s", out)
	}
}

func TestDecryptNonStreamResponse_ScorePlaintextAccepted(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	body := map[string]any{
		"data": []map[string]any{
			{
				"score": 0.42,
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	out, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointChat)
	if err != nil {
		t.Fatalf("unexpected error for plaintext score response: %v", err)
	}

	var parsed struct {
		Data []struct {
			Score float64 `json:"score"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(parsed.Data) != 1 || parsed.Data[0].Score != 0.42 {
		t.Fatalf("unexpected score output: %s", out)
	}
}

func TestDecryptNonStreamResponse_ScoreNullPassthrough(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	body := map[string]any{
		"data": []map[string]any{
			{
				"score": nil,
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	out, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointScore)
	if err != nil {
		t.Fatalf("unexpected error for null score field: %v", err)
	}

	var parsed struct {
		Data []struct {
			Score any `json:"score"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(parsed.Data) != 1 || parsed.Data[0].Score != nil {
		t.Fatalf("unexpected score output: %s", out)
	}
}

func TestDecryptNonStreamResponse_ScorePlaintextAccepted_WhenChoicesDecrypted(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	encContent := encryptForClient(t, "assistant plaintext", session)
	body := map[string]any{
		"choices": []map[string]any{
			{
				"message": map[string]any{
					"role":    "assistant",
					"content": encContent,
				},
			},
		},
		"data": []map[string]any{
			{
				"score": 0.42,
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	out, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointChat)
	if err != nil {
		t.Fatalf("unexpected error when choice decrypts and score is plaintext: %v", err)
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Data []struct {
			Score float64 `json:"score"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(parsed.Choices) != 1 || parsed.Choices[0].Message.Content != "assistant plaintext" {
		t.Fatalf("unexpected choices output: %s", out)
	}
	if len(parsed.Data) != 1 || parsed.Data[0].Score != 0.42 {
		t.Fatalf("unexpected score output: %s", out)
	}
}

func TestDecryptNonStreamResponseForEndpoint_EmbeddingsMalformedDataRejected(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	body := []byte(`{"data":{"embedding":"unexpected"}}`)
	_, err := DecryptNonStreamResponseForEndpoint(body, session, EndpointEmbeddings)
	if err == nil {
		t.Fatal("expected error for malformed embeddings data shape")
	}
	if !strings.Contains(err.Error(), "parse data as embeddings array") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptNonStreamResponseForEndpoint_ScoreMalformedDataRejected(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	body := []byte(`{"data":{"score":"unexpected"}}`)
	_, err := DecryptNonStreamResponseForEndpoint(body, session, EndpointScore)
	if err == nil {
		t.Fatal("expected error for malformed score data shape")
	}
	if !strings.Contains(err.Error(), "parse data as score array") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptNonStreamResponseForEndpoint_EmbeddingsMissingFieldRejected(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	body := map[string]any{
		"data": []map[string]any{{"index": 0}},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	_, err = DecryptNonStreamResponseForEndpoint(b, session, EndpointEmbeddings)
	if err == nil {
		t.Fatal("expected error for embeddings item missing required field")
	}
	if !strings.Contains(err.Error(), "data[0].embedding: missing") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptNonStreamResponseForEndpoint_ScoreMissingFieldRejected(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	body := map[string]any{
		"data": []map[string]any{{"index": 0}},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	_, err = DecryptNonStreamResponseForEndpoint(b, session, EndpointScore)
	if err == nil {
		t.Fatal("expected error for score item missing required field")
	}
	if !strings.Contains(err.Error(), "data[0].score: missing") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptNonStreamResponseForEndpoint_EmbeddingsDecryptedWrongTypePassthrough(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	encEmbedding := encryptForClient(t, `{"unexpected":true}`, session)
	body := map[string]any{
		"data": []map[string]any{{"embedding": encEmbedding}},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	out, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointEmbeddings)
	if err != nil {
		t.Fatalf("unexpected error for decrypted embeddings alternative shape: %v", err)
	}

	var parsed struct {
		Data []struct {
			Embedding map[string]bool `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(parsed.Data) != 1 || !parsed.Data[0].Embedding["unexpected"] {
		t.Fatalf("unexpected embeddings output: %s", out)
	}
}

func TestDecryptNonStreamResponseForEndpoint_ScoreDecryptedWrongTypePassthrough(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	encScore := encryptForClient(t, `{"unexpected":true}`, session)
	body := map[string]any{
		"data": []map[string]any{{"score": encScore}},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	out, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointScore)
	if err != nil {
		t.Fatalf("unexpected error for decrypted score alternative shape: %v", err)
	}

	var parsed struct {
		Data []struct {
			Score map[string]bool `json:"score"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(parsed.Data) != 1 || !parsed.Data[0].Score["unexpected"] {
		t.Fatalf("unexpected score output: %s", out)
	}
}

// benchVeniceSession creates a Venice session for benchmarks (no *testing.T).
func benchVeniceSession(b *testing.B) *VeniceSession {
	b.Helper()
	session, err := NewVeniceSession()
	if err != nil {
		b.Fatalf("NewVeniceSession: %v", err)
	}
	return session
}

// benchEncryptForClient encrypts plaintext for benchmarks (no *testing.T).
func benchEncryptForClient(b *testing.B, plaintext string, session *VeniceSession) string {
	b.Helper()
	ct, err := EncryptVenice([]byte(plaintext), session.ClientPubKey())
	if err != nil {
		b.Fatalf("EncryptVenice: %v", err)
	}
	return ct
}

// benchSSEChunkJSON builds an SSE chunk JSON for benchmarks.
func benchSSEChunkJSON(b *testing.B, encrypted string) string {
	b.Helper()
	chunk := map[string]any{
		"id":    "chatcmpl-1",
		"model": "test-model",
		"choices": []map[string]any{
			{
				"index": 0,
				"delta": map[string]string{
					"role":    "assistant",
					"content": encrypted,
				},
			},
		},
	}
	out, err := json.Marshal(chunk)
	if err != nil {
		b.Fatalf("marshal SSE chunk: %v", err)
	}
	return string(out)
}

func BenchmarkDecryptSSEChunk(b *testing.B) {
	session := benchVeniceSession(b)
	defer session.Zero()

	encrypted := benchEncryptForClient(b, "Hello, world! This is a typical streaming token.", session)
	chunkJSON := benchSSEChunkJSON(b, encrypted)
	b.Logf("chunk size: %d bytes", len(chunkJSON))

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		result, err := DecryptSSEChunk(chunkJSON, session, EndpointChat)
		if err != nil {
			b.Fatalf("DecryptSSEChunk: %v", err)
		}
		if result == "" {
			b.Fatal("empty result")
		}
	}
}

func BenchmarkDecryptSSEChunk_Parallel(b *testing.B) {
	session := benchVeniceSession(b)
	defer session.Zero()

	encrypted := benchEncryptForClient(b, "Hello, world! This is a typical streaming token.", session)
	chunkJSON := benchSSEChunkJSON(b, encrypted)

	b.ResetTimer()
	b.ReportAllocs()
	var firstErr atomic.Value
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			result, err := DecryptSSEChunk(chunkJSON, session, EndpointChat)
			if err != nil {
				firstErr.CompareAndSwap(nil, err)
				return
			}
			if result == "" {
				firstErr.CompareAndSwap(nil, errors.New("empty result"))
				return
			}
		}
	})
	if err := firstErr.Load(); err != nil {
		b.Fatalf("parallel DecryptSSEChunk: %v", err)
	}
}

func TestDecryptDeltaFields_EmptyStringSkipped(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	fields := map[string]json.RawMessage{
		"content": json.RawMessage(`""`),
	}

	changed, err := decryptChatObject(fields, session, "test", EndpointChat)
	if err != nil {
		t.Fatalf("decryptChatObject: %v", err)
	}
	if changed {
		t.Error("expected no changes for empty string")
	}
}

func TestEffectiveTokens(t *testing.T) {
	tests := []struct {
		name   string
		tokens int
		chunks int
		want   int
	}{
		{"tokens available", 42, 10, 42},
		{"tokens zero, falls back to chunks", 0, 10, 10},
		{"both zero", 0, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ss := &StreamStats{Tokens: tc.tokens, Chunks: tc.chunks}
			got := ss.EffectiveTokens()
			if got != tc.want {
				t.Errorf("EffectiveTokens() = %d, want %d", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Relay error sentinel tests
// ---------------------------------------------------------------------------

func TestRelayStream_NoFlusher_ReturnsRelayFailed(t *testing.T) {
	// Writer that does not implement http.Flusher.
	w := &noFlushWriter{}
	_, err := RelayStream(context.Background(), w, strings.NewReader("data: {}\n\n"), nil, EndpointChat)
	if err == nil {
		t.Fatal("expected non-nil error when writer lacks Flusher")
	}
	if !errors.Is(err, ErrRelayFailed) {
		t.Errorf("error should wrap ErrRelayFailed, got: %v", err)
	}
	if errors.Is(err, ErrDecryptionFailed) {
		t.Error("error should NOT be ErrDecryptionFailed")
	}
}

func TestRelayStream_ScannerError_ReturnsRelayFailed(t *testing.T) {
	_, err := RelayStream(context.Background(), httptest.NewRecorder(), &failReader{}, nil, EndpointChat)
	if err == nil {
		t.Fatal("expected non-nil error on scanner failure")
	}
	if !errors.Is(err, ErrRelayFailed) {
		t.Errorf("error should wrap ErrRelayFailed, got: %v", err)
	}
}

func TestRelayNonStream_ReadError_ReturnsRelayFailed(t *testing.T) {
	_, err := RelayNonStreamForEndpoint(context.Background(), httptest.NewRecorder(), &failReader{}, nil, EndpointChat)
	if err == nil {
		t.Fatal("expected non-nil error on read failure")
	}
	if !errors.Is(err, ErrRelayFailed) {
		t.Errorf("error should wrap ErrRelayFailed, got: %v", err)
	}
}

func TestRelayNonStream_DecryptError_ReturnsDecryptionFailed(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	// Build a non-stream response with a fake encrypted content that passes
	// IsEncryptedChunkVenice (≥186 hex chars starting with "04") but fails Decrypt.
	fakeEncrypted := "04" + strings.Repeat("ab", 92) // 186 hex chars
	body := fmt.Sprintf(
		`{"choices":[{"message":{"role":"assistant","content":%q}}]}`,
		fakeEncrypted,
	)
	rec := httptest.NewRecorder()
	_, err := RelayNonStreamForEndpoint(context.Background(), rec, strings.NewReader(body), session, EndpointChat)
	if err == nil {
		t.Fatal("expected error for decryption failure")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("error should wrap ErrDecryptionFailed, got: %v", err)
	}
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	t.Logf("RelayNonStream decrypt error: %v", err)
}

func TestRelayStream_DecryptError_ReturnsDecryptionFailed(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	// Build an SSE data line with fake encrypted content that passes
	// IsEncryptedChunkVenice (≥186 hex chars starting with "04") but fails Decrypt.
	fakeEncrypted := "04" + strings.Repeat("ab", 92) // 186 hex chars
	chunk := fmt.Sprintf(`{"id":"1","choices":[{"delta":{"content":%q}}]}`, fakeEncrypted)
	sseBody := fmt.Sprintf("data: %s\n\n", chunk)

	rec := httptest.NewRecorder()
	_, err := RelayStream(context.Background(), rec, strings.NewReader(sseBody), session, EndpointChat)
	if err == nil {
		t.Fatal("expected error for decryption failure")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("error should wrap ErrDecryptionFailed, got: %v", err)
	}
	t.Logf("RelayStream decrypt error: %v", err)
}

func TestErrSentinels_Distinct(t *testing.T) {
	if errors.Is(ErrRelayFailed, ErrDecryptionFailed) {
		t.Error("ErrRelayFailed should not match ErrDecryptionFailed")
	}
	if errors.Is(ErrDecryptionFailed, ErrRelayFailed) {
		t.Error("ErrDecryptionFailed should not match ErrRelayFailed")
	}
}

// noFlushWriter is an http.ResponseWriter that does not implement http.Flusher.
type noFlushWriter struct {
	code int
	body []byte
}

func (w *noFlushWriter) Header() http.Header { return http.Header{} }
func (w *noFlushWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return len(b), nil
}
func (w *noFlushWriter) WriteHeader(code int) { w.code = code }

// failReader always returns an error on Read.
type failReader struct{}

func (*failReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

// failAfterReader succeeds for the first read (returning data) then fails.
type failAfterReader struct {
	data []byte
	read bool
}

func (r *failAfterReader) Read(p []byte) (int, error) {
	if !r.read {
		r.read = true
		n := copy(p, r.data)
		return n, nil
	}
	return 0, errors.New("mid-stream read failure")
}

func TestRelayStream_MidStreamScannerError_ReturnsRelayFailed(t *testing.T) {
	// First scan succeeds (valid SSE line), then scanner hits a read error.
	// The scanner.Err() at end of RelayStream should return ErrRelayFailed.
	data := []byte("data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n")
	r := &failAfterReader{data: data}

	rec := httptest.NewRecorder()
	_, err := RelayStream(context.Background(), rec, r, nil, EndpointChat)
	if err == nil {
		t.Fatal("expected non-nil error on mid-stream scanner failure")
	}
	if !errors.Is(err, ErrRelayFailed) {
		t.Errorf("error should wrap ErrRelayFailed, got: %v", err)
	}
	if errors.Is(err, ErrDecryptionFailed) {
		t.Error("error should NOT be ErrDecryptionFailed")
	}
}

func TestMergeToolCallDelta_MissingIndex(t *testing.T) {
	calls := make(map[int]*reassembledToolCall)

	// Delta with no "index" field → should error.
	raw := []byte(`{"id":"call_1","type":"function","function":{"name":"foo","arguments":""}}`)
	err := mergeToolCallDelta(calls, raw)
	if err == nil {
		t.Fatal("expected error for missing index")
	}
	if !strings.Contains(err.Error(), "missing required index") {
		t.Errorf("unexpected error: %v", err)
	}
	if len(calls) != 0 {
		t.Errorf("calls map should be empty after error, got %d entries", len(calls))
	}
}

func TestMergeToolCallDelta_NullIndex(t *testing.T) {
	calls := make(map[int]*reassembledToolCall)

	// Delta with explicit null index → should error.
	raw := []byte(`{"id":"call_1","type":"function","index":null,"function":{"name":"foo","arguments":""}}`)
	err := mergeToolCallDelta(calls, raw)
	if err == nil {
		t.Fatal("expected error for null index")
	}
	if !strings.Contains(err.Error(), "missing required index") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMergeToolCallDelta_ValidIndex(t *testing.T) {
	calls := make(map[int]*reassembledToolCall)

	raw := []byte(`{"id":"call_1","type":"function","index":0,"function":{"name":"foo","arguments":"bar"}}`)
	if err := mergeToolCallDelta(calls, raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(calls))
	}
	tc := calls[0]
	if tc.ID != "call_1" || tc.Function.Name != "foo" || tc.Function.Arguments != "bar" {
		t.Errorf("unexpected tool call: %+v", tc)
	}
}

// ---------------------------------------------------------------------------
// DecryptSSEChunk: malformed choices and delta parse errors
// ---------------------------------------------------------------------------

func TestDecryptSSEChunk_ChoicesNotArray(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	input := `{"choices": "not-an-array", "id": "test"}`
	t.Logf("input: %s", input)

	_, err := DecryptSSEChunk(input, session, EndpointChat)
	if err == nil {
		t.Fatal("expected error when choices is not an array")
	}
	if !strings.Contains(err.Error(), "parse choices array") {
		t.Errorf("unexpected error message: %v", err)
	}
	t.Logf("got expected error: %v", err)
}

func TestDecryptSSEChunk_DeltaNotObject(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	input := `{"choices":[{"delta":"not-an-object"}]}`
	t.Logf("input: %s", input)

	_, err := DecryptSSEChunk(input, session, EndpointChat)
	if err == nil {
		t.Fatal("expected error when delta is not an object")
	}
	if !strings.Contains(err.Error(), "parse delta object") {
		t.Errorf("unexpected error message: %v", err)
	}
	t.Logf("got expected error: %v", err)
}

// ---------------------------------------------------------------------------
// decryptSSEChunkContent: targeted coverage of each error/early-return branch
// ---------------------------------------------------------------------------

func TestDecryptSSEChunkContent_InvalidJSON(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	t.Logf("calling decryptSSEChunkContent with invalid JSON")
	_, err := decryptSSEChunkContent("not-valid-json", session, EndpointChat)
	if err == nil {
		t.Fatal("expected error for invalid JSON input")
	}
	if !strings.Contains(err.Error(), "parse SSE chunk JSON") {
		t.Errorf("unexpected error message: %v", err)
	}
	t.Logf("got expected error: %v", err)
}

func TestDecryptSSEChunkContent_NoChoicesKey(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	t.Logf("calling decryptSSEChunkContent with empty object (no choices key)")
	result, err := decryptSSEChunkContent("{}", session, EndpointChat)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty map, got %v", result)
	}
	t.Logf("got empty map as expected")
}

func TestDecryptSSEChunkContent_ChoicesNotArray(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	input := `{"choices": 42}`
	t.Logf("calling decryptSSEChunkContent with choices=42 (not an array)")
	_, err := decryptSSEChunkContent(input, session, EndpointChat)
	if err == nil {
		t.Fatal("expected error when choices is not an array")
	}
	if !strings.Contains(err.Error(), "parse choices array") {
		t.Errorf("unexpected error message: %v", err)
	}
	t.Logf("got expected error: %v", err)
}

func TestDecryptSSEChunkContent_EmptyChoices(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	input := `{"choices":[]}`
	t.Logf("calling decryptSSEChunkContent with empty choices array")
	result, err := decryptSSEChunkContent(input, session, EndpointChat)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty map, got %v", result)
	}
	t.Logf("got empty map as expected")
}

func TestDecryptSSEChunkContent_NoDeltaKey(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	input := `{"choices":[{}]}`
	t.Logf("calling decryptSSEChunkContent with choices[0] missing delta key")
	result, err := decryptSSEChunkContent(input, session, EndpointChat)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty map, got %v", result)
	}
	t.Logf("got empty map as expected")
}

func TestDecryptSSEChunkContent_DeltaNotObject(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	input := `{"choices":[{"delta":"not-an-object"}]}`
	t.Logf("calling decryptSSEChunkContent with delta as a string (not an object)")
	_, err := decryptSSEChunkContent(input, session, EndpointChat)
	if err == nil {
		t.Fatal("expected error when delta is not an object")
	}
	if !strings.Contains(err.Error(), "parse delta object") {
		t.Errorf("unexpected error message: %v", err)
	}
	t.Logf("got expected error: %v", err)
}

// ---------------------------------------------------------------------------
// testDecryptor: a minimal Decryptor mock for relay tests.
// ---------------------------------------------------------------------------

type testDecryptor struct {
	isEncrypted func(string) bool
	decrypt     func(string) ([]byte, error)
}

func (m *testDecryptor) IsEncryptedChunk(val string) bool  { return m.isEncrypted(val) }
func (m *testDecryptor) Decrypt(ct string) ([]byte, error) { return m.decrypt(ct) }

func (m *testDecryptor) IsResponseFieldEncrypted(fieldPath string, endpoint EndpointType) bool {
	switch fieldPath {
	case "role", "finish_reason", "index", "object", "created", "id", "system_fingerprint":
		return false
	default:
		return true
	}
}
func (m *testDecryptor) Zero() {}

// ---------------------------------------------------------------------------
// recordChunk with usage tokens (line 55-57)
// ---------------------------------------------------------------------------

func TestRecordChunk_WithUsage(t *testing.T) {
	var stats StreamStats
	var firstChunk time.Time
	data := `{"usage":{"completion_tokens":42,"prompt_tokens":10,"total_tokens":52}}`
	stats.recordChunk(data, &firstChunk)
	t.Logf("recordChunk tokens=%d chunks=%d", stats.Tokens, stats.Chunks)
	if stats.Tokens != 42 {
		t.Errorf("Tokens = %d, want 42", stats.Tokens)
	}
}

// ---------------------------------------------------------------------------
// decryptResponseChoices edge cases
// ---------------------------------------------------------------------------

func TestDecryptResponseChoices_NoMessage(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()
	// choice with no "message" key - should be skipped
	choicesJSON := `[{"index":0,"no_message":true}]`
	out, err := decryptResponseChoices(json.RawMessage(choicesJSON), session, EndpointChat)
	t.Logf("decryptResponseChoices(no message): out=%v err=%v", out, err)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != nil {
		t.Errorf("expected nil output when nothing changed, got %s", out)
	}
}

func TestDecryptResponseChoices_BadMessageJSON(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()
	choicesJSON := `[{"message": "not-an-object"}]`
	_, err := decryptResponseChoices(json.RawMessage(choicesJSON), session, EndpointChat)
	t.Logf("decryptResponseChoices(bad message): err=%v", err)
	if err == nil {
		t.Fatal("expected error for non-object message")
	}
}

// ---------------------------------------------------------------------------
// decryptResponseImageData edge cases
// ---------------------------------------------------------------------------

// TestDecryptResponseImageData_FieldNotString: field present but not a string
// (e.g. a number) - should continue without error and return nil.
func TestDecryptResponseImageData_FieldNotString(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()
	dataJSON := `[{"b64_json": 123}]`
	out, err := decryptResponseImageData(json.RawMessage(dataJSON), session, EndpointImages)
	t.Logf("decryptResponseImageData(not string): out=%v err=%v", out, err)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != nil {
		t.Errorf("expected nil (nothing changed), got: %s", out)
	}
}

// TestDecryptResponseImageData_FieldNotEncrypted: field present but not an
// encrypted chunk - should continue without error and return nil.
func TestDecryptResponseImageData_FieldNotEncrypted(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()
	dataJSON := `[{"b64_json": "plaintext_not_encrypted"}]`
	out, err := decryptResponseImageData(json.RawMessage(dataJSON), session, EndpointImages)
	t.Logf("decryptResponseImageData(not encrypted): out=%v err=%v", out, err)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != nil {
		t.Errorf("expected nil (nothing changed), got: %s", out)
	}
}

// TestDecryptResponseImageData_DecryptError: decrypt error in image data.
func TestDecryptResponseImageData_DecryptError(t *testing.T) {
	decryptErr := errors.New("simulated decrypt error")
	mock := &testDecryptor{
		isEncrypted: func(s string) bool { return true },
		decrypt:     func(s string) ([]byte, error) { return nil, decryptErr },
	}
	dataJSON := `[{"b64_json": "some_encrypted_value"}]`
	_, err := decryptResponseImageData(json.RawMessage(dataJSON), mock, EndpointImages)
	t.Logf("decryptResponseImageData(decrypt error): err=%v", err)
	if err == nil {
		t.Fatal("expected error from decrypt failure")
	}
}

func TestDecryptResponseImageData_MalformedShapeFailsClosed(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	dataJSON := `{"b64_json": "plaintext_not_encrypted"}`
	_, err := decryptResponseImageData(json.RawMessage(dataJSON), session, EndpointImages)
	if err == nil {
		t.Fatal("expected error for malformed image data shape")
	}
	if !strings.Contains(err.Error(), "parse data as image array") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptResponseImageData_PlaintextRejectedForFullFieldSession(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	dataJSON := `[{"b64_json": "plaintext_not_encrypted"}]`
	_, err := decryptResponseImageData(json.RawMessage(dataJSON), session, EndpointImages)
	if err == nil {
		t.Fatal("expected error for plaintext image field in full-field session")
	}
	if !strings.Contains(err.Error(), "data[0].b64_json: expected encrypted string") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// decryptSSEChunkContent with decrypt error
// ---------------------------------------------------------------------------

func TestDecryptSSEChunkContent_DecryptError(t *testing.T) {
	decryptErr := errors.New("decrypt failed")
	mock := &testDecryptor{
		isEncrypted: func(s string) bool { return true },
		decrypt:     func(s string) ([]byte, error) { return nil, decryptErr },
	}
	// chunk with a "content" field in delta that the mock claims is encrypted
	data := `{"choices":[{"delta":{"content":"some_encrypted_value"}}]}`
	_, err := decryptSSEChunkContent(data, mock, EndpointChat)
	t.Logf("decryptSSEChunkContent(decrypt error): err=%v", err)
	if err == nil {
		t.Fatal("expected error from decrypt failure")
	}
}

func TestDecryptSSEChunkContent_VeniceAllowsPlaintextNameAndRefusal(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	input := `{"choices":[{"delta":{"role":"assistant","name":"bot","refusal":"none"}}]}`
	result, err := decryptSSEChunkContent(input, session, EndpointChat)
	if err != nil {
		t.Fatalf("unexpected error for Venice plaintext optional fields: %v", err)
	}
	if result["name"] != "bot" {
		t.Fatalf("name = %q, want plaintext bot", result["name"])
	}
	if result["refusal"] != "none" {
		t.Fatalf("refusal = %q, want plaintext none", result["refusal"])
	}
}

func TestDecryptNonStreamResponse_ScorePlaintextRejectedForFullFieldSession(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	body := map[string]any{
		"data": []map[string]any{{"score": 0.42}},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	_, err = DecryptNonStreamResponseForEndpoint(b, session, EndpointScore)
	if err == nil {
		t.Fatal("expected error for plaintext score on full-field session")
	}
	if !strings.Contains(err.Error(), "data[0].score: expected encrypted string") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// nearCloudLikeSession simulates a full-field session that has the NearCloud
// score-endpoint exception: data[].score is plaintext on /v1/score only.
type nearCloudLikeSession struct {
	*fullFieldVeniceSession
}

func (s *nearCloudLikeSession) IsResponseFieldEncrypted(fieldPath string, endpoint EndpointType) bool {
	if endpoint == EndpointScore && fieldPath == "score" {
		return false
	}
	return s.fullFieldVeniceSession.IsResponseFieldEncrypted(fieldPath, endpoint)
}

func testNearCloudLikeSession(t *testing.T) *nearCloudLikeSession {
	t.Helper()
	return &nearCloudLikeSession{fullFieldVeniceSession: testFullFieldVeniceSession(t)}
}

// logprobsPathAwareSession lets tests vary policy by canonical logprobs leaf path.
// It intentionally allows plaintext content bytes but requires encrypted refusal bytes.
type logprobsPathAwareSession struct {
	*fullFieldVeniceSession
}

func (s *logprobsPathAwareSession) IsResponseFieldEncrypted(fieldPath string, endpoint EndpointType) bool {
	switch fieldPath {
	case "logprobs.content[].token":
		return false
	case "logprobs.content[].bytes":
		return false
	case "logprobs.refusal[].bytes":
		return true
	default:
		return s.fullFieldVeniceSession.IsResponseFieldEncrypted(fieldPath, endpoint)
	}
}

func testLogprobsPathAwareSession(t *testing.T) *logprobsPathAwareSession {
	t.Helper()
	return &logprobsPathAwareSession{fullFieldVeniceSession: testFullFieldVeniceSession(t)}
}

// TestDecryptNonStreamResponseForEndpoint_ScorePlaintext_EndpointThreaded verifies
// that the endpoint path is forwarded to decryptResponseScoreData rather than being
// hard-coded. A NearCloud-like session allows plaintext score on /v1/score but should
// reject it when no endpoint is provided (via DecryptNonStreamResponse).
func TestDecryptNonStreamResponseForEndpoint_ScorePlaintext_EndpointThreaded(t *testing.T) {
	session := testNearCloudLikeSession(t)
	defer session.Zero()

	body := map[string]any{
		"data": []map[string]any{{"score": 0.42}},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	// Explicit /v1/score endpoint: NearCloud exception applies → plaintext score accepted.
	out, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointScore)
	if err != nil {
		t.Fatalf("expected plaintext score accepted for /v1/score endpoint: %v", err)
	}
	var parsed struct {
		Data []struct {
			Score float64 `json:"score"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(parsed.Data) != 1 || parsed.Data[0].Score != 0.42 {
		t.Fatalf("unexpected score output: %s", out)
	}
}

// TestDecryptNonStreamResponse_ScorePlaintext_NoEndpointFailsClosed verifies that
// endpoint-typed non-stream decryption now fails closed when endpoint is omitted.
func TestDecryptNonStreamResponse_ScorePlaintext_NoEndpointFailsClosed(t *testing.T) {
	session := testNearCloudLikeSession(t)
	defer session.Zero()

	body := map[string]any{
		"data": []map[string]any{{"score": 0.42}},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	_, err = DecryptNonStreamResponseForEndpoint(b, session, "")
	if err == nil {
		t.Fatal("expected error when endpoint is omitted")
	}
	if !strings.Contains(err.Error(), "endpoint type is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptNonStreamResponseForEndpoint_RejectsUnknownEndpointValue(t *testing.T) {
	session := testNearCloudLikeSession(t)
	defer session.Zero()

	body := map[string]any{"choices": []any{}}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	_, err = DecryptNonStreamResponseForEndpoint(b, session, EndpointType("typo"))
	if err == nil {
		t.Fatal("expected error for unsupported endpoint value")
	}
	if !strings.Contains(err.Error(), "unsupported endpoint type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptNonStreamResponseForEndpoint_TopLevelScoreDecrypted(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	encScore := encryptForClient(t, `0.42`, session.VeniceSession)
	body := map[string]any{"score": encScore}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	out, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointScore)
	if err != nil {
		t.Fatalf("DecryptNonStreamResponseForEndpoint: %v", err)
	}

	var parsed struct {
		Score float64 `json:"score"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if parsed.Score != 0.42 {
		t.Fatalf("score = %v, want 0.42", parsed.Score)
	}
}

func TestDecryptNonStreamResponseForEndpoint_TopLevelScorePlaintextAccepted(t *testing.T) {
	session := testNearCloudLikeSession(t)
	defer session.Zero()

	body := map[string]any{"score": 0.42}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	out, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointScore)
	if err != nil {
		t.Fatalf("expected plaintext top-level score accepted for /v1/score endpoint: %v", err)
	}

	var parsed struct {
		Score float64 `json:"score"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if parsed.Score != 0.42 {
		t.Fatalf("score = %v, want 0.42", parsed.Score)
	}
}

func TestDecryptNonStreamResponseForEndpoint_AudioAccepted(t *testing.T) {
	session := testNearCloudLikeSession(t)
	defer session.Zero()

	body := map[string]any{"text": "hello"}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	out, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointAudio)
	if err != nil {
		t.Fatalf("DecryptNonStreamResponseForEndpoint audio: %v", err)
	}
	if subtle.ConstantTimeCompare(b, out) != 1 {
		t.Fatalf("audio response changed unexpectedly: got %s want %s", out, b)
	}
}

func TestDecryptNonStreamResponse_TopLevelScorePlaintextNoEndpointFailsClosed(t *testing.T) {
	session := testNearCloudLikeSession(t)
	defer session.Zero()

	body := map[string]any{"score": 0.42}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	_, err = DecryptNonStreamResponseForEndpoint(b, session, EndpointChat)
	if err == nil {
		t.Fatal("expected error: plaintext top-level score must be rejected when no endpoint is provided to a full-field session")
	}
	if !strings.Contains(err.Error(), "score: expected encrypted string") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDecryptNonStreamResponse_LogprobsBytesPolicyUsesCanonicalPath verifies
// bytes policy checks are keyed by canonical paths (logprobs.content[].bytes /
// logprobs.refusal[].bytes) rather than an ambiguous bare "bytes" key.
func TestDecryptNonStreamResponse_LogprobsBytesPolicyUsesCanonicalPath(t *testing.T) {
	session := testLogprobsPathAwareSession(t)
	defer session.Zero()

	encContent := encryptForClient(t, "ok", session.VeniceSession)
	encContentToken := encryptForClient(t, "content-token", session.VeniceSession)
	encRefusalToken := encryptForClient(t, "refusal-token", session.VeniceSession)

	body := map[string]any{
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]any{
					"role":    "assistant",
					"content": encContent,
				},
				"logprobs": map[string]any{
					"content": []map[string]any{
						{
							"token": encContentToken,
							"bytes": []int{99, 111, 110, 116, 101, 110, 116},
						},
					},
					"refusal": []map[string]any{
						{
							"token": encRefusalToken,
							"bytes": []int{114, 101, 102, 117, 115, 97, 108},
						},
					},
				},
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	_, err = DecryptNonStreamResponseForEndpoint(b, session, EndpointChat)
	if err == nil {
		t.Fatal("expected refusal bytes plaintext to be rejected")
	}
	if !strings.Contains(err.Error(), "logprobs.refusal[0].bytes: expected encrypted string") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptNonStreamResponse_LogprobsTokenPolicyUsesCanonicalPath(t *testing.T) {
	session := testLogprobsPathAwareSession(t)
	defer session.Zero()

	encContent := encryptForClient(t, "ok", session.VeniceSession)
	body := map[string]any{
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]any{
					"role":    "assistant",
					"content": encContent,
				},
				"logprobs": map[string]any{
					"content": []map[string]any{
						{
							"token": "plaintext-token",
							"bytes": []int{112, 116},
						},
					},
				},
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	out, err := DecryptNonStreamResponseForEndpoint(b, session, EndpointChat)
	if err != nil {
		t.Fatalf("expected plaintext logprobs token accepted for content path policy exception: %v", err)
	}

	var parsed struct {
		Choices []struct {
			Logprobs struct {
				Content []struct {
					Token string `json:"token"`
				} `json:"content"`
			} `json:"logprobs"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(parsed.Choices) != 1 || len(parsed.Choices[0].Logprobs.Content) != 1 || parsed.Choices[0].Logprobs.Content[0].Token != "plaintext-token" {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestDecryptSSEChunkContent_UnchangedCiphertextRejected(t *testing.T) {
	mock := &testDecryptor{
		isEncrypted: func(s string) bool { return strings.HasPrefix(s, "enc:") },
		decrypt: func(s string) ([]byte, error) {
			// Simulate a broken decryptor that returns ciphertext unchanged.
			return []byte(s), nil
		},
	}
	data := `{"choices":[{"delta":{"content":"enc:still-ciphertext"}}]}`

	_, err := decryptSSEChunkContent(data, mock, EndpointChat)
	if err == nil {
		t.Fatal("expected error for unchanged ciphertext")
	}
	if !strings.Contains(err.Error(), "expected decrypted plaintext, got unchanged ciphertext") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDecryptSSEChunk_AudioAndFunctionFieldsDecrypted_FullFieldSession verifies that
// audio.data, tool_calls[].function.name/arguments, and function_call.name/arguments
// are all decrypted when the session requires full-field encryption (regression for
// findings 3 and 4: decryptFunctionObject and decryptAudioDataField previously
// bypassed DecryptFieldOrSkip and ignored the endpoint policy parameter).
func TestDecryptSSEChunk_AudioAndFunctionFieldsDecrypted_FullFieldSession(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	encAudio := encryptForClient(t, "BASE64AUDIO", session.VeniceSession)
	encFnName := encryptForClient(t, "get_weather", session.VeniceSession)
	encFnArgs := encryptForClient(t, `{"city":"SF"}`, session.VeniceSession)
	encFCName := encryptForClient(t, "legacy_fn", session.VeniceSession)
	encFCArgs := encryptForClient(t, `{"k":1}`, session.VeniceSession)

	chunk := map[string]any{
		"choices": []map[string]any{
			{
				"delta": map[string]any{
					"role":  "assistant",
					"audio": map[string]any{"data": encAudio},
					"tool_calls": []map[string]any{
						{
							"index": 0,
							"function": map[string]any{
								"name":      encFnName,
								"arguments": encFnArgs,
							},
						},
					},
					"function_call": map[string]any{
						"name":      encFCName,
						"arguments": encFCArgs,
					},
				},
			},
		},
	}
	b, err := json.Marshal(chunk)
	if err != nil {
		t.Fatalf("marshal chunk: %v", err)
	}

	decrypted, err := DecryptSSEChunk(string(b), session, EndpointChat)
	if err != nil {
		t.Fatalf("DecryptSSEChunk: %v", err)
	}

	var out struct {
		Choices []struct {
			Delta struct {
				Audio struct {
					Data string `json:"data"`
				} `json:"audio"`
				ToolCalls []struct {
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
				FunctionCall struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function_call"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(decrypted), &out); err != nil {
		t.Fatalf("unmarshal decrypted output: %v", err)
	}
	if out.Choices[0].Delta.Audio.Data != "BASE64AUDIO" {
		t.Errorf("audio.data = %q, want BASE64AUDIO", out.Choices[0].Delta.Audio.Data)
	}
	if len(out.Choices[0].Delta.ToolCalls) < 1 {
		t.Fatal("no tool_calls in decrypted output")
	}
	if out.Choices[0].Delta.ToolCalls[0].Function.Name != "get_weather" {
		t.Errorf("tool_calls[0].function.name = %q, want get_weather", out.Choices[0].Delta.ToolCalls[0].Function.Name)
	}
	if out.Choices[0].Delta.ToolCalls[0].Function.Arguments != `{"city":"SF"}` {
		t.Errorf("tool_calls[0].function.arguments = %q, want {\"city\":\"SF\"}", out.Choices[0].Delta.ToolCalls[0].Function.Arguments)
	}
	if out.Choices[0].Delta.FunctionCall.Name != "legacy_fn" {
		t.Errorf("function_call.name = %q, want legacy_fn", out.Choices[0].Delta.FunctionCall.Name)
	}
	if out.Choices[0].Delta.FunctionCall.Arguments != `{"k":1}` {
		t.Errorf("function_call.arguments = %q, want {\"k\":1}", out.Choices[0].Delta.FunctionCall.Arguments)
	}
}

// TestDecryptSSEChunk_FunctionObjectPlaintextRejected_FullFieldSession verifies
// that plaintext tool_call function fields are rejected fail-closed when the session
// requires full-field encryption (regression for finding 3: decryptFunctionObject
// now delegates policy enforcement to decryptMaybeEncryptedStringField).
func TestDecryptSSEChunk_FunctionObjectPlaintextRejected_FullFieldSession(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	chunk := map[string]any{
		"choices": []map[string]any{
			{
				"delta": map[string]any{
					"tool_calls": []map[string]any{
						{
							"function": map[string]any{
								"name":      "get_weather",
								"arguments": `{"city":"SF"}`,
							},
						},
					},
				},
			},
		},
	}
	b, err := json.Marshal(chunk)
	if err != nil {
		t.Fatalf("marshal chunk: %v", err)
	}

	_, err = DecryptSSEChunk(string(b), session, EndpointChat)
	if err == nil {
		t.Fatal("expected error for plaintext tool_call function fields in full-field session")
	}
	if !strings.Contains(err.Error(), "expected encrypted") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDecryptSSEChunk_AudioDataPlaintextRejected_FullFieldSession verifies that
// plaintext audio.data is rejected fail-closed when the session requires full-field
// encryption (regression for finding 4: decryptAudioDataField previously ignored the
// endpoint parameter and bypassed IsResponseFieldEncrypted policy lookup).
func TestDecryptSSEChunk_AudioDataPlaintextRejected_FullFieldSession(t *testing.T) {
	session := testFullFieldVeniceSession(t)
	defer session.Zero()

	chunk := map[string]any{
		"choices": []map[string]any{
			{
				"delta": map[string]any{
					"audio": map[string]any{"data": "plaintext-audio-data"},
				},
			},
		},
	}
	b, err := json.Marshal(chunk)
	if err != nil {
		t.Fatalf("marshal chunk: %v", err)
	}

	_, err = DecryptSSEChunk(string(b), session, EndpointChat)
	if err == nil {
		t.Fatal("expected error for plaintext audio.data in full-field session")
	}
	if !strings.Contains(err.Error(), "expected encrypted") {
		t.Fatalf("unexpected error: %v", err)
	}
}
