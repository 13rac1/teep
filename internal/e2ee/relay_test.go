package e2ee

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
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

	decrypted, err := DecryptSSEChunk(chunkJSON, session)
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
	result, err := DecryptSSEChunk(input, session)
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
	result, err := DecryptSSEChunk(input, session)
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
	result, err := DecryptSSEChunk(input, session)
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

	decrypted, err := DecryptNonStreamResponse(body, session)
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

func TestDecryptNonStreamResponse_ImageData(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	encB64JSON := encryptForClient(t, "iVBORw0KGgo=", session)
	encPrompt := encryptForClient(t, "a solid red square", session)

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

	decrypted, err := DecryptNonStreamResponse(body, session)
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
	result, err := DecryptNonStreamResponse(body, session)
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

	result, ss, err := ReassembleNonStream(strings.NewReader(sb.String()), session)
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
					"function": map[string]string{"arguments": `{"location"`},
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
					"function": map[string]string{"arguments": `: "SF"}`},
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

	result, _, err := ReassembleNonStream(strings.NewReader(sb.String()), session)
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
					{"index": 0, "function": map[string]string{"arguments": `{"x":1}`}},
					{"index": 1, "function": map[string]string{"arguments": `{"y":2}`}},
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

	result, _, err := ReassembleNonStream(strings.NewReader(sb.String()), session)
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
	_, err := RelayStream(context.Background(), rec, strings.NewReader(input), session)
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
	_, err := RelayStream(context.Background(), rec, strings.NewReader(input), nil)
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
	_, err := RelayNonStream(context.Background(), rec, strings.NewReader(input), nil)
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
	_, err := RelayNonStream(context.Background(), rec, strings.NewReader(string(body)), session)
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
	_, err := RelayReassembledNonStream(context.Background(), rec, strings.NewReader(input), session)
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
	_, err := RelayReassembledNonStream(context.Background(), rec, strings.NewReader(body), session)
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
	_, err := RelayStream(context.Background(), rec, strings.NewReader(""), nil)
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

	decrypted, err := DecryptSSEChunk(chunkJSON, session)
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

	decrypted, err := DecryptSSEChunk(chunkJSON, session)
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

	decrypted, err := DecryptSSEChunk(chunkJSON, session)
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

	decrypted, err := DecryptSSEChunk(chunk, session)
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

func TestDecryptDeltaFields_NonEncryptedSkipped(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	// Build fields map with non-encrypted fields that should be skipped.
	fields := map[string]json.RawMessage{
		"role":    json.RawMessage(`"assistant"`),
		"refusal": json.RawMessage(`"none"`),
		"name":    json.RawMessage(`"bot"`),
	}

	changed, err := decryptDeltaFields(fields, session, "test")
	if err != nil {
		t.Fatalf("decryptDeltaFields: %v", err)
	}
	if changed {
		t.Error("expected no changes for non-encrypted fields")
	}
	t.Logf("non-encrypted fields correctly skipped")
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
		result, err := DecryptSSEChunk(chunkJSON, session)
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
			result, err := DecryptSSEChunk(chunkJSON, session)
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

	changed, err := decryptDeltaFields(fields, session, "test")
	if err != nil {
		t.Fatalf("decryptDeltaFields: %v", err)
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
	_, err := RelayStream(context.Background(), w, strings.NewReader("data: {}\n\n"), nil)
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
	_, err := RelayStream(context.Background(), httptest.NewRecorder(), &failReader{}, nil)
	if err == nil {
		t.Fatal("expected non-nil error on scanner failure")
	}
	if !errors.Is(err, ErrRelayFailed) {
		t.Errorf("error should wrap ErrRelayFailed, got: %v", err)
	}
}

func TestRelayNonStream_ReadError_ReturnsRelayFailed(t *testing.T) {
	_, err := RelayNonStream(context.Background(), httptest.NewRecorder(), &failReader{}, nil)
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
	_, err := RelayNonStream(context.Background(), rec, strings.NewReader(body), session)
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
	_, err := RelayStream(context.Background(), rec, strings.NewReader(sseBody), session)
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
	_, err := RelayStream(context.Background(), rec, r, nil)
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
