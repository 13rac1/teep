package e2ee

import (
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

func TestRelayStream(t *testing.T) {
	session := testVeniceSession(t)
	defer session.Zero()

	encrypted := encryptForClient(t, "streamed", session)
	data := sseChunkJSON(t, encrypted)
	input := fmt.Sprintf("data: %s\n\ndata: [DONE]\n\n", data)

	rec := httptest.NewRecorder()
	RelayStream(context.Background(), rec, strings.NewReader(input), session)

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
	RelayStream(context.Background(), rec, strings.NewReader(input), nil)

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
	RelayNonStream(context.Background(), rec, strings.NewReader(input), nil)

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
	RelayNonStream(context.Background(), rec, strings.NewReader(string(body)), session)

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
	RelayReassembledNonStream(context.Background(), rec, strings.NewReader(input), session)

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

func TestRelayStream_EmptyBody(t *testing.T) {
	rec := httptest.NewRecorder()
	RelayStream(context.Background(), rec, strings.NewReader(""), nil)

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
