package e2ee

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

	result, err := ReassembleNonStream(strings.NewReader(sb.String()), session)
	if err != nil {
		t.Fatalf("ReassembleNonStream: %v", err)
	}
	t.Logf("reassembled: %s", result)

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
	RelayStream(rec, strings.NewReader(input), session)

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
	RelayStream(rec, strings.NewReader(input), nil)

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
	RelayNonStream(rec, strings.NewReader(input), nil)

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
	RelayNonStream(rec, strings.NewReader(string(body)), session)

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
	RelayReassembledNonStream(rec, strings.NewReader(input), session)

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
	RelayStream(rec, strings.NewReader(""), nil)

	// Empty body should produce a bad gateway error.
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	t.Logf("empty body response: %d %s", rec.Code, rec.Body.String())
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
