package e2ee

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// simulateServerStreamInit simulates the server-side of Chutes stream init:
// encapsulates against the client's ML-KEM public key, derives the stream key,
// and returns the KEM ciphertext (base64) + stream key.
func simulateServerStreamInit(t *testing.T, clientSession *ChutesSession) (kemCtB64 string, streamKey []byte) {
	t.Helper()
	sharedSecret, kemCt := clientSession.mlkemEncapKey.Encapsulate()
	streamKey, err := deriveKeyMLKEM(sharedSecret, kemCt, hkdfInfoChutesStream)
	if err != nil {
		t.Fatalf("derive stream key: %v", err)
	}
	kemCtB64 = base64.StdEncoding.EncodeToString(kemCt)
	t.Logf("server stream init: KEM ct size=%d, stream key size=%d", len(kemCt), len(streamKey))
	return kemCtB64, streamKey
}

// simulateServerResponseBlob simulates the server encrypting a non-stream
// response blob: KEM encapsulate + encrypt payload with response key.
func simulateServerResponseBlob(t *testing.T, clientSession *ChutesSession, plaintext []byte) []byte {
	t.Helper()
	sharedSecret, kemCt := clientSession.mlkemEncapKey.Encapsulate()
	respKey, err := deriveKeyMLKEM(sharedSecret, kemCt, hkdfInfoChutesResp)
	if err != nil {
		t.Fatalf("derive response key: %v", err)
	}
	encrypted, err := encryptPayloadChaCha20(plaintext, respKey)
	if err != nil {
		t.Fatalf("encryptPayloadChaCha20: %v", err)
	}
	blob := make([]byte, 0, len(kemCt)+len(encrypted))
	blob = append(blob, kemCt...)
	blob = append(blob, encrypted...)
	t.Logf("server response blob: KEM ct=%d, encrypted=%d, total=%d", len(kemCt), len(encrypted), len(blob))
	return blob
}

// buildChutesSSE builds a complete Chutes E2EE SSE stream with e2e_init + e2e events.
func buildChutesSSE(t *testing.T, kemCtB64 string, streamKey []byte, plainChunks []string) string {
	t.Helper()
	var sb strings.Builder

	// e2e_init event.
	initJSON, _ := json.Marshal(map[string]string{"e2e_init": kemCtB64})
	fmt.Fprintf(&sb, "data: %s\n\n", initJSON)

	// e2e events.
	for _, chunk := range plainChunks {
		encrypted, err := encryptStreamChunkChutes([]byte(chunk), streamKey)
		if err != nil {
			t.Fatalf("encryptStreamChunkChutes: %v", err)
		}
		encB64 := base64.StdEncoding.EncodeToString(encrypted)
		eventJSON, _ := json.Marshal(map[string]string{"e2e": encB64})
		fmt.Fprintf(&sb, "data: %s\n\n", eventJSON)
	}

	sb.WriteString("data: [DONE]\n\n")
	return sb.String()
}

func TestRelayStreamChutes(t *testing.T) {
	session, err := NewChutesSession()
	if err != nil {
		t.Fatalf("NewChutesSession: %v", err)
	}

	kemCtB64, streamKey := simulateServerStreamInit(t, session)

	// Build OpenAI-format SSE lines that the server would encrypt.
	// The Chutes server encrypts the full SSE line including "data: " prefix
	// and trailing newlines; the relay writes decrypted bytes verbatim.
	chunk1 := "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n"
	chunk2 := "data: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n"
	sseInput := buildChutesSSE(t, kemCtB64, streamKey, []string{chunk1, chunk2})
	t.Logf("SSE input length: %d bytes", len(sseInput))

	rec := httptest.NewRecorder()
	RelayStreamChutes(context.Background(), rec, strings.NewReader(sseInput), session)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}

	body := rec.Body.String()
	t.Logf("relay output:\n%s", body)

	if !strings.Contains(body, `"content":"Hello"`) {
		t.Error("chunk 1 content not found in relay output")
	}
	if !strings.Contains(body, `"content":" world"`) {
		t.Error("chunk 2 content not found in relay output")
	}
	if !strings.Contains(body, "data: [DONE]") {
		t.Error("[DONE] marker not found")
	}
}

func TestRelayStreamChutes_MissingInit(t *testing.T) {
	session, err := NewChutesSession()
	if err != nil {
		t.Fatalf("NewChutesSession: %v", err)
	}

	// Send e2e event without prior e2e_init.
	input := `data: {"e2e":"dGVzdA=="}` + "\n\n"

	rec := httptest.NewRecorder()
	RelayStreamChutes(context.Background(), rec, strings.NewReader(input), session)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	t.Logf("missing init response: %d %s", rec.Code, rec.Body.String())
}

func TestRelayStreamChutes_E2EError(t *testing.T) {
	session, err := NewChutesSession()
	if err != nil {
		t.Fatalf("NewChutesSession: %v", err)
	}

	kemCtB64, _ := simulateServerStreamInit(t, session)

	// e2e_init followed by e2e_error.
	initJSON, _ := json.Marshal(map[string]string{"e2e_init": kemCtB64})
	errJSON, _ := json.Marshal(map[string]string{"e2e_error": "server exploded"})
	input := fmt.Sprintf("data: %s\n\ndata: %s\n\n", initJSON, errJSON)

	rec := httptest.NewRecorder()
	RelayStreamChutes(context.Background(), rec, strings.NewReader(input), session)

	body := rec.Body.String()
	t.Logf("e2e_error response: status=%d body=%s", rec.Code, body)
	// Stream hasn't started (no chunks decrypted), so we get a plain HTTP error.
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(body, "E2E error") {
		t.Error("expected 'E2E error' in error body")
	}
}

func TestRelayNonStreamChutes(t *testing.T) {
	session, err := NewChutesSession()
	if err != nil {
		t.Fatalf("NewChutesSession: %v", err)
	}

	plainJSON := `{"choices":[{"message":{"role":"assistant","content":"Hi!"}}]}`
	blob := simulateServerResponseBlob(t, session, []byte(plainJSON))

	rec := httptest.NewRecorder()
	RelayNonStreamChutes(context.Background(), rec, strings.NewReader(string(blob)), session)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	body := rec.Body.String()
	t.Logf("decrypted non-stream: %s", body)
	if body != plainJSON {
		t.Errorf("body mismatch:\n  got:  %s\n  want: %s", body, plainJSON)
	}
}

func TestRelayStreamChutes_UnparseableEvent(t *testing.T) {
	session, err := NewChutesSession()
	if err != nil {
		t.Fatalf("NewChutesSession: %v", err)
	}

	// An unparseable JSON event in the E2EE stream must abort (not continue).
	input := "data: not-valid-json!!!\n\ndata: [DONE]\n\n"

	rec := httptest.NewRecorder()
	stats := RelayStreamChutes(context.Background(), rec, strings.NewReader(input), session)

	body := rec.Body.String()
	t.Logf("unparseable event response: status=%d body=%q chunks=%d", rec.Code, body, stats.Chunks)

	// Stream hasn't started (no headers written), so we get a plain HTTP error.
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(body, "unparseable event") {
		t.Error("expected 'unparseable event' in error body")
	}
	if stats.Chunks != 0 {
		t.Errorf("chunks = %d, want 0 (stream should abort before any chunks)", stats.Chunks)
	}
}

func TestRelayStreamChutes_DoneWithoutChunks(t *testing.T) {
	session, err := NewChutesSession()
	if err != nil {
		t.Fatalf("NewChutesSession: %v", err)
	}

	kemCtB64, _ := simulateServerStreamInit(t, session)
	initJSON, _ := json.Marshal(map[string]string{"e2e_init": kemCtB64})
	input := fmt.Sprintf("data: %s\n\ndata: [DONE]\n\n", initJSON)

	rec := httptest.NewRecorder()
	RelayStreamChutes(context.Background(), rec, strings.NewReader(input), session)

	// [DONE] without header written: should not write [DONE] to output.
	body := rec.Body.String()
	t.Logf("done-without-chunks: status=%d body=%q", rec.Code, body)
}
