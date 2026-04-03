package e2ee

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// ErrDecryptionFailed is a sentinel error returned by relay functions when
// E2EE decryption fails on the upstream response. Callers use this to
// distinguish cryptographic failures (indicating possible MITM or server-side
// E2EE breakage) from other relay errors.
var ErrDecryptionFailed = errors.New("e2ee decryption failed")

// StreamStats holds token throughput metrics collected during SSE relay.
type StreamStats struct {
	Chunks   int           // number of SSE data chunks with delta/content
	Tokens   int           // completion_tokens from usage (0 if unavailable)
	Duration time.Duration // time from first to last chunk
}

// EffectiveTokens returns Tokens if available (from usage), else Chunks.
func (s *StreamStats) EffectiveTokens() int {
	if s.Tokens > 0 {
		return s.Tokens
	}
	return s.Chunks
}

// recordChunk updates chunk timing and extracts usage from an SSE data payload.
func (s *StreamStats) recordChunk(data string, firstChunk *time.Time) {
	now := time.Now()
	if firstChunk.IsZero() {
		*firstChunk = now
	}
	s.Chunks++
	s.Duration = now.Sub(*firstChunk)
	var u usageInfo
	if json.Unmarshal([]byte(data), &u) == nil && u.Usage != nil {
		s.Tokens = u.Usage.CompletionTokens
	}
}

// usageInfo is used for partial unmarshal of the usage field in SSE chunks.
type usageInfo struct {
	Usage *struct {
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// NonEncryptedFields is the set of known string-valued fields in OpenAI chat
// delta/message objects that are never encrypted by the E2EE layer. Expanding
// this allowlist prevents false-positive IsEncryptedChunk matches on
// non-content hex-like fields (e.g. trace IDs).
//
// The upstream NEAR AI inference-proxy encrypts only: content,
// reasoning_content, reasoning, and audio.data. All other string fields
// pass through unencrypted.
//
// Source: https://github.com/nearai/inference-proxy/blob/main/src/encryption.rs
//   - encrypt_chat_response_choices (server → client encryption)
//   - decrypt_chat_message_fields   (client → server decryption)
//
// Protocol docs: https://github.com/nearai/docs/blob/main/docs/cloud/guides/e2ee-chat-completions.mdx
var NonEncryptedFields = map[string]bool{
	"role":          true,
	"refusal":       true,
	"name":          true,
	"tool_call_id":  true,
	"type":          true,
	"finish_reason": true,
	"function_call": true,
	"id":            true,
}

// decryptDeltaFields iterates all string-valued fields in a delta (or message)
// map, decrypts any that pass the session's IsEncryptedChunk check,
// and returns true if any field was decrypted.
func decryptDeltaFields(fields map[string]json.RawMessage, session Decryptor, ctx string) (bool, error) {
	changed := false
	for key, raw := range fields {
		var s string
		if json.Unmarshal(raw, &s) != nil || s == "" {
			continue
		}
		if NonEncryptedFields[key] {
			continue
		}
		if !session.IsEncryptedChunk(s) {
			return false, fmt.Errorf("%s.%s: expected encrypted but not recognised (len=%d prefix=%q)", ctx, key, len(s), SafePrefix(s, 8))
		}
		plaintext, err := session.Decrypt(s)
		if err != nil {
			return false, fmt.Errorf("decrypt %s.%s: %w", ctx, key, err)
		}
		plaintextJSON, err := json.Marshal(string(plaintext))
		if err != nil {
			return false, fmt.Errorf("marshal %s.%s plaintext: %w", ctx, key, err)
		}
		fields[key] = plaintextJSON
		changed = true
	}
	return changed, nil
}

// DecryptSSEChunk parses one SSE data JSON payload, decrypts all encrypted
// fields in the delta object, and returns the JSON with plaintext substituted.
func DecryptSSEChunk(data string, session Decryptor) (string, error) {
	var full map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &full); err != nil {
		return "", fmt.Errorf("parse SSE chunk JSON: %w", err)
	}

	choicesRaw, ok := full["choices"]
	if !ok {
		return data, nil
	}

	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(choicesRaw, &choices); err != nil {
		return "", fmt.Errorf("parse choices array: %w", err)
	}
	if len(choices) == 0 {
		return data, nil
	}

	deltaRaw, ok := choices[0]["delta"]
	if !ok {
		return data, nil
	}

	var delta map[string]json.RawMessage
	if err := json.Unmarshal(deltaRaw, &delta); err != nil {
		return "", fmt.Errorf("parse delta object: %w", err)
	}

	changed, err := decryptDeltaFields(delta, session, "delta")
	if err != nil {
		return "", err
	}
	if !changed {
		return data, nil
	}

	// Re-serialize delta → choices[0] → choices → full.
	deltaOut, err := json.Marshal(delta)
	if err != nil {
		return "", fmt.Errorf("marshal rewritten delta: %w", err)
	}
	choices[0]["delta"] = deltaOut

	choicesOut, err := json.Marshal(choices)
	if err != nil {
		return "", fmt.Errorf("marshal rewritten choices: %w", err)
	}
	full["choices"] = choicesOut

	out, err := json.Marshal(full)
	if err != nil {
		return "", fmt.Errorf("marshal rewritten chunk: %w", err)
	}
	return string(out), nil
}

// decryptSSEChunkContent decrypts all encrypted fields from the first choice's
// delta in one SSE JSON chunk and returns them as a map of field name to
// plaintext string.
func decryptSSEChunkContent(data string, session Decryptor) (map[string]string, error) {
	var full map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &full); err != nil {
		return nil, fmt.Errorf("parse SSE chunk JSON: %w", err)
	}

	choicesRaw, ok := full["choices"]
	if !ok {
		return map[string]string{}, nil
	}

	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(choicesRaw, &choices); err != nil {
		return nil, fmt.Errorf("parse choices array: %w", err)
	}
	if len(choices) == 0 {
		return map[string]string{}, nil
	}

	deltaRaw, ok := choices[0]["delta"]
	if !ok {
		return map[string]string{}, nil
	}

	var delta map[string]json.RawMessage
	if err := json.Unmarshal(deltaRaw, &delta); err != nil {
		return nil, fmt.Errorf("parse delta object: %w", err)
	}

	result := make(map[string]string)
	for key, raw := range delta {
		var s string
		if json.Unmarshal(raw, &s) != nil || s == "" {
			continue
		}
		if NonEncryptedFields[key] {
			continue
		}
		if !session.IsEncryptedChunk(s) {
			return nil, fmt.Errorf("delta.%s: expected encrypted but not recognised (len=%d prefix=%q)", key, len(s), SafePrefix(s, 8))
		}
		plaintext, err := session.Decrypt(s)
		if err != nil {
			return nil, fmt.Errorf("decrypt delta.%s: %w", key, err)
		}
		result[key] = string(plaintext)
	}

	if len(result) == 0 {
		return map[string]string{}, nil
	}
	return result, nil
}

// DecryptNonStreamResponse decrypts all encrypted string fields in each
// choice's message of an OpenAI-format non-streaming response body.
func DecryptNonStreamResponse(body []byte, session Decryptor) ([]byte, error) {
	var full map[string]json.RawMessage
	if err := json.Unmarshal(body, &full); err != nil {
		return nil, fmt.Errorf("parse response JSON: %w", err)
	}

	choicesRaw, ok := full["choices"]
	if !ok {
		return body, nil
	}

	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(choicesRaw, &choices); err != nil {
		return nil, fmt.Errorf("parse choices: %w", err)
	}

	for i, choice := range choices {
		msgRaw, ok := choice["message"]
		if !ok {
			continue
		}
		var msg map[string]json.RawMessage
		if err := json.Unmarshal(msgRaw, &msg); err != nil {
			return nil, fmt.Errorf("parse choice[%d].message: %w", i, err)
		}

		changed, err := decryptDeltaFields(msg, session, fmt.Sprintf("choice[%d].message", i))
		if err != nil {
			return nil, err
		}
		if !changed {
			continue
		}

		msgOut, err := json.Marshal(msg)
		if err != nil {
			return nil, fmt.Errorf("choice[%d]: marshal rewritten message: %w", i, err)
		}
		choices[i]["message"] = msgOut
	}

	choicesOut, err := json.Marshal(choices)
	if err != nil {
		return nil, fmt.Errorf("marshal rewritten choices: %w", err)
	}
	full["choices"] = choicesOut

	return json.Marshal(full)
}

// ReassembleNonStream reads an SSE stream (forced by E2EE), decrypts each
// chunk, and reassembles the result into a single non-streaming OpenAI response.
// Returns the assembled JSON and token throughput stats.
func ReassembleNonStream(body io.Reader, session Decryptor) ([]byte, StreamStats, error) {
	scanner, cleanup := newSSEScanner(body)
	defer cleanup()

	fields := make(map[string]*strings.Builder)
	var lastData string
	var stats StreamStats
	var firstChunk time.Time

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[len("data: "):]
		if data == "[DONE]" {
			break
		}

		stats.recordChunk(data, &firstChunk)

		decrypted, err := decryptSSEChunkContent(data, session)
		if err != nil {
			return nil, stats, fmt.Errorf("reassemble: %w", err)
		}
		for k, v := range decrypted {
			b, ok := fields[k]
			if !ok {
				b = &strings.Builder{}
				fields[k] = b
			}
			b.WriteString(v)
		}
		lastData = data
	}
	if err := scanner.Err(); err != nil {
		return nil, stats, fmt.Errorf("reassemble: scanner: %w", err)
	}

	if lastData == "" {
		return nil, stats, errors.New("reassemble: no SSE chunks received")
	}

	var meta struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Created int64  `json:"created"`
	}
	if err := json.Unmarshal([]byte(lastData), &meta); err != nil {
		return nil, stats, fmt.Errorf("reassemble: parse metadata from last chunk: %w", err)
	}

	msg := make(map[string]any, len(fields)+1)
	msg["role"] = "assistant"
	for k, b := range fields {
		msg[k] = b.String()
	}

	resp := map[string]any{
		"id":      meta.ID,
		"object":  "chat.completion",
		"created": meta.Created,
		"model":   meta.Model,
		"choices": []map[string]any{
			{
				"index":         0,
				"message":       msg,
				"finish_reason": "stop",
			},
		},
	}

	result, err := json.Marshal(resp)
	return result, stats, err
}

// RelayStream reads an SSE stream from body, decrypts chunks when session is
// non-nil, and writes the decrypted SSE lines to w. Returns token throughput
// stats and a non-nil error wrapping ErrDecryptionFailed on decryption failure.
func RelayStream(ctx context.Context, w http.ResponseWriter, body io.Reader, session Decryptor) (StreamStats, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return StreamStats{}, nil
	}

	scanner, cleanup := newSSEScanner(body)
	defer cleanup()

	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			http.Error(w, "upstream stream error", http.StatusBadGateway)
		} else {
			http.Error(w, "empty upstream stream", http.StatusBadGateway)
		}
		return StreamStats{}, nil
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	var stats StreamStats
	var firstChunk time.Time
	var decryptErr error

	process := func(line string) bool {
		done, derr := relaySSELine(ctx, w, flusher, line, session)
		if derr != nil {
			decryptErr = derr
		}
		if !done {
			if data, ok := strings.CutPrefix(line, "data: "); ok && data != "[DONE]" {
				stats.recordChunk(data, &firstChunk)
			}
		}
		return done
	}

	if process(scanner.Text()) {
		return stats, decryptErr
	}
	for scanner.Scan() {
		if process(scanner.Text()) {
			return stats, decryptErr
		}
	}

	if err := scanner.Err(); err != nil {
		slog.ErrorContext(ctx, "SSE scanner error", "err", err)
	}
	return stats, decryptErr
}

// relaySSELine processes a single SSE line, writing it to w. Returns
// (done, error) where done=true means the stream should end. error is non-nil
// only on decryption failure (wraps ErrDecryptionFailed).
func relaySSELine(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, line string, session Decryptor) (bool, error) {
	if !strings.HasPrefix(line, "data: ") {
		fmt.Fprintf(w, "%s\n", line)
		flusher.Flush()
		return false, nil
	}

	data := line[len("data: "):]
	if data == "[DONE]" {
		fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
		return true, nil
	}

	if session == nil {
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		return false, nil
	}

	decrypted, err := DecryptSSEChunk(data, session)
	if err != nil {
		slog.ErrorContext(ctx, "stream decryption failed", "err", err)
		fmt.Fprintf(w, "event: error\ndata: {\"error\":{\"message\":\"stream decryption failed\",\"type\":\"decryption_error\"}}\n\n")
		flusher.Flush()
		return true, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}

	fmt.Fprintf(w, "data: %s\n\n", decrypted)
	flusher.Flush()
	return false, nil
}

// RelayReassembledNonStream reads an SSE stream from the E2EE upstream,
// decrypts each chunk, and writes a single non-streaming JSON response.
// Returns token throughput stats and a non-nil error wrapping
// ErrDecryptionFailed on decryption failure.
func RelayReassembledNonStream(ctx context.Context, w http.ResponseWriter, body io.Reader, session Decryptor) (StreamStats, error) {
	result, stats, err := ReassembleNonStream(body, session)
	if err != nil {
		slog.ErrorContext(ctx, "E2EE non-stream reassembly failed", "err", err)
		http.Error(w, "response decryption failed", http.StatusBadGateway)
		return stats, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result)
	return stats, nil
}

// RelayNonStream reads a non-streaming JSON response from body, decrypts the
// content fields if session is non-nil, and writes the result to w. Returns a
// non-nil error wrapping ErrDecryptionFailed on decryption failure.
func RelayNonStream(ctx context.Context, w http.ResponseWriter, body io.Reader, session Decryptor) (StreamStats, error) {
	responseBody, err := io.ReadAll(io.LimitReader(body, 10<<20))
	if err != nil {
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return StreamStats{}, err
	}

	if session == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(responseBody)
		return StreamStats{}, nil
	}

	decrypted, err := DecryptNonStreamResponse(responseBody, session)
	if err != nil {
		slog.ErrorContext(ctx, "non-stream decryption failed", "err", err)
		http.Error(w, "response decryption failed", http.StatusBadGateway)
		return StreamStats{}, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(decrypted)
	return StreamStats{}, nil
}
