package e2ee

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

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
func ReassembleNonStream(body io.Reader, session Decryptor) ([]byte, error) {
	scanner, cleanup := newSSEScanner(body)
	defer cleanup()

	fields := make(map[string]*strings.Builder)
	var lastData string

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[len("data: "):]
		if data == "[DONE]" {
			break
		}

		decrypted, err := decryptSSEChunkContent(data, session)
		if err != nil {
			return nil, fmt.Errorf("reassemble: %w", err)
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
		return nil, fmt.Errorf("reassemble: scanner: %w", err)
	}

	if lastData == "" {
		return nil, errors.New("reassemble: no SSE chunks received")
	}

	var meta struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Created int64  `json:"created"`
	}
	if err := json.Unmarshal([]byte(lastData), &meta); err != nil {
		return nil, fmt.Errorf("reassemble: parse metadata from last chunk: %w", err)
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

	return json.Marshal(resp)
}

// RelayStream reads an SSE stream from body, decrypts chunks when session is
// non-nil, and writes the decrypted SSE lines to w. Aborts on decryption failure.
func RelayStream(w http.ResponseWriter, body io.Reader, session Decryptor) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	scanner, cleanup := newSSEScanner(body)
	defer cleanup()

	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			http.Error(w, "upstream stream error", http.StatusBadGateway)
		} else {
			http.Error(w, "empty upstream stream", http.StatusBadGateway)
		}
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	if relaySSELine(w, flusher, scanner.Text(), session) {
		return
	}

	for scanner.Scan() {
		if relaySSELine(w, flusher, scanner.Text(), session) {
			return
		}
	}

	if err := scanner.Err(); err != nil {
		slog.Error("SSE scanner error", "err", err)
	}
}

// relaySSELine processes a single SSE line, writing it to w. Returns true if
// the stream should end (DONE marker or decryption error).
func relaySSELine(w http.ResponseWriter, flusher http.Flusher, line string, session Decryptor) bool {
	if !strings.HasPrefix(line, "data: ") {
		fmt.Fprintf(w, "%s\n", line)
		flusher.Flush()
		return false
	}

	data := line[len("data: "):]
	if data == "[DONE]" {
		fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
		return true
	}

	if session == nil {
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		return false
	}

	decrypted, err := DecryptSSEChunk(data, session)
	if err != nil {
		slog.Error("stream decryption failed", "err", err)
		fmt.Fprintf(w, "event: error\ndata: {\"error\":{\"message\":\"stream decryption failed\",\"type\":\"decryption_error\"}}\n\n")
		flusher.Flush()
		return true
	}

	fmt.Fprintf(w, "data: %s\n\n", decrypted)
	flusher.Flush()
	return false
}

// RelayReassembledNonStream reads an SSE stream from the E2EE upstream,
// decrypts each chunk, and writes a single non-streaming JSON response.
func RelayReassembledNonStream(w http.ResponseWriter, body io.Reader, session Decryptor) {
	result, err := ReassembleNonStream(body, session)
	if err != nil {
		slog.Error("E2EE non-stream reassembly failed", "err", err)
		http.Error(w, "response decryption failed", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result)
}

// RelayNonStream reads a non-streaming JSON response from body, decrypts the
// content fields if session is non-nil, and writes the result to w.
func RelayNonStream(w http.ResponseWriter, body io.Reader, session Decryptor) {
	responseBody, err := io.ReadAll(io.LimitReader(body, 10<<20))
	if err != nil {
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return
	}

	if session == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(responseBody)
		return
	}

	decrypted, err := DecryptNonStreamResponse(responseBody, session)
	if err != nil {
		slog.Error("non-stream decryption failed", "err", err)
		http.Error(w, "response decryption failed", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(decrypted)
}
