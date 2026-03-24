package proxy

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/13rac1/teep/internal/attestation"
)

// nonEncryptedFields is the set of known string-valued fields in OpenAI chat
// delta/message objects that are never encrypted by the E2EE layer. Expanding
// this allowlist prevents false-positive IsEncryptedChunkV2 matches on
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
var nonEncryptedFields = map[string]bool{
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
// map, decrypts any that pass the version-appropriate IsEncryptedChunk check,
// and returns true if any field was decrypted. Non-string fields and
// non-encrypted strings are left unchanged.
func decryptDeltaFields(fields map[string]json.RawMessage, session *attestation.Session, ctx string) (bool, error) {
	changed := false
	for key, raw := range fields {
		var s string
		if json.Unmarshal(raw, &s) != nil || s == "" {
			continue
		}
		if !attestation.IsEncryptedChunkForSession(s, session) {
			// Non-empty string that doesn't look encrypted — error in E2EE mode.
			// Exception: known non-content fields are never encrypted.
			if nonEncryptedFields[key] {
				continue
			}
			return false, fmt.Errorf("%s.%s: expected encrypted but not recognised (len=%d prefix=%q)", ctx, key, len(s), safePrefix(s, 8))
		}
		plaintext, err := attestation.DecryptForSession(s, session)
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

// decryptSSEChunk parses one SSE data JSON payload, decrypts all encrypted
// fields in the delta object, and returns the JSON with plaintext substituted.
// All fields in the delta are inspected — not just "content" — so fields like
// "reasoning_content" are also decrypted. Returns the original data unchanged
// for chunks with no choices or no delta (e.g. usage-only, finish_reason).
func decryptSSEChunk(data string, session *attestation.Session) (string, error) {
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
// plaintext string. Returns (nil, nil) for chunks with no choices or no delta
// (role announcements, finish_reason, usage-only).
func decryptSSEChunkContent(data string, session *attestation.Session) (map[string]string, error) {
	var full map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &full); err != nil {
		return nil, fmt.Errorf("parse SSE chunk JSON: %w", err)
	}

	choicesRaw, ok := full["choices"]
	if !ok {
		return nil, nil //nolint:nilnil // nil map = no decrypted fields; callers iterate with range
	}

	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(choicesRaw, &choices); err != nil {
		return nil, fmt.Errorf("parse choices array: %w", err)
	}
	if len(choices) == 0 {
		return nil, nil //nolint:nilnil // nil map = no decrypted fields
	}

	deltaRaw, ok := choices[0]["delta"]
	if !ok {
		return nil, nil //nolint:nilnil // nil map = no decrypted fields
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
		if !attestation.IsEncryptedChunkForSession(s, session) {
			if nonEncryptedFields[key] {
				continue
			}
			return nil, fmt.Errorf("delta.%s: expected encrypted but not recognised (len=%d prefix=%q)", key, len(s), safePrefix(s, 8))
		}
		plaintext, err := attestation.DecryptForSession(s, session)
		if err != nil {
			return nil, fmt.Errorf("decrypt delta.%s: %w", key, err)
		}
		result[key] = string(plaintext)
	}

	if len(result) == 0 {
		return nil, nil //nolint:nilnil // nil map = no decrypted fields
	}
	return result, nil
}

// decryptNonStreamResponse decrypts all encrypted string fields in each
// choice's message of an OpenAI-format non-streaming response body. Fields
// like "content", "reasoning_content", and any future encrypted fields are
// all handled. Returns an error if any non-empty string field (other than
// "role") is not a recognised encrypted chunk or fails to decrypt.
func decryptNonStreamResponse(body []byte, session *attestation.Session) ([]byte, error) {
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

// reassembleNonStream reads an SSE stream (forced by E2EE), decrypts each
// chunk, and reassembles the result into a single non-streaming OpenAI
// response. All encrypted delta fields (content, reasoning_content, etc.)
// are accumulated independently and included in the final message.
func reassembleNonStream(body io.Reader, session *attestation.Session) ([]byte, error) {
	scanner := bufio.NewScanner(body)
	bufp := sseScannerBufPool.Get().(*[]byte) //nolint:forcetypeassert // pool always stores *[]byte
	defer sseScannerBufPool.Put(bufp)
	scanner.Buffer((*bufp)[:cap(*bufp)], sseScannerBufSize)

	fields := make(map[string]*strings.Builder)
	var lastData string // last raw SSE data line for metadata extraction

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

	// Extract metadata (id, model, created) from the last raw SSE chunk.
	// These fields are not encrypted, so we parse the original data directly.
	var meta struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Created int64  `json:"created"`
	}
	if err := json.Unmarshal([]byte(lastData), &meta); err != nil {
		return nil, fmt.Errorf("reassemble: parse metadata from last chunk: %w", err)
	}

	// Build the message with all accumulated fields.
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

// safePrefix returns up to n characters of s for safe use in log messages.
func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
