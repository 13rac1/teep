package e2ee

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/13rac1/teep/internal/jsonstrict"
)

// ErrDecryptionFailed is a sentinel error returned by relay functions when
// E2EE decryption fails on the upstream response. Callers use this to
// distinguish cryptographic failures (indicating possible MITM or server-side
// E2EE breakage) from other relay errors.
var ErrDecryptionFailed = errors.New("e2ee decryption failed")

// ErrRelayFailed is a sentinel error returned by relay functions for
// non-decryption failures (e.g. streaming not supported, empty upstream,
// read errors). Callers should treat any non-nil relay error as terminal
// but use errors.Is to distinguish decryption failures from other relay
// failures.
var ErrRelayFailed = errors.New("relay failed")

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

// IsNonEncryptedField reports whether key is known plaintext metadata in
// OpenAI chat delta/message objects.
//
// Note: "refusal", "name", and "function_call" are intentionally absent —
// they are encrypted by NearCloud/NearDirect when X-Encrypt-All-Fields is
// active. Only structural metadata that the inference-proxy never encrypts
// belongs here.
func IsNonEncryptedField(key string) bool {
	switch key {
	case "role", "tool_call_id", "type", "finish_reason", "id":
		return true
	default:
		return false
	}
}

func setChanged(changed *bool, c bool, err error) error {
	if err != nil {
		return err
	}
	if c {
		*changed = true
	}
	return nil
}

func decryptContentField(fields map[string]json.RawMessage, session Decryptor, ctx string, endpoint EndpointType) (bool, error) {
	raw, ok := fields["content"]
	if !ok || IsJSONNull(raw) {
		return false, nil
	}
	// Chat completions endpoint path documented here: /v1/chat/completions or /api/v1/chat/completions
	requiresEncrypted := session.IsResponseFieldEncrypted(EncFieldContent, endpoint)

	if jsonRawStartsWithToken(raw, '"') {
		plaintext, err := DecryptFieldOrSkip(raw, session, requiresEncrypted, ctx+".content")
		if err != nil {
			return false, err
		}
		if plaintext == nil {
			return false, nil
		}
		plaintextJSON, _ := json.Marshal(string(plaintext)) //nolint:errchkjson // strings always marshal
		fields["content"] = plaintextJSON
		return true, nil
	}

	if !jsonRawStartsWithToken(raw, '[') {
		if requiresEncrypted {
			return false, fmt.Errorf("%s.content: expected encrypted string or content-part array, got %s", ctx, rawTypeDescription(raw))
		}
		return false, nil
	}

	// Multimodal content array encryption: /v1/chat/completions
	if !session.IsResponseFieldEncrypted(EncFieldContentText, endpoint) {
		if requiresEncrypted {
			return false, fmt.Errorf("%s.content: expected encrypted string but got array", ctx)
		}
		return false, nil
	}

	var parts []json.RawMessage
	if err := json.Unmarshal(raw, &parts); err != nil {
		return false, fmt.Errorf("%s.content: parse array: %w", ctx, err)
	}

	changed := false
	for i, partRaw := range parts {
		if IsJSONNull(partRaw) {
			continue
		}
		if !jsonRawStartsWithToken(partRaw, '{') {
			return false, fmt.Errorf("%s.content[%d]: expected object, got %s", ctx, i, rawTypeDescription(partRaw))
		}
		var part map[string]json.RawMessage
		if err := json.Unmarshal(partRaw, &part); err != nil {
			return false, fmt.Errorf("%s.content[%d]: parse object: %w", ctx, i, err)
		}
		c, err := decryptMaybeEncryptedStringField(part, "text", session, fmt.Sprintf("%s.content[%d]", ctx, i), EncFieldContentText, endpoint)
		if err != nil {
			return false, err
		}
		if !c {
			continue
		}
		partOut, _ := json.Marshal(part) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
		parts[i] = partOut
		changed = true
	}

	if !changed {
		return false, nil
	}
	partsOut, _ := json.Marshal(parts) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	fields["content"] = partsOut
	return true, nil
}

func decryptAudioDataField(fields map[string]json.RawMessage, session Decryptor, ctx string, endpoint EndpointType) (bool, error) {
	audioRaw, ok := fields["audio"]
	if !ok || IsJSONNull(audioRaw) {
		return false, nil
	}
	var audio map[string]json.RawMessage
	if err := json.Unmarshal(audioRaw, &audio); err != nil {
		return false, fmt.Errorf("%s.audio: parse object: %w", ctx, err)
	}
	c, err := decryptMaybeEncryptedStringField(audio, "data", session, ctx+".audio", EncFieldAudioData, endpoint)
	if err != nil {
		return false, err
	}
	if !c {
		return false, nil
	}
	audioOut, _ := json.Marshal(audio) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	fields["audio"] = audioOut
	return true, nil
}

func decryptFunctionObject(obj map[string]json.RawMessage, session Decryptor, ctx, policyBase string, endpoint EndpointType) (bool, error) {
	changed := false
	for _, key := range functionObjectFields {
		c, err := decryptMaybeEncryptedStringField(obj, key, session, ctx, policyBase+"."+key, endpoint)
		if err != nil {
			return false, err
		}
		if c {
			changed = true
		}
	}
	return changed, nil
}

func decryptToolCallsField(fields map[string]json.RawMessage, session Decryptor, ctx string, endpoint EndpointType) (bool, error) {
	raw, ok := fields["tool_calls"]
	if !ok || IsJSONNull(raw) {
		return false, nil
	}
	var calls []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &calls); err != nil {
		return false, fmt.Errorf("%s.tool_calls: parse array: %w", ctx, err)
	}
	changed := false
	for i := range calls {
		fnRaw, ok := calls[i]["function"]
		if !ok || IsJSONNull(fnRaw) {
			continue
		}
		var fn map[string]json.RawMessage
		if err := json.Unmarshal(fnRaw, &fn); err != nil {
			return false, fmt.Errorf("%s.tool_calls[%d].function: parse object: %w", ctx, i, err)
		}
		c, err := decryptFunctionObject(fn, session, fmt.Sprintf("%s.tool_calls[%d].function", ctx, i), "tool_calls[].function", endpoint)
		if err != nil {
			return false, err
		}
		if c {
			fnOut, _ := json.Marshal(fn) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
			calls[i]["function"] = fnOut
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	callsOut, _ := json.Marshal(calls) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	fields["tool_calls"] = callsOut
	return true, nil
}

func decryptFunctionCallField(fields map[string]json.RawMessage, session Decryptor, ctx string, endpoint EndpointType) (bool, error) {
	raw, ok := fields["function_call"]
	if !ok || IsJSONNull(raw) {
		return false, nil
	}
	if !jsonRawStartsWithToken(raw, '{') {
		// Deprecated function_call can be a string; keep unchanged.
		return false, nil
	}
	var fc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fc); err != nil {
		return false, fmt.Errorf("%s.function_call: parse object: %w", ctx, err)
	}
	changed, err := decryptFunctionObject(fc, session, ctx+".function_call", "function_call", endpoint)
	if err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}
	fcOut, _ := json.Marshal(fc) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	fields["function_call"] = fcOut
	return true, nil
}

func decryptChoiceLogprobs(choice map[string]json.RawMessage, session Decryptor, ctx string, endpoint EndpointType) (bool, error) {
	raw, ok := choice["logprobs"]
	if !ok || IsJSONNull(raw) {
		return false, nil
	}
	if !jsonRawStartsWithToken(raw, '{') {
		return false, nil
	}
	var logprobs map[string]json.RawMessage
	if err := json.Unmarshal(raw, &logprobs); err != nil {
		return false, fmt.Errorf("%s.logprobs: parse object: %w", ctx, err)
	}
	changed := false
	for _, key := range []string{"content", "refusal"} {
		policyBase := "logprobs." + key + "[]"
		keyChanged := false
		entriesRaw, ok := logprobs[key]
		if !ok || IsJSONNull(entriesRaw) {
			continue
		}
		var entries []map[string]json.RawMessage
		if err := json.Unmarshal(entriesRaw, &entries); err != nil {
			return false, fmt.Errorf("%s.logprobs.%s: parse array: %w", ctx, key, err)
		}
		for i := range entries {
			entryChanged, err := decryptLogprobsTokenEntry(entries[i], session, fmt.Sprintf("%s.logprobs.%s[%d]", ctx, key, i), policyBase, endpoint)
			if err != nil {
				return false, err
			}
			if entryChanged {
				changed = true
				keyChanged = true
			}
		}
		if keyChanged {
			entriesOut, _ := json.Marshal(entries) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
			logprobs[key] = entriesOut
		}
	}
	if !changed {
		return false, nil
	}
	logprobsOut, _ := json.Marshal(logprobs) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	choice["logprobs"] = logprobsOut
	return true, nil
}

func decryptLogprobsTokenEntry(entry map[string]json.RawMessage, session Decryptor, ctx, policyBase string, endpoint EndpointType) (bool, error) {
	changed := false
	c, err := decryptMaybeEncryptedStringField(entry, "token", session, ctx, policyBase+".token", endpoint)
	if err := setChanged(&changed, c, err); err != nil {
		return false, err
	}
	c, err = decryptJSONValueField(entry, "bytes", session, ctx+".bytes", policyBase+".bytes", endpoint)
	if err := setChanged(&changed, c, err); err != nil {
		return false, err
	}
	topRaw, ok := entry["top_logprobs"]
	if !ok || IsJSONNull(topRaw) {
		return changed, nil
	}
	var top []map[string]json.RawMessage
	if err := json.Unmarshal(topRaw, &top); err != nil {
		return false, fmt.Errorf("%s.top_logprobs: parse array: %w", ctx, err)
	}
	topChanged := false
	for i := range top {
		c, err := decryptLogprobsTokenEntry(top[i], session, fmt.Sprintf("%s.top_logprobs[%d]", ctx, i), policyBase+".top_logprobs[]", endpoint)
		if err != nil {
			return false, err
		}
		if c {
			topChanged = true
		}
	}
	if topChanged {
		changed = true
		topOut, _ := json.Marshal(top) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
		entry["top_logprobs"] = topOut
	}
	return changed, nil
}

func decryptMaybeEncryptedStringField(obj map[string]json.RawMessage, key string, session Decryptor, ctx, policyPath string, endpoint EndpointType) (bool, error) {
	raw, ok := obj[key]
	if !ok || IsJSONNull(raw) {
		return false, nil
	}
	requiresEncrypted := session.IsResponseFieldEncrypted(policyPath, endpoint)
	plaintext, err := DecryptFieldOrSkip(raw, session, requiresEncrypted, ctx+"."+key)
	if err != nil {
		return false, err
	}
	if plaintext == nil {
		return false, nil
	}
	plaintextJSON, _ := json.Marshal(string(plaintext)) //nolint:errchkjson // strings always marshal
	obj[key] = plaintextJSON
	return true, nil
}

// decryptJSONValueField decrypts an encrypted-JSON field in obj[key] and
// stores the result back as a raw JSON value (number, array, or object).
// Unlike decryptMaybeEncryptedStringField the plaintext is not re-wrapped as a
// JSON string. fieldCtx is the full dot-path used in error messages.
func decryptJSONValueField(obj map[string]json.RawMessage, key string, session Decryptor, fieldCtx, policyPath string, endpoint EndpointType) (bool, error) {
	raw, ok := obj[key]
	if !ok || IsJSONNull(raw) {
		return false, nil
	}
	requiresEncrypted := session.IsResponseFieldEncrypted(policyPath, endpoint)
	plaintext, err := DecryptFieldOrSkip(raw, session, requiresEncrypted, fieldCtx)
	if err != nil {
		return false, err
	}
	if plaintext == nil {
		return false, nil
	}
	obj[key] = applyDecryptedJSON(plaintext)
	return true, nil
}

func decryptChatObject(fields map[string]json.RawMessage, session Decryptor, ctx string, endpoint EndpointType) (bool, error) {
	changed := false
	for key := range fields {
		if IsNonEncryptedField(key) {
			continue
		}
		if key == "content" {
			c, err := decryptContentField(fields, session, ctx, endpoint)
			if err != nil {
				return false, err
			}
			if c {
				changed = true
			}
			continue
		}
		// audio, tool_calls, and function_call are structured object/array fields
		// handled by dedicated helpers below.
		if key == "audio" || key == "tool_calls" || key == "function_call" {
			continue
		}
		c, err := decryptMaybeEncryptedStringField(fields, key, session, ctx, key, endpoint)
		if err != nil {
			return false, err
		}
		if c {
			changed = true
		}
	}
	// Each nested field group is gated by its own canonical encrypted leaf path rather
	// than a shared proxy (audio.data). This ensures a future provider that encrypts
	// tool_calls but not audio, or function_call but not tool_calls, is handled correctly.
	if session.IsResponseFieldEncrypted(EncFieldAudioData, endpoint) {
		c, err := decryptAudioDataField(fields, session, ctx, endpoint)
		if err := setChanged(&changed, c, err); err != nil {
			return false, err
		}
	}
	if session.IsResponseFieldEncrypted(EncFieldToolCallsFuncName, endpoint) {
		c, err := decryptToolCallsField(fields, session, ctx, endpoint)
		if err := setChanged(&changed, c, err); err != nil {
			return false, err
		}
	}
	if session.IsResponseFieldEncrypted(EncFieldFuncCallName, endpoint) {
		c, err := decryptFunctionCallField(fields, session, ctx, endpoint)
		if err := setChanged(&changed, c, err); err != nil {
			return false, err
		}
	}
	return changed, nil
}

func jsonRawStartsWithToken(raw json.RawMessage, token byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == token
}

// logprobLeafEncFields lists all logprobs leaf field enc paths that may be
// encrypted. anyLogprobsLeafEncrypted and decryptLogprobsTokenEntry both depend
// on these paths; keeping them in a shared slice ensures coverage stays in sync
// when new logprob leaves are added.
var logprobLeafEncFields = []string{
	EncFieldLogprobsContentToken, EncFieldLogprobsContentBytes,
	EncFieldLogprobsRefusalToken, EncFieldLogprobsRefusalBytes,
}

// anyLogprobsLeafEncrypted reports whether any logprobs leaf field (content or
// refusal token/bytes) requires encryption for the given endpoint. Used to gate
// decryptChoiceLogprobs in both streaming and non-streaming paths so that
// mixed-policy cases (e.g. only refusal[].token encrypted) are handled correctly.
func anyLogprobsLeafEncrypted(session Decryptor, endpoint EndpointType) bool {
	for _, path := range logprobLeafEncFields {
		if session.IsResponseFieldEncrypted(path, endpoint) {
			return true
		}
	}
	return false
}

// rawTypeDescription returns a human-readable description of the JSON type
// represented by a json.RawMessage (e.g. "array", "object", "number").
// Used in error messages to clarify what was found when an encrypted string was expected.
func rawTypeDescription(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "empty"
	}
	switch trimmed[0] {
	case '[':
		return "array"
	case '{':
		return "object"
	case '"':
		return "string"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return "number"
	default:
		return "unknown"
	}
}

// DecryptFieldOrSkip attempts to decrypt raw as an encrypted JSON string ciphertext.
// Returns:
//   - (plaintext, nil) if decryption succeeded (AEAD MAC validated).
//   - (nil, nil) if the value is empty, non-string, or not recognised as a ciphertext,
//     and requiresEncrypted is false (policy allows plaintext passthrough).
//   - (nil, err) if requiresEncrypted is true and the value is not encrypted, or if
//     Decrypt fails.
//
// Callers must handle null/absent checks before calling; raw must not be null.
func DecryptFieldOrSkip(raw json.RawMessage, session Decryptor, requiresEncrypted bool, ctx string) ([]byte, error) {
	if !jsonRawStartsWithToken(raw, '"') {
		if !requiresEncrypted {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: expected encrypted string, got %s", ctx, rawTypeDescription(raw))
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("parse %s as string: %w", ctx, err)
	}
	if s == "" {
		return nil, nil
	}
	if !session.IsEncryptedChunk(s) {
		if !requiresEncrypted {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: expected encrypted string but not recognised (len=%d prefix=%q)", ctx, len(s), SafePrefix(s, 8))
	}
	plaintext, err := session.Decrypt(s)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", ctx, err)
	}
	return plaintext, nil
}

// decryptJSONArrayObjects parses an array of JSON objects, lets visit mutate each
// object, and re-marshals the array if any item changed. If strict is false and raw
// is not an array of objects, the helper returns (nil, false, nil).
func decryptJSONArrayObjects(raw json.RawMessage, strict bool, parseContext string, visit func(i int, item map[string]json.RawMessage) (bool, error)) (json.RawMessage, bool, error) {
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		if strict {
			return nil, false, fmt.Errorf("%s: %w", parseContext, err)
		}
		return nil, false, nil
	}

	changed := false
	for i := range items {
		itemChanged, err := visit(i, items[i])
		if err != nil {
			return nil, false, err
		}
		if itemChanged {
			changed = true
		}
	}

	if !changed {
		return nil, false, nil
	}
	out, _ := json.Marshal(items) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	return out, true, nil
}

// applyDecryptedJSON stores a successfully decrypted payload as a json.RawMessage.
// If plaintext is valid JSON it is used directly; otherwise it is wrapped as a JSON string.
func applyDecryptedJSON(plaintext []byte) json.RawMessage {
	if json.Valid(plaintext) {
		return json.RawMessage(plaintext)
	}
	b, _ := json.Marshal(string(plaintext)) //nolint:errchkjson // strings always marshal
	return b
}

// DecryptSSEChunk parses one SSE data JSON payload, decrypts all encrypted
// fields in the delta object, and returns the JSON with plaintext substituted.
// The endpoint parameter identifies the proxy route kind; currently only EndpointChat is supported.
// Actual provider paths: /v1/chat/completions (NearCloud) or /api/v1/chat/completions (Venice).
func DecryptSSEChunk(data string, session Decryptor, endpoint EndpointType) (string, error) {
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

	changed, err := decryptChatObject(delta, session, "delta", endpoint)
	if err != nil {
		return "", err
	}
	// Gate on any encrypted logprobs leaf rather than only content[].token so that
	// mixed-policy cases (e.g. only refusal[].token encrypted) are handled correctly.
	// NearCloud/NearDirect report "logprobs" container as false but encrypt leaves.
	if anyLogprobsLeafEncrypted(session, endpoint) {
		c, err := decryptChoiceLogprobs(choices[0], session, "choice[0]", endpoint)
		if err := setChanged(&changed, c, err); err != nil {
			return "", err
		}
	}
	if !changed {
		return data, nil
	}

	// Re-serialize delta → choices[0] → choices → full.
	deltaOut, _ := json.Marshal(delta) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	choices[0]["delta"] = deltaOut

	choicesOut, _ := json.Marshal(choices) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	full["choices"] = choicesOut

	out, _ := json.Marshal(full) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	return string(out), nil
}

// collectOriginalStringFields snapshots all non-metadata, non-empty string
// fields from delta before decryption. The snapshot is used after
// decryptChatObject to classify fields as originally-encrypted vs plaintext
// (via constant-time compare) and to verify that expected ciphertexts were
// actually decrypted.
func collectOriginalStringFields(delta map[string]json.RawMessage) map[string]string {
	result := make(map[string]string, len(delta))
	for key, raw := range delta {
		if IsNonEncryptedField(key) {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) != nil || s == "" {
			continue
		}
		result[key] = s
	}
	return result
}

// decryptSSEChunkContent decrypts all encrypted fields from the first choice's
// delta in one SSE JSON chunk and returns them as a map of field name to
// plaintext string.
// The endpoint parameter identifies the proxy route kind (currently only EndpointChat is supported).
func decryptSSEChunkContent(data string, session Decryptor, endpoint EndpointType) (map[string]string, error) {
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

	originalStringFields := collectOriginalStringFields(delta)

	if _, err := decryptChatObject(delta, session, "delta", endpoint); err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for key, original := range originalStringFields {
		if IsNonEncryptedField(key) {
			continue
		}
		raw := delta[key]
		var s string
		if json.Unmarshal(raw, &s) != nil || s == "" {
			continue
		}
		if !session.IsEncryptedChunk(original) {
			if !IsNonEncryptedField(key) && session.IsResponseFieldEncrypted(key, endpoint) {
				return nil, fmt.Errorf("delta.%s: expected encrypted string before decryption", key)
			}
			result[key] = s
			continue
		}
		if subtle.ConstantTimeCompare([]byte(original), []byte(s)) == 1 {
			return nil, fmt.Errorf("delta.%s: expected decrypted plaintext, got unchanged ciphertext", key)
		}
		result[key] = s
	}

	if len(result) == 0 {
		return map[string]string{}, nil
	}
	return result, nil
}

// DecryptNonStreamResponseForEndpoint decrypts all encrypted string fields in
// an OpenAI-format non-streaming response body for a specific endpoint path.
func DecryptNonStreamResponseForEndpoint(body []byte, session Decryptor, endpoint EndpointType) ([]byte, error) {
	if endpoint == "" {
		return nil, errors.New("decrypt non-stream response: endpoint type is required")
	}

	var full map[string]json.RawMessage
	if err := json.Unmarshal(body, &full); err != nil {
		return nil, fmt.Errorf("parse response JSON: %w", err)
	}

	var changed bool

	// Chat completions: decrypt choices[].message content fields.
	if choicesRaw, ok := full["choices"]; ok {
		c, err := decryptResponseChoices(choicesRaw, session, endpoint)
		if err != nil {
			return nil, err
		}
		if c != nil {
			full["choices"] = c
			changed = true
		}
	}

	// Per-endpoint data[] decryption. Unknown endpoints are rejected here so
	// the allowlist and dispatch are co-located rather than split across two
	// separate guards.
	switch endpoint {
	case EndpointChat:
		// choices[] already handled above; no data[] to decrypt.
	case EndpointImages:
		// Image generation endpoint path: /v1/images/generations.
		if dataRaw, ok := full["data"]; ok {
			d, err := decryptResponseImageData(dataRaw, session, endpoint)
			if err != nil {
				return nil, err
			}
			if d != nil {
				full["data"] = d
				changed = true
			}
		}
	case EndpointEmbeddings:
		// Embeddings endpoint path: /v1/embeddings.
		if dataRaw, ok := full["data"]; ok {
			d, err := decryptResponseEmbeddingsData(dataRaw, session, endpoint)
			if err != nil {
				return nil, err
			}
			if d != nil {
				full["data"] = d
				changed = true
			}
		}
	case EndpointScore:
		// Score endpoint path: /v1/score.
		if dataRaw, ok := full["data"]; ok {
			d, err := decryptResponseScoreData(dataRaw, session, endpoint)
			if err != nil {
				return nil, err
			}
			if d != nil {
				full["data"] = d
				changed = true
			}
		}
	case EndpointRerank:
		// Reranking: decrypt results[] document text fields.
		// Reranking endpoint path: /v1/rerank.
		if resultsRaw, ok := full["results"]; ok {
			r, err := decryptResponseRerankResults(resultsRaw, session, endpoint)
			if err != nil {
				return nil, err
			}
			if r != nil {
				full["results"] = r
				changed = true
			}
		}
	case EndpointAudio:
		// Audio transcription endpoint path: /v1/audio/transcriptions.
		// This route is multipart and does not use field-level response E2EE,
		// so there is no endpoint-specific body field decryption here.
	default:
		return nil, fmt.Errorf("decrypt non-stream response: unsupported endpoint type %q", endpoint)
	}

	// Top-level score field: decrypt or fail-closed for any endpoint. For full-
	// field sessions (e.g. NearCloud), the policy returns true for unknown leaves
	// on non-score endpoints, so a stray plaintext score field is rejected.
	c, err := decryptJSONValueField(full, EncFieldScore, session, EncFieldScore, EncFieldScore, endpoint)
	if err := setChanged(&changed, c, err); err != nil {
		return nil, err
	}

	if !changed {
		return body, nil
	}
	return json.Marshal(full)
}

// decryptResponseChoices decrypts content fields in choices[].message objects.
// Returns the rewritten choices JSON, or nil if nothing was decrypted.
func decryptResponseChoices(choicesRaw json.RawMessage, session Decryptor, endpoint EndpointType) (json.RawMessage, error) {
	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(choicesRaw, &choices); err != nil {
		return nil, fmt.Errorf("parse choices: %w", err)
	}

	changed := false
	for i, choice := range choices {
		msgRaw, ok := choice["message"]
		if !ok {
			continue
		}
		var msg map[string]json.RawMessage
		if err := json.Unmarshal(msgRaw, &msg); err != nil {
			return nil, fmt.Errorf("parse choice[%d].message: %w", i, err)
		}

		c, err := decryptChatObject(msg, session, fmt.Sprintf("choice[%d].message", i), endpoint)
		if err != nil {
			return nil, err
		}
		// Gate on any encrypted logprobs leaf rather than only content[].token.
		// Providers can encrypt only a subset of logprobs leaves.
		// Chat completions endpoint path: /v1/chat/completions or /api/v1/chat/completions
		if anyLogprobsLeafEncrypted(session, endpoint) {
			if lc, err := decryptChoiceLogprobs(choices[i], session, fmt.Sprintf("choice[%d]", i), endpoint); err != nil {
				return nil, err
			} else if lc {
				c = true
			}
		}
		if !c {
			continue
		}

		msgOut, _ := json.Marshal(msg) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
		choices[i]["message"] = msgOut
		changed = true
	}

	if !changed {
		return nil, nil
	}
	out, _ := json.Marshal(choices) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	return out, nil
}

// imageEncryptedFields lists the policy-path constants for fields in an images
// response data item that the NearCloud inference-proxy encrypts with the E2EE
// session key. The values double as both JSON field names and policy paths.
var imageEncryptedFields = []string{EncFieldB64JSON, EncFieldRevisedPrompt}

// functionObjectFields lists the string-valued fields of an OpenAI function
// call object (tool_calls[].function and function_call) that are encrypted
// end-to-end. Both the encryption (nearcloud.go) and decryption (relay.go)
// paths iterate this slice so that field coverage stays in sync.
var functionObjectFields = []string{"name", "arguments"}

// decryptResponseImageData decrypts encrypted fields in data[] items of an
// images generation response. Returns the rewritten data JSON, or nil if
// nothing was decrypted.
// Image generation endpoint path: /v1/images/generations.
func decryptResponseImageData(dataRaw json.RawMessage, session Decryptor, endpoint EndpointType) (json.RawMessage, error) {
	out, changed, err := decryptJSONArrayObjects(dataRaw, true, "parse data as image array", func(i int, item map[string]json.RawMessage) (bool, error) {
		itemChanged := false
		for _, field := range imageEncryptedFields {
			c, err := decryptMaybeEncryptedStringField(item, field, session, fmt.Sprintf("data[%d]", i), field, endpoint)
			if err != nil {
				return false, err
			}
			if c {
				itemChanged = true
			}
		}
		return itemChanged, nil
	})
	if err != nil {
		return nil, err
	}
	if !changed {
		return nil, nil
	}
	return out, nil
}

// decryptResponseDataArrayField decrypts a single named JSON-value field in
// each data[] item of an OpenAI endpoint response. Requires the field to be
// present in every data[] object. Returns nil when no items contain the
// field or nothing changes. parseContext is used in error messages when the
// data array cannot be parsed (e.g. "parse data as embeddings array").
func decryptResponseDataArrayField(dataRaw json.RawMessage, fieldName, parseContext, policyPath string, session Decryptor, endpoint EndpointType) (json.RawMessage, error) {
	// Pre-compute once; policyPath, session, and endpoint are fixed across all items.
	requiresEncrypted := session.IsResponseFieldEncrypted(policyPath, endpoint)
	sawField := false
	out, changed, err := decryptJSONArrayObjects(dataRaw, true, parseContext, func(i int, item map[string]json.RawMessage) (bool, error) {
		raw, ok := item[fieldName]
		if !ok {
			return false, fmt.Errorf("data[%d].%s: missing", i, fieldName)
		}
		sawField = true
		if IsJSONNull(raw) {
			// NearAI skips null values during encryption. Treat null as absent.
			return false, nil
		}
		plaintext, err := DecryptFieldOrSkip(raw, session, requiresEncrypted, fmt.Sprintf("data[%d].%s", i, fieldName))
		if err != nil {
			return false, err
		}
		if plaintext == nil {
			return false, nil
		}
		item[fieldName] = applyDecryptedJSON(plaintext)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if !sawField || !changed {
		return nil, nil
	}
	return out, nil
}

// decryptResponseEmbeddingsData decrypts encrypted embedding vectors in data[] items.
// Each embedding is stored as an encrypted JSON string that deserialises to a float array.
// Returns the rewritten data JSON, or nil if nothing was decrypted.
// Embeddings endpoint path: /v1/embeddings.
func decryptResponseEmbeddingsData(dataRaw json.RawMessage, session Decryptor, endpoint EndpointType) (json.RawMessage, error) {
	return decryptResponseDataArrayField(dataRaw, EncFieldEmbedding, "parse data as embeddings array", EncFieldEmbedding, session, endpoint)
}

// decryptResponseRerankResults decrypts document text fields in results[] items of a reranking response.
// Returns the rewritten results JSON, or nil if nothing was decrypted.
// Reranking endpoint path: /v1/rerank.
func decryptResponseRerankResults(resultsRaw json.RawMessage, session Decryptor, endpoint EndpointType) (json.RawMessage, error) {
	// Pre-compute once; policy, session, and endpoint are fixed across all items.
	requiresEncrypted := session.IsResponseFieldEncrypted(EncFieldRerankDocumentText, endpoint)
	out, changed, err := decryptJSONArrayObjects(resultsRaw, true, "parse results", func(i int, item map[string]json.RawMessage) (bool, error) {
		docRaw, ok := item["document"]
		if !ok {
			return false, fmt.Errorf("results[%d].document: missing", i)
		}
		if IsJSONNull(docRaw) {
			// NearAI only encrypts document.text when document is an object.
			// Null document is treated as absent and passed through.
			return false, nil
		}
		if !jsonRawStartsWithToken(docRaw, '{') {
			if requiresEncrypted {
				return false, fmt.Errorf("results[%d].document: expected object", i)
			}
			return false, nil
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(docRaw, &doc); err != nil {
			return false, fmt.Errorf("parse results[%d].document: %w", i, err)
		}
		if _, ok := doc["text"]; !ok {
			if requiresEncrypted {
				return false, fmt.Errorf("results[%d].document.text: missing", i)
			}
			return false, nil
		}
		// decryptMaybeEncryptedStringField handles null text (returns false, nil) and
		// updates doc["text"] in place on success.
		c, err := decryptMaybeEncryptedStringField(doc, "text", session, fmt.Sprintf("results[%d].document", i), EncFieldRerankDocumentText, endpoint)
		if err != nil {
			return false, err
		}
		if !c {
			return false, nil
		}
		docOut, _ := json.Marshal(doc) // map[string]json.RawMessage always marshals without error
		item["document"] = docOut
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if !changed {
		return nil, nil
	}
	return out, nil
}

// decryptResponseScoreData processes score fields in data[] items of a score response.
// It decrypts encrypted score strings when present; if the score is plaintext,
// the session policy determines whether plaintext is allowed.
// Returns the rewritten data JSON, or nil if nothing was decrypted.
// Score endpoint path: /v1/score.
func decryptResponseScoreData(dataRaw json.RawMessage, session Decryptor, endpoint EndpointType) (json.RawMessage, error) {
	return decryptResponseDataArrayField(dataRaw, EncFieldScore, "parse data as score array", EncFieldScore, session, endpoint)
}

// ReassembleNonStream reads an SSE stream (forced by E2EE), decrypts each
// chunk, and reassembles the result into a single non-streaming OpenAI response.
// Handles tool_calls and finish_reason from delta chunks. Returns the assembled
// JSON and token throughput stats.
// The endpoint parameter identifies the proxy route kind (currently only EndpointChat is supported).
// Actual provider paths: /v1/chat/completions (NearCloud) or /api/v1/chat/completions (Venice).
func ReassembleNonStream(body io.Reader, session Decryptor, endpoint EndpointType) ([]byte, StreamStats, error) {
	scanner, cleanup := newSSEScanner(body)
	defer cleanup()

	fields := make(map[string]*strings.Builder)
	toolCalls := make(map[int]*reassembledToolCall)
	var finishReason string
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

		decrypted, err := decryptSSEChunkContent(data, session, endpoint)
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

		meta, err := extractChunkMeta(data, session, endpoint)
		if err != nil {
			return nil, stats, fmt.Errorf("reassemble: %w", err)
		}
		for _, tc := range meta.ToolCalls {
			if err := mergeToolCallDelta(toolCalls, tc); err != nil {
				return nil, stats, fmt.Errorf("reassemble: %w", err)
			}
		}
		if meta.FinishReason != "" {
			finishReason = meta.FinishReason
		}

		lastData = data
	}
	if err := scanner.Err(); err != nil {
		return nil, stats, fmt.Errorf("reassemble: scanner: %w", err)
	}

	if lastData == "" {
		return nil, stats, errors.New("reassemble: no SSE chunks received")
	}

	var responseMeta struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Created int64  `json:"created"`
	}
	if err := json.Unmarshal([]byte(lastData), &responseMeta); err != nil {
		return nil, stats, fmt.Errorf("reassemble: parse metadata from last chunk: %w", err)
	}

	msg := make(map[string]any, len(fields)+2)
	msg["role"] = "assistant"
	for k, b := range fields {
		msg[k] = b.String()
	}
	if len(toolCalls) > 0 {
		msg["tool_calls"] = sortedToolCalls(toolCalls)
	}

	if finishReason == "" {
		finishReason = "stop"
	}

	resp := map[string]any{
		"id":      responseMeta.ID,
		"object":  "chat.completion",
		"created": responseMeta.Created,
		"model":   responseMeta.Model,
		"choices": []map[string]any{
			{
				"index":         0,
				"message":       msg,
				"finish_reason": finishReason,
			},
		},
	}

	result, err := json.Marshal(resp)
	return result, stats, err
}

// reassembledToolCall accumulates a single tool call from streaming deltas.
type reassembledToolCall struct {
	ID       string                  `json:"id"`
	Type     string                  `json:"type"`
	Function reassembledToolCallFunc `json:"function"`
}

type reassembledToolCallFunc struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// chunkMeta holds non-encrypted metadata extracted from an SSE chunk.
type chunkMeta struct {
	ToolCalls    []json.RawMessage
	FinishReason string
}

// extractChunkMeta extracts tool_calls and finish_reason from the first
// choice's delta in an SSE chunk.
func extractChunkMeta(data string, session Decryptor, endpoint EndpointType) (chunkMeta, error) {
	var parsed struct {
		Choices []struct {
			Delta struct {
				ToolCalls []json.RawMessage `json:"tool_calls"`
			} `json:"delta"`
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(data), &parsed); err != nil {
		return chunkMeta{}, fmt.Errorf("extractChunkMeta: %w", err)
	}
	var m chunkMeta
	if len(parsed.Choices) > 0 {
		m.ToolCalls = parsed.Choices[0].Delta.ToolCalls
		if session != nil && len(m.ToolCalls) > 0 {
			delta := map[string]json.RawMessage{}
			toolCallsJSON, _ := json.Marshal(m.ToolCalls) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
			delta["tool_calls"] = toolCallsJSON
			if _, err := decryptChatObject(delta, session, "delta", endpoint); err != nil {
				return chunkMeta{}, err
			}
			if raw, ok := delta["tool_calls"]; ok {
				if err := json.Unmarshal(raw, &m.ToolCalls); err != nil {
					return chunkMeta{}, fmt.Errorf("extractChunkMeta: parse decrypted tool_calls: %w", err)
				}
			}
		}
		if parsed.Choices[0].FinishReason != nil {
			m.FinishReason = *parsed.Choices[0].FinishReason
		}
	}
	return m, nil
}

// toolCallDelta is the streaming delta format for a single tool call entry.
type toolCallDelta struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Index    *int   `json:"index"`
	Function *struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// mergeToolCallDelta merges a streaming tool_call delta into the accumulated
// tool calls map, keyed by index. Arguments are concatenated across chunks.
func mergeToolCallDelta(calls map[int]*reassembledToolCall, raw json.RawMessage) error {
	var d toolCallDelta
	if _, _, err := jsonstrict.UnmarshalWarn(raw, &d, "e2ee SSE data"); err != nil {
		return fmt.Errorf("parse tool_call delta: %w", err)
	}
	if d.Index == nil {
		return errors.New("tool_call delta missing required index field")
	}
	idx := *d.Index
	tc, ok := calls[idx]
	if !ok {
		tc = &reassembledToolCall{}
		calls[idx] = tc
	}
	if d.ID != "" {
		tc.ID = d.ID
	}
	if d.Type != "" {
		tc.Type = d.Type
	}
	if d.Function != nil {
		if d.Function.Name != "" {
			tc.Function.Name = d.Function.Name
		}
		tc.Function.Arguments += d.Function.Arguments
	}
	return nil
}

// sortedToolCalls returns the accumulated tool calls sorted by index.
func sortedToolCalls(calls map[int]*reassembledToolCall) []reassembledToolCall {
	indices := make([]int, 0, len(calls))
	for idx := range calls {
		indices = append(indices, idx)
	}
	sort.Ints(indices)
	result := make([]reassembledToolCall, 0, len(calls))
	for _, idx := range indices {
		result = append(result, *calls[idx])
	}
	return result
}

// RelayStream reads an SSE stream from body, decrypts chunks when session is
// non-nil, and writes the decrypted SSE lines to w. Returns token throughput
// stats and a non-nil error: ErrDecryptionFailed on decryption failure,
// ErrRelayFailed on other terminal failures.
// The endpoint parameter identifies the proxy route kind (currently only EndpointChat is supported).
func RelayStream(ctx context.Context, w http.ResponseWriter, body io.Reader, session Decryptor, endpoint EndpointType) (StreamStats, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return StreamStats{}, fmt.Errorf("%w: streaming not supported", ErrRelayFailed)
	}

	scanner, cleanup := newSSEScanner(body)
	defer cleanup()

	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			http.Error(w, "upstream stream error", http.StatusBadGateway)
			return StreamStats{}, fmt.Errorf("%w: %w", ErrRelayFailed, err)
		}
		http.Error(w, "empty upstream stream", http.StatusBadGateway)
		return StreamStats{}, fmt.Errorf("%w: empty upstream stream", ErrRelayFailed)
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	var stats StreamStats
	var firstChunk time.Time
	var decryptErr error

	process := func(line string) bool {
		done, derr := relaySSELine(ctx, w, flusher, line, session, endpoint)
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
		return stats, fmt.Errorf("%w: %w", ErrRelayFailed, err)
	}
	return stats, decryptErr
}

// relaySSELine processes a single SSE line, writing it to w. Returns
// (done, error) where done=true means the stream should end. error is non-nil
// only on decryption failure (wraps ErrDecryptionFailed).
// The endpoint parameter identifies the proxy route kind (currently only EndpointChat is supported).
func relaySSELine(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, line string, session Decryptor, endpoint EndpointType) (bool, error) {
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

	decrypted, err := DecryptSSEChunk(data, session, endpoint)
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
// The endpoint parameter identifies the proxy route kind (currently only EndpointChat is supported).
func RelayReassembledNonStream(ctx context.Context, w http.ResponseWriter, body io.Reader, session Decryptor, endpoint EndpointType) (StreamStats, error) {
	result, stats, err := ReassembleNonStream(body, session, endpoint)
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

// RelayNonStreamForEndpoint reads a non-streaming JSON response from body,
// decrypts endpoint-specific content fields if session is non-nil, and writes
// the result to w. The endpoint parameter identifies the proxy route kind
// (chat, embeddings, images, etc.); actual provider paths are documented
// in DecryptNonStreamResponseForEndpoint.
func RelayNonStreamForEndpoint(ctx context.Context, w http.ResponseWriter, body io.Reader, session Decryptor, endpoint EndpointType) (StreamStats, error) {
	responseBody, err := io.ReadAll(io.LimitReader(body, 10<<20))
	if err != nil {
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return StreamStats{}, fmt.Errorf("%w: %w", ErrRelayFailed, err)
	}

	if session == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(responseBody)
		return StreamStats{}, nil
	}

	decrypted, err := DecryptNonStreamResponseForEndpoint(responseBody, session, endpoint)
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
