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

// NonEncryptedFields are known plaintext metadata fields in OpenAI chat
// delta/message objects.
var NonEncryptedFields = map[string]bool{
	"role":          true,
	"tool_call_id":  true,
	"type":          true,
	"finish_reason": true,
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
		plaintextJSON, _ := json.Marshal(string(plaintext)) //nolint:errchkjson // strings always marshal
		fields[key] = plaintextJSON
		changed = true
	}
	return changed, nil
}

func decryptAudioDataField(fields map[string]json.RawMessage, session Decryptor, ctx string) (bool, error) {
	audioRaw, ok := fields["audio"]
	if !ok || IsJSONNull(audioRaw) {
		return false, nil
	}
	var audio map[string]json.RawMessage
	if err := json.Unmarshal(audioRaw, &audio); err != nil {
		return false, fmt.Errorf("%s.audio: parse object: %w", ctx, err)
	}
	raw, ok := audio["data"]
	if !ok || IsJSONNull(raw) {
		return false, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return false, fmt.Errorf("%s.audio.data: parse string: %w", ctx, err)
	}
	if s == "" {
		return false, nil
	}
	if !session.IsEncryptedChunk(s) {
		return false, fmt.Errorf("%s.audio.data: expected encrypted but not recognised (len=%d prefix=%q)", ctx, len(s), SafePrefix(s, 8))
	}
	plaintext, err := session.Decrypt(s)
	if err != nil {
		return false, fmt.Errorf("decrypt %s.audio.data: %w", ctx, err)
	}
	plaintextJSON, _ := json.Marshal(string(plaintext)) //nolint:errchkjson // strings always marshal
	audio["data"] = plaintextJSON
	audioOut, _ := json.Marshal(audio) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	fields["audio"] = audioOut
	return true, nil
}

func decryptFunctionObject(obj map[string]json.RawMessage, session Decryptor, ctx string) (bool, error) {
	changed := false
	for _, key := range []string{"name", "arguments"} {
		raw, ok := obj[key]
		if !ok || IsJSONNull(raw) {
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return false, fmt.Errorf("%s.%s: parse string: %w", ctx, key, err)
		}
		if s == "" {
			continue
		}
		if !session.IsEncryptedChunk(s) {
			return false, fmt.Errorf("%s.%s: expected encrypted but not recognised (len=%d prefix=%q)", ctx, key, len(s), SafePrefix(s, 8))
		}
		plaintext, err := session.Decrypt(s)
		if err != nil {
			return false, fmt.Errorf("decrypt %s.%s: %w", ctx, key, err)
		}
		plaintextJSON, _ := json.Marshal(string(plaintext)) //nolint:errchkjson // strings always marshal
		obj[key] = plaintextJSON
		changed = true
	}
	return changed, nil
}

func decryptToolCallsField(fields map[string]json.RawMessage, session Decryptor, ctx string) (bool, error) {
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
		c, err := decryptFunctionObject(fn, session, fmt.Sprintf("%s.tool_calls[%d].function", ctx, i))
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

func decryptFunctionCallField(fields map[string]json.RawMessage, session Decryptor, ctx string) (bool, error) {
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
	changed, err := decryptFunctionObject(fc, session, ctx+".function_call")
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

func decryptChoiceLogprobs(choice map[string]json.RawMessage, session Decryptor, ctx string) (bool, error) {
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
		entriesRaw, ok := logprobs[key]
		if !ok || IsJSONNull(entriesRaw) {
			continue
		}
		var entries []map[string]json.RawMessage
		if err := json.Unmarshal(entriesRaw, &entries); err != nil {
			return false, fmt.Errorf("%s.logprobs.%s: parse array: %w", ctx, key, err)
		}
		for i := range entries {
			entryChanged, err := decryptLogprobsTokenEntry(entries[i], session, fmt.Sprintf("%s.logprobs.%s[%d]", ctx, key, i))
			if err != nil {
				return false, err
			}
			if entryChanged {
				changed = true
			}
		}
		entriesOut, _ := json.Marshal(entries) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
		logprobs[key] = entriesOut
	}
	if !changed {
		return false, nil
	}
	logprobsOut, _ := json.Marshal(logprobs) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	choice["logprobs"] = logprobsOut
	return true, nil
}

func decryptLogprobsTokenEntry(entry map[string]json.RawMessage, session Decryptor, ctx string) (bool, error) {
	changed := false
	if c, err := decryptMaybeEncryptedStringField(entry, "token", session, ctx); err != nil {
		return false, err
	} else if c {
		changed = true
	}
	if c, err := decryptLogprobsBytesField(entry, session, ctx); err != nil {
		return false, err
	} else if c {
		changed = true
	}
	topRaw, ok := entry["top_logprobs"]
	if !ok || IsJSONNull(topRaw) {
		return changed, nil
	}
	var top []map[string]json.RawMessage
	if err := json.Unmarshal(topRaw, &top); err != nil {
		return false, fmt.Errorf("%s.top_logprobs: parse array: %w", ctx, err)
	}
	for i := range top {
		c, err := decryptLogprobsTokenEntry(top[i], session, fmt.Sprintf("%s.top_logprobs[%d]", ctx, i))
		if err != nil {
			return false, err
		}
		if c {
			changed = true
		}
	}
	topOut, _ := json.Marshal(top) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	entry["top_logprobs"] = topOut
	return changed, nil
}

func decryptMaybeEncryptedStringField(obj map[string]json.RawMessage, key string, session Decryptor, ctx string) (bool, error) {
	raw, ok := obj[key]
	if !ok || IsJSONNull(raw) {
		return false, nil
	}
	if !jsonRawStartsWithToken(raw, '"') {
		return false, fmt.Errorf("%s.%s: expected string", ctx, key)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return false, fmt.Errorf("parse %s.%s as string: %w", ctx, key, err)
	}
	if s == "" {
		return false, nil
	}
	if !session.IsEncryptedChunk(s) {
		return false, fmt.Errorf("%s.%s: expected encrypted but not recognised (len=%d prefix=%q)", ctx, key, len(s), SafePrefix(s, 8))
	}
	plaintext, err := session.Decrypt(s)
	if err != nil {
		return false, fmt.Errorf("decrypt %s.%s: %w", ctx, key, err)
	}
	plaintextJSON, _ := json.Marshal(string(plaintext)) //nolint:errchkjson // strings always marshal
	obj[key] = plaintextJSON
	return true, nil
}

type nonStreamEndpointType int

const (
	nonStreamEndpointUnknown nonStreamEndpointType = iota
	nonStreamEndpointChat
	nonStreamEndpointImages
	nonStreamEndpointEmbeddings
	nonStreamEndpointRerank
	nonStreamEndpointScore
)

func classifyNonStreamEndpoint(endpointPath string) nonStreamEndpointType {
	switch endpointPath {
	case "/v1/chat/completions", "/api/v1/chat/completions":
		return nonStreamEndpointChat
	case "/v1/images/generations":
		return nonStreamEndpointImages
	case "/v1/embeddings":
		return nonStreamEndpointEmbeddings
	case "/v1/rerank":
		return nonStreamEndpointRerank
	case "/v1/score":
		return nonStreamEndpointScore
	default:
		return nonStreamEndpointUnknown
	}
}

func jsonTopLevelNumber(raw []byte) bool {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	_, ok := v.(float64)
	return ok
}

func jsonArrayOfNumbers(raw []byte) bool {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	arr, ok := v.([]any)
	if !ok {
		return false
	}
	for _, elem := range arr {
		if _, ok := elem.(float64); !ok {
			return false
		}
	}
	return true
}

func decryptLogprobsBytesField(entry map[string]json.RawMessage, session Decryptor, ctx string) (bool, error) {
	raw, ok := entry["bytes"]
	if !ok || IsJSONNull(raw) {
		return false, nil
	}
	if !jsonRawStartsWithToken(raw, '"') {
		// Plaintext bytes are usually JSON arrays, so only attempt string decryptions.
		return false, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return false, fmt.Errorf("parse %s.bytes as string: %w", ctx, err)
	}
	if s == "" {
		return false, nil
	}
	if !session.IsEncryptedChunk(s) {
		return false, fmt.Errorf("%s.bytes: expected encrypted string but not recognised (len=%d prefix=%q)", ctx, len(s), SafePrefix(s, 8))
	}
	plaintext, err := session.Decrypt(s)
	if err != nil {
		return false, fmt.Errorf("decrypt %s.bytes: %w", ctx, err)
	}
	if json.Valid(plaintext) {
		entry["bytes"] = json.RawMessage(plaintext)
	} else {
		plaintextJSON, _ := json.Marshal(string(plaintext)) //nolint:errchkjson // strings always marshal
		entry["bytes"] = plaintextJSON
	}
	return true, nil
}

func decryptChatObject(fields map[string]json.RawMessage, session Decryptor, ctx string) (bool, error) {
	changed := false
	if c, err := decryptDeltaFields(fields, session, ctx); err != nil {
		return false, err
	} else if c {
		changed = true
	}
	if c, err := decryptAudioDataField(fields, session, ctx); err != nil {
		return false, err
	} else if c {
		changed = true
	}
	if c, err := decryptToolCallsField(fields, session, ctx); err != nil {
		return false, err
	} else if c {
		changed = true
	}
	if c, err := decryptFunctionCallField(fields, session, ctx); err != nil {
		return false, err
	} else if c {
		changed = true
	}
	return changed, nil
}

func jsonRawStartsWithToken(raw json.RawMessage, token byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == token
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

	changed, err := decryptChatObject(delta, session, "delta")
	if err != nil {
		return "", err
	}
	if c, err := decryptChoiceLogprobs(choices[0], session, "choice[0]"); err != nil {
		return "", err
	} else if c {
		changed = true
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

	originalEncrypted := make(map[string]string, len(delta))
	for key, raw := range delta {
		if NonEncryptedFields[key] {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) != nil || s == "" {
			continue
		}
		originalEncrypted[key] = s
	}

	if _, err := decryptChatObject(delta, session, "delta"); err != nil {
		return nil, err
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
		original, ok := originalEncrypted[key]
		if !ok {
			return nil, fmt.Errorf("delta.%s: expected encrypted string before decryption", key)
		}
		if !session.IsEncryptedChunk(original) {
			return nil, fmt.Errorf("delta.%s: expected encrypted string before decryption", key)
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

// DecryptNonStreamResponse decrypts all encrypted string fields in each
// choice's message of an OpenAI-format non-streaming response body.
func DecryptNonStreamResponse(body []byte, session Decryptor) ([]byte, error) {
	return DecryptNonStreamResponseForEndpoint(body, session, "")
}

// DecryptNonStreamResponseForEndpoint decrypts all encrypted string fields in
// an OpenAI-format non-streaming response body for a specific endpoint path.
func DecryptNonStreamResponseForEndpoint(body []byte, session Decryptor, endpointPath string) ([]byte, error) {
	var full map[string]json.RawMessage
	if err := json.Unmarshal(body, &full); err != nil {
		return nil, fmt.Errorf("parse response JSON: %w", err)
	}

	var changed bool
	endpointType := classifyNonStreamEndpoint(endpointPath)

	// Chat completions: decrypt choices[].message content fields.
	if choicesRaw, ok := full["choices"]; ok {
		c, err := decryptResponseChoices(choicesRaw, session)
		if err != nil {
			return nil, err
		}
		if c != nil {
			full["choices"] = c
			changed = true
		}
	}

	// Images and embeddings: decrypt data[] fields.
	if dataRaw, ok := full["data"]; ok {
		switch endpointType {
		case nonStreamEndpointImages:
			d, err := decryptResponseImageData(dataRaw, session)
			if err != nil {
				return nil, err
			}
			if d != nil {
				full["data"] = d
				changed = true
			}
		case nonStreamEndpointEmbeddings:
			d, err := decryptResponseEmbeddingsData(dataRaw, session, true)
			if err != nil {
				return nil, err
			}
			if d != nil {
				full["data"] = d
				changed = true
			}
		case nonStreamEndpointScore:
			d, err := decryptResponseScoreData(dataRaw, session, true)
			if err != nil {
				return nil, err
			}
			if d != nil {
				full["data"] = d
				changed = true
			}
		default:
			// Try images first (has b64_json/revised_prompt).
			d, err := decryptResponseImageData(dataRaw, session)
			if err != nil {
				return nil, err
			}
			if d != nil {
				full["data"] = d
				changed = true
			} else {
				// If not images, try embeddings (has embedding vectors).
				d, err := decryptResponseEmbeddingsData(dataRaw, session, false)
				if err != nil {
					return nil, err
				}
				if d != nil {
					full["data"] = d
					changed = true
				}
			}
		}
	}

	// Reranking: decrypt results[] document text fields.
	if resultsRaw, ok := full["results"]; ok {
		r, err := decryptResponseRerankResults(resultsRaw, session)
		if err != nil {
			return nil, err
		}
		if r != nil {
			full["results"] = r
			changed = true
		}
	}

	// Score: when endpoint is unknown, attempt score fallback after others.
	if endpointType == nonStreamEndpointUnknown {
		if scoreDataRaw, ok := full["data"]; ok {
			s, err := decryptResponseScoreData(scoreDataRaw, session, false)
			if err != nil {
				return nil, err
			}
			if s != nil {
				full["data"] = s
				changed = true
			}
		}
	}

	if !changed {
		return body, nil
	}
	return json.Marshal(full)
}

// decryptResponseChoices decrypts content fields in choices[].message objects.
// Returns the rewritten choices JSON, or nil if nothing was decrypted.
func decryptResponseChoices(choicesRaw json.RawMessage, session Decryptor) (json.RawMessage, error) {
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

		c, err := decryptChatObject(msg, session, fmt.Sprintf("choice[%d].message", i))
		if err != nil {
			return nil, err
		}
		if lc, err := decryptChoiceLogprobs(choices[i], session, fmt.Sprintf("choice[%d]", i)); err != nil {
			return nil, err
		} else if lc {
			c = true
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

// imageEncryptedFields lists the fields in an images response data item that
// the NearCloud inference-proxy encrypts with the E2EE session key.
var imageEncryptedFields = []string{"b64_json", "revised_prompt"}

// decryptResponseImageData decrypts encrypted fields in data[] items of an
// images generation response. Returns the rewritten data JSON, or nil if
// nothing was decrypted.
func decryptResponseImageData(dataRaw json.RawMessage, session Decryptor) (json.RawMessage, error) {
	var data []map[string]json.RawMessage
	if err := json.Unmarshal(dataRaw, &data); err != nil {
		// Not an array of objects (e.g. embeddings float array) -- skip.
		return nil, nil //nolint:nilerr // unmarshal error means data is not image objects
	}

	changed := false
	for i, item := range data {
		for _, field := range imageEncryptedFields {
			raw, ok := item[field]
			if !ok || IsJSONNull(raw) {
				continue
			}
			var val string
			if err := json.Unmarshal(raw, &val); err != nil {
				continue // not a string field
			}
			if !session.IsEncryptedChunk(val) {
				continue
			}
			plaintext, err := session.Decrypt(val)
			if err != nil {
				return nil, fmt.Errorf("decrypt data[%d].%s: %w", i, field, err)
			}
			rewritten, _ := json.Marshal(string(plaintext)) //nolint:errchkjson // strings always marshal
			data[i][field] = rewritten
			changed = true
		}
	}

	if !changed {
		return nil, nil
	}
	out, _ := json.Marshal(data) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	return out, nil
}

// decryptResponseEmbeddingsData decrypts encrypted embedding vectors in data[] items.
// Each embedding is stored as an encrypted JSON string that deserializes to a float array.
// Returns the rewritten data JSON, or nil if nothing was decrypted.
func decryptResponseEmbeddingsData(dataRaw json.RawMessage, session Decryptor, strictDataShape bool) (json.RawMessage, error) {
	var data []map[string]json.RawMessage
	if err := json.Unmarshal(dataRaw, &data); err != nil {
		if strictDataShape {
			return nil, fmt.Errorf("parse data as embeddings array: %w", err)
		}
		// Not an array of objects -- skip.
		return nil, nil
	}

	changed := false
	sawEmbedding := false
	for i, item := range data {
		embRaw, ok := item["embedding"]
		if !ok {
			continue
		}
		sawEmbedding = true
		if IsJSONNull(embRaw) {
			return nil, fmt.Errorf("data[%d].embedding: expected encrypted string, got null", i)
		}
		// Check if embedding is a string (encrypted form) or array (plaintext).
		if len(embRaw) == 0 || embRaw[0] != '"' {
			return nil, fmt.Errorf("data[%d].embedding: expected encrypted string", i)
		}
		var embStr string
		if err := json.Unmarshal(embRaw, &embStr); err != nil {
			return nil, fmt.Errorf("parse data[%d].embedding: %w", i, err)
		}
		if !session.IsEncryptedChunk(embStr) {
			return nil, fmt.Errorf("data[%d].embedding: expected encrypted string", i)
		}
		plaintext, err := session.Decrypt(embStr)
		if err != nil {
			return nil, fmt.Errorf("decrypt data[%d].embedding: %w", i, err)
		}
		if !jsonArrayOfNumbers(plaintext) {
			return nil, fmt.Errorf("data[%d].embedding: expected JSON array of numbers", i)
		}
		data[i]["embedding"] = json.RawMessage(plaintext)
		changed = true
	}

	if !sawEmbedding {
		return nil, nil
	}
	if !changed {
		return nil, errors.New("data.embedding: expected encrypted content")
	}
	out, _ := json.Marshal(data) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	return out, nil
}

// decryptResponseRerankResults decrypts document text fields in results[] items of a reranking response.
// Returns the rewritten results JSON, or nil if nothing was decrypted.
func decryptResponseRerankResults(resultsRaw json.RawMessage, session Decryptor) (json.RawMessage, error) {
	var results []map[string]json.RawMessage
	if err := json.Unmarshal(resultsRaw, &results); err != nil {
		return nil, fmt.Errorf("parse results: %w", err)
	}

	changed := false
	for i, item := range results {
		docRaw, ok := item["document"]
		if !ok {
			return nil, fmt.Errorf("results[%d].document: missing", i)
		}
		if IsJSONNull(docRaw) {
			return nil, fmt.Errorf("results[%d].document: expected object, got null", i)
		}
		// Document is an object with a text field.
		if len(docRaw) == 0 || docRaw[0] != '{' {
			return nil, fmt.Errorf("results[%d].document: expected object", i)
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(docRaw, &doc); err != nil {
			return nil, fmt.Errorf("parse results[%d].document: %w", i, err)
		}
		textRaw, ok := doc["text"]
		if !ok {
			return nil, fmt.Errorf("results[%d].document.text: missing", i)
		}
		if IsJSONNull(textRaw) {
			return nil, fmt.Errorf("results[%d].document.text: expected encrypted string, got null", i)
		}
		var textStr string
		if err := json.Unmarshal(textRaw, &textStr); err != nil {
			return nil, fmt.Errorf("parse results[%d].document.text: %w", i, err)
		}
		if !session.IsEncryptedChunk(textStr) {
			return nil, fmt.Errorf("results[%d].document.text: expected encrypted string", i)
		}
		plaintext, err := session.Decrypt(textStr)
		if err != nil {
			return nil, fmt.Errorf("decrypt results[%d].document.text: %w", i, err)
		}
		rewritten, _ := json.Marshal(string(plaintext)) //nolint:errchkjson // strings always marshal
		doc["text"] = rewritten
		docOut, _ := json.Marshal(doc) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
		results[i]["document"] = docOut
		changed = true
	}

	if !changed {
		return nil, nil
	}
	out, _ := json.Marshal(results) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	return out, nil
}

// decryptResponseScoreData decrypts score fields in data[] items of a score response.
// Returns the rewritten data JSON, or nil if nothing was decrypted.
func decryptResponseScoreData(dataRaw json.RawMessage, session Decryptor, strictDataShape bool) (json.RawMessage, error) {
	var data []map[string]json.RawMessage
	if err := json.Unmarshal(dataRaw, &data); err != nil {
		if strictDataShape {
			return nil, fmt.Errorf("parse data as score array: %w", err)
		}
		// Not an array of objects -- skip.
		return nil, nil
	}

	changed := false
	sawScore := false
	for i, item := range data {
		scoreRaw, ok := item["score"]
		if !ok {
			continue
		}
		sawScore = true
		if IsJSONNull(scoreRaw) {
			return nil, fmt.Errorf("data[%d].score: expected encrypted string, got null", i)
		}
		// Score can be a number or a string (encrypted).
		if len(scoreRaw) == 0 || scoreRaw[0] != '"' {
			return nil, fmt.Errorf("data[%d].score: expected encrypted string", i)
		}
		var scoreStr string
		if err := json.Unmarshal(scoreRaw, &scoreStr); err != nil {
			return nil, fmt.Errorf("parse data[%d].score: %w", i, err)
		}
		if !session.IsEncryptedChunk(scoreStr) {
			return nil, fmt.Errorf("data[%d].score: expected encrypted string", i)
		}
		plaintext, err := session.Decrypt(scoreStr)
		if err != nil {
			return nil, fmt.Errorf("decrypt data[%d].score: %w", i, err)
		}
		if !jsonTopLevelNumber(plaintext) {
			return nil, fmt.Errorf("data[%d].score: expected JSON number", i)
		}
		data[i]["score"] = json.RawMessage(plaintext)
		changed = true
	}

	if !sawScore {
		return nil, nil
	}
	if !changed {
		return nil, errors.New("data.score: expected encrypted content")
	}
	out, _ := json.Marshal(data) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	return out, nil
}

// ReassembleNonStream reads an SSE stream (forced by E2EE), decrypts each
// chunk, and reassembles the result into a single non-streaming OpenAI response.
// Handles tool_calls and finish_reason from delta chunks. Returns the assembled
// JSON and token throughput stats.
func ReassembleNonStream(body io.Reader, session Decryptor) ([]byte, StreamStats, error) {
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

		meta, err := extractChunkMeta(data, session)
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
func extractChunkMeta(data string, session Decryptor) (chunkMeta, error) {
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
		if session != nil {
			for i := range m.ToolCalls {
				decrypted, err := decryptToolCallMetaRaw(m.ToolCalls[i], session, fmt.Sprintf("delta.tool_calls[%d]", i))
				if err != nil {
					return chunkMeta{}, err
				}
				m.ToolCalls[i] = decrypted
			}
		}
		if parsed.Choices[0].FinishReason != nil {
			m.FinishReason = *parsed.Choices[0].FinishReason
		}
	}
	return m, nil
}

func decryptToolCallMetaRaw(raw json.RawMessage, session Decryptor, ctx string) (json.RawMessage, error) {
	var tc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &tc); err != nil {
		return nil, fmt.Errorf("%s: parse object: %w", ctx, err)
	}
	fnRaw, ok := tc["function"]
	if !ok || IsJSONNull(fnRaw) {
		return raw, nil
	}
	var fn map[string]json.RawMessage
	if err := json.Unmarshal(fnRaw, &fn); err != nil {
		return nil, fmt.Errorf("%s.function: parse object: %w", ctx, err)
	}
	changed, err := decryptFunctionObject(fn, session, ctx+".function")
	if err != nil {
		return nil, err
	}
	if !changed {
		return raw, nil
	}
	fnOut, _ := json.Marshal(fn) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	tc["function"] = fnOut
	tcOut, _ := json.Marshal(tc) //nolint:errchkjson // re-marshaling previously-unmarshaled JSON
	return tcOut, nil
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
	if unknown, err := jsonstrict.Unmarshal(raw, &d); err != nil {
		return fmt.Errorf("parse tool_call delta: %w", err)
	} else if len(unknown) > 0 {
		slog.Debug("unexpected JSON fields", "fields", unknown, "context", "e2ee SSE data")
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
func RelayStream(ctx context.Context, w http.ResponseWriter, body io.Reader, session Decryptor) (StreamStats, error) {
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
		return stats, fmt.Errorf("%w: %w", ErrRelayFailed, err)
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
// non-nil error: ErrDecryptionFailed on decryption failure, ErrRelayFailed on
// other terminal failures.
func RelayNonStream(ctx context.Context, w http.ResponseWriter, body io.Reader, session Decryptor) (StreamStats, error) {
	return RelayNonStreamForEndpoint(ctx, w, body, session, "")
}

// RelayNonStreamForEndpoint reads a non-streaming JSON response from body,
// decrypts endpoint-specific content fields if session is non-nil, and writes
// the result to w.
func RelayNonStreamForEndpoint(ctx context.Context, w http.ResponseWriter, body io.Reader, session Decryptor, endpointPath string) (StreamStats, error) {
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

	decrypted, err := DecryptNonStreamResponseForEndpoint(responseBody, session, endpointPath)
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
