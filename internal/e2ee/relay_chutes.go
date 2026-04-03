package e2ee

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// handleChutesInit decodes the e2e_init event and derives the stream key.
func handleChutesInit(initB64 json.RawMessage, session *ChutesSession) ([]byte, error) {
	var b64 string
	if err := json.Unmarshal(initB64, &b64); err != nil {
		return nil, fmt.Errorf("parse e2e_init string: %w", err)
	}
	streamKey, err := session.DecryptStreamInitChutes(b64)
	if err != nil {
		return nil, fmt.Errorf("derive stream key: %w", err)
	}
	return streamKey, nil
}

// handleChutesChunk decodes and decrypts a single e2e chunk.
func handleChutesChunk(encB64 json.RawMessage, streamKey []byte) ([]byte, error) {
	var b64 string
	if err := json.Unmarshal(encB64, &b64); err != nil {
		return nil, fmt.Errorf("parse e2e chunk string: %w", err)
	}
	encrypted, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode e2e chunk: %w", err)
	}
	plaintext, err := DecryptStreamChunkChutes(encrypted, streamKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt chunk: %w", err)
	}
	return plaintext, nil
}

// writeStreamError writes an SSE error event if the stream has started, or
// falls back to http.Error if headers haven't been written yet.
func writeStreamError(w http.ResponseWriter, flusher http.Flusher, headerWritten bool, msg string) {
	if headerWritten {
		WriteSSEError(w, flusher, msg)
		return
	}
	http.Error(w, msg, http.StatusBadGateway)
}

// RelayStreamChutes reads a Chutes E2EE SSE stream (e2e_init + e2e events),
// decrypts each chunk using the stream key derived from the e2e_init KEM
// ciphertext, and writes standard OpenAI-format SSE to w. Returns token
// throughput stats and a non-nil error: ErrDecryptionFailed on decryption
// failure, ErrRelayFailed on other terminal failures.
func RelayStreamChutes(ctx context.Context, w http.ResponseWriter, body io.Reader, session *ChutesSession) (StreamStats, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return StreamStats{}, fmt.Errorf("%w: streaming not supported", ErrRelayFailed)
	}

	scanner, cleanup := newSSEScanner(body)
	defer cleanup()

	var streamKey []byte
	var stats StreamStats
	var firstChunk time.Time
	headerWritten := false

	for scanner.Scan() {
		line := scanner.Text()

		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[len("data: "):]
		if data == "[DONE]" {
			if headerWritten {
				fmt.Fprintf(w, "data: [DONE]\n\n")
				flusher.Flush()
			}
			return stats, nil
		}

		// Chutes SSE events are JSON objects with "e2e_init", "e2e", "usage",
		// or "e2e_error" keys in the data field.
		var event map[string]json.RawMessage
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			slog.ErrorContext(ctx, "chutes stream: parse event JSON", "err", err, "data_len", len(data))
			writeStreamError(w, flusher, headerWritten, "chutes stream: unparseable event")
			return stats, fmt.Errorf("%w: parse event: %w", ErrDecryptionFailed, err)
		}

		if initB64, ok := event["e2e_init"]; ok {
			var err error
			streamKey, err = handleChutesInit(initB64, session)
			if err != nil {
				slog.ErrorContext(ctx, "chutes stream: init failed", "err", err)
				http.Error(w, "chutes stream decryption failed", http.StatusBadGateway)
				return stats, fmt.Errorf("%w: init: %w", ErrDecryptionFailed, err)
			}
		} else if encB64, ok := event["e2e"]; ok {
			if streamKey == nil {
				slog.ErrorContext(ctx, "chutes stream: e2e event before e2e_init")
				http.Error(w, "chutes stream decryption failed", http.StatusBadGateway)
				return stats, fmt.Errorf("%w: e2e event before e2e_init", ErrDecryptionFailed)
			}
			plaintext, err := handleChutesChunk(encB64, streamKey)
			if err != nil {
				slog.ErrorContext(ctx, "chutes stream: chunk failed", "err", err)
				writeStreamError(w, flusher, headerWritten, "chutes stream decryption failed")
				return stats, fmt.Errorf("%w: chunk: %w", ErrDecryptionFailed, err)
			}

			if !headerWritten {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				w.Header().Set("X-Accel-Buffering", "no")
				w.WriteHeader(http.StatusOK)
				headerWritten = true
			}

			now := time.Now()
			if firstChunk.IsZero() {
				firstChunk = now
			}
			stats.Chunks++
			stats.Duration = now.Sub(firstChunk)

			w.Write(plaintext)
			flusher.Flush()
		} else if usageRaw, ok := event["usage"]; ok {
			// Parse completion_tokens from usage event.
			var u struct {
				CompletionTokens int `json:"completion_tokens"`
			}
			if json.Unmarshal(usageRaw, &u) == nil && u.CompletionTokens > 0 {
				stats.Tokens = u.CompletionTokens
			}
		} else if errMsg, ok := event["e2e_error"]; ok {
			slog.ErrorContext(ctx, "chutes stream: server-side E2E error", "error", string(errMsg))
			writeStreamError(w, flusher, headerWritten, "chutes server-side E2E error")
			return stats, fmt.Errorf("%w: server-side E2E error", ErrDecryptionFailed)
		}
	}
	if err := scanner.Err(); err != nil {
		slog.ErrorContext(ctx, "chutes SSE scanner error", "err", err)
	}
	return stats, nil
}

// RelayNonStreamChutes reads a Chutes non-streaming E2EE response blob,
// decrypts it, and writes the plaintext JSON to the client.
// Wire format: mlkem_ct(1088) + nonce(12) + ciphertext + tag(16).
// Returns a non-nil error wrapping ErrDecryptionFailed on decryption failure.
func RelayNonStreamChutes(ctx context.Context, w http.ResponseWriter, body io.Reader, session *ChutesSession) (StreamStats, error) {
	blob, err := io.ReadAll(io.LimitReader(body, 10<<20))
	if err != nil {
		slog.ErrorContext(ctx, "chutes E2EE non-stream read failed", "err", err)
		http.Error(w, "response read failed", http.StatusBadGateway)
		return StreamStats{}, fmt.Errorf("%w: read response blob: %w", ErrRelayFailed, err)
	}
	result, err := session.DecryptResponseBlobChutes(blob)
	if err != nil {
		slog.ErrorContext(ctx, "chutes E2EE non-stream decryption failed", "err", err)
		http.Error(w, "response decryption failed", http.StatusBadGateway)
		return StreamStats{}, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result)
	return StreamStats{}, nil
}
