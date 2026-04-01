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
)

// RelayStreamChutes reads a Chutes E2EE SSE stream (e2e_init + e2e events),
// decrypts each chunk using the stream key derived from the e2e_init KEM
// ciphertext, and writes standard OpenAI-format SSE to w.
func RelayStreamChutes(ctx context.Context, w http.ResponseWriter, body io.Reader, session *ChutesSession) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	scanner, cleanup := newSSEScanner(body)
	defer cleanup()

	var streamKey []byte
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
			return
		}

		// Chutes SSE events are JSON objects with "e2e_init", "e2e", "usage",
		// or "e2e_error" keys in the data field.
		var event map[string]json.RawMessage
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			slog.ErrorContext(ctx, "chutes stream: parse event JSON", "err", err, "data", SafePrefix(data, 200))
			continue
		}

		if initB64, ok := event["e2e_init"]; ok {
			// First event: contains base64 KEM ciphertext for stream key derivation.
			var b64 string
			if err := json.Unmarshal(initB64, &b64); err != nil {
				slog.ErrorContext(ctx, "chutes stream: parse e2e_init string", "err", err)
				http.Error(w, "chutes stream decryption failed", http.StatusBadGateway)
				return
			}
			var err error
			streamKey, err = session.DecryptStreamInitChutes(b64)
			if err != nil {
				slog.ErrorContext(ctx, "chutes stream: derive stream key", "err", err)
				http.Error(w, "chutes stream decryption failed", http.StatusBadGateway)
				return
			}
		} else if encB64, ok := event["e2e"]; ok {
			if streamKey == nil {
				slog.ErrorContext(ctx, "chutes stream: e2e event before e2e_init")
				http.Error(w, "chutes stream decryption failed", http.StatusBadGateway)
				return
			}
			var b64 string
			if err := json.Unmarshal(encB64, &b64); err != nil {
				slog.ErrorContext(ctx, "chutes stream: parse e2e chunk string", "err", err)
				WriteSSEError(w, flusher, "chutes stream decryption failed")
				return
			}
			encrypted, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				slog.ErrorContext(ctx, "chutes stream: decode e2e chunk", "err", err)
				WriteSSEError(w, flusher, "chutes stream decryption failed")
				return
			}
			plaintext, err := DecryptStreamChunkChutes(encrypted, streamKey)
			if err != nil {
				slog.ErrorContext(ctx, "chutes stream: decrypt chunk", "err", err)
				WriteSSEError(w, flusher, "chutes stream decryption failed")
				return
			}

			if !headerWritten {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				w.Header().Set("X-Accel-Buffering", "no")
				w.WriteHeader(http.StatusOK)
				headerWritten = true
			}

			fmt.Fprintf(w, "data: %s\n\n", plaintext)
			flusher.Flush()
		} else if errMsg, ok := event["e2e_error"]; ok {
			slog.ErrorContext(ctx, "chutes stream: server-side E2E error", "error", string(errMsg))
			WriteSSEError(w, flusher, "chutes server-side E2E error")
			return
		}
		// "usage" events are passed through as-is (no encryption).
	}
	if err := scanner.Err(); err != nil {
		slog.ErrorContext(ctx, "chutes SSE scanner error", "err", err)
	}
}

// RelayNonStreamChutes reads a Chutes non-streaming E2EE response blob,
// decrypts it, and writes the plaintext JSON to the client.
// Wire format: mlkem_ct(1088) + nonce(12) + ciphertext + tag(16).
func RelayNonStreamChutes(ctx context.Context, w http.ResponseWriter, body io.Reader, session *ChutesSession) {
	blob, err := io.ReadAll(io.LimitReader(body, 10<<20))
	if err != nil {
		slog.ErrorContext(ctx, "chutes E2EE non-stream read failed", "err", err)
		http.Error(w, "response read failed", http.StatusBadGateway)
		return
	}
	result, err := session.DecryptResponseBlobChutes(blob)
	if err != nil {
		slog.ErrorContext(ctx, "chutes E2EE non-stream decryption failed", "err", err)
		http.Error(w, "response decryption failed", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result)
}
