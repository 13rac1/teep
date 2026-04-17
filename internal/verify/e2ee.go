package verify

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/tlsct"
)

// testE2EE runs a live E2EE test inference if the provider is E2EE-capable.
// Returns nil if the provider doesn't support E2EE, signalling callers to skip.
// Returns a result with NoAPIKey=true if the API key is missing, or with Err
// set on any failure.
func testE2EE(ctx context.Context, raw *attestation.RawAttestation, providerName string, cp *config.Provider, model string, offline bool) *attestation.E2EETestResult {
	if !e2eeEnabledByDefault(providerName) {
		return nil
	}
	if raw.SigningKey == "" {
		return nil // e2ee_capable will fail; no point testing
	}
	if offline {
		return &attestation.E2EETestResult{Detail: "offline mode; E2EE test skipped"}
	}
	envVar := ProviderEnvVars[providerName]
	if cp.APIKey == "" {
		return &attestation.E2EETestResult{NoAPIKey: true, APIKeyEnv: envVar}
	}

	switch providerName {
	case "venice":
		return testE2EEVenice(ctx, raw, cp, model)
	case "nearcloud":
		return testE2EENearCloud(ctx, raw, cp, model)
	case "neardirect":
		return testE2EENeardirect(ctx, raw, cp, model)
	case "chutes":
		return testE2EEChutes(ctx, raw, cp, model)
	default:
		return nil
	}
}

// testE2EEVenice tests Venice E2EE (secp256k1 ECDH + AES-256-GCM).
func testE2EEVenice(ctx context.Context, raw *attestation.RawAttestation, cp *config.Provider, model string) *attestation.E2EETestResult {
	session, err := e2ee.NewVeniceSession()
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("create session: %w", err)}
	}
	defer session.Zero()

	if err := session.SetModelKey(raw.SigningKey); err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("set model key: %w", err)}
	}

	ct, err := e2ee.EncryptVenice([]byte("Say hello"), session.ModelPubKey())
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("encrypt: %w", err)}
	}

	body, err := json.Marshal(map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": ct}},
		"stream":   true,
	})
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("marshal body: %w", err)}
	}

	chatURL := cp.BaseURL + chatPathForProvider("venice")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, chatURL, bytes.NewReader(body))
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("build request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Venice-Tee-Client-Pub-Key", session.ClientPubKeyHex())
	req.Header.Set("X-Venice-Tee-Model-Pub-Key", raw.SigningKey)
	req.Header.Set("X-Venice-Tee-Signing-Algo", "ecdsa")
	req.Header.Set("Authorization", "Bearer "+cp.APIKey)
	req.Header.Set("Connection", "close")

	return doE2EEStreamTest(req, session, "venice")
}

// testE2EENearCloud tests NearCloud E2EE (Ed25519/XChaCha20-Poly1305) via
// direct HTTPS request with E2EE headers.
func testE2EENearCloud(ctx context.Context, raw *attestation.RawAttestation, cp *config.Provider, model string) *attestation.E2EETestResult {
	baseURL := cp.BaseURL
	if baseURL == "" {
		baseURL = "https://cloud-api.near.ai"
	}
	return testE2EENearAI(ctx, raw, cp, model, baseURL, "nearcloud")
}

// testE2EENeardirect tests neardirect E2EE (same Ed25519/XChaCha20-Poly1305
// protocol as NearCloud) via direct HTTPS request to the resolved model domain.
func testE2EENeardirect(ctx context.Context, raw *attestation.RawAttestation, cp *config.Provider, model string) *attestation.E2EETestResult {
	resolver := neardirect.NewEndpointResolver()
	domain, err := resolver.Resolve(ctx, model)
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("resolve model domain: %w", err)}
	}
	return testE2EENearAI(ctx, raw, cp, model, "https://"+domain, "neardirect")
}

// testE2EENearAI runs a NEAR AI E2EE test inference (Ed25519/XChaCha20-Poly1305).
// Shared by nearcloud and neardirect.
func testE2EENearAI(ctx context.Context, raw *attestation.RawAttestation, cp *config.Provider, model, baseURL, label string) *attestation.E2EETestResult {
	body, err := json.Marshal(map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": "Say hello"}},
		"stream":   true,
	})
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("marshal body: %w", err)}
	}

	encBody, session, err := e2ee.EncryptChatMessagesNearCloud(body, raw.SigningKey)
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("encrypt v2: %w", err)}
	}
	defer session.Zero()

	chatURL := baseURL + "/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, chatURL, bytes.NewReader(encBody))
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("build request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signing-Algo", "ed25519")
	req.Header.Set("X-Client-Pub-Key", session.ClientEd25519PubHex())
	req.Header.Set("X-Encryption-Version", "2")
	req.Header.Set("Authorization", "Bearer "+cp.APIKey)
	req.Header.Set("Connection", "close")

	return doE2EEStreamTest(req, session, label)
}

// testE2EEChutes tests Chutes E2EE (ML-KEM-768 + ChaCha20-Poly1305) via
// direct HTTPS request to the /e2e/invoke endpoint.
func testE2EEChutes(ctx context.Context, raw *attestation.RawAttestation, cp *config.Provider, model string) *attestation.E2EETestResult {
	if raw.InstanceID == "" {
		return &attestation.E2EETestResult{Attempted: true, Err: errors.New("chutes E2EE: instance_id absent from attestation")}
	}
	if raw.E2ENonce == "" {
		return &attestation.E2EETestResult{Attempted: true, Err: errors.New("chutes E2EE: e2e_nonce absent from attestation")}
	}

	// Use the resolved chute UUID for the X-Chute-Id header.
	// FetchAttestation resolves model names to UUIDs and stores the
	// result in raw.ChuteID.
	chuteID := raw.ChuteID
	if chuteID == "" {
		return &attestation.E2EETestResult{Attempted: true, Err: errors.New("chutes E2EE: chute_id absent from attestation")}
	}

	body, err := json.Marshal(map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": "Say hello"}},
		"stream":   true,
	})
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("marshal body: %w", err)}
	}

	encPayload, session, err := e2ee.EncryptChatRequestChutes(body, raw.SigningKey)
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("encrypt: %w", err)}
	}
	defer session.Zero()

	baseURL := cp.BaseURL
	if baseURL == "" {
		baseURL = "https://api.chutes.ai"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/e2e/invoke", bytes.NewReader(encPayload))
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("build request: %w", err)}
	}
	req.Header.Set("Authorization", "Bearer "+cp.APIKey)
	req.Header.Set("X-Chute-Id", chuteID)
	req.Header.Set("X-Instance-Id", raw.InstanceID)
	req.Header["X-E2E-Nonce"] = []string{raw.E2ENonce}
	req.Header["X-E2E-Stream"] = []string{"true"}
	req.Header["X-E2E-Path"] = []string{chatPathForProvider("chutes")}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Connection", "close")

	return doE2EEChutesStreamTest(req, session)
}

// doE2EEChutesStreamTest sends an encrypted Chutes E2EE request and validates
// the SSE response, which uses Chutes-specific envelope events (e2e_init,
// e2e, e2e_error, usage) instead of the per-field encryption used by other
// providers.
func doE2EEChutesStreamTest(req *http.Request, session *e2ee.ChutesSession) *attestation.E2EETestResult {
	client := tlsct.NewHTTPClient(60 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("HTTP request: %w", err)}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &attestation.E2EETestResult{
			Attempted: true,
			Err:       fmt.Errorf("HTTP %d: %s", resp.StatusCode, body),
		}
	}

	// Collect non-standard response headers for leak reporting.
	var headerNotes []string
	for name := range resp.Header {
		switch strings.ToLower(name) {
		case "content-type", "cache-control", "date", "server",
			"transfer-encoding", "connection", "keep-alive",
			"x-request-id", "x-trace-id",
			"access-control-allow-origin", "access-control-allow-headers",
			"access-control-allow-methods", "access-control-max-age",
			"access-control-expose-headers",
			"vary", "strict-transport-security", "x-content-type-options":
			// Standard/infra headers — skip.
		default:
			headerNotes = append(headerNotes, fmt.Sprintf("%s: %s", name, strings.Join(resp.Header[name], ", ")))
		}
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)

	var streamKey []byte
	decryptedChunks := 0
	usageEvents := 0

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[len("data: "):]
		if data == "[DONE]" {
			break
		}

		var event struct {
			E2EInit  *string `json:"e2e_init,omitempty"`
			E2E      *string `json:"e2e,omitempty"`
			E2EError *string `json:"e2e_error,omitempty"`
			Usage    any     `json:"usage,omitempty"`
		}
		if unknown, err := jsonstrict.Unmarshal([]byte(data), &event); err != nil {
			return &attestation.E2EETestResult{
				Attempted: true,
				Err:       fmt.Errorf("parse SSE event: %w (prefix=%q)", err, safePrefix(data, 64)),
			}
		} else if len(unknown) > 0 {
			slog.Debug("unexpected JSON fields", "fields", unknown, "context", "e2ee SSE event")
		}

		switch {
		case event.E2EInit != nil:
			streamKey, err = session.DecryptStreamInitChutes(*event.E2EInit)
			if err != nil {
				return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("derive stream key: %w", err)}
			}
		case event.E2E != nil:
			if streamKey == nil {
				return &attestation.E2EETestResult{Attempted: true, Err: errors.New("e2e event before e2e_init")}
			}
			encrypted, err := base64.StdEncoding.DecodeString(*event.E2E)
			if err != nil {
				return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("decode e2e chunk: %w", err)}
			}
			plaintext, err := e2ee.DecryptStreamChunkChutes(encrypted, streamKey)
			if err != nil {
				return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("decrypt e2e chunk %d: %w", decryptedChunks+1, err)}
			}
			// The Chutes server encrypts full SSE lines including
			// "data: " prefix and trailing newlines. Strip these
			// before validating the JSON payload.
			chunk := bytes.TrimSpace(plaintext)
			chunk = bytes.TrimPrefix(chunk, []byte("data: "))
			// Empty chunks (inter-event newlines) and the [DONE]
			// sentinel are valid decrypted content, not JSON.
			if len(chunk) == 0 || string(chunk) == "[DONE]" {
				decryptedChunks++
				continue
			}
			if !json.Valid(chunk) {
				return &attestation.E2EETestResult{
					Attempted: true,
					Err:       fmt.Errorf("decrypted chunk %d is not valid JSON (prefix=%q)", decryptedChunks+1, safePrefix(string(plaintext), 64)),
				}
			}
			decryptedChunks++
		case event.E2EError != nil:
			return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("server e2e_error: %s", *event.E2EError)}
		case event.Usage != nil:
			usageEvents++
		}
	}
	if err := scanner.Err(); err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("read SSE stream: %w", err)}
	}

	if streamKey == nil {
		return &attestation.E2EETestResult{Attempted: true, Err: errors.New("no e2e_init event received")}
	}
	if decryptedChunks == 0 {
		return &attestation.E2EETestResult{Attempted: true, Err: errors.New("no encrypted chunks received")}
	}

	detail := fmt.Sprintf("E2EE chutes ML-KEM-768: %d encrypted chunks decrypted", decryptedChunks)
	if usageEvents > 0 {
		detail += fmt.Sprintf("; %d cleartext usage events (expected)", usageEvents)
	}
	if len(headerNotes) > 0 {
		sort.Strings(headerNotes)
		detail += "; non-standard response headers: " + strings.Join(headerNotes, "; ")
	}
	return &attestation.E2EETestResult{Attempted: true, Detail: detail}
}

// doE2EEStreamTest sends an E2EE chat completions request and validates
// that the SSE response contains properly encrypted content fields.
func doE2EEStreamTest(req *http.Request, session e2ee.Decryptor, version string) *attestation.E2EETestResult {
	client := tlsct.NewHTTPClient(60 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("HTTP request: %w", err)}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &attestation.E2EETestResult{
			Attempted: true,
			Err:       fmt.Errorf("HTTP %d: %s", resp.StatusCode, body),
		}
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)
	encryptedCount := 0
	chunkCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}
		chunkCount++

		var chunk struct {
			ID                string `json:"id"`
			Object            string `json:"object"`
			Created           int64  `json:"created"`
			Model             string `json:"model"`
			SystemFingerprint string `json:"system_fingerprint"`
			Choices           []struct {
				Index        int `json:"index"`
				Delta        any `json:"delta"`
				FinishReason any `json:"finish_reason"`
			} `json:"choices"`
			Usage any `json:"usage"`
		}
		if unknown, err := jsonstrict.Unmarshal([]byte(data), &chunk); err != nil {
			return &attestation.E2EETestResult{
				Attempted: true,
				Err:       fmt.Errorf("parse SSE chunk %d: %w", chunkCount, err),
			}
		} else if len(unknown) > 0 {
			slog.Debug("unexpected JSON fields", "fields", unknown, "context", "e2ee SSE chunk")
		}
		if len(chunk.Choices) == 0 {
			continue
		}

		delta := chunk.Choices[0].Delta
		if delta == nil {
			continue
		}
		fields, ok := delta.(map[string]any)
		if !ok {
			return &attestation.E2EETestResult{
				Attempted: true,
				Err:       fmt.Errorf("delta in chunk %d is %T, expected map", chunkCount, delta),
			}
		}

		for key, val := range fields {
			s, ok := val.(string)
			if !ok || s == "" {
				continue
			}
			if e2ee.NonEncryptedFields[key] {
				continue
			}
			// This field should be encrypted.
			if !session.IsEncryptedChunk(s) {
				return &attestation.E2EETestResult{
					Attempted: true,
					Err:       fmt.Errorf("field %q not encrypted (len=%d, prefix=%q)", key, len(s), safePrefix(s, 16)),
				}
			}
			if _, err := session.Decrypt(s); err != nil {
				return &attestation.E2EETestResult{
					Attempted: true,
					Err:       fmt.Errorf("decrypt field %q: %w", key, err),
				}
			}
			encryptedCount++
		}
	}
	if err := scanner.Err(); err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("read SSE stream: %w", err)}
	}

	if encryptedCount == 0 {
		return &attestation.E2EETestResult{
			Attempted: true,
			Err:       fmt.Errorf("no encrypted content fields received in %d chunks", chunkCount),
		}
	}

	return &attestation.E2EETestResult{
		Attempted: true,
		Detail:    fmt.Sprintf("E2EE %s: %d encrypted fields decrypted across %d chunks", version, encryptedCount, chunkCount),
	}
}

// safePrefix returns the first n characters of s, or s if shorter.
func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
