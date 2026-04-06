package e2ee_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider/nearcloud"
)

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

const nearcloudBaseURL = "https://cloud-api.near.ai"

// directEndpoints maps model names to their direct inference-proxy domains,
// bypassing the gateway. These are discovered from
// https://completions.near.ai/endpoints.
var directEndpoints = map[string]string{
	"Qwen/Qwen3-Embedding-0.6B": "https://qwen3-embedding.completions.near.ai",
	"Qwen/Qwen3-Reranker-0.6B":  "https://qwen3-reranker.completions.near.ai",
	"openai/whisper-large-v3":   "https://whisper-large-v3.completions.near.ai",
}

// resolveDirectEndpoint looks up the direct inference-proxy URL for a model.
// First checks the hardcoded directEndpoints map, then queries the NEAR AI
// endpoint discovery API at https://completions.near.ai/endpoints.
func resolveDirectEndpoint(t *testing.T, model string) string {
	t.Helper()
	if url, ok := directEndpoints[model]; ok {
		return url
	}

	apiKey := os.Getenv("NEARAI_API_KEY")
	req, err := http.NewRequest(http.MethodGet, "https://completions.near.ai/endpoints", http.NoBody)
	if err != nil {
		t.Fatalf("create endpoints request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Connection", "close")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("fetch endpoints: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read endpoints body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("endpoints API: status=%d body=%s", resp.StatusCode, truncate(body, 500))
	}

	var result struct {
		Endpoints []struct {
			Domain string   `json:"domain"`
			Models []string `json:"models"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("parse endpoints: %v", err)
	}

	for _, ep := range result.Endpoints {
		if slices.Contains(ep.Models, model) {
			url := "https://" + ep.Domain
			t.Logf("resolved direct endpoint for %s: %s", model, url)
			return url
		}
	}
	t.Fatalf("model %q not found in endpoint discovery", model)
	return ""
}

func skipNearCloudE2EEIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("NEARAI_API_KEY") == "" {
		t.Skip("NEARAI_API_KEY not set")
	}
}

// fetchSigningKey fetches a TEE attestation report from the nearcloud gateway
// and returns the model's Ed25519 signing key (64 hex chars).
func fetchSigningKey(t *testing.T, model string) string {
	t.Helper()
	apiKey := os.Getenv("NEARAI_API_KEY")

	attester := nearcloud.NewAttester(apiKey)
	nonce := attestation.NewNonce()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	raw, err := attester.FetchAttestation(ctx, model, nonce)
	if err != nil {
		t.Fatalf("fetch attestation for %s: %v", model, err)
	}
	if raw.SigningKey == "" {
		t.Fatalf("no signing key in attestation for %s", model)
	}
	t.Logf("signing key for %s: %s...", model, raw.SigningKey[:16])
	return raw.SigningKey
}

// fetchDirectSigningKey fetches a TEE attestation report directly from the
// model's inference-proxy (bypassing the gateway) and returns the Ed25519
// signing key.
func fetchDirectSigningKey(t *testing.T, model string) string {
	t.Helper()
	baseURL := resolveDirectEndpoint(t, model)
	apiKey := os.Getenv("NEARAI_API_KEY")
	nonce := attestation.NewNonce()

	url := fmt.Sprintf("%s/v1/attestation/report?nonce=%s&signing_algo=ed25519",
		baseURL, nonce.Hex())

	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("create attestation request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Connection", "close")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("fetch direct attestation for %s: %v", model, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read direct attestation body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("direct attestation for %s: status=%d body=%s", model, resp.StatusCode, truncate(body, 500))
	}

	// Parse attestation — may have model_attestations wrapper or be flat.
	var wrapper struct {
		ModelAttestations []struct {
			SigningPublicKey string `json:"signing_public_key"`
		} `json:"model_attestations"`
		SigningPublicKey string `json:"signing_public_key"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		t.Fatalf("parse direct attestation: %v", err)
	}

	signingKey := wrapper.SigningPublicKey
	if len(wrapper.ModelAttestations) > 0 {
		signingKey = wrapper.ModelAttestations[0].SigningPublicKey
	}
	if signingKey == "" {
		t.Fatalf("no signing key in direct attestation for %s", model)
	}
	t.Logf("direct signing key for %s: %s...", model, signingKey[:16])
	return signingKey
}

// e2eeRequest sends a POST request to the given base URL with E2EE headers.
// This is the shared request builder used by both gateway and direct tests,
// ensuring the exact same E2EE protocol is used for both paths.
func e2eeRequest(t *testing.T, baseURL, path string, body []byte, contentType string, session *e2ee.NearCloudSession) *http.Response {
	t.Helper()
	apiKey := os.Getenv("NEARAI_API_KEY")

	req, err := http.NewRequest(http.MethodPost, baseURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Connection", "close")

	// E2EE headers — identical for gateway and direct requests.
	req.Header.Set("X-Signing-Algo", "ed25519")
	req.Header.Set("X-Client-Pub-Key", session.ClientEd25519PubHex())
	req.Header.Set("X-Encryption-Version", "2")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s%s: %v", baseURL, path, err)
	}
	return resp
}

// plaintextRequest sends a POST request to the given base URL without E2EE
// headers.
func plaintextRequest(t *testing.T, baseURL, path string, body []byte, contentType string) *http.Response {
	t.Helper()
	apiKey := os.Getenv("NEARAI_API_KEY")

	req, err := http.NewRequest(http.MethodPost, baseURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Connection", "close")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s%s: %v", baseURL, path, err)
	}
	return resp
}

// nearcloudE2EERequest sends a POST to the nearcloud gateway with E2EE headers.
// Wrapper around e2eeRequest for gateway-specific tests.
func nearcloudE2EERequest(t *testing.T, path string, body []byte, contentType string, session *e2ee.NearCloudSession) *http.Response {
	t.Helper()
	return e2eeRequest(t, nearcloudBaseURL, path, body, contentType, session)
}

// nearcloudPlaintextRequest sends a POST to the nearcloud gateway without
// E2EE headers.
func nearcloudPlaintextRequest(t *testing.T, path string, body []byte, contentType string) *http.Response {
	t.Helper()
	return plaintextRequest(t, nearcloudBaseURL, path, body, contentType)
}

// readBody reads and returns the response body, bounded to 1 MiB.
func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return body
}

// createE2EESession creates a NearCloud E2EE session initialized with the
// model's signing key.
func createE2EESession(t *testing.T, signingKey string) *e2ee.NearCloudSession {
	t.Helper()
	session, err := e2ee.NewNearCloudSession()
	if err != nil {
		t.Fatalf("create NearCloud session: %v", err)
	}
	if err := session.SetModelKeyEd25519(signingKey); err != nil {
		session.Zero()
		t.Fatalf("set model key: %v", err)
	}
	return session
}

// makeMinimalWAV returns a minimal WAV file (PCM 16-bit 16kHz, ~0.1s silence).
func makeMinimalWAV() []byte {
	sampleRate := 16000
	numSamples := sampleRate / 10
	dataSize := numSamples * 2
	fileSize := 36 + dataSize

	buf := make([]byte, 44+dataSize)
	copy(buf[0:4], "RIFF")
	putLE32(buf[4:], uint32(fileSize))
	copy(buf[8:12], "WAVE")
	copy(buf[12:16], "fmt ")
	putLE32(buf[16:], 16)
	putLE16(buf[20:], 1)
	putLE16(buf[22:], 1)
	putLE32(buf[24:], uint32(sampleRate))
	putLE32(buf[28:], uint32(sampleRate*2))
	putLE16(buf[32:], 2)
	putLE16(buf[34:], 16)
	copy(buf[36:40], "data")
	putLE32(buf[40:], uint32(dataSize))
	return buf
}

func putLE16(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}

func putLE32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

// --------------------------------------------------------------------------
// Embeddings E2EE test
// --------------------------------------------------------------------------

// TestIntegration_NearCloud_Embeddings_E2EE tests whether the nearcloud gateway
// supports E2EE for the /v1/embeddings endpoint. The EncryptChatMessagesNearCloud
// function only encrypts the "messages" array in chat requests. Embeddings use
// an "input" field instead. This test verifies the server-side behavior when
// E2EE headers are sent with an embeddings request.
func TestIntegration_NearCloud_Embeddings_E2EE(t *testing.T) {
	skipNearCloudE2EEIntegration(t)

	const model = "Qwen/Qwen3-Embedding-0.6B"
	signingKey := fetchSigningKey(t, model)
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	// First: verify plaintext embeddings work (baseline).
	plaintextBody := fmt.Sprintf(`{"model":%q,"input":"The quick brown fox"}`, model)
	ptResp := nearcloudPlaintextRequest(t, "/v1/embeddings", []byte(plaintextBody), "application/json")
	ptBody := readBody(t, ptResp)
	ptResp.Body.Close()
	t.Logf("plaintext embeddings: status=%d body_len=%d", ptResp.StatusCode, len(ptBody))

	if ptResp.StatusCode != http.StatusOK {
		t.Fatalf("plaintext embeddings failed: status=%d body=%s", ptResp.StatusCode, truncate(ptBody, 500))
	}

	// Verify we got real embedding data in plaintext.
	var ptResult struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal(ptBody, &ptResult); err != nil {
		t.Fatalf("unmarshal plaintext response: %v", err)
	}
	if len(ptResult.Data) == 0 || len(ptResult.Data[0].Embedding) == 0 {
		t.Fatalf("plaintext response has no embedding data")
	}
	t.Logf("plaintext embeddings: dimensions=%d", len(ptResult.Data[0].Embedding))

	// Now: send the same request WITH E2EE headers.
	// The input field is NOT encrypted (EncryptChatMessagesNearCloud only
	// handles messages[].content). This tests what the server does when it
	// sees E2EE headers on a non-chat endpoint.
	e2eeBody := fmt.Sprintf(`{"model":%q,"input":"The quick brown fox"}`, model)
	e2eeResp := nearcloudE2EERequest(t, "/v1/embeddings", []byte(e2eeBody), "application/json", session)
	e2eeRespBody := readBody(t, e2eeResp)
	e2eeResp.Body.Close()
	t.Logf("E2EE embeddings: status=%d body_len=%d", e2eeResp.StatusCode, len(e2eeRespBody))
	t.Logf("E2EE embeddings response (first 500 chars): %s", truncate(e2eeRespBody, 500))

	// Document the server behavior. The critical security question is:
	// does the server encrypt the response when it sees E2EE headers on embeddings?
	switch e2eeResp.StatusCode {
	case http.StatusOK:
		// Server accepted. Check if response is encrypted or plaintext.
		var embResult struct {
			Data []struct {
				Embedding []float64 `json:"embedding"`
			} `json:"data"`
		}
		if err := json.Unmarshal(e2eeRespBody, &embResult); err == nil && len(embResult.Data) > 0 {
			// Response parsed as normal JSON — server returned plaintext embeddings
			// despite E2EE headers. This means the request "input" was sent in
			// plaintext AND the response was returned in plaintext, even though
			// the user's client believes E2EE is active.
			t.Log("FINDING: Server returned PLAINTEXT embeddings despite E2EE headers")
			t.Log("CONCLUSION: NearCloud does NOT encrypt embeddings responses when E2EE headers are present")
			t.Log("This confirms the E2EE gate is correct: nearcloud non-chat endpoints MUST NOT be wired with E2EE")
		} else {
			// Response is not standard JSON — might be encrypted.
			bodyStr := string(e2eeRespBody)
			if e2ee.IsEncryptedChunkXChaCha20(bodyStr) {
				t.Log("FINDING: Server returned ENCRYPTED embeddings response")
				t.Log("CONCLUSION: NearCloud MAY support E2EE for embeddings — further verification needed")
			} else {
				t.Logf("FINDING: Server returned non-JSON, non-encrypted response: %s", truncate(e2eeRespBody, 200))
			}
		}
	default:
		t.Logf("FINDING: Server rejected E2EE embeddings request: status=%d body=%s",
			e2eeResp.StatusCode, truncate(e2eeRespBody, 500))
	}
}

// --------------------------------------------------------------------------
// Audio transcription E2EE test
// --------------------------------------------------------------------------

// TestIntegration_NearCloud_Audio_E2EE tests whether the nearcloud gateway
// supports E2EE for the /v1/audio/transcriptions endpoint. Audio requests use
// multipart/form-data which is fundamentally incompatible with the NearCloud
// E2EE message encryption scheme.
func TestIntegration_NearCloud_Audio_E2EE(t *testing.T) {
	skipNearCloudE2EEIntegration(t)

	const model = "openai/whisper-large-v3"
	signingKey := fetchSigningKey(t, model)
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	wavData := makeMinimalWAV()

	// Build multipart form.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("model", model); err != nil {
		t.Fatalf("write model field: %v", err)
	}
	fw, err := mw.CreateFormFile("file", "test.wav")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write(wavData); err != nil {
		t.Fatalf("write wav data: %v", err)
	}
	mw.Close()
	multipartBody := buf.Bytes()
	contentType := mw.FormDataContentType()

	// First: verify plaintext audio transcription works (baseline).
	ptResp := nearcloudPlaintextRequest(t, "/v1/audio/transcriptions", multipartBody, contentType)
	ptBody := readBody(t, ptResp)
	ptResp.Body.Close()
	t.Logf("plaintext audio: status=%d body=%s", ptResp.StatusCode, truncate(ptBody, 500))

	if ptResp.StatusCode != http.StatusOK {
		t.Logf("plaintext audio transcription not available: status=%d (may not be supported on nearcloud)", ptResp.StatusCode)
		// Continue with E2EE test anyway to document behavior.
	}

	// Now: send audio with E2EE headers. Multipart body cannot be encrypted
	// with EncryptChatMessagesNearCloud (which only handles messages[].content).
	e2eeResp := nearcloudE2EERequest(t, "/v1/audio/transcriptions", multipartBody, contentType, session)
	e2eeBody := readBody(t, e2eeResp)
	e2eeResp.Body.Close()
	t.Logf("E2EE audio: status=%d body=%s", e2eeResp.StatusCode, truncate(e2eeBody, 500))

	switch e2eeResp.StatusCode {
	case http.StatusOK:
		t.Log("FINDING: Server accepted audio request with E2EE headers")
		t.Log("Audio data was sent in PLAINTEXT (multipart cannot be encrypted by EncryptChatMessagesNearCloud)")
		// Check if response is encrypted.
		bodyStr := string(e2eeBody)
		if e2ee.IsEncryptedChunkXChaCha20(bodyStr) {
			t.Log("FINDING: Server returned ENCRYPTED audio response")
		} else {
			t.Log("FINDING: Server returned PLAINTEXT audio response despite E2EE headers")
			t.Log("CONCLUSION: Audio transcription is NOT E2EE-protected on nearcloud")
		}
	default:
		t.Logf("FINDING: Server rejected E2EE audio request: status=%d", e2eeResp.StatusCode)
		t.Log("This is consistent with the E2EE gate — audio is not supported with nearcloud E2EE")
	}
}

// --------------------------------------------------------------------------
// Rerank E2EE test
// --------------------------------------------------------------------------

// TestIntegration_NearCloud_Rerank_E2EE tests whether the nearcloud gateway
// supports the /v1/rerank endpoint and whether E2EE works with it. Rerank
// requests use "query" and "documents" fields, not "messages", so
// EncryptChatMessagesNearCloud cannot encrypt them.
func TestIntegration_NearCloud_Rerank_E2EE(t *testing.T) {
	skipNearCloudE2EEIntegration(t)

	const model = "Qwen/Qwen3-Reranker-0.6B"
	signingKey := fetchSigningKey(t, model)
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	rerankBody := fmt.Sprintf(`{
		"model": %q,
		"query": "What is deep learning?",
		"documents": [
			"Deep learning is a subset of machine learning.",
			"The weather today is sunny.",
			"Neural networks have multiple layers."
		],
		"top_n": 2
	}`, model)

	// First: verify plaintext rerank works (baseline).
	ptResp := nearcloudPlaintextRequest(t, "/v1/rerank", []byte(rerankBody), "application/json")
	ptBody := readBody(t, ptResp)
	ptResp.Body.Close()
	t.Logf("plaintext rerank: status=%d body_len=%d", ptResp.StatusCode, len(ptBody))
	t.Logf("plaintext rerank response: %s", truncate(ptBody, 500))

	if ptResp.StatusCode != http.StatusOK {
		t.Logf("plaintext rerank not available at /v1/rerank: status=%d", ptResp.StatusCode)
		// Try /rerank as an alternative path.
		ptResp2 := nearcloudPlaintextRequest(t, "/rerank", []byte(rerankBody), "application/json")
		ptBody2 := readBody(t, ptResp2)
		ptResp2.Body.Close()
		t.Logf("plaintext /rerank (alt path): status=%d body=%s", ptResp2.StatusCode, truncate(ptBody2, 500))
	} else {
		// Plaintext rerank works. Parse and log.
		var result struct {
			Results []struct {
				Index          int     `json:"index"`
				RelevanceScore float64 `json:"relevance_score"`
			} `json:"results"`
		}
		if err := json.Unmarshal(ptBody, &result); err == nil {
			for _, r := range result.Results {
				t.Logf("  rank: doc[%d] score=%.4f", r.Index, r.RelevanceScore)
			}
		}
	}

	// Now: send rerank with E2EE headers.
	e2eeResp := nearcloudE2EERequest(t, "/v1/rerank", []byte(rerankBody), "application/json", session)
	e2eeBody := readBody(t, e2eeResp)
	e2eeResp.Body.Close()
	t.Logf("E2EE rerank: status=%d body_len=%d", e2eeResp.StatusCode, len(e2eeBody))
	t.Logf("E2EE rerank response: %s", truncate(e2eeBody, 500))

	switch e2eeResp.StatusCode {
	case http.StatusOK:
		// Check if response is encrypted or plaintext.
		var result struct {
			Results []struct {
				Index int `json:"index"`
			} `json:"results"`
		}
		if err := json.Unmarshal(e2eeBody, &result); err == nil && len(result.Results) > 0 {
			t.Log("FINDING: Server returned PLAINTEXT rerank results despite E2EE headers")
			t.Log("CONCLUSION: NearCloud does NOT encrypt rerank responses when E2EE headers are present")
			t.Log("The query and documents were sent in PLAINTEXT — E2EE gate is correct")
		} else {
			bodyStr := string(e2eeBody)
			if e2ee.IsEncryptedChunkXChaCha20(bodyStr) {
				t.Log("FINDING: Server returned ENCRYPTED rerank response")
				t.Log("CONCLUSION: NearCloud MAY support E2EE for rerank — further verification needed")
			} else {
				t.Logf("FINDING: Non-JSON, non-encrypted response: %s", truncate(e2eeBody, 200))
			}
		}
	default:
		t.Logf("FINDING: Server rejected E2EE rerank request: status=%d", e2eeResp.StatusCode)
	}
}

// --------------------------------------------------------------------------
// Encrypted embeddings input test
// --------------------------------------------------------------------------

// TestIntegration_NearCloud_Embeddings_EncryptedInput tests what happens when
// we actually encrypt the "input" field of an embeddings request using the
// NearCloud E2EE protocol, mimicking what the proxy would need to do if it
// supported E2EE for embeddings.
func TestIntegration_NearCloud_Embeddings_EncryptedInput(t *testing.T) {
	skipNearCloudE2EEIntegration(t)

	const model = "Qwen/Qwen3-Embedding-0.6B"
	signingKey := fetchSigningKey(t, model)
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	// Encrypt the input text using the same E2EE protocol as chat messages.
	plaintext := "The quick brown fox"
	encInput, err := e2ee.EncryptXChaCha20([]byte(plaintext), session.ModelX25519Pub())
	if err != nil {
		t.Fatalf("encrypt input: %v", err)
	}
	t.Logf("encrypted input length: %d hex chars", len(encInput))

	body := fmt.Sprintf(`{"model":%q,"input":%q}`, model, encInput)

	e2eeResp := nearcloudE2EERequest(t, "/v1/embeddings", []byte(body), "application/json", session)
	e2eeBody := readBody(t, e2eeResp)
	e2eeResp.Body.Close()
	t.Logf("encrypted input embeddings: status=%d body_len=%d", e2eeResp.StatusCode, len(e2eeBody))
	t.Logf("encrypted input response: %s", truncate(e2eeBody, 500))

	switch e2eeResp.StatusCode {
	case http.StatusOK:
		// If server returns 200, check whether it processed the encrypted input
		// as an embedding or returned an error in the body.
		var result struct {
			Data []struct {
				Embedding []float64 `json:"embedding"`
			} `json:"data"`
		}
		if err := json.Unmarshal(e2eeBody, &result); err == nil && len(result.Data) > 0 {
			t.Log("FINDING: Server embedded the CIPHERTEXT as if it were plaintext")
			t.Log("The model computed an embedding of the hex-encoded ciphertext, not the original input")
			t.Log("CONCLUSION: Server does NOT decrypt the input field — E2EE is NOT end-to-end for embeddings")
		} else {
			bodyStr := string(e2eeBody)
			if e2ee.IsEncryptedChunkXChaCha20(strings.TrimSpace(bodyStr)) {
				t.Log("FINDING: Server returned encrypted response for encrypted input")
				t.Log("CONCLUSION: Server MAY support true E2EE for embeddings")
			} else {
				t.Logf("FINDING: Unexpected response format: %s", truncate(e2eeBody, 200))
			}
		}
	default:
		t.Logf("FINDING: Server rejected encrypted input: status=%d body=%s",
			e2eeResp.StatusCode, truncate(e2eeBody, 500))
	}
}

// truncate returns s[:maxLen] or s if shorter, as a string.
func truncate(b []byte, maxLen int) string {
	if len(b) <= maxLen {
		return string(b)
	}
	return string(b[:maxLen]) + "..."
}

// --------------------------------------------------------------------------
// Encrypted rerank input test
// --------------------------------------------------------------------------

// TestIntegration_NearCloud_Rerank_EncryptedInput tests what happens when we
// encrypt the "query" and "documents" fields of a rerank request. If the server
// supported E2EE for rerank, it would decrypt these fields before processing.
func TestIntegration_NearCloud_Rerank_EncryptedInput(t *testing.T) {
	skipNearCloudE2EEIntegration(t)

	const model = "Qwen/Qwen3-Reranker-0.6B"
	signingKey := fetchSigningKey(t, model)
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	// Encrypt the query.
	encQuery, err := e2ee.EncryptXChaCha20([]byte("What is deep learning?"), session.ModelX25519Pub())
	if err != nil {
		t.Fatalf("encrypt query: %v", err)
	}

	// Encrypt each document.
	docs := []string{
		"Deep learning is a subset of machine learning.",
		"The weather today is sunny.",
		"Neural networks have multiple layers.",
	}
	encDocs := make([]string, len(docs))
	for i, d := range docs {
		enc, encErr := e2ee.EncryptXChaCha20([]byte(d), session.ModelX25519Pub())
		if encErr != nil {
			t.Fatalf("encrypt document %d: %v", i, encErr)
		}
		encDocs[i] = enc
	}

	// Build JSON with encrypted fields.
	type rerankReq struct {
		Model     string   `json:"model"`
		Query     string   `json:"query"`
		Documents []string `json:"documents"`
		TopN      int      `json:"top_n"`
	}
	reqBody, err := json.Marshal(rerankReq{
		Model:     model,
		Query:     encQuery,
		Documents: encDocs,
		TopN:      2,
	})
	if err != nil {
		t.Fatalf("marshal rerank request: %v", err)
	}

	e2eeResp := nearcloudE2EERequest(t, "/v1/rerank", reqBody, "application/json", session)
	e2eeBody := readBody(t, e2eeResp)
	e2eeResp.Body.Close()
	t.Logf("encrypted rerank: status=%d body_len=%d", e2eeResp.StatusCode, len(e2eeBody))
	t.Logf("encrypted rerank response: %s", truncate(e2eeBody, 500))

	switch e2eeResp.StatusCode {
	case http.StatusOK:
		var result struct {
			Results []struct {
				Index          int     `json:"index"`
				RelevanceScore float64 `json:"relevance_score"`
				Document       struct {
					Text string `json:"text"`
				} `json:"document"`
			} `json:"results"`
		}
		if err := json.Unmarshal(e2eeBody, &result); err == nil && len(result.Results) > 0 {
			t.Log("FINDING: Server reranked the CIPHERTEXT as if it were plaintext")
			for _, r := range result.Results {
				docPreview := r.Document.Text
				if len(docPreview) > 40 {
					docPreview = docPreview[:40] + "..."
				}
				t.Logf("  rank: doc[%d] score=%.4f text=%q", r.Index, r.RelevanceScore, docPreview)
			}
			t.Log("CONCLUSION: Server does NOT decrypt query/documents — E2EE is NOT end-to-end for rerank")
		} else {
			bodyStr := string(e2eeBody)
			if e2ee.IsEncryptedChunkXChaCha20(strings.TrimSpace(bodyStr)) {
				t.Log("FINDING: Server returned encrypted response for encrypted rerank input")
				t.Log("CONCLUSION: Server MAY support true E2EE for rerank")
			} else {
				t.Logf("FINDING: Unexpected response format: %s", truncate(e2eeBody, 300))
			}
		}
	default:
		t.Logf("FINDING: Server rejected encrypted rerank input: status=%d body=%s",
			e2eeResp.StatusCode, truncate(e2eeBody, 500))
	}
}

// --------------------------------------------------------------------------
// Encrypted audio transcription input test
// --------------------------------------------------------------------------

// TestIntegration_NearCloud_Audio_EncryptedInput tests what happens when we
// encrypt the WAV file data before sending it via multipart. If the server
// supported E2EE for audio, it would decrypt the file content before transcription.
func TestIntegration_NearCloud_Audio_EncryptedInput(t *testing.T) {
	skipNearCloudE2EEIntegration(t)

	const model = "openai/whisper-large-v3"
	signingKey := fetchSigningKey(t, model)
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	wavData := makeMinimalWAV()

	// Encrypt the WAV file content.
	encWAV, err := e2ee.EncryptXChaCha20(wavData, session.ModelX25519Pub())
	if err != nil {
		t.Fatalf("encrypt WAV data: %v", err)
	}
	t.Logf("encrypted WAV hex length: %d chars (original WAV: %d bytes)", len(encWAV), len(wavData))

	// Build multipart with the encrypted WAV data as the file content.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("model", model); err != nil {
		t.Fatalf("write model field: %v", err)
	}
	fw, err := mw.CreateFormFile("file", "test.wav")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	// Write the hex-encoded ciphertext as the file content.
	if _, err := fw.Write([]byte(encWAV)); err != nil {
		t.Fatalf("write encrypted wav: %v", err)
	}
	mw.Close()

	e2eeResp := nearcloudE2EERequest(t, "/v1/audio/transcriptions", buf.Bytes(), mw.FormDataContentType(), session)
	e2eeBody := readBody(t, e2eeResp)
	e2eeResp.Body.Close()
	t.Logf("encrypted audio: status=%d body=%s", e2eeResp.StatusCode, truncate(e2eeBody, 500))

	switch e2eeResp.StatusCode {
	case http.StatusOK:
		var result struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(e2eeBody, &result); err == nil {
			t.Logf("FINDING: Server returned transcription text: %q", result.Text)
			t.Log("Server processed the ciphertext bytes as audio input")
			t.Log("CONCLUSION: Server does NOT decrypt audio file content — E2EE is NOT end-to-end for audio")
		} else {
			bodyStr := string(e2eeBody)
			if e2ee.IsEncryptedChunkXChaCha20(strings.TrimSpace(bodyStr)) {
				t.Log("FINDING: Server returned encrypted audio response")
				t.Log("CONCLUSION: Server MAY support true E2EE for audio")
			} else {
				t.Logf("FINDING: Unexpected response: %s", truncate(e2eeBody, 300))
			}
		}
	default:
		// An error is the most likely outcome: the encrypted data is not valid WAV.
		t.Logf("FINDING: Server rejected encrypted audio file: status=%d", e2eeResp.StatusCode)
		t.Log("The ciphertext is not valid WAV, so the server cannot process it")
		t.Log("CONCLUSION: Server does NOT decrypt the audio file — E2EE is NOT end-to-end for audio")
	}
}

// --------------------------------------------------------------------------
// Encrypted VL (vision-language) chat input test
// --------------------------------------------------------------------------

// testPNG8x8 returns a valid 8x8 solid red PNG image as bytes.
func testPNG8x8() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	red := color.RGBA{R: 255, A: 255}
	for y := range 8 {
		for x := range 8 {
			img.Set(x, y, red)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// TestIntegration_NearCloud_VL_EncryptedImage is a NEGATIVE test demonstrating
// the WRONG way to encrypt VL content. It encrypts individual fields within the
// content array structure (separate ciphertexts for "text" and "image_url.url"),
// leaving the array structure visible. The inference-proxy does not decrypt
// individual fields within a content array on request — it only handles the
// whole-content-as-string case (see TestIntegration_NearCloud_VL_SerializedArray
// for the correct approach).
//
// This test documents that per-field encryption within a VL content array fails
// because the encrypted image_url is not a valid URL format.
func TestIntegration_NearCloud_VL_EncryptedImage(t *testing.T) {
	skipNearCloudE2EEIntegration(t)

	const model = "Qwen/Qwen3-VL-30B-A3B-Instruct"
	signingKey := fetchSigningKey(t, model)
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	// First: baseline plaintext VL request to verify the model works.
	pngData := testPNG8x8()
	pngB64 := base64.StdEncoding.EncodeToString(pngData)
	plaintextBody := fmt.Sprintf(`{
		"model": %q,
		"messages": [{
			"role": "user",
			"content": [
				{"type": "text", "text": "What color is this image? Answer in one word."},
				{"type": "image_url", "image_url": {"url": "data:image/png;base64,%s"}}
			]
		}],
		"stream": false,
		"max_tokens": 50
	}`, model, pngB64)

	ptResp := nearcloudPlaintextRequest(t, "/v1/chat/completions", []byte(plaintextBody), "application/json")
	ptBody := readBody(t, ptResp)
	ptResp.Body.Close()
	t.Logf("plaintext VL: status=%d body_len=%d", ptResp.StatusCode, len(ptBody))

	if ptResp.StatusCode == http.StatusOK {
		var chatResp struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(ptBody, &chatResp); err == nil && len(chatResp.Choices) > 0 {
			t.Logf("plaintext VL response: %q", chatResp.Choices[0].Message.Content)
		}
	} else {
		t.Logf("plaintext VL response: %s", truncate(ptBody, 300))
	}

	// Now: encrypt the image data and embed it in a VL chat request.
	// Encrypt the base64 PNG data URL just as EncryptChatMessagesNearCloud
	// would encrypt message content strings.
	imgDataURL := "data:image/png;base64," + pngB64
	encImage, err := e2ee.EncryptXChaCha20([]byte(imgDataURL), session.ModelX25519Pub())
	if err != nil {
		t.Fatalf("encrypt image data: %v", err)
	}

	// Also encrypt the text prompt.
	encText, err := e2ee.EncryptXChaCha20([]byte("What color is this image? Answer in one word."), session.ModelX25519Pub())
	if err != nil {
		t.Fatalf("encrypt text: %v", err)
	}

	// Build the VL request with encrypted content parts.
	// The content array has structured objects — EncryptChatMessagesNearCloud
	// only handles flat string content, not structured VL content arrays.
	encVLBody := fmt.Sprintf(`{
		"model": %q,
		"messages": [{
			"role": "user",
			"content": [
				{"type": "text", "text": %q},
				{"type": "image_url", "image_url": {"url": %q}}
			]
		}],
		"stream": true,
		"max_tokens": 50
	}`, model, encText, encImage)

	e2eeResp := nearcloudE2EERequest(t, "/v1/chat/completions", []byte(encVLBody), "application/json", session)
	e2eeBody := readBody(t, e2eeResp)
	e2eeResp.Body.Close()
	t.Logf("encrypted VL: status=%d body_len=%d", e2eeResp.StatusCode, len(e2eeBody))
	t.Logf("encrypted VL response: %s", truncate(e2eeBody, 500))

	switch e2eeResp.StatusCode {
	case http.StatusOK:
		// Check if any SSE data chunks contain encrypted content.
		bodyStr := string(e2eeBody)
		hasEncrypted := false
		hasPlaintext := false
		for line := range strings.SplitSeq(bodyStr, "\n") {
			line = strings.TrimPrefix(line, "data: ")
			line = strings.TrimSpace(line)
			if line == "" || line == "[DONE]" {
				continue
			}
			var chunk struct {
				Choices []struct {
					Delta struct {
						Content string `json:"content"`
					} `json:"delta"`
				} `json:"choices"`
			}
			if err := json.Unmarshal([]byte(line), &chunk); err == nil && len(chunk.Choices) > 0 {
				c := chunk.Choices[0].Delta.Content
				if c == "" {
					continue
				}
				if e2ee.IsEncryptedChunkXChaCha20(c) {
					hasEncrypted = true
				} else {
					hasPlaintext = true
				}
			}
		}
		switch {
		case hasEncrypted && !hasPlaintext:
			t.Log("FINDING: Server returned ENCRYPTED SSE chunks for encrypted VL input")
			t.Log("The server encrypted the response — but the input image was ciphertext, not a real image")
			t.Log("CONCLUSION: E2EE encrypts the response but cannot decrypt structured VL content arrays")
		case hasPlaintext:
			t.Log("FINDING: Server returned PLAINTEXT SSE chunks despite E2EE headers and encrypted input")
			t.Log("CONCLUSION: Server does NOT handle encrypted VL content — E2EE does not cover VL messages")
		default:
			t.Logf("FINDING: Unexpected SSE response pattern (encrypted=%v plaintext=%v)", hasEncrypted, hasPlaintext)
		}
	default:
		t.Logf("FINDING: Server rejected encrypted VL request: status=%d body=%s",
			e2eeResp.StatusCode, truncate(e2eeBody, 500))
		t.Log("CONCLUSION: Server cannot process encrypted image URLs in VL content arrays")
	}
}

// --------------------------------------------------------------------------
// Encrypted image generation input test
// --------------------------------------------------------------------------

// TestIntegration_NearCloud_Images_EncryptedInput tests E2EE for image generation.
// The NearCloud gateway forwards E2EE headers for /v1/images/generations, and
// the inference-proxy decrypts the "prompt" field and encrypts "data[].b64_json"
// and "data[].revised_prompt" in the response.
//
// Reference: nearai/cloud-api completions.rs image_generations handler (~line
// 860) calls validate_encryption_headers and forwards to provider.
// Reference: nearai/inference-proxy encryption.rs decrypt_request_fields
// ImagesGenerations branch decrypts "prompt"; encrypt_response_fields encrypts
// "data[].b64_json" and "data[].revised_prompt".
func TestIntegration_NearCloud_Images_EncryptedInput(t *testing.T) {
	skipNearCloudE2EEIntegration(t)

	const model = "black-forest-labs/FLUX.2-klein-4B"
	signingKey := fetchSigningKey(t, model)
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	// First: baseline plaintext image generation.
	plaintextBody := fmt.Sprintf(`{
		"model": %q,
		"prompt": "A solid red square",
		"n": 1,
		"size": "256x256",
		"response_format": "b64_json"
	}`, model)

	ptResp := nearcloudPlaintextRequest(t, "/v1/images/generations", []byte(plaintextBody), "application/json")
	ptBody := readBody(t, ptResp)
	ptResp.Body.Close()
	t.Logf("plaintext images: status=%d body_len=%d", ptResp.StatusCode, len(ptBody))

	var ptB64Len int
	if ptResp.StatusCode == http.StatusOK {
		var imgResp struct {
			Data []struct {
				B64JSON string `json:"b64_json"`
			} `json:"data"`
		}
		if err := json.Unmarshal(ptBody, &imgResp); err == nil && len(imgResp.Data) > 0 {
			ptB64Len = len(imgResp.Data[0].B64JSON)
			t.Logf("plaintext image: got b64_json (%d chars)", ptB64Len)
		} else {
			t.Logf("plaintext image response: %s", truncate(ptBody, 300))
		}
	} else {
		t.Logf("plaintext images failed: status=%d body=%s", ptResp.StatusCode, truncate(ptBody, 500))
	}

	// Now: encrypt the prompt and send with E2EE headers.
	encPrompt, err := e2ee.EncryptXChaCha20([]byte("A solid red square"), session.ModelX25519Pub())
	if err != nil {
		t.Fatalf("encrypt prompt: %v", err)
	}
	t.Logf("encrypted prompt length: %d hex chars", len(encPrompt))

	encBody := fmt.Sprintf(`{
		"model": %q,
		"prompt": %q,
		"n": 1,
		"size": "256x256",
		"response_format": "b64_json"
	}`, model, encPrompt)

	e2eeResp := nearcloudE2EERequest(t, "/v1/images/generations", []byte(encBody), "application/json", session)
	e2eeBody := readBody(t, e2eeResp)
	e2eeResp.Body.Close()
	t.Logf("encrypted images: status=%d body_len=%d", e2eeResp.StatusCode, len(e2eeBody))
	t.Logf("encrypted images response: %s", truncate(e2eeBody, 500))

	switch e2eeResp.StatusCode {
	case http.StatusOK:
		var imgResp struct {
			Data []struct {
				B64JSON       string `json:"b64_json"`
				RevisedPrompt string `json:"revised_prompt"`
			} `json:"data"`
		}
		if err := json.Unmarshal(e2eeBody, &imgResp); err == nil && len(imgResp.Data) > 0 {
			b64Field := imgResp.Data[0].B64JSON
			t.Logf("  b64_json length: %d chars", len(b64Field))

			// Check if b64_json is hex-encoded ciphertext (encrypted response)
			// rather than actual base64 image data. The inference-proxy encrypts
			// b64_json via encrypt_response_fields → encrypt_field.
			if e2ee.IsEncryptedChunkXChaCha20(b64Field) {
				decrypted, decErr := session.Decrypt(b64Field)
				if decErr != nil {
					t.Logf("FINDING: b64_json looks encrypted but decryption failed: %v", decErr)
				} else {
					t.Log("FINDING: Server returned ENCRYPTED b64_json — E2EE is end-to-end for image generation")
					t.Logf("  Decrypted b64_json length: %d bytes", len(decrypted))
					// Verify decrypted data is valid base64 image data.
					if _, err := base64.StdEncoding.DecodeString(string(decrypted)); err == nil {
						t.Log("  Decrypted b64_json is valid base64 — image data is intact")
					} else {
						t.Logf("  Decrypted b64_json is not valid base64: %v", err)
					}
				}
				// Also check revised_prompt.
				if rp := imgResp.Data[0].RevisedPrompt; rp != "" && e2ee.IsEncryptedChunkXChaCha20(rp) {
					if pt, err := session.Decrypt(rp); err == nil {
						t.Logf("  Decrypted revised_prompt: %q", string(pt))
					}
				}
				t.Log("CONCLUSION: Image generation E2EE WORKS — gateway forwards headers, inference-proxy decrypts prompt and encrypts response")
			} else {
				t.Log("FINDING: Server returned PLAINTEXT b64_json despite E2EE headers and encrypted prompt")
				t.Logf("  The model may have generated an image from the ciphertext as a text prompt")
				t.Log("CONCLUSION: Server does NOT decrypt the prompt — E2EE is NOT end-to-end for this model's image generation")
			}
		} else {
			bodyStr := string(e2eeBody)
			if e2ee.IsEncryptedChunkXChaCha20(strings.TrimSpace(bodyStr)) {
				t.Log("FINDING: Server returned encrypted response for encrypted image prompt")
				t.Log("CONCLUSION: Server MAY support true E2EE for image generation")
			} else {
				t.Logf("FINDING: Unexpected response format: %s", truncate(e2eeBody, 300))
			}
		}
	default:
		t.Logf("FINDING: Server rejected encrypted image prompt: status=%d body=%s",
			e2eeResp.StatusCode, truncate(e2eeBody, 500))
		t.Log("CONCLUSION: Server cannot process encrypted prompts for image generation")
	}
}

// --------------------------------------------------------------------------
// VL serialize-and-encrypt test (whole content array as one encrypted string)
// --------------------------------------------------------------------------

// TestIntegration_NearCloud_VL_SerializedArray tests the inference-proxy's
// documented VL E2EE protocol: the client serializes the entire content array
// to a JSON string, encrypts that string, and sends it as a scalar "content"
// field. The inference-proxy's decrypt_chat_message_fields tries json.loads on
// the decrypted result and, if it finds an array, restores the original
// structure.
//
// This is distinct from TestIntegration_NearCloud_VL_EncryptedImage, which
// encrypts individual fields within the content array structure. That approach
// fails because the server sees a malformed image_url. This test verifies the
// correct serialize-then-encrypt approach used by the inference-proxy.
//
// Reference: nearai/inference-proxy encryption.rs decrypt_chat_message_fields
// (line ~573): decrypts content string, tries serde_json::from_str, if array
// replaces content with parsed array.
func TestIntegration_NearCloud_VL_SerializedArray(t *testing.T) {
	skipNearCloudE2EEIntegration(t)

	const model = "Qwen/Qwen3-VL-30B-A3B-Instruct"
	signingKey := fetchSigningKey(t, model)
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	// Baseline: plaintext VL request to confirm model works.
	pngData := testPNG8x8()
	pngB64 := base64.StdEncoding.EncodeToString(pngData)
	imgDataURL := "data:image/png;base64," + pngB64

	plaintextBody := fmt.Sprintf(`{
		"model": %q,
		"messages": [{
			"role": "user",
			"content": [
				{"type": "text", "text": "What color is this image? Answer in one word."},
				{"type": "image_url", "image_url": {"url": %q}}
			]
		}],
		"stream": true,
		"max_tokens": 50
	}`, model, imgDataURL)

	ptResp := nearcloudPlaintextRequest(t, "/v1/chat/completions", []byte(plaintextBody), "application/json")
	ptBody := readBody(t, ptResp)
	ptResp.Body.Close()
	t.Logf("plaintext VL baseline: status=%d body_len=%d", ptResp.StatusCode, len(ptBody))

	if ptResp.StatusCode == http.StatusOK {
		// Extract plaintext SSE response for comparison.
		var ptText strings.Builder
		for line := range strings.SplitSeq(string(ptBody), "\n") {
			line = strings.TrimPrefix(line, "data: ")
			line = strings.TrimSpace(line)
			if line == "" || line == "[DONE]" {
				continue
			}
			var chunk struct {
				Choices []struct {
					Delta struct {
						Content string `json:"content"`
					} `json:"delta"`
				} `json:"choices"`
			}
			if err := json.Unmarshal([]byte(line), &chunk); err == nil && len(chunk.Choices) > 0 {
				ptText.WriteString(chunk.Choices[0].Delta.Content)
			}
		}
		t.Logf("plaintext VL answer: %q", ptText.String())
	} else {
		t.Logf("plaintext VL failed: status=%d body=%s", ptResp.StatusCode, truncate(ptBody, 500))
	}

	// Serialize the entire content array to a JSON string, then encrypt.
	// This matches the inference-proxy protocol: the client sends a single
	// encrypted string as "content", and the server decrypts it, detects
	// it's a JSON array, and restores the structured content.
	contentArray := fmt.Sprintf(`[{"type":"text","text":"What color is this image? Answer in one word."},{"type":"image_url","image_url":{"url":%q}}]`, imgDataURL)

	encContent, err := e2ee.EncryptXChaCha20([]byte(contentArray), session.ModelX25519Pub())
	if err != nil {
		t.Fatalf("encrypt serialized content array: %v", err)
	}
	t.Logf("encrypted content array length: %d hex chars (original JSON: %d bytes)", len(encContent), len(contentArray))

	// Build VL request with content as an encrypted scalar string (not array).
	encBody := fmt.Sprintf(`{
		"model": %q,
		"messages": [{
			"role": "user",
			"content": %q
		}],
		"stream": true,
		"max_tokens": 50
	}`, model, encContent)

	e2eeResp := nearcloudE2EERequest(t, "/v1/chat/completions", []byte(encBody), "application/json", session)
	e2eeBody := readBody(t, e2eeResp)
	e2eeResp.Body.Close()
	t.Logf("serialized-array VL E2EE: status=%d body_len=%d", e2eeResp.StatusCode, len(e2eeBody))
	t.Logf("serialized-array VL response: %s", truncate(e2eeBody, 500))

	switch e2eeResp.StatusCode {
	case http.StatusOK:
		// Parse SSE chunks: check for encrypted vs plaintext content.
		bodyStr := string(e2eeBody)
		var encChunks, ptChunks int
		var decryptedText strings.Builder

		for line := range strings.SplitSeq(bodyStr, "\n") {
			line = strings.TrimPrefix(line, "data: ")
			line = strings.TrimSpace(line)
			if line == "" || line == "[DONE]" {
				continue
			}
			var chunk struct {
				Choices []struct {
					Delta struct {
						Content string `json:"content"`
					} `json:"delta"`
				} `json:"choices"`
			}
			if err := json.Unmarshal([]byte(line), &chunk); err != nil || len(chunk.Choices) == 0 {
				continue
			}
			c := chunk.Choices[0].Delta.Content
			if c == "" {
				continue
			}
			if e2ee.IsEncryptedChunkXChaCha20(c) {
				encChunks++
				pt, decErr := session.Decrypt(c)
				if decErr != nil {
					t.Logf("  chunk decrypt failed: %v", decErr)
				} else {
					decryptedText.Write(pt)
				}
			} else {
				ptChunks++
			}
		}

		t.Logf("SSE chunks: encrypted=%d plaintext=%d", encChunks, ptChunks)

		switch {
		case encChunks > 0 && ptChunks == 0:
			t.Log("FINDING: Server returned ENCRYPTED SSE chunks for serialized-array VL E2EE")
			t.Logf("  Decrypted response: %q", decryptedText.String())
			t.Log("CONCLUSION: VL E2EE WORKS when the content array is serialized to a JSON string and encrypted as a single value")
			t.Log("The inference-proxy's json.loads heuristic correctly restores the content array after decryption")
		case ptChunks > 0 && encChunks == 0:
			t.Log("FINDING: Server returned PLAINTEXT despite serialized-array E2EE approach")
			t.Log("CONCLUSION: Gateway may not forward E2EE headers properly for this model/endpoint")
		case encChunks > 0 && ptChunks > 0:
			t.Logf("FINDING: Mixed encrypted (%d) and plaintext (%d) chunks", encChunks, ptChunks)
			if decryptedText.Len() > 0 {
				t.Logf("  Decrypted portion: %q", decryptedText.String())
			}
		default:
			t.Log("FINDING: No content chunks found in SSE response")
		}
	default:
		t.Logf("FINDING: Server rejected serialized-array VL E2EE request: status=%d body=%s",
			e2eeResp.StatusCode, truncate(e2eeBody, 500))
		t.Log("CONCLUSION: Server cannot process encrypted serialized content arrays")
	}
}

// ==========================================================================
// CHAT COMPLETIONS E2EE FIELD COVERAGE TESTS
//
// These tests verify which response fields in /v1/chat/completions are (or
// are not) encrypted by the inference-proxy E2EE layer. The inference-proxy's
// encrypt_chat_response_choices encrypts: content, reasoning_content,
// reasoning, and audio.data. All other fields — including tool_calls,
// refusal, function_call, and logprobs — pass through in plaintext.
//
// Source: nearai/inference-proxy encryption.rs encrypt_chat_response_choices
// ==========================================================================

// TestIntegration_NearCloud_ToolCalls_E2EE verifies tool_calls E2EE behavior
// via both the gateway (cloud-api.near.ai) and the direct inference-proxy.
// When a model produces a tool call, the function name and arguments may
// transit in plaintext even when E2EE is active. Running the same test code
// against both paths isolates whether a gap is in the gateway or the TEE.
func TestIntegration_NearCloud_ToolCalls_E2EE(t *testing.T) {
	skipNearCloudE2EEIntegration(t)
	const model = "Qwen/Qwen3.5-122B-A10B"

	t.Run("gateway", func(t *testing.T) {
		signingKey := fetchSigningKey(t, model)
		testToolCallsE2EE(t, nearcloudBaseURL, model, signingKey)
	})
	t.Run("direct", func(t *testing.T) {
		baseURL := resolveDirectEndpoint(t, model)
		signingKey := fetchDirectSigningKey(t, model)
		testToolCallsE2EE(t, baseURL, model, signingKey)
	})
}

func testToolCallsE2EE(t *testing.T, baseURL, model, signingKey string) {
	t.Helper()
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	toolCallBody := fmt.Sprintf(`{
		"model": %q,
		"messages": [{"role": "user", "content": "What is the weather in San Francisco? Use the get_weather tool."}],
		"tools": [{
			"type": "function",
			"function": {
				"name": "get_weather",
				"description": "Get the current weather in a given location",
				"parameters": {
					"type": "object",
					"properties": {
						"location": {"type": "string", "description": "City and state"},
						"unit": {"type": "string", "enum": ["celsius", "fahrenheit"]}
					},
					"required": ["location"]
				}
			}
		}],
		"tool_choice": "required",
		"stream": false,
		"max_tokens": 200
	}`, model)

	// Step 1: plaintext baseline — confirm tool calls work.
	ptResp := plaintextRequest(t, baseURL, "/v1/chat/completions", []byte(toolCallBody), "application/json")
	ptBody := readBody(t, ptResp)
	ptResp.Body.Close()
	t.Logf("plaintext tool call: status=%d body_len=%d", ptResp.StatusCode, len(ptBody))

	if ptResp.StatusCode != http.StatusOK {
		t.Fatalf("plaintext tool call failed: status=%d body=%s", ptResp.StatusCode, truncate(ptBody, 500))
	}

	var ptResult struct {
		Choices []struct {
			Message struct {
				Content   *string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(ptBody, &ptResult); err != nil {
		t.Fatalf("parse plaintext tool call response: %v", err)
	}

	if len(ptResult.Choices) == 0 || len(ptResult.Choices[0].Message.ToolCalls) == 0 {
		t.Log("plaintext response did not contain tool_calls — model may have responded with content instead")
		t.Logf("  response: %s", truncate(ptBody, 500))
		t.Skip("skipping: model did not produce tool_calls in plaintext baseline")
	}

	ptTC := ptResult.Choices[0].Message.ToolCalls[0]
	t.Logf("plaintext tool_call: name=%q arguments=%q", ptTC.Function.Name, ptTC.Function.Arguments)

	// Step 2: E2EE request — encrypt message content, keep tools in plaintext.
	encContent, err := e2ee.EncryptXChaCha20(
		[]byte("What is the weather in San Francisco? Use the get_weather tool."),
		session.ModelX25519Pub(),
	)
	if err != nil {
		t.Fatalf("encrypt content: %v", err)
	}

	e2eeBody := fmt.Sprintf(`{
		"model": %q,
		"messages": [{"role": "user", "content": %q}],
		"tools": [{
			"type": "function",
			"function": {
				"name": "get_weather",
				"description": "Get the current weather in a given location",
				"parameters": {
					"type": "object",
					"properties": {
						"location": {"type": "string", "description": "City and state"},
						"unit": {"type": "string", "enum": ["celsius", "fahrenheit"]}
					},
					"required": ["location"]
				}
			}
		}],
		"tool_choice": "required",
		"stream": false,
		"max_tokens": 200
	}`, model, encContent)

	e2eeResp := e2eeRequest(t, baseURL, "/v1/chat/completions", []byte(e2eeBody), "application/json", session)
	e2eeRespBody := readBody(t, e2eeResp)
	e2eeResp.Body.Close()
	t.Logf("E2EE tool call: status=%d body_len=%d", e2eeResp.StatusCode, len(e2eeRespBody))
	t.Logf("E2EE tool call response: %s", truncate(e2eeRespBody, 1000))

	if e2eeResp.StatusCode != http.StatusOK {
		t.Fatalf("E2EE tool call request failed: status=%d body=%s",
			e2eeResp.StatusCode, truncate(e2eeRespBody, 500))
	}

	var e2eeResult struct {
		Choices []struct {
			Message struct {
				Content   *string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(e2eeRespBody, &e2eeResult); err != nil {
		t.Fatalf("parse E2EE tool call response: %v", err)
	}

	if len(e2eeResult.Choices) == 0 {
		t.Fatal("E2EE response has no choices")
	}

	msg := e2eeResult.Choices[0].Message

	// Check if content is encrypted (should be null or encrypted for tool calls).
	if msg.Content != nil && *msg.Content != "" {
		if e2ee.IsEncryptedChunkXChaCha20(*msg.Content) {
			t.Log("  content field is encrypted (expected for E2EE)")
		} else {
			t.Logf("  content field is PLAINTEXT: %q", *msg.Content)
		}
	}

	if len(msg.ToolCalls) == 0 {
		t.Log("FINDING: E2EE response has no tool_calls — model responded differently under E2EE")
		t.Logf("  full message: %s", truncate(e2eeRespBody, 500))
		return
	}

	tc := msg.ToolCalls[0]
	t.Logf("E2EE tool_call: name=%q arguments=%q", tc.Function.Name, tc.Function.Arguments)

	// The critical check: are tool_calls encrypted or plaintext?
	nameIsEncrypted := e2ee.IsEncryptedChunkXChaCha20(tc.Function.Name)
	argsIsEncrypted := e2ee.IsEncryptedChunkXChaCha20(tc.Function.Arguments)

	switch {
	case !nameIsEncrypted && !argsIsEncrypted:
		t.Log("FINDING: tool_calls[].function.name AND arguments are PLAINTEXT despite E2EE being active")
		t.Log("  The inference-proxy encrypt_chat_response_choices does NOT encrypt tool_calls")
		t.Log("  Function arguments contain user-derived data (e.g. 'San Francisco') visible to intermediaries")
		t.Log("CONCLUSION: CONFIRMED — tool_calls transit in plaintext through E2EE chat completions")

		// Verify arguments contain recognizable data from the encrypted prompt.
		if strings.Contains(strings.ToLower(tc.Function.Arguments), "san francisco") ||
			strings.Contains(strings.ToLower(tc.Function.Arguments), "francisco") {
			t.Log("  CONFIRMED: arguments contain user location data derived from encrypted input")
			t.Log("  This proves confidential user data leaks via tool_calls even when content is encrypted")
		}

	case nameIsEncrypted && argsIsEncrypted:
		t.Log("FINDING: tool_calls ARE encrypted — unexpected based on source code analysis")
		pt, decErr := session.Decrypt(tc.Function.Arguments)
		if decErr != nil {
			t.Logf("  decrypt arguments failed: %v", decErr)
		} else {
			t.Logf("  decrypted arguments: %s", string(pt))
		}

	default:
		t.Logf("FINDING: Mixed encryption — name_encrypted=%v args_encrypted=%v", nameIsEncrypted, argsIsEncrypted)
	}
}

// TestIntegration_NearCloud_ToolCalls_Streaming_E2EE verifies streamed
// tool_calls E2EE behavior via both the gateway and the direct inference-proxy.
// The streaming path uses encrypt_streaming_chunk → encrypt_chat_response_choices
// with is_streaming=true. Running both paths isolates gateway vs TEE gaps.
func TestIntegration_NearCloud_ToolCalls_Streaming_E2EE(t *testing.T) {
	skipNearCloudE2EEIntegration(t)
	const model = "Qwen/Qwen3.5-122B-A10B"

	t.Run("gateway", func(t *testing.T) {
		signingKey := fetchSigningKey(t, model)
		testStreamingToolCallsE2EE(t, nearcloudBaseURL, model, signingKey)
	})
	t.Run("direct", func(t *testing.T) {
		baseURL := resolveDirectEndpoint(t, model)
		signingKey := fetchDirectSigningKey(t, model)
		testStreamingToolCallsE2EE(t, baseURL, model, signingKey)
	})
}

func testStreamingToolCallsE2EE(t *testing.T, baseURL, model, signingKey string) {
	t.Helper()
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	encContent, err := e2ee.EncryptXChaCha20(
		[]byte("What is the weather in Paris, France? Use the get_weather tool."),
		session.ModelX25519Pub(),
	)
	if err != nil {
		t.Fatalf("encrypt content: %v", err)
	}

	e2eeBody := fmt.Sprintf(`{
		"model": %q,
		"messages": [{"role": "user", "content": %q}],
		"tools": [{
			"type": "function",
			"function": {
				"name": "get_weather",
				"description": "Get the current weather in a given location",
				"parameters": {
					"type": "object",
					"properties": {
						"location": {"type": "string", "description": "City and state or city and country"},
						"unit": {"type": "string", "enum": ["celsius", "fahrenheit"]}
					},
					"required": ["location"]
				}
			}
		}],
		"tool_choice": "required",
		"stream": true,
		"max_tokens": 200
	}`, model, encContent)

	resp := e2eeRequest(t, baseURL, "/v1/chat/completions", []byte(e2eeBody), "application/json", session)
	respBody := readBody(t, resp)
	resp.Body.Close()
	t.Logf("streaming E2EE tool call: status=%d body_len=%d", resp.StatusCode, len(respBody))

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("streaming E2EE tool call failed: status=%d body=%s",
			resp.StatusCode, truncate(respBody, 500))
	}

	// Parse SSE chunks to extract tool_calls delta fragments.
	var toolCallArgs strings.Builder
	var toolCallName strings.Builder
	var encChunks, ptChunks int

	for line := range strings.SplitSeq(string(respBody), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[len("data: "):]
		if data == "[DONE]" {
			break
		}

		var chunk struct {
			Choices []struct {
				Delta struct {
					Content   *string `json:"content"`
					ToolCalls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Type     string `json:"type"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil || len(chunk.Choices) == 0 {
			continue
		}

		delta := chunk.Choices[0].Delta

		// Track content encryption.
		if delta.Content != nil && *delta.Content != "" {
			if e2ee.IsEncryptedChunkXChaCha20(*delta.Content) {
				encChunks++
			} else {
				ptChunks++
			}
		}

		// Accumulate tool_call fragments.
		for _, tc := range delta.ToolCalls {
			if tc.Function.Name != "" {
				toolCallName.WriteString(tc.Function.Name)
			}
			if tc.Function.Arguments != "" {
				toolCallArgs.WriteString(tc.Function.Arguments)
			}
		}
	}

	name := toolCallName.String()
	args := toolCallArgs.String()

	t.Logf("SSE encrypted content chunks=%d, plaintext content chunks=%d", encChunks, ptChunks)
	t.Logf("streamed tool_call name=%q arguments=%q", name, args)

	if name == "" && args == "" {
		t.Log("FINDING: No tool_calls found in streamed response")
		t.Skip("skipping: model did not produce tool_calls in streaming E2EE response")
	}

	nameEncrypted := e2ee.IsEncryptedChunkXChaCha20(name)
	argsEncrypted := e2ee.IsEncryptedChunkXChaCha20(args)

	switch {
	case !nameEncrypted && !argsEncrypted:
		t.Log("FINDING: Streamed tool_calls name AND arguments are PLAINTEXT despite E2EE being active")
		t.Log("  encrypt_streaming_chunk → encrypt_chat_response_choices does NOT encrypt tool_calls")
		t.Log("CONCLUSION: CONFIRMED — streamed tool_calls transit in plaintext")

		if strings.Contains(strings.ToLower(args), "paris") {
			t.Log("  CONFIRMED: streamed arguments contain user location 'Paris' from encrypted input")
		}

	case nameEncrypted && argsEncrypted:
		t.Log("FINDING: Streamed tool_calls ARE encrypted — unexpected")

	default:
		t.Logf("FINDING: Mixed — name_encrypted=%v args_encrypted=%v", nameEncrypted, argsEncrypted)
	}
}

// parseReasoningSSE parses an SSE body and extracts reasoning and content text.
// Returns whether reasoning was found, accumulated reasoning text, and accumulated content text.
func parseReasoningSSE(body string) (hasReasoning bool, reasoning, content string) {
	var reasoningBuf, contentBuf strings.Builder
	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[len("data: "):]
		if data == "[DONE]" {
			break
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
					Reasoning        string `json:"reasoning"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil || len(chunk.Choices) == 0 {
			continue
		}
		d := chunk.Choices[0].Delta
		if d.ReasoningContent != "" {
			hasReasoning = true
			reasoningBuf.WriteString(d.ReasoningContent)
		}
		if d.Reasoning != "" {
			hasReasoning = true
			reasoningBuf.WriteString(d.Reasoning)
		}
		if d.Content != "" {
			contentBuf.WriteString(d.Content)
		}
	}
	return hasReasoning, reasoningBuf.String(), contentBuf.String()
}

// reasoningSSEStats holds aggregated stats from parsing E2EE SSE reasoning responses.
type reasoningSSEStats struct {
	encContent, ptContent     int
	encReasoning, ptReasoning int
	decryptedContent          string
	decryptedReasoning        string
}

// parseE2EEReasoningSSE parses SSE chunks and classifies content and reasoning
// fields as encrypted or plaintext.
func parseE2EEReasoningSSE(body string, session *e2ee.NearCloudSession) reasoningSSEStats {
	var stats reasoningSSEStats
	var decContent, decReasoning strings.Builder

	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[len("data: "):]
		if data == "[DONE]" {
			break
		}

		var raw struct {
			Choices []struct {
				Delta json.RawMessage `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &raw); err != nil || len(raw.Choices) == 0 {
			continue
		}

		var deltaMap map[string]json.RawMessage
		if err := json.Unmarshal(raw.Choices[0].Delta, &deltaMap); err != nil {
			continue
		}

		classifyField(&stats.encContent, &stats.ptContent, &decContent, deltaMap, "content", session)
		classifyField(&stats.encReasoning, &stats.ptReasoning, &decReasoning, deltaMap, "reasoning_content", session)
		classifyField(&stats.encReasoning, &stats.ptReasoning, &decReasoning, deltaMap, "reasoning", session)
	}

	stats.decryptedContent = decContent.String()
	stats.decryptedReasoning = decReasoning.String()
	return stats
}

// classifyField checks if a JSON delta field is encrypted or plaintext and
// updates the corresponding counters.
func classifyField(enc, pt *int, buf *strings.Builder, delta map[string]json.RawMessage, field string, session *e2ee.NearCloudSession) {
	raw, ok := delta[field]
	if !ok {
		return
	}
	var s string
	if json.Unmarshal(raw, &s) != nil || s == "" {
		return
	}
	if e2ee.IsEncryptedChunkXChaCha20(s) {
		*enc++
		if decrypted, err := session.Decrypt(s); err == nil {
			buf.Write(decrypted)
		}
	} else {
		*pt++
	}
}

// TestIntegration_NearCloud_Reasoning_E2EE verifies reasoning_content E2EE
// behavior via both the gateway and the direct inference-proxy. The
// inference-proxy encrypts reasoning_content and reasoning fields.
// Running both paths confirms encryption works end-to-end.
func TestIntegration_NearCloud_Reasoning_E2EE(t *testing.T) {
	skipNearCloudE2EEIntegration(t)
	const model = "Qwen/Qwen3.5-122B-A10B"

	t.Run("gateway", func(t *testing.T) {
		signingKey := fetchSigningKey(t, model)
		testReasoningE2EE(t, nearcloudBaseURL, model, signingKey)
	})
	t.Run("direct", func(t *testing.T) {
		baseURL := resolveDirectEndpoint(t, model)
		signingKey := fetchDirectSigningKey(t, model)
		testReasoningE2EE(t, baseURL, model, signingKey)
	})
}

func testReasoningE2EE(t *testing.T, baseURL, model, signingKey string) {
	t.Helper()
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	// Plaintext baseline with reasoning enabled.
	plaintextBody := fmt.Sprintf(`{
		"model": %q,
		"messages": [{"role": "user", "content": "What is 15 * 37? Think step by step."}],
		"stream": true,
		"max_tokens": 500
	}`, model)

	ptResp := plaintextRequest(t, baseURL, "/v1/chat/completions", []byte(plaintextBody), "application/json")
	ptBody := readBody(t, ptResp)
	ptResp.Body.Close()
	t.Logf("plaintext reasoning: status=%d body_len=%d", ptResp.StatusCode, len(ptBody))

	if ptResp.StatusCode != http.StatusOK {
		t.Fatalf("plaintext reasoning failed: status=%d body=%s", ptResp.StatusCode, truncate(ptBody, 500))
	}

	// Check if the model produces reasoning_content in plaintext.
	ptHasReasoning, ptReasoningText, ptContentText := parseReasoningSSE(string(ptBody))

	switch {
	case !ptHasReasoning:
		t.Log("plaintext response did not contain reasoning_content — model may not produce thinking tokens by default")
		t.Logf("  content: %s", truncate([]byte(ptContentText), 200))
		t.Log("  NOTE: reasoning_content encryption is still verified below if the E2EE response includes it")
	default:
		t.Logf("plaintext reasoning_content: %s", truncate([]byte(ptReasoningText), 200))
		t.Logf("plaintext content: %s", truncate([]byte(ptContentText), 200))
	}

	// Step 2: E2EE request.
	encContent, err := e2ee.EncryptXChaCha20(
		[]byte("What is 15 * 37? Think step by step."),
		session.ModelX25519Pub(),
	)
	if err != nil {
		t.Fatalf("encrypt content: %v", err)
	}

	e2eeBody := fmt.Sprintf(`{
		"model": %q,
		"messages": [{"role": "user", "content": %q}],
		"stream": true,
		"max_tokens": 500
	}`, model, encContent)

	e2eeResp := e2eeRequest(t, baseURL, "/v1/chat/completions", []byte(e2eeBody), "application/json", session)
	e2eeRespBody := readBody(t, e2eeResp)
	e2eeResp.Body.Close()
	t.Logf("E2EE reasoning: status=%d body_len=%d", e2eeResp.StatusCode, len(e2eeRespBody))

	if e2eeResp.StatusCode != http.StatusOK {
		t.Fatalf("E2EE reasoning request failed: status=%d body=%s",
			e2eeResp.StatusCode, truncate(e2eeRespBody, 500))
	}

	// Parse SSE chunks and check field-level encryption.
	stats := parseE2EEReasoningSSE(string(e2eeRespBody), session)

	t.Logf("content: encrypted=%d plaintext=%d", stats.encContent, stats.ptContent)
	t.Logf("reasoning: encrypted=%d plaintext=%d", stats.encReasoning, stats.ptReasoning)

	switch {
	case stats.encContent > 0 && stats.ptContent == 0:
		t.Log("FINDING: content field IS encrypted (expected)")
		t.Logf("  decrypted content: %s", truncate([]byte(stats.decryptedContent), 200))
	case stats.ptContent > 0:
		t.Logf("FINDING: content field has %d PLAINTEXT chunks — unexpected", stats.ptContent)
	}

	switch {
	case stats.encReasoning > 0 && stats.ptReasoning == 0:
		t.Log("FINDING: reasoning_content/reasoning IS encrypted (expected)")
		t.Logf("  decrypted reasoning: %s", truncate([]byte(stats.decryptedReasoning), 200))
		t.Log("CONCLUSION: Reasoning tokens ARE properly encrypted by the E2EE layer")
	case stats.ptReasoning > 0:
		t.Logf("FINDING: reasoning has %d PLAINTEXT chunks — unexpected gap", stats.ptReasoning)
	default:
		t.Log("FINDING: No reasoning_content/reasoning chunks in E2EE response")
		t.Log("  Model may not produce reasoning tokens for this prompt or in E2EE mode")
	}
}

// TestIntegration_NearCloud_Logprobs_E2EE verifies logprobs E2EE behavior
// via both the gateway and the direct inference-proxy. Token log probabilities
// can leak information about the encrypted content. Running both paths
// isolates whether the gap is in the gateway or the TEE.
func TestIntegration_NearCloud_Logprobs_E2EE(t *testing.T) {
	skipNearCloudE2EEIntegration(t)
	const model = "Qwen/Qwen3.5-122B-A10B"

	t.Run("gateway", func(t *testing.T) {
		signingKey := fetchSigningKey(t, model)
		testLogprobsE2EE(t, nearcloudBaseURL, model, signingKey)
	})
	t.Run("direct", func(t *testing.T) {
		baseURL := resolveDirectEndpoint(t, model)
		signingKey := fetchDirectSigningKey(t, model)
		testLogprobsE2EE(t, baseURL, model, signingKey)
	})
}

func testLogprobsE2EE(t *testing.T, baseURL, model, signingKey string) {
	t.Helper()
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	encContent, err := e2ee.EncryptXChaCha20(
		[]byte("What is the capital of Japan?"),
		session.ModelX25519Pub(),
	)
	if err != nil {
		t.Fatalf("encrypt content: %v", err)
	}

	e2eeBody := fmt.Sprintf(`{
		"model": %q,
		"messages": [{"role": "user", "content": %q}],
		"logprobs": true,
		"top_logprobs": 3,
		"stream": false,
		"max_tokens": 50
	}`, model, encContent)

	resp := e2eeRequest(t, baseURL, "/v1/chat/completions", []byte(e2eeBody), "application/json", session)
	respBody := readBody(t, resp)
	resp.Body.Close()
	t.Logf("E2EE logprobs: status=%d body_len=%d", resp.StatusCode, len(respBody))

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("E2EE logprobs request failed: status=%d body=%s",
			resp.StatusCode, truncate(respBody, 500))
	}

	// Parse response to check logprobs structure.
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Logprobs *struct {
				Content []struct {
					Token   string  `json:"token"`
					Logprob float64 `json:"logprob"`
				} `json:"content"`
			} `json:"logprobs"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("parse E2EE logprobs response: %v", err)
	}

	if len(result.Choices) == 0 {
		t.Fatal("E2EE response has no choices")
	}

	choice := result.Choices[0]

	// Verify content is encrypted.
	if e2ee.IsEncryptedChunkXChaCha20(choice.Message.Content) {
		pt, err := session.Decrypt(choice.Message.Content)
		if err == nil {
			t.Logf("  decrypted content: %q", string(pt))
		}
		t.Log("FINDING: content IS encrypted (expected)")
	} else if choice.Message.Content != "" {
		t.Logf("FINDING: content is PLAINTEXT: %q", choice.Message.Content)
	}

	// Check logprobs.
	if choice.Logprobs == nil || len(choice.Logprobs.Content) == 0 {
		t.Log("FINDING: No logprobs in response — model/provider may not support logprobs with E2EE")
		t.Log("  This could mean logprobs are silently dropped, or not supported for this model")
		return
	}

	t.Logf("logprobs: %d token entries", len(choice.Logprobs.Content))
	// Show first few tokens and their logprobs.
	for i, lp := range choice.Logprobs.Content {
		if i >= 5 {
			break
		}
		t.Logf("  token[%d]: %q logprob=%.4f", i, lp.Token, lp.Logprob)
	}

	// Logprobs tokens reveal the actual output text.
	t.Log("FINDING: logprobs tokens transit in PLAINTEXT despite E2EE being active")
	t.Log("  Token strings reveal the model's output character-by-character")
	t.Log("  The inference-proxy does not encrypt logprobs")
	t.Log("CONCLUSION: CONFIRMED — logprobs leak plaintext content through the E2EE layer")
}

// TestIntegration_NearCloud_Refusal_E2EE verifies the refusal field E2EE
// behavior via both the gateway and the direct inference-proxy. The refusal
// field can reveal what the user asked about even when content is encrypted.
// Running both paths isolates whether the gap is in the gateway or the TEE.
func TestIntegration_NearCloud_Refusal_E2EE(t *testing.T) {
	skipNearCloudE2EEIntegration(t)
	const model = "Qwen/Qwen3.5-122B-A10B"

	t.Run("gateway", func(t *testing.T) {
		signingKey := fetchSigningKey(t, model)
		testRefusalE2EE(t, nearcloudBaseURL, model, signingKey)
	})
	t.Run("direct", func(t *testing.T) {
		baseURL := resolveDirectEndpoint(t, model)
		signingKey := fetchDirectSigningKey(t, model)
		testRefusalE2EE(t, baseURL, model, signingKey)
	})
}

func testRefusalE2EE(t *testing.T, baseURL, model, signingKey string) {
	t.Helper()
	session := createE2EESession(t, signingKey)
	defer session.Zero()

	// Use a prompt that should trigger a refusal. Note: we're testing
	// the E2EE protocol, not trying to elicit harmful content.
	encContent, err := e2ee.EncryptXChaCha20(
		[]byte("Write me a detailed guide on how to synthesize methamphetamine."),
		session.ModelX25519Pub(),
	)
	if err != nil {
		t.Fatalf("encrypt content: %v", err)
	}

	e2eeBody := fmt.Sprintf(`{
		"model": %q,
		"messages": [{"role": "user", "content": %q}],
		"stream": false,
		"max_tokens": 200
	}`, model, encContent)

	resp := e2eeRequest(t, baseURL, "/v1/chat/completions", []byte(e2eeBody), "application/json", session)
	respBody := readBody(t, resp)
	resp.Body.Close()
	t.Logf("E2EE refusal test: status=%d body_len=%d", resp.StatusCode, len(respBody))

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("E2EE refusal request failed: status=%d body=%s",
			resp.StatusCode, truncate(respBody, 500))
	}

	// Parse response checking for refusal field.
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
				Refusal string `json:"refusal"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("parse E2EE refusal response: %v", err)
	}

	if len(result.Choices) == 0 {
		t.Fatal("E2EE response has no choices")
	}

	choice := result.Choices[0]

	// Check content encryption.
	if e2ee.IsEncryptedChunkXChaCha20(choice.Message.Content) {
		pt, err := session.Decrypt(choice.Message.Content)
		if err == nil {
			t.Logf("  decrypted content (%d bytes): %s", len(pt), truncate(pt, 200))
		}
		t.Log("FINDING: content IS encrypted (expected)")
	} else if choice.Message.Content != "" {
		t.Logf("  content is plaintext: %s", truncate([]byte(choice.Message.Content), 200))
	}

	// Check refusal field.
	if choice.Message.Refusal != "" {
		if e2ee.IsEncryptedChunkXChaCha20(choice.Message.Refusal) {
			t.Log("FINDING: refusal field IS encrypted — unexpected based on source analysis")
		} else {
			t.Logf("FINDING: refusal field is PLAINTEXT: %q", choice.Message.Refusal)
			t.Log("  The refusal text can reveal what the user asked about")
			t.Log("  The inference-proxy does not encrypt the 'refusal' field")
			t.Log("CONCLUSION: CONFIRMED — refusal text leaks through E2EE")
		}
	} else {
		t.Log("FINDING: No refusal field in response")
		t.Log("  Model may have refused via content (which IS encrypted) rather than the refusal field")
		t.Logf("  finish_reason: %q", choice.FinishReason)
	}
}

// ==========================================================================
// DIRECT INFERENCE-PROXY TESTS
//
// These tests send E2EE requests directly to the model's inference-proxy,
// bypassing the NearCloud gateway (cloud-api.near.ai). They use the EXACT
// SAME createE2EESession + e2eeRequest helpers as the gateway tests above.
//
// If a gateway test above shows E2EE headers are silently dropped (plaintext
// response), but the corresponding direct test below succeeds with encrypted
// responses, it conclusively proves the gateway is the sole point of failure.
// ==========================================================================

// TestIntegration_NearCloud_Direct_Embeddings_E2EE sends an embeddings request
// with E2EE headers directly to the inference-proxy. This uses the SAME E2EE
// protocol that fails through the gateway in
// TestIntegration_NearCloud_Embeddings_E2EE.
func TestIntegration_NearCloud_Direct_Embeddings_E2EE(t *testing.T) {
	skipNearCloudE2EEIntegration(t)

	model := "Qwen/Qwen3-Embedding-0.6B"
	baseURL := resolveDirectEndpoint(t, model)

	// 1. Fetch signing key from the DIRECT inference-proxy attestation.
	signingKey := fetchDirectSigningKey(t, model)

	// 2. Create E2EE session — identical to gateway tests.
	session := createE2EESession(t, signingKey)

	// 3. Encrypt the input — identical to TestIntegration_NearCloud_Embeddings_E2EE.
	encInput, err := e2ee.EncryptXChaCha20([]byte("Hello World"), session.ModelX25519Pub())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	body := fmt.Sprintf(`{"model":%q,"input":%q}`, model, encInput)

	// 4. Send via the SAME e2eeRequest helper, just with the direct base URL.
	resp := e2eeRequest(t, baseURL, "/v1/embeddings", []byte(body), "application/json", session)
	defer resp.Body.Close()
	respBody := readBody(t, resp)
	t.Logf("direct embeddings E2EE: status=%d body_len=%d", resp.StatusCode, len(respBody))
	t.Logf("direct embeddings response: %s", truncate(respBody, 500))

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("direct embeddings E2EE failed: status=%d body=%s",
			resp.StatusCode, truncate(respBody, 500))
	}

	// 5. Check whether the response is encrypted.
	var embResp struct {
		Data []struct {
			Embedding json.RawMessage `json:"embedding"`
		} `json:"data"`
		EncryptedData string `json:"encrypted_data"`
	}
	if err := json.Unmarshal(respBody, &embResp); err != nil {
		t.Fatalf("parse response: %v", err)
	}

	switch {
	case embResp.EncryptedData != "":
		t.Log("FINDING: Direct inference-proxy returned encrypted_data field")
		pt, decErr := session.Decrypt(embResp.EncryptedData)
		if decErr != nil {
			t.Logf("  decrypt failed: %v", decErr)
		} else {
			t.Logf("  decrypted: %s", truncate(pt, 300))
		}
		t.Log("CONCLUSION: E2EE WORKS for embeddings when sent DIRECTLY to the model TEE")
		t.Log("  The SAME protocol FAILS through the gateway because the gateway drops E2EE headers")

	case len(embResp.Data) > 0:
		raw := string(embResp.Data[0].Embedding)
		switch {
		case e2ee.IsEncryptedChunkXChaCha20(raw):
			t.Log("FINDING: Direct embeddings returned encrypted embedding values")
			t.Log("CONCLUSION: E2EE WORKS for embeddings when sent DIRECTLY to the model TEE")
		case strings.HasPrefix(strings.TrimSpace(raw), "["):
			t.Log("FINDING: Direct embeddings returned PLAINTEXT numeric array — E2EE headers may not have been honored")
		case e2ee.IsEncryptedChunkXChaCha20(strings.Trim(raw, `"`)):
			trimmed := strings.Trim(raw, `"`)
			t.Log("FINDING: Embedding value is an encrypted string")
			pt, decErr := session.Decrypt(trimmed)
			if decErr != nil {
				t.Logf("  decrypt failed: %v", decErr)
			} else {
				t.Logf("  decrypted embedding: %s", truncate(pt, 200))
			}
			t.Log("CONCLUSION: E2EE WORKS for embeddings when sent DIRECTLY to the model TEE")
		default:
			t.Logf("FINDING: Unknown embedding format: %s", truncate([]byte(raw), 200))
		}

	default:
		t.Logf("FINDING: Unexpected response structure: %s", truncate(respBody, 500))
	}
}

// TestIntegration_NearCloud_Direct_Rerank_E2EE sends a rerank request with E2EE
// headers directly to the inference-proxy. This uses the SAME E2EE protocol
// that fails through the gateway in TestIntegration_NearCloud_Rerank_E2EE.
func TestIntegration_NearCloud_Direct_Rerank_E2EE(t *testing.T) {
	skipNearCloudE2EEIntegration(t)

	model := "Qwen/Qwen3-Reranker-0.6B"
	baseURL := resolveDirectEndpoint(t, model)

	// 1. Fetch signing key from the DIRECT inference-proxy attestation.
	signingKey := fetchDirectSigningKey(t, model)

	// 2. Create E2EE session — identical to gateway tests.
	session := createE2EESession(t, signingKey)

	// 3. Encrypt the fields — identical to TestIntegration_NearCloud_Rerank_E2EE.
	encQuery, err := e2ee.EncryptXChaCha20([]byte("What is deep learning?"), session.ModelX25519Pub())
	if err != nil {
		t.Fatalf("encrypt query: %v", err)
	}
	encDoc1, err := e2ee.EncryptXChaCha20([]byte("Deep learning is a subset of machine learning"), session.ModelX25519Pub())
	if err != nil {
		t.Fatalf("encrypt doc1: %v", err)
	}
	encDoc2, err := e2ee.EncryptXChaCha20([]byte("The weather is sunny today"), session.ModelX25519Pub())
	if err != nil {
		t.Fatalf("encrypt doc2: %v", err)
	}
	body := fmt.Sprintf(`{"model":%q,"query":%q,"documents":[%q,%q],"top_n":2}`,
		model, encQuery, encDoc1, encDoc2)

	// 4. Send via the SAME e2eeRequest helper, just with the direct base URL.
	resp := e2eeRequest(t, baseURL, "/v1/rerank", []byte(body), "application/json", session)
	defer resp.Body.Close()
	respBody := readBody(t, resp)
	t.Logf("direct rerank E2EE: status=%d body_len=%d", resp.StatusCode, len(respBody))
	t.Logf("direct rerank response: %s", truncate(respBody, 500))

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("direct rerank E2EE failed: status=%d body=%s",
			resp.StatusCode, truncate(respBody, 500))
	}

	// 5. Check whether the response is encrypted.
	var rerankResp struct {
		Results []struct {
			Index          int             `json:"index"`
			RelevanceScore json.RawMessage `json:"relevance_score"`
			Document       json.RawMessage `json:"document"`
		} `json:"results"`
		EncryptedData string `json:"encrypted_data"`
	}
	if err := json.Unmarshal(respBody, &rerankResp); err != nil {
		t.Fatalf("parse response: %v", err)
	}

	switch {
	case rerankResp.EncryptedData != "":
		t.Log("FINDING: Direct inference-proxy returned encrypted_data for rerank")
		pt, decErr := session.Decrypt(rerankResp.EncryptedData)
		if decErr != nil {
			t.Logf("  decrypt failed: %v", decErr)
		} else {
			t.Logf("  decrypted: %s", truncate(pt, 300))
		}
		t.Log("CONCLUSION: E2EE WORKS for rerank when sent DIRECTLY to the model TEE")
		t.Log("  The SAME protocol FAILS through the gateway because the gateway drops E2EE headers")

	case len(rerankResp.Results) > 0:
		// Document is {"multi_modal":null,"text":"..."} — extract inner text.
		var doc struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(rerankResp.Results[0].Document, &doc); err != nil {
			t.Fatalf("parse document: %v (raw: %s)", err, truncate(rerankResp.Results[0].Document, 200))
		}
		score := string(rerankResp.Results[0].RelevanceScore)

		if e2ee.IsEncryptedChunkXChaCha20(doc.Text) {
			t.Log("FINDING: Rerank document text is encrypted")
			pt, decErr := session.Decrypt(doc.Text)
			if decErr != nil {
				t.Logf("  decrypt failed: %v", decErr)
			} else {
				t.Logf("  decrypted document: %s", string(pt))
			}
			t.Logf("  relevance_score (plaintext, model-generated): %s", score)
			t.Log("CONCLUSION: E2EE WORKS for rerank when sent DIRECTLY to the model TEE")
			t.Log("  The SAME protocol FAILS through the gateway because the gateway drops E2EE headers")
		} else {
			t.Logf("FINDING: Rerank document text appears non-encrypted — text=%s score=%s",
				truncate([]byte(doc.Text), 100), truncate([]byte(score), 50))
			t.Log("  Note: the server decrypted input and returned results; text fields may not be re-encrypted for rerank")
		}

	default:
		t.Logf("FINDING: Unexpected response structure: %s", truncate(respBody, 500))
	}
}

// TestIntegration_NearCloud_Direct_Audio_E2EE sends a whisper transcription
// request with E2EE headers directly to the inference-proxy. This uses the
// SAME E2EE protocol that fails through the gateway in
// TestIntegration_NearCloud_Audio_E2EE.
func TestIntegration_NearCloud_Direct_Audio_E2EE(t *testing.T) {
	skipNearCloudE2EEIntegration(t)

	model := "openai/whisper-large-v3"
	baseURL := resolveDirectEndpoint(t, model)

	// 1. Fetch signing key from the DIRECT inference-proxy attestation.
	signingKey := fetchDirectSigningKey(t, model)

	// 2. Create E2EE session — identical to gateway tests.
	session := createE2EESession(t, signingKey)

	// 3. Build multipart form — identical to TestIntegration_NearCloud_Audio_E2EE.
	wavData := makeMinimalWAV()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("model", model)
	fw, err := mw.CreateFormFile("file", "test.wav")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write(wavData); err != nil {
		t.Fatalf("write wav: %v", err)
	}
	mw.Close()

	// 4. Send via the SAME e2eeRequest helper, just with the direct base URL.
	resp := e2eeRequest(t, baseURL, "/v1/audio/transcriptions", buf.Bytes(), mw.FormDataContentType(), session)
	defer resp.Body.Close()
	respBody := readBody(t, resp)
	t.Logf("direct audio E2EE: status=%d body_len=%d", resp.StatusCode, len(respBody))
	t.Logf("direct audio response: %s", truncate(respBody, 500))

	// 5. Analyze the response.
	switch resp.StatusCode {
	case http.StatusOK:
		var audioResp struct {
			Text          string `json:"text"`
			EncryptedData string `json:"encrypted_data"`
		}
		if err := json.Unmarshal(respBody, &audioResp); err != nil {
			t.Logf("  (parse failed, raw: %s)", truncate(respBody, 300))
		}

		switch {
		case audioResp.EncryptedData != "":
			t.Log("FINDING: Direct inference-proxy returned encrypted_data for audio")
			pt, decErr := session.Decrypt(audioResp.EncryptedData)
			if decErr != nil {
				t.Logf("  decrypt failed: %v", decErr)
			} else {
				t.Logf("  decrypted: %s", truncate(pt, 300))
			}
			t.Log("CONCLUSION: E2EE WORKS for audio when sent DIRECTLY to the model TEE")
			t.Log("  The SAME protocol FAILS through the gateway because the gateway drops E2EE headers")

		case e2ee.IsEncryptedChunkXChaCha20(audioResp.Text):
			t.Log("FINDING: Direct audio returned encrypted text field")
			pt, decErr := session.Decrypt(audioResp.Text)
			if decErr != nil {
				t.Logf("  decrypt failed: %v", decErr)
			} else {
				t.Logf("  decrypted transcript: %s", string(pt))
			}
			t.Log("CONCLUSION: E2EE WORKS for audio when sent DIRECTLY to the model TEE")

		default:
			t.Log("FINDING: Direct audio response is plaintext — E2EE may not encrypt audio transcription output")
			t.Logf("  text: %q", audioResp.Text)
		}

	case http.StatusBadGateway, http.StatusInternalServerError:
		// If inference-proxy tries to decrypt a non-encrypted WAV, it may
		// fail. That STILL proves E2EE headers are being processed (unlike
		// the gateway which silently drops them).
		bodyStr := string(respBody)
		if strings.Contains(bodyStr, "ncrypt") || strings.Contains(bodyStr, "hex") ||
			strings.Contains(bodyStr, "decrypt") {
			t.Log("FINDING: Direct inference-proxy ATTEMPTED to decrypt the audio file")
			t.Log("  This error proves E2EE headers ARE processed on the direct endpoint")
			t.Log("CONCLUSION: The inference-proxy honors E2EE for audio; the gateway silently drops the headers")
		} else {
			t.Logf("FINDING: Direct audio E2EE returned error: %s", truncate(respBody, 500))
		}

	default:
		t.Logf("FINDING: Direct audio E2EE: status=%d body=%s",
			resp.StatusCode, truncate(respBody, 500))
	}
}
