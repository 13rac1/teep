package proxy_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	nearcloudpkg "github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/proxy"
)

// mockNearKeys holds the model's key material for the mock.
type mockNearKeys struct {
	edPub      ed25519.PublicKey
	edPubHex   string
	x25519Priv *ecdh.PrivateKey
}

// generateMockKeys creates a fresh Ed25519 keypair and derives the X25519
// private key for the mock model backend.
func generateMockKeys(t *testing.T) *mockNearKeys {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	h := sha512.Sum512(priv.Seed())
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	x25519Priv, err := ecdh.X25519().NewPrivateKey(h[:32])
	if err != nil {
		t.Fatalf("derive x25519 private key: %v", err)
	}
	return &mockNearKeys{
		edPub:      pub,
		edPubHex:   hex.EncodeToString(pub),
		x25519Priv: x25519Priv,
	}
}

// mockNearPinnedHandler implements provider.PinnedHandler with real NearCloud
// E2EE crypto. It receives plaintext bodies from the proxy, performs
// client-side encryption + server-side decryption, generates a mock response,
// encrypts it, and returns the session for proxy-side decryption.
type mockNearPinnedHandler struct {
	keys         *mockNearKeys
	providerName string // "nearcloud" or "neardirect"
	// responseFunc optionally overrides the default response generation.
	// Receives the decrypted request body and endpoint path, returns the
	// plaintext response body to encrypt.
	responseFunc func(body []byte, path string) string
}

func (m *mockNearPinnedHandler) HandlePinned(_ context.Context, req *provider.PinnedRequest) (*provider.PinnedResponse, error) {
	report := &attestation.VerificationReport{
		Provider: m.providerName,
		Model:    req.Model,
		Factors: []attestation.FactorResult{
			{Name: "nonce_match", Status: attestation.Pass, Detail: "match"},
			{Name: "tdx_reportdata_binding", Status: attestation.Pass, Detail: "binding ok"},
		},
	}

	if !req.E2EE {
		// Plaintext path: echo back a simple response.
		respBody := m.buildPlaintextResponse(req.Body, req.Path)
		return &provider.PinnedResponse{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(respBody)),
			Report:     report,
			SigningKey:  m.keys.edPubHex,
		}, nil
	}

	// E2EE path: encrypt the body (client side), decrypt it (server side),
	// generate response, encrypt it (server side), return with session.
	switch req.Path {
	case "/v1/chat/completions":
		return m.handleChatE2EE(req, report)
	case "/v1/images/generations":
		return m.handleImageE2EE(req, report)
	default:
		return nil, fmt.Errorf("mock %s: unsupported E2EE endpoint %q", m.providerName, req.Path)
	}
}

func (m *mockNearPinnedHandler) handleChatE2EE(req *provider.PinnedRequest, report *attestation.VerificationReport) (*provider.PinnedResponse, error) {
	// Client-side: encrypt the body and create a session.
	encBody, session, err := e2ee.EncryptChatMessagesNearCloud(req.Body, m.keys.edPubHex)
	if err != nil {
		return nil, fmt.Errorf("mock encrypt chat: %w", err)
	}

	// Server-side: decrypt messages to verify round-trip.
	decrypted, err := m.decryptChatBody(encBody)
	if err != nil {
		session.Zero()
		return nil, fmt.Errorf("mock server-side decrypt: %w", err)
	}

	// Generate response and encrypt it for the client.
	responsePlain := m.chatResponse(decrypted)
	responseSSE, err := m.encryptSSEResponse(responsePlain, session.ClientEd25519PubHex())
	if err != nil {
		session.Zero()
		return nil, fmt.Errorf("mock encrypt response: %w", err)
	}

	return &provider.PinnedResponse{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":     []string{"text/event-stream"},
			"X-Client-Pub-Key": []string{session.ClientEd25519PubHex()},
		},
		Body:       io.NopCloser(strings.NewReader(responseSSE)),
		Report:     report,
		SigningKey:  m.keys.edPubHex,
		Session:    session,
	}, nil
}

func (m *mockNearPinnedHandler) handleImageE2EE(req *provider.PinnedRequest, report *attestation.VerificationReport) (*provider.PinnedResponse, error) {
	// Client-side: encrypt the prompt and create a session.
	encBody, session, err := e2ee.EncryptImagePromptNearCloud(req.Body, m.keys.edPubHex)
	if err != nil {
		return nil, fmt.Errorf("mock encrypt image: %w", err)
	}

	// Server-side: decrypt prompt to verify round-trip.
	decryptedPrompt, err := m.decryptImageBody(encBody)
	if err != nil {
		session.Zero()
		return nil, fmt.Errorf("mock server-side decrypt image: %w", err)
	}

	// Generate encrypted image response.
	responseJSON, err := m.encryptImageResponse(decryptedPrompt, session.ClientEd25519PubHex())
	if err != nil {
		session.Zero()
		return nil, fmt.Errorf("mock encrypt image response: %w", err)
	}

	return &provider.PinnedResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(responseJSON)),
		Report:     report,
		SigningKey:  m.keys.edPubHex,
		Session:    session,
	}, nil
}

// decryptChatBody decrypts all message content fields from an encrypted chat body.
func (m *mockNearPinnedHandler) decryptChatBody(encBody []byte) ([]map[string]json.RawMessage, error) {
	var full map[string]json.RawMessage
	if err := json.Unmarshal(encBody, &full); err != nil {
		return nil, fmt.Errorf("parse encrypted body: %w", err)
	}

	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(full["messages"], &messages); err != nil {
		return nil, fmt.Errorf("parse messages: %w", err)
	}

	for i, msg := range messages {
		contentRaw, ok := msg["content"]
		if !ok || e2ee.IsJSONNull(contentRaw) {
			continue
		}
		var ctHex string
		if err := json.Unmarshal(contentRaw, &ctHex); err != nil {
			return nil, fmt.Errorf("message %d: parse encrypted content: %w", i, err)
		}
		plaintext, err := e2ee.DecryptXChaCha20(ctHex, m.keys.x25519Priv)
		if err != nil {
			return nil, fmt.Errorf("message %d: decrypt content: %w", i, err)
		}
		// Store decrypted content back as JSON string.
		ptJSON, err := json.Marshal(string(plaintext))
		if err != nil {
			return nil, fmt.Errorf("message %d: marshal decrypted content: %w", i, err)
		}
		msg["content"] = ptJSON
	}
	return messages, nil
}

// decryptImageBody decrypts the prompt field from an encrypted image body.
func (m *mockNearPinnedHandler) decryptImageBody(encBody []byte) (string, error) {
	var full map[string]json.RawMessage
	if err := json.Unmarshal(encBody, &full); err != nil {
		return "", fmt.Errorf("parse encrypted body: %w", err)
	}
	var ctHex string
	if err := json.Unmarshal(full["prompt"], &ctHex); err != nil {
		return "", fmt.Errorf("parse encrypted prompt: %w", err)
	}
	plaintext, err := e2ee.DecryptXChaCha20(ctHex, m.keys.x25519Priv)
	if err != nil {
		return "", fmt.Errorf("decrypt prompt: %w", err)
	}
	return string(plaintext), nil
}

// chatResponse generates a mock chat response from decrypted messages.
func (m *mockNearPinnedHandler) chatResponse(messages []map[string]json.RawMessage) string {
	// Extract the last user message content for the echo response.
	content := "echo"
	for i := len(messages) - 1; i >= 0; i-- {
		roleRaw, ok := messages[i]["role"]
		if !ok {
			continue
		}
		var role string
		if json.Unmarshal(roleRaw, &role) != nil || role != "user" {
			continue
		}
		contentRaw, ok := messages[i]["content"]
		if !ok || e2ee.IsJSONNull(contentRaw) {
			continue
		}
		var s string
		if json.Unmarshal(contentRaw, &s) == nil {
			content = "echo: " + s
		}
		break
	}
	return content
}

// encryptSSEResponse builds an SSE stream with one encrypted content chunk.
func (m *mockNearPinnedHandler) encryptSSEResponse(content, clientEdPubHex string) (string, error) {
	clientX25519, err := clientEdToX25519(clientEdPubHex)
	if err != nil {
		return "", err
	}
	encContent, err := e2ee.EncryptXChaCha20([]byte(content), clientX25519)
	if err != nil {
		return "", fmt.Errorf("encrypt response content: %w", err)
	}

	chunk := fmt.Sprintf(`{"id":"chatcmpl-mock","object":"chat.completion.chunk","created":1234567890,"model":"mock-model","choices":[{"index":0,"delta":{"role":"assistant","content":%q},"finish_reason":null}]}`, encContent)
	return fmt.Sprintf("data: %s\n\ndata: [DONE]\n\n", chunk), nil
}

// encryptImageResponse builds a non-streaming image response with encrypted b64_json.
func (m *mockNearPinnedHandler) encryptImageResponse(decryptedPrompt, clientEdPubHex string) (string, error) {
	clientX25519, err := clientEdToX25519(clientEdPubHex)
	if err != nil {
		return "", err
	}

	// Simulate image data as base64.
	fakeB64 := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
	encB64, err := e2ee.EncryptXChaCha20([]byte(fakeB64), clientX25519)
	if err != nil {
		return "", fmt.Errorf("encrypt b64_json: %w", err)
	}

	encPrompt, err := e2ee.EncryptXChaCha20([]byte(decryptedPrompt), clientX25519)
	if err != nil {
		return "", fmt.Errorf("encrypt revised_prompt: %w", err)
	}

	resp := fmt.Sprintf(`{"created":1234567890,"data":[{"b64_json":%q,"revised_prompt":%q}]}`, encB64, encPrompt)
	return resp, nil
}

// buildPlaintextResponse generates a simple JSON response for non-E2EE requests.
func (m *mockNearPinnedHandler) buildPlaintextResponse(body []byte, path string) string {
	if m.responseFunc != nil {
		return m.responseFunc(body, path)
	}
	switch path {
	case "/v1/images/generations":
		return `{"created":1234567890,"data":[{"b64_json":"dGVzdA==","revised_prompt":"a test image"}]}`
	default:
		return nonStreamResponse("ok")
	}
}

// clientEdToX25519 converts a client's Ed25519 public key hex to X25519.
func clientEdToX25519(edPubHex string) (*ecdh.PublicKey, error) {
	edPubBytes, err := hex.DecodeString(edPubHex)
	if err != nil {
		return nil, fmt.Errorf("decode client ed25519 pub hex: %w", err)
	}
	return e2ee.Ed25519PubToX25519(edPubBytes)
}

// newMockNearCloudProxyServer creates a proxy with a mock NearCloud
// PinnedHandler that uses real XChaCha20 E2EE crypto. Caches are primed
// with a passing attestation report and the model's signing key.
func newMockNearCloudProxyServer(t *testing.T, e2eeEnabled bool) *httptest.Server {
	t.Helper()

	keys := generateMockKeys(t)
	handler := &mockNearPinnedHandler{keys: keys, providerName: "nearcloud"}

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"nearcloud": {
				Name:    "nearcloud",
				BaseURL: "https://api.near.ai",
				APIKey:  "test-key",
				E2EE:    e2eeEnabled,
			},
		},
		AllowFail: attestation.KnownFactors,
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	prov := srv.ProviderByName("nearcloud")
	prov.PinnedHandler = handler
	prov.E2EE = e2eeEnabled

	// Prime caches so the proxy doesn't try real attestation.
	passingReport := &attestation.VerificationReport{
		Provider: "nearcloud",
		Model:    "test-model",
		Factors: []attestation.FactorResult{
			{Name: "nonce_match", Status: attestation.Pass, Detail: "match"},
			{Name: "tdx_reportdata_binding", Status: attestation.Pass, Detail: "binding ok"},
		},
	}
	srv.PutAttestationCache("nearcloud", "test-model", passingReport)
	if e2eeEnabled {
		srv.PutSigningKeyCache("nearcloud", "test-model", keys.edPubHex)
	}

	return httptest.NewServer(srv)
}

// newMockNeardirectE2EEServer creates a proxy with a mock neardirect
// PinnedHandler that uses real XChaCha20 E2EE crypto. The neardirect
// provider is wired with all 5 endpoint paths and E2EE enabled.
func newMockNeardirectE2EEServer(t *testing.T, e2eeEnabled bool) *httptest.Server {
	t.Helper()

	keys := generateMockKeys(t)
	handler := &mockNearPinnedHandler{keys: keys, providerName: "neardirect"}

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"neardirect": {
				Name:    "neardirect",
				BaseURL: "https://completions.near.ai",
				APIKey:  "test-key",
				E2EE:    e2eeEnabled,
			},
		},
		AllowFail: attestation.KnownFactors,
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	prov := srv.ProviderByName("neardirect")
	prov.PinnedHandler = handler
	prov.E2EE = e2eeEnabled
	if e2eeEnabled {
		prov.Encryptor = nearcloudpkg.NewE2EE()
	}

	// Prime caches so the proxy doesn't try real attestation.
	passingReport := &attestation.VerificationReport{
		Provider: "neardirect",
		Model:    "test-model",
		Factors: []attestation.FactorResult{
			{Name: "nonce_match", Status: attestation.Pass, Detail: "match"},
			{Name: "tdx_reportdata_binding", Status: attestation.Pass, Detail: "binding ok"},
		},
	}
	srv.PutAttestationCache("neardirect", "test-model", passingReport)
	if e2eeEnabled {
		srv.PutSigningKeyCache("neardirect", "test-model", keys.edPubHex)
	}

	return httptest.NewServer(srv)
}
