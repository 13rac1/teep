package proxy_test

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/proxy"
	"github.com/13rac1/teep/internal/tlsct/testtls"
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

// mockNearUpstream serves TLS requests with real NearCloud
// E2EE crypto. It receives plaintext bodies from the proxy, performs
// client-side encryption + server-side decryption, generates a mock response,
// encrypts it, and returns the session for proxy-side decryption.
type mockNearUpstream struct {
	keys         *mockNearKeys
	providerName string // "nearcloud" or "neardirect"
	// responseFunc optionally overrides the default response generation.
	// Receives the decrypted request body and endpoint path, returns the
	// plaintext response body to encrypt.
	responseFunc func(body []byte, path string) string
}

func (m *mockNearUpstream) serve(w http.ResponseWriter, r *http.Request, encrypted bool) {
	if r.ProtoMajor != 2 {
		http.Error(w, "HTTP/2 required", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if !encrypted {
		_, _ = io.WriteString(w, m.buildPlaintextResponse(body, r.URL.Path))
		return
	}
	if r.Header.Get("X-Encrypt-All-Fields") != "true" || r.Header.Get("Connection") != "" {
		http.Error(w, "invalid encryption headers", http.StatusBadRequest)
		return
	}
	var response string
	switch r.URL.Path {
	case "/v1/chat/completions":
		var messages []map[string]json.RawMessage
		messages, err = m.decryptChatBody(body)
		if err == nil {
			response, err = m.encryptSSEResponse(m.chatResponse(messages), r.Header.Get("X-Client-Pub-Key"))
		}
		w.Header().Set("Content-Type", "text/event-stream")
	case "/v1/images/generations":
		var prompt string
		prompt, err = m.decryptImageBody(body)
		if err == nil {
			response, err = m.encryptImageResponse(prompt, r.Header.Get("X-Client-Pub-Key"))
		}
	default:
		http.Error(w, "unsupported encrypted test endpoint", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "test encryption failed", http.StatusInternalServerError)
		return
	}
	_, _ = io.WriteString(w, response)
}

func (m *mockNearUpstream) decryptChatBody(encBody []byte) ([]map[string]json.RawMessage, error) {
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
func (m *mockNearUpstream) decryptImageBody(encBody []byte) (string, error) {
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
func (m *mockNearUpstream) chatResponse(messages []map[string]json.RawMessage) string {
	// Extract the last user message content for the echo response.
	content := "echo"
	for i := range slices.Backward(messages) {
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
func (m *mockNearUpstream) encryptSSEResponse(content, clientEdPubHex string) (string, error) {
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
func (m *mockNearUpstream) encryptImageResponse(decryptedPrompt, clientEdPubHex string) (string, error) {
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
func (m *mockNearUpstream) buildPlaintextResponse(body []byte, path string) string {
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

func newMockNearCloudProxyServer(t *testing.T, authority *testtls.Authority, encrypted bool) *httptest.Server {
	t.Helper()
	return newMockNearHTTPServer(t, authority, "nearcloud", encrypted)
}

func newMockNeardirectE2EEServer(t *testing.T, authority *testtls.Authority, encrypted bool) *httptest.Server {
	t.Helper()
	return newMockNearHTTPServer(t, authority, "neardirect", encrypted)
}

func newMockNearHTTPServer(t *testing.T, authority *testtls.Authority, name string, encrypted bool) *httptest.Server {
	t.Helper()
	keys := generateMockKeys(t)
	handler := &mockNearUpstream{keys: keys, providerName: name}
	upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.serve(w, r, encrypted) }))
	t.Cleanup(upstream.Close)
	srv, err := proxy.New(&config.Config{Providers: map[string]*config.Provider{name: {Name: name, BaseURL: upstream.URL, APIKey: "test-key", E2EE: encrypted}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	prov := srv.ProviderByName(name)
	route, err := provider.NewResolvedRoute(upstream.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	prov.StaticRoute, prov.ResolveRoute, prov.BaseURL, prov.Attester = route, nil, route.BaseURL(), nil
	prov.Encryptor = neardirect.NewE2EE()
	fp := sha256.Sum256(upstream.Certificate().RawSubjectPublicKeyInfo)
	report := &attestation.VerificationReport{Provider: name, Model: "test-model", TLSAuthority: route.Authority(), TLSKeyFP: hex.EncodeToString(fp[:]), Factors: []attestation.FactorResult{{Name: attestation.FactorTEEReportData, Status: attestation.Pass}, {Name: attestation.FactorE2EEUsable, Status: attestation.Skip}}}
	if err := srv.PutAuthorizationForTest(t.Context(), name, "test-model", route, report, keys.edPubHex); err != nil {
		t.Fatal(err)
	}
	return authority.NewTLSServer(t, srv)
}
