package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// --------------------------------------------------------------------------
// safePrefix
// --------------------------------------------------------------------------

func TestSafePrefix(t *testing.T) {
	tests := []struct {
		s    string
		n    int
		want string
	}{
		{"hello", 3, "hel"},
		{"hi", 5, "hi"},
		{"", 3, ""},
		{"abcdef", 6, "abcdef"},
	}
	for _, tc := range tests {
		if got := safePrefix(tc.s, tc.n); got != tc.want {
			t.Errorf("safePrefix(%q, %d) = %q, want %q", tc.s, tc.n, got, tc.want)
		}
	}
}

// --------------------------------------------------------------------------
// testE2EE early-exit paths
// --------------------------------------------------------------------------

func TestTestE2EE_SkipNonE2EEProvider(t *testing.T) {
	raw := &attestation.RawAttestation{SigningKey: "04aabb"}
	cp := &config.Provider{APIKey: "key"}
	got := testE2EE(context.Background(), raw, "nanogpt", cp, "model", false)
	if got != nil {
		t.Errorf("testE2EE for nanogpt should return nil, got %+v", got)
	}
}

func TestTestE2EE_SkipNoSigningKey(t *testing.T) {
	raw := &attestation.RawAttestation{SigningKey: ""}
	cp := &config.Provider{APIKey: "key"}
	got := testE2EE(context.Background(), raw, "venice", cp, "model", false)
	if got != nil {
		t.Errorf("testE2EE with no signing key should return nil, got %+v", got)
	}
}

func TestTestE2EE_SkipOffline(t *testing.T) {
	raw := &attestation.RawAttestation{SigningKey: "04aabb"}
	cp := &config.Provider{APIKey: "key"}
	got := testE2EE(context.Background(), raw, "venice", cp, "model", true)
	if got == nil {
		t.Fatal("testE2EE in offline mode should return non-nil result")
	}
	if got.Attempted {
		t.Error("should not be Attempted in offline mode")
	}
	if got.Detail == "" {
		t.Error("should have Detail explaining offline skip")
	}
}

func TestTestE2EE_NoAPIKey(t *testing.T) {
	raw := &attestation.RawAttestation{SigningKey: "04aabb"}
	cp := &config.Provider{APIKey: ""}
	got := testE2EE(context.Background(), raw, "venice", cp, "model", false)
	if got == nil {
		t.Fatal("testE2EE with no API key should return non-nil result")
	}
	if !got.NoAPIKey {
		t.Error("NoAPIKey should be true")
	}
	if got.APIKeyEnv != "VENICE_API_KEY" {
		t.Errorf("APIKeyEnv = %q, want %q", got.APIKeyEnv, "VENICE_API_KEY")
	}
}

// --------------------------------------------------------------------------
// testE2EEChutes early-exit paths
// --------------------------------------------------------------------------

func TestTestE2EEChutes_MissingInstanceID(t *testing.T) {
	raw := &attestation.RawAttestation{
		SigningKey: "dGVzdA==",
		InstanceID: "",
		E2ENonce:   "nonce-token",
	}
	cp := &config.Provider{APIKey: "key", BaseURL: "https://example.com"}
	got := testE2EEChutes(context.Background(), raw, cp, "model")
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if !got.Attempted {
		t.Error("Attempted should be true")
	}
	if got.Err == nil {
		t.Fatal("expected error for missing instance_id")
	}
	if !strings.Contains(got.Err.Error(), "instance_id") {
		t.Errorf("error should mention instance_id, got: %v", got.Err)
	}
}

func TestTestE2EEChutes_MissingE2ENonce(t *testing.T) {
	raw := &attestation.RawAttestation{
		SigningKey: "dGVzdA==",
		InstanceID: "inst-1",
		E2ENonce:   "",
	}
	cp := &config.Provider{APIKey: "key", BaseURL: "https://example.com"}
	got := testE2EEChutes(context.Background(), raw, cp, "model")
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got.Err == nil {
		t.Fatal("expected error for missing e2e_nonce")
	}
	if !strings.Contains(got.Err.Error(), "e2e_nonce") {
		t.Errorf("error should mention e2e_nonce, got: %v", got.Err)
	}
}

func TestTestE2EEChutes_MissingChuteID(t *testing.T) {
	raw := &attestation.RawAttestation{
		SigningKey: "dGVzdA==",
		InstanceID: "inst-1",
		E2ENonce:   "nonce-token",
		ChuteID:    "",
	}
	cp := &config.Provider{APIKey: "key", BaseURL: "https://example.com"}
	got := testE2EEChutes(context.Background(), raw, cp, "human-readable-model-name")
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got.Err == nil {
		t.Fatal("expected error for missing chute_id")
	}
	if !strings.Contains(got.Err.Error(), "chute_id") {
		t.Errorf("error should mention chute_id, got: %v", got.Err)
	}
}

// --------------------------------------------------------------------------
// doE2EEChutesStreamTest
// --------------------------------------------------------------------------

func TestDoE2EEChutesStreamTest(t *testing.T) {
	// Generate a server-side ML-KEM-768 key pair.
	serverDecap, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("generate ML-KEM key: %v", err)
	}
	serverEncap := serverDecap.EncapsulationKey()
	serverPubB64 := base64.StdEncoding.EncodeToString(serverEncap.Bytes())

	// Build encrypted request body to get the client session.
	body, _ := json.Marshal(map[string]any{
		"model":    "test-model",
		"messages": []map[string]string{{"role": "user", "content": "Say hello"}},
		"stream":   true,
	})
	_, session, err := e2ee.EncryptChatRequestChutes(body, serverPubB64)
	if err != nil {
		t.Fatalf("EncryptChatRequestChutes: %v", err)
	}
	defer session.Zero()

	// Simulate server-side stream: KEM encapsulate against client's pub key,
	// derive stream key, encrypt chunks.
	clientPubB64 := session.MLKEMClientPubKeyBase64()
	clientPubBytes, _ := base64.StdEncoding.DecodeString(clientPubB64)
	clientEncapKey, err := mlkem.NewEncapsulationKey768(clientPubBytes)
	if err != nil {
		t.Fatalf("parse client encap key: %v", err)
	}

	sharedSecret, kemCt := clientEncapKey.Encapsulate()
	streamKey := deriveStreamKeyForTest(t, sharedSecret, kemCt)
	kemCtB64 := base64.StdEncoding.EncodeToString(kemCt)

	// Encrypt two JSON chunks.
	chunk1 := `{"choices":[{"delta":{"content":"Hello"}}]}`
	chunk2 := `{"choices":[{"delta":{"content":"!"}}]}`
	enc1 := encryptChunkForTest(t, []byte(chunk1), streamKey)
	enc2 := encryptChunkForTest(t, []byte(chunk2), streamKey)

	// Build mock SSE response.
	initEvent, _ := json.Marshal(map[string]string{"e2e_init": kemCtB64})
	e2e1, _ := json.Marshal(map[string]string{"e2e": base64.StdEncoding.EncodeToString(enc1)})
	e2e2, _ := json.Marshal(map[string]string{"e2e": base64.StdEncoding.EncodeToString(enc2)})

	sseBody := fmt.Sprintf("data: %s\n\ndata: %s\n\ndata: %s\n\ndata: [DONE]\n\n",
		initEvent, e2e1, e2e2)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEChutesStreamTest(req, session)
	if result.Err != nil {
		t.Fatalf("doE2EEChutesStreamTest error: %v", result.Err)
	}
	if !result.Attempted {
		t.Error("Attempted should be true")
	}
	if !strings.Contains(result.Detail, "2 encrypted chunks") {
		t.Errorf("Detail should mention 2 encrypted chunks, got: %s", result.Detail)
	}
}

func TestDoE2EEChutesStreamTest_NoE2EInit(t *testing.T) {
	e2eEvent, _ := json.Marshal(map[string]string{"e2e": base64.StdEncoding.EncodeToString([]byte("garbage"))})
	sseBody := fmt.Sprintf("data: %s\n\ndata: [DONE]\n\n", e2eEvent)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer ts.Close()

	session, _ := e2ee.NewChutesSession()
	defer session.Zero()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEChutesStreamTest(req, session)
	if result.Err == nil {
		t.Fatal("expected error for e2e event before e2e_init")
	}
	if !strings.Contains(result.Err.Error(), "before e2e_init") {
		t.Errorf("error should mention missing e2e_init, got: %v", result.Err)
	}
}

func TestDoE2EEChutesStreamTest_E2EError(t *testing.T) {
	errEvent, _ := json.Marshal(map[string]string{"e2e_error": "nonce expired"})
	sseBody := fmt.Sprintf("data: %s\n\ndata: [DONE]\n\n", errEvent)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer ts.Close()

	session, _ := e2ee.NewChutesSession()
	defer session.Zero()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEChutesStreamTest(req, session)
	if result.Err == nil {
		t.Fatal("expected error for e2e_error event")
	}
	if !strings.Contains(result.Err.Error(), "e2e_error") {
		t.Errorf("error should mention e2e_error, got: %v", result.Err)
	}
}

func TestDoE2EEChutesStreamTest_HTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer ts.Close()

	session, _ := e2ee.NewChutesSession()
	defer session.Zero()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEChutesStreamTest(req, session)
	if result.Err == nil {
		t.Fatal("expected error for HTTP 401")
	}
	if !strings.Contains(result.Err.Error(), "401") {
		t.Errorf("error should mention 401, got: %v", result.Err)
	}
}

// --------------------------------------------------------------------------
// doE2EEStreamTest
// --------------------------------------------------------------------------

// mockDecryptor is a test implementation of e2ee.Decryptor.
type mockDecryptor struct {
	encrypted bool
	decryptFn func(string) ([]byte, error)
}

func (m *mockDecryptor) IsEncryptedChunk(val string) bool { return m.encrypted }
func (m *mockDecryptor) Decrypt(val string) ([]byte, error) {
	if m.decryptFn != nil {
		return m.decryptFn(val)
	}
	return []byte("decrypted"), nil
}
func (m *mockDecryptor) Zero() {}

func TestDoE2EEStreamTest_HTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEStreamTest(req, &mockDecryptor{encrypted: true}, "venice")
	if result.Err == nil {
		t.Fatal("expected error for HTTP 401")
	}
	if !strings.Contains(result.Err.Error(), "401") {
		t.Errorf("error should mention 401, got: %v", result.Err)
	}
}

func TestDoE2EEStreamTest_FieldNotEncrypted(t *testing.T) {
	chunk := `{"choices":[{"delta":{"content":"plain-text"},"index":0,"finish_reason":null}]}`
	sseBody := "data: " + chunk + "\n\ndata: [DONE]\n\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEStreamTest(req, &mockDecryptor{encrypted: false}, "venice")
	if result.Err == nil {
		t.Fatal("expected error for non-encrypted field")
	}
	if !strings.Contains(result.Err.Error(), "not encrypted") {
		t.Errorf("error should mention 'not encrypted', got: %v", result.Err)
	}
}

func TestDoE2EEStreamTest_NoEncryptedFields(t *testing.T) {
	// Only NonEncryptedFields in delta → encryptedCount stays 0.
	chunk := `{"choices":[{"delta":{"role":"assistant"},"index":0}]}`
	sseBody := "data: " + chunk + "\n\ndata: [DONE]\n\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEStreamTest(req, &mockDecryptor{encrypted: true}, "venice")
	if result.Err == nil {
		t.Fatal("expected error when no encrypted content fields received")
	}
	if !strings.Contains(result.Err.Error(), "no encrypted content") {
		t.Errorf("error should mention 'no encrypted content', got: %v", result.Err)
	}
}

func TestDoE2EEStreamTest_Success(t *testing.T) {
	chunk := `{"choices":[{"delta":{"content":"encrypted-data"},"index":0,"finish_reason":null}]}`
	sseBody := "data: " + chunk + "\n\ndata: [DONE]\n\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEStreamTest(req, &mockDecryptor{encrypted: true}, "venice")
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if !result.Attempted {
		t.Error("Attempted should be true")
	}
	if !strings.Contains(result.Detail, "1 encrypted fields") {
		t.Errorf("Detail should mention encrypted fields, got: %s", result.Detail)
	}
}

// --------------------------------------------------------------------------
// testE2EEVenice / testE2EENearCloud — error path (invalid signing key)
// --------------------------------------------------------------------------

func TestTestE2EEVenice_InvalidSigningKey(t *testing.T) {
	raw := &attestation.RawAttestation{SigningKey: "not-a-valid-secp256k1-key"}
	cp := &config.Provider{APIKey: "key", BaseURL: "http://localhost"}
	got := testE2EE(context.Background(), raw, "venice", cp, "test-model", false)
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if !got.Attempted {
		t.Error("Attempted should be true")
	}
	if got.Err == nil {
		t.Error("expected error for invalid signing key")
	}
}

// TestTestE2EENeardirect_ResolveError tests the error path in testE2EENeardirect
// when the endpoint resolver fails (canceled context → immediate failure).
func TestTestE2EENeardirect_ResolveError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so resolver.Resolve fails

	raw := &attestation.RawAttestation{SigningKey: "04aabbcc"}
	cp := &config.Provider{APIKey: "key"}
	got := testE2EE(ctx, raw, "neardirect", cp, "nonexistent-model", false)
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if !got.Attempted {
		t.Error("Attempted should be true")
	}
	if got.Err == nil {
		t.Error("expected error from failed resolve")
	}
	t.Logf("testE2EENeardirect resolve error: %v", got.Err)
}

func TestTestE2EENearCloud_InvalidSigningKey(t *testing.T) {
	raw := &attestation.RawAttestation{SigningKey: "not-a-valid-ed25519-key"}
	cp := &config.Provider{APIKey: "key"}
	got := testE2EE(context.Background(), raw, "nearcloud", cp, "test-model", false)
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if !got.Attempted {
		t.Error("Attempted should be true")
	}
	if got.Err == nil {
		t.Error("expected error for invalid signing key")
	}
}

// --------------------------------------------------------------------------
// testE2EEVenice — HTTP error path with valid key
// --------------------------------------------------------------------------

func TestTestE2EEVenice_HTTPError(t *testing.T) {
	// Create a Venice session and use its own public key as the "model" key.
	// This is the pattern used in the e2ee package's own tests.
	session, err := e2ee.NewVeniceSession()
	if err != nil {
		t.Fatalf("NewVeniceSession: %v", err)
	}
	defer session.Zero()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer ts.Close()

	raw := &attestation.RawAttestation{SigningKey: session.ClientPubKeyHex()}
	cp := &config.Provider{APIKey: "key", BaseURL: ts.URL}
	got := testE2EEVenice(context.Background(), raw, cp, "test-model")
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if !got.Attempted {
		t.Error("Attempted should be true")
	}
	if got.Err == nil {
		t.Error("expected error from HTTP 401")
	}
	t.Logf("testE2EEVenice HTTP error: %v", got.Err)
}

// --------------------------------------------------------------------------
// testE2EENearAI — HTTP error path with valid Ed25519 key
// --------------------------------------------------------------------------

func TestTestE2EENearAI_HTTPError(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer ts.Close()

	raw := &attestation.RawAttestation{SigningKey: pubHex}
	cp := &config.Provider{APIKey: "key"}
	got := testE2EENearAI(context.Background(), raw, cp, "test-model", ts.URL, "nearcloud")
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if !got.Attempted {
		t.Error("Attempted should be true")
	}
	if got.Err == nil {
		t.Error("expected error from HTTP 401")
	}
	t.Logf("testE2EENearAI HTTP error: %v", got.Err)
}

// --------------------------------------------------------------------------
// testE2EEChutes — encrypt error path with invalid signing key
// --------------------------------------------------------------------------

func TestTestE2EEChutes_InvalidSigningKey(t *testing.T) {
	raw := &attestation.RawAttestation{
		SigningKey: "not-a-valid-mlkem-key",
		InstanceID: "inst-1",
		E2ENonce:   "nonce-token",
		ChuteID:    "chute-uuid",
	}
	cp := &config.Provider{APIKey: "key", BaseURL: "https://example.com"}
	got := testE2EEChutes(context.Background(), raw, cp, "model")
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if !got.Attempted {
		t.Error("Attempted should be true")
	}
	if got.Err == nil {
		t.Error("expected error for invalid signing key")
	}
	t.Logf("testE2EEChutes invalid key error: %v", got.Err)
}

func TestTestE2EEChutes_HTTPError(t *testing.T) {
	// Generate a valid ML-KEM-768 key to get past EncryptChatRequestChutes.
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768: %v", err)
	}
	serverPubB64 := base64.StdEncoding.EncodeToString(dk.EncapsulationKey().Bytes())

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer ts.Close()

	raw := &attestation.RawAttestation{
		SigningKey: serverPubB64,
		InstanceID: "inst-1",
		E2ENonce:   "nonce-token",
		ChuteID:    "chute-uuid",
	}
	cp := &config.Provider{APIKey: "key", BaseURL: ts.URL}
	got := testE2EEChutes(context.Background(), raw, cp, "model")
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if !got.Attempted {
		t.Error("Attempted should be true")
	}
	if got.Err == nil {
		t.Error("expected error from HTTP 401")
	}
	t.Logf("testE2EEChutes HTTP error: %v", got.Err)
}

// --------------------------------------------------------------------------
// Test helpers
// --------------------------------------------------------------------------

func deriveStreamKeyForTest(t *testing.T, sharedSecret, ciphertext []byte) []byte {
	t.Helper()
	salt := ciphertext[:16]
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte("e2e-stream-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	return key
}

func encryptChunkForTest(t *testing.T, plaintext, key []byte) []byte {
	t.Helper()
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("chacha20: %v", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("rand nonce: %v", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	wire := make([]byte, 0, len(nonce)+len(ct))
	wire = append(wire, nonce...)
	wire = append(wire, ct...)
	return wire
}
