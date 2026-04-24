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
	"errors"
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

// --------------------------------------------------------------------------
// testE2EE switch — chutes dispatch path (L52-53)
// --------------------------------------------------------------------------

// TestTestE2EE_ChutesDispatch exercises the "chutes" case in the testE2EE
// switch by supplying a valid signing key and API key but no instance_id, so
// testE2EEChutes returns an error immediately after being called.
func TestTestE2EE_ChutesDispatch(t *testing.T) {
	t.Logf("testing chutes case in testE2EE switch (L52-53)")
	raw := &attestation.RawAttestation{
		SigningKey: "dGVzdA==",
		InstanceID: "", // causes testE2EEChutes to fail fast
	}
	cp := &config.Provider{APIKey: "key", BaseURL: "https://example.com"}
	got := testE2EE(context.Background(), raw, "chutes", cp, "model", false)
	if got == nil {
		t.Fatal("expected non-nil result from chutes dispatch")
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
	t.Logf("chutes dispatch error: %v", got.Err)
}

// --------------------------------------------------------------------------
// doE2EEStreamTest — JSON parse error (L393-398)
// --------------------------------------------------------------------------

// TestDoE2EEStreamTest_JSONParseError exercises the JSON unmarshal error path
// (L393-398) by serving an SSE line that is not valid JSON.
func TestDoE2EEStreamTest_JSONParseError(t *testing.T) {
	t.Logf("testing JSON parse error in doE2EEStreamTest (L393-398)")
	sseBody := "data: not-valid-json\n\ndata: [DONE]\n\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEStreamTest(req, &mockDecryptor{encrypted: true}, "venice")
	if result.Err == nil {
		t.Fatal("expected error for invalid JSON SSE chunk")
	}
	t.Logf("JSON parse error: %v", result.Err)
}

// --------------------------------------------------------------------------
// doE2EEStreamTest — empty choices (L401-402)
// --------------------------------------------------------------------------

// TestDoE2EEStreamTest_EmptyChoices exercises the empty-choices continue path
// (L401-402): with no choices the chunk is skipped, encryptedCount stays 0,
// and the function returns "no encrypted content" at the end.
func TestDoE2EEStreamTest_EmptyChoices(t *testing.T) {
	t.Logf("testing empty choices path in doE2EEStreamTest (L401-402)")
	sseBody := `data: {"choices":[]}` + "\n\ndata: [DONE]\n\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEStreamTest(req, &mockDecryptor{encrypted: true}, "venice")
	if result.Err == nil {
		t.Fatal("expected error when all chunks have empty choices")
	}
	if !strings.Contains(result.Err.Error(), "no encrypted content") {
		t.Errorf("error should mention 'no encrypted content', got: %v", result.Err)
	}
	t.Logf("empty choices result: %v", result.Err)
}

// --------------------------------------------------------------------------
// doE2EEStreamTest — nil delta (L406-407)
// --------------------------------------------------------------------------

// TestDoE2EEStreamTest_NilDelta exercises the nil-delta continue path
// (L406-407): with a null delta the chunk is skipped, encryptedCount stays 0,
// and the function returns "no encrypted content" at the end.
func TestDoE2EEStreamTest_NilDelta(t *testing.T) {
	t.Logf("testing nil delta path in doE2EEStreamTest (L406-407)")
	sseBody := `data: {"choices":[{"delta":null}]}` + "\n\ndata: [DONE]\n\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEStreamTest(req, &mockDecryptor{encrypted: true}, "venice")
	if result.Err == nil {
		t.Fatal("expected error when all chunks have null delta")
	}
	if !strings.Contains(result.Err.Error(), "no encrypted content") {
		t.Errorf("error should mention 'no encrypted content', got: %v", result.Err)
	}
	t.Logf("nil delta result: %v", result.Err)
}

// --------------------------------------------------------------------------
// doE2EEStreamTest — non-map delta (L410-415)
// --------------------------------------------------------------------------

// TestDoE2EEStreamTest_NonMapDelta exercises the non-map-delta error path
// (L410-415): a delta that is a JSON number rather than an object causes the
// map[string]any type assertion to fail.
func TestDoE2EEStreamTest_NonMapDelta(t *testing.T) {
	t.Logf("testing non-map delta path in doE2EEStreamTest (L410-415)")
	sseBody := `data: {"choices":[{"delta":42}]}` + "\n\ndata: [DONE]\n\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEStreamTest(req, &mockDecryptor{encrypted: true}, "venice")
	if result.Err == nil {
		t.Fatal("expected error for non-map delta")
	}
	if !strings.Contains(result.Err.Error(), "delta") {
		t.Errorf("error should mention 'delta', got: %v", result.Err)
	}
	t.Logf("non-map delta error: %v", result.Err)
}

// --------------------------------------------------------------------------
// doE2EEStreamTest — decrypt error (L432-437)
// --------------------------------------------------------------------------

// TestDoE2EEStreamTest_DecryptError exercises the decrypt-failure path
// (L432-437): IsEncryptedChunk returns true so the field is treated as
// encrypted, but Decrypt returns an error.
func TestDoE2EEStreamTest_DecryptError(t *testing.T) {
	t.Logf("testing decrypt error path in doE2EEStreamTest (L432-437)")
	chunk := `{"choices":[{"delta":{"content":"encrypted-data"},"index":0}]}`
	sseBody := "data: " + chunk + "\n\ndata: [DONE]\n\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer ts.Close()

	dec := &mockDecryptor{
		encrypted: true,
		decryptFn: func(s string) ([]byte, error) {
			return nil, errors.New("simulated decrypt failure")
		},
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEStreamTest(req, dec, "venice")
	if result.Err == nil {
		t.Fatal("expected error from decrypt failure")
	}
	if !strings.Contains(result.Err.Error(), "decrypt") {
		t.Errorf("error should mention 'decrypt', got: %v", result.Err)
	}
	t.Logf("decrypt error: %v", result.Err)
}

// --------------------------------------------------------------------------
// doE2EEChutesStreamTest — no e2e_init event (L325-327)
// --------------------------------------------------------------------------

// TestDoE2EEChutesStreamTest_NoE2EInitEvent exercises the missing-e2e_init
// error path (L325-327): the stream ends with only [DONE], so streamKey stays
// nil and the function returns "no e2e_init event received".
func TestDoE2EEChutesStreamTest_NoE2EInitEvent(t *testing.T) {
	t.Logf("testing no e2e_init event path in doE2EEChutesStreamTest (L325-327)")
	sseBody := "data: [DONE]\n\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer ts.Close()

	session, err := e2ee.NewChutesSession()
	if err != nil {
		t.Fatalf("NewChutesSession: %v", err)
	}
	defer session.Zero()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEChutesStreamTest(req, session)
	if result.Err == nil {
		t.Fatal("expected error for missing e2e_init")
	}
	if !strings.Contains(result.Err.Error(), "no e2e_init event received") {
		t.Errorf("error should mention 'no e2e_init event received', got: %v", result.Err)
	}
	t.Logf("no e2e_init error: %v", result.Err)
}

// --------------------------------------------------------------------------
// doE2EEChutesStreamTest — e2e_init received but no encrypted chunks (L328-330)
// --------------------------------------------------------------------------

// TestDoE2EEChutesStreamTest_NoEncryptedChunks exercises the zero-decrypted-
// chunks error path (L328-330): the stream has a valid e2e_init event but no
// subsequent e2e events, so decryptedChunks stays 0.
func TestDoE2EEChutesStreamTest_NoEncryptedChunks(t *testing.T) {
	t.Logf("testing no encrypted chunks path in doE2EEChutesStreamTest (L328-330)")

	// Build a session so we can produce a valid e2e_init event.
	body, _ := json.Marshal(map[string]any{
		"model":    "test-model",
		"messages": []map[string]string{{"role": "user", "content": "Say hello"}},
		"stream":   true,
	})
	// We need a real server ML-KEM key to encrypt against.
	serverDecap, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("generate ML-KEM key: %v", err)
	}
	serverPubB64 := base64.StdEncoding.EncodeToString(serverDecap.EncapsulationKey().Bytes())

	_, session, err := e2ee.EncryptChatRequestChutes(body, serverPubB64)
	if err != nil {
		t.Fatalf("EncryptChatRequestChutes: %v", err)
	}
	defer session.Zero()

	// Build a valid e2e_init using the client's public key.
	clientPubBytes, _ := base64.StdEncoding.DecodeString(session.MLKEMClientPubKeyBase64())
	clientEncapKey, err := mlkem.NewEncapsulationKey768(clientPubBytes)
	if err != nil {
		t.Fatalf("parse client encap key: %v", err)
	}
	_, kemCt := clientEncapKey.Encapsulate()
	kemCtB64 := base64.StdEncoding.EncodeToString(kemCt)

	initEvent, _ := json.Marshal(map[string]string{"e2e_init": kemCtB64})
	// No e2e events — only the init and DONE.
	sseBody := fmt.Sprintf("data: %s\n\ndata: [DONE]\n\n", initEvent)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEChutesStreamTest(req, session)
	if result.Err == nil {
		t.Fatal("expected error for no encrypted chunks")
	}
	if !strings.Contains(result.Err.Error(), "no encrypted chunks") {
		t.Errorf("error should mention 'no encrypted chunks', got: %v", result.Err)
	}
	t.Logf("no encrypted chunks error: %v", result.Err)
}

// --------------------------------------------------------------------------
// doE2EEChutesStreamTest — usage event path (L317-318)
// --------------------------------------------------------------------------

// TestDoE2EEChutesStreamTest_WithUsageEvent exercises the usage-event counter
// path (L317-318): the stream includes a usage event alongside valid e2e_init
// and e2e events, and the final detail string mentions the cleartext usage event.
func TestDoE2EEChutesStreamTest_WithUsageEvent(t *testing.T) {
	t.Logf("testing usage event path in doE2EEChutesStreamTest (L317-318)")

	// Build a valid Chutes session.
	serverDecap, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("generate ML-KEM key: %v", err)
	}
	serverPubB64 := base64.StdEncoding.EncodeToString(serverDecap.EncapsulationKey().Bytes())

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

	// Simulate the server encapsulating against the client's public key.
	clientPubBytes, _ := base64.StdEncoding.DecodeString(session.MLKEMClientPubKeyBase64())
	clientEncapKey, err := mlkem.NewEncapsulationKey768(clientPubBytes)
	if err != nil {
		t.Fatalf("parse client encap key: %v", err)
	}
	sharedSecret, kemCt := clientEncapKey.Encapsulate()
	streamKey := deriveStreamKeyForTest(t, sharedSecret, kemCt)
	kemCtB64 := base64.StdEncoding.EncodeToString(kemCt)

	// Encrypt one chunk.
	enc := encryptChunkForTest(t, []byte(`{"choices":[{"delta":{"content":"Hi"}}]}`), streamKey)

	initEvent, _ := json.Marshal(map[string]string{"e2e_init": kemCtB64})
	e2eEvent, _ := json.Marshal(map[string]string{"e2e": base64.StdEncoding.EncodeToString(enc)})
	usageEvent, _ := json.Marshal(map[string]any{"usage": map[string]int{"prompt_tokens": 5, "completion_tokens": 3}})

	sseBody := fmt.Sprintf("data: %s\n\ndata: %s\n\ndata: %s\n\ndata: [DONE]\n\n",
		initEvent, e2eEvent, usageEvent)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEChutesStreamTest(req, session)
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if !result.Attempted {
		t.Error("Attempted should be true")
	}
	if !strings.Contains(result.Detail, "usage events") {
		t.Errorf("Detail should mention usage events, got: %s", result.Detail)
	}
	t.Logf("usage event result detail: %s", result.Detail)
}

// --------------------------------------------------------------------------
// doE2EEChutesStreamTest — malformed JSON SSE event (L270-275, 2 stmts)
// --------------------------------------------------------------------------

func TestDoE2EEChutesStreamTest_MalformedEvent(t *testing.T) {
	// Send malformed JSON that can't be parsed as the event struct.
	sseBody := "data: {not valid json\n\ndata: [DONE]\n\n"
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
	t.Logf("doE2EEChutesStreamTest(malformed event): err=%v", result.Err)
	if result.Err == nil {
		t.Fatal("expected error for malformed SSE event")
	}
	if !strings.Contains(result.Err.Error(), "parse SSE event") {
		t.Errorf("error should mention parse failure, got: %v", result.Err)
	}
}

// --------------------------------------------------------------------------
// doE2EEChutesStreamTest — bad e2e_init value (L282-284, 1 stmt)
// --------------------------------------------------------------------------

func TestDoE2EEChutesStreamTest_BadE2EInit(t *testing.T) {
	// Valid base64 but wrong size (ML-KEM-768 ciphertext is 1088 bytes).
	shortCT := base64.StdEncoding.EncodeToString([]byte("too short"))
	initEvent, _ := json.Marshal(map[string]string{"e2e_init": shortCT})
	sseBody := fmt.Sprintf("data: %s\n\ndata: [DONE]\n\n", initEvent)

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
	t.Logf("doE2EEChutesStreamTest(bad e2e_init): err=%v", result.Err)
	if result.Err == nil {
		t.Fatal("expected error for bad e2e_init")
	}
	if !strings.Contains(result.Err.Error(), "derive stream key") {
		t.Errorf("error should mention derive stream key, got: %v", result.Err)
	}
}

// --------------------------------------------------------------------------
// doE2EEChutesStreamTest — bad base64 in e2e field (L290-292, 1 stmt)
// --------------------------------------------------------------------------

func TestDoE2EEChutesStreamTest_InvalidBase64Chunk(t *testing.T) {
	// Set up proper server-side KEM for the e2e_init.
	serverDecap, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("generate ML-KEM key: %v", err)
	}
	serverEncap := serverDecap.EncapsulationKey()
	serverPubB64 := base64.StdEncoding.EncodeToString(serverEncap.Bytes())

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

	clientPubB64 := session.MLKEMClientPubKeyBase64()
	clientPubBytes, _ := base64.StdEncoding.DecodeString(clientPubB64)
	clientEncapKey, err := mlkem.NewEncapsulationKey768(clientPubBytes)
	if err != nil {
		t.Fatalf("parse client encap key: %v", err)
	}
	_, kemCt := clientEncapKey.Encapsulate()
	kemCtB64 := base64.StdEncoding.EncodeToString(kemCt)

	initEvent, _ := json.Marshal(map[string]string{"e2e_init": kemCtB64})
	// After valid init, send e2e with invalid base64.
	badChunkEvent, _ := json.Marshal(map[string]string{"e2e": "not-valid-base64!!"})
	sseBody := fmt.Sprintf("data: %s\n\ndata: %s\n\ndata: [DONE]\n\n", initEvent, badChunkEvent)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEChutesStreamTest(req, session)
	t.Logf("doE2EEChutesStreamTest(bad base64 chunk): err=%v", result.Err)
	if result.Err == nil {
		t.Fatal("expected error for bad base64 in e2e field")
	}
	if !strings.Contains(result.Err.Error(), "decode e2e chunk") {
		t.Errorf("error should mention decode failure, got: %v", result.Err)
	}
}

// --------------------------------------------------------------------------
// doE2EEChutesStreamTest — auth fail in e2e field (L294-296, 1 stmt)
// --------------------------------------------------------------------------

func TestDoE2EEChutesStreamTest_DecryptChunkFail(t *testing.T) {
	// Full KEM setup.
	serverDecap, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("generate ML-KEM key: %v", err)
	}
	serverEncap := serverDecap.EncapsulationKey()
	serverPubB64 := base64.StdEncoding.EncodeToString(serverEncap.Bytes())

	body, _ := json.Marshal(map[string]any{"model": "test", "messages": []map[string]string{{"role": "user", "content": "hi"}}, "stream": true})
	_, session, err := e2ee.EncryptChatRequestChutes(body, serverPubB64)
	if err != nil {
		t.Fatalf("EncryptChatRequestChutes: %v", err)
	}
	defer session.Zero()

	clientPubB64 := session.MLKEMClientPubKeyBase64()
	clientPubBytes, _ := base64.StdEncoding.DecodeString(clientPubB64)
	clientEncapKey, err := mlkem.NewEncapsulationKey768(clientPubBytes)
	if err != nil {
		t.Fatalf("parse client encap key: %v", err)
	}
	_, kemCt := clientEncapKey.Encapsulate()
	kemCtB64 := base64.StdEncoding.EncodeToString(kemCt)

	initEvent, _ := json.Marshal(map[string]string{"e2e_init": kemCtB64})
	// Valid base64 but garbage data that fails ChaCha20-Poly1305 authentication.
	// Must be >= 28 bytes (nonce(12)+tag(16)) to pass the length check.
	garbled := make([]byte, 40)
	garbledB64 := base64.StdEncoding.EncodeToString(garbled)
	badChunkEvent, _ := json.Marshal(map[string]string{"e2e": garbledB64})
	sseBody := fmt.Sprintf("data: %s\n\ndata: %s\n\ndata: [DONE]\n\n", initEvent, badChunkEvent)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseBody))
	}))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, http.NoBody)
	result := doE2EEChutesStreamTest(req, session)
	t.Logf("doE2EEChutesStreamTest(bad decrypt): err=%v", result.Err)
	if result.Err == nil {
		t.Fatal("expected error for bad e2e ciphertext")
	}
	if !strings.Contains(result.Err.Error(), "decrypt e2e chunk") {
		t.Errorf("error should mention decrypt failure, got: %v", result.Err)
	}
}
