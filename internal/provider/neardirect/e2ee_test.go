package neardirect_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

func ed25519ModelPubHex(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return hex.EncodeToString(pub)
}

func nearE2EEChatBody(t *testing.T) []byte {
	t.Helper()
	body := map[string]any{
		"model":    "test-model",
		"messages": []map[string]string{{"role": "user", "content": "Hello"}, {"role": "assistant", "content": "Hi"}},
		"stream":   false,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestE2EE_EncryptRequest(t *testing.T) {
	pubHex := ed25519ModelPubHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}

	enc := neardirect.NewE2EE()
	encBody, decryptor, chutesE2EE, err := enc.EncryptRequest(nearE2EEChatBody(t), raw, "/v1/chat/completions")
	if err != nil {
		t.Fatalf("EncryptRequest: %v", err)
	}
	defer decryptor.Zero()

	if decryptor == nil {
		t.Fatal("expected non-nil Decryptor")
	}
	if chutesE2EE != nil {
		t.Error("expected nil ChutesE2EE for NEAR AI")
	}

	t.Logf("encrypted body length: %d", len(encBody))

	// Parse and verify structure.
	var out map[string]json.RawMessage
	if err := json.Unmarshal(encBody, &out); err != nil {
		t.Fatalf("unmarshal encrypted body: %v", err)
	}

	// stream must be forced to true.
	var stream bool
	if err := json.Unmarshal(out["stream"], &stream); err != nil {
		t.Fatalf("unmarshal stream: %v", err)
	}
	if !stream {
		t.Error("expected stream=true in encrypted body")
	}

	// Messages must be encrypted.
	var messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(out["messages"], &messages); err != nil {
		t.Fatalf("unmarshal messages: %v", err)
	}
	if len(messages) != 2 {
		t.Fatalf("message count = %d, want 2", len(messages))
	}

	for i, msg := range messages {
		t.Logf("message[%d]: role=%q content_len=%d", i, msg.Role, len(msg.Content))

		if msg.Content == "Hello" || msg.Content == "Hi" {
			t.Errorf("message[%d]: content appears unencrypted: %q", i, msg.Content)
		}
		if !e2ee.IsEncryptedChunkXChaCha20(msg.Content) {
			t.Errorf("message[%d]: content does not look like XChaCha20 encrypted chunk", i)
		}
	}

	// Roles must be preserved.
	if messages[0].Role != "user" {
		t.Errorf("messages[0].Role = %q, want user", messages[0].Role)
	}
	if messages[1].Role != "assistant" {
		t.Errorf("messages[1].Role = %q, want assistant", messages[1].Role)
	}
}

func TestE2EE_EncryptRequest_InvalidSigningKey(t *testing.T) {
	raw := &attestation.RawAttestation{SigningKey: "bad-key"}
	enc := neardirect.NewE2EE()
	_, _, _, err := enc.EncryptRequest(nearE2EEChatBody(t), raw, "/v1/chat/completions")
	t.Logf("invalid signing key error: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid signing key")
	}
}

func TestE2EE_EncryptRequest_InvalidBody(t *testing.T) {
	pubHex := ed25519ModelPubHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}
	enc := neardirect.NewE2EE()
	_, _, _, err := enc.EncryptRequest([]byte("not json"), raw, "/v1/chat/completions")
	t.Logf("invalid body error: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid body")
	}
}

func TestE2EE_EncryptRequest_InvalidMessages(t *testing.T) {
	pubHex := ed25519ModelPubHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}
	enc := neardirect.NewE2EE()
	_, _, _, err := enc.EncryptRequest([]byte(`{"model":"m","messages":"not-an-array"}`), raw, "/v1/chat/completions")
	t.Logf("invalid messages error: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid messages")
	}
}

func nearE2EEImageBody(t *testing.T) []byte {
	t.Helper()
	body := map[string]any{
		"model":  "flux-model",
		"prompt": "A beautiful sunset over the ocean",
		"n":      1,
		"size":   "1024x1024",
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestE2EE_EncryptRequest_Images(t *testing.T) {
	pubHex := ed25519ModelPubHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}

	enc := neardirect.NewE2EE()
	encBody, decryptor, chutesE2EE, err := enc.EncryptRequest(nearE2EEImageBody(t), raw, "/v1/images/generations")
	if err != nil {
		t.Fatalf("EncryptRequest images: %v", err)
	}
	defer decryptor.Zero()

	if decryptor == nil {
		t.Fatal("expected non-nil Decryptor")
	}
	if chutesE2EE != nil {
		t.Error("expected nil ChutesE2EE for NEAR AI")
	}

	// Parse and verify structure.
	var out map[string]json.RawMessage
	if err := json.Unmarshal(encBody, &out); err != nil {
		t.Fatalf("unmarshal encrypted body: %v", err)
	}

	// Non-prompt fields must be preserved.
	var model string
	if err := json.Unmarshal(out["model"], &model); err != nil {
		t.Fatalf("unmarshal model: %v", err)
	}
	if model != "flux-model" {
		t.Errorf("model = %q, want flux-model", model)
	}

	// Prompt must be encrypted.
	var prompt string
	if err := json.Unmarshal(out["prompt"], &prompt); err != nil {
		t.Fatalf("unmarshal prompt: %v", err)
	}
	if prompt == "A beautiful sunset over the ocean" {
		t.Error("prompt appears unencrypted")
	}
	if !e2ee.IsEncryptedChunkXChaCha20(prompt) {
		t.Fatalf("prompt does not look encrypted: %q", e2ee.SafePrefix(prompt, 40))
	}
}

func TestE2EE_EncryptRequest_Embeddings(t *testing.T) {
	pubHex := ed25519ModelPubHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}
	enc := neardirect.NewE2EE()

	encBody, decryptor, _, err := enc.EncryptRequest([]byte(`{"model":"test-model","input":["alpha",42,"beta"]}`), raw, "/v1/embeddings")
	if err != nil {
		t.Fatalf("EncryptRequest embeddings: %v", err)
	}
	defer decryptor.Zero()

	var out struct {
		Input []json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(encBody, &out); err != nil {
		t.Fatalf("unmarshal encrypted embeddings body: %v", err)
	}
	if len(out.Input) != 3 {
		t.Fatalf("input length = %d, want 3", len(out.Input))
	}
	for _, idx := range []int{0, 2} {
		var value string
		if err := json.Unmarshal(out.Input[idx], &value); err != nil {
			t.Fatalf("unmarshal input[%d]: %v", idx, err)
		}
		if !e2ee.IsEncryptedChunkXChaCha20(value) {
			t.Fatalf("input[%d] does not look encrypted: %q", idx, value)
		}
	}
}

func TestE2EE_EncryptRequest_Rerank(t *testing.T) {
	pubHex := ed25519ModelPubHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}
	enc := neardirect.NewE2EE()

	encBody, decryptor, _, err := enc.EncryptRequest([]byte(`{"model":"test-model","query":"hello","documents":["doc1","doc2"]}`), raw, "/v1/rerank")
	if err != nil {
		t.Fatalf("EncryptRequest rerank: %v", err)
	}
	defer decryptor.Zero()

	var out struct {
		Query     string   `json:"query"`
		Documents []string `json:"documents"`
	}
	if err := json.Unmarshal(encBody, &out); err != nil {
		t.Fatalf("unmarshal encrypted rerank body: %v", err)
	}
	if !e2ee.IsEncryptedChunkXChaCha20(out.Query) {
		t.Fatalf("query does not look encrypted: %q", out.Query)
	}
	if len(out.Documents) != 2 {
		t.Fatalf("documents length = %d, want 2", len(out.Documents))
	}
	for i, doc := range out.Documents {
		if !e2ee.IsEncryptedChunkXChaCha20(doc) {
			t.Fatalf("documents[%d] does not look encrypted: %q", i, doc)
		}
	}
}

func TestE2EE_EncryptRequest_Score(t *testing.T) {
	pubHex := ed25519ModelPubHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}
	enc := neardirect.NewE2EE()

	encBody, decryptor, _, err := enc.EncryptRequest([]byte(`{"model":"test-model","text_1":"left text","text_2":"right text"}`), raw, "/v1/score")
	if err != nil {
		t.Fatalf("EncryptRequest score: %v", err)
	}
	defer decryptor.Zero()

	var out struct {
		Text1 string `json:"text_1"`
		Text2 string `json:"text_2"`
	}
	if err := json.Unmarshal(encBody, &out); err != nil {
		t.Fatalf("unmarshal encrypted score body: %v", err)
	}
	if !e2ee.IsEncryptedChunkXChaCha20(out.Text1) {
		t.Fatalf("text_1 does not look encrypted: %q", out.Text1)
	}
	if !e2ee.IsEncryptedChunkXChaCha20(out.Text2) {
		t.Fatalf("text_2 does not look encrypted: %q", out.Text2)
	}
}

func TestE2EE_EncryptRequest_UnsupportedEndpoint(t *testing.T) {
	pubHex := ed25519ModelPubHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}
	enc := neardirect.NewE2EE()

	unsupported := []string{
		"/v1/audio/transcriptions",
		"/unknown",
	}
	for _, ep := range unsupported {
		_, _, _, err := enc.EncryptRequest(nearE2EEChatBody(t), raw, ep)
		if err == nil {
			t.Errorf("expected error for unsupported endpoint %q, got nil", ep)
		}
	}
}
