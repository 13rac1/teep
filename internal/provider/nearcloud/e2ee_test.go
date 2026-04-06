package nearcloud_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider/nearcloud"
)

func ed25519ModelPubHex(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return hex.EncodeToString(pub)
}

func nearcloudChatBody(t *testing.T) []byte {
	t.Helper()
	body := map[string]any{
		"model":    "nearcloud-model",
		"messages": []map[string]string{{"role": "user", "content": "Hello"}, {"role": "assistant", "content": "Hi"}},
		"stream":   false,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestNearCloudE2EE_EncryptRequest(t *testing.T) {
	pubHex := ed25519ModelPubHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}

	enc := nearcloud.NewE2EE()
	encBody, decryptor, chutesE2EE, err := enc.EncryptRequest(nearcloudChatBody(t), raw, "/v1/chat/completions")
	if err != nil {
		t.Fatalf("EncryptRequest: %v", err)
	}
	defer decryptor.Zero()

	if decryptor == nil {
		t.Fatal("expected non-nil Decryptor")
	}
	if chutesE2EE != nil {
		t.Error("expected nil ChutesE2EE for NearCloud")
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

func TestNearCloudE2EE_EncryptRequest_InvalidSigningKey(t *testing.T) {
	raw := &attestation.RawAttestation{SigningKey: "bad-key"}
	enc := nearcloud.NewE2EE()
	_, _, _, err := enc.EncryptRequest(nearcloudChatBody(t), raw, "/v1/chat/completions")
	t.Logf("invalid signing key error: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid signing key")
	}
}

func TestNearCloudE2EE_EncryptRequest_InvalidBody(t *testing.T) {
	pubHex := ed25519ModelPubHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}
	enc := nearcloud.NewE2EE()
	_, _, _, err := enc.EncryptRequest([]byte("not json"), raw, "/v1/chat/completions")
	t.Logf("invalid body error: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid body")
	}
}

func TestNearCloudE2EE_EncryptRequest_InvalidMessages(t *testing.T) {
	pubHex := ed25519ModelPubHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}
	enc := nearcloud.NewE2EE()
	_, _, _, err := enc.EncryptRequest([]byte(`{"model":"m","messages":"not-an-array"}`), raw, "/v1/chat/completions")
	t.Logf("invalid messages error: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid messages")
	}
}

func nearcloudImageBody(t *testing.T) []byte {
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

func TestNearCloudE2EE_EncryptRequest_Images(t *testing.T) {
	pubHex := ed25519ModelPubHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}

	enc := nearcloud.NewE2EE()
	encBody, decryptor, chutesE2EE, err := enc.EncryptRequest(nearcloudImageBody(t), raw, "/v1/images/generations")
	if err != nil {
		t.Fatalf("EncryptRequest images: %v", err)
	}
	defer decryptor.Zero()

	if decryptor == nil {
		t.Fatal("expected non-nil Decryptor")
	}
	if chutesE2EE != nil {
		t.Error("expected nil ChutesE2EE for NearCloud")
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

func TestNearCloudE2EE_EncryptRequest_UnsupportedEndpoint(t *testing.T) {
	pubHex := ed25519ModelPubHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}
	enc := nearcloud.NewE2EE()

	unsupported := []string{
		"/v1/embeddings",
		"/v1/audio/transcriptions",
		"/v1/rerank",
		"/v1/scoring",
		"/unknown",
	}
	for _, ep := range unsupported {
		_, _, _, err := enc.EncryptRequest(nearcloudChatBody(t), raw, ep)
		if err == nil {
			t.Errorf("expected error for unsupported endpoint %q, got nil", ep)
		}
	}
}
