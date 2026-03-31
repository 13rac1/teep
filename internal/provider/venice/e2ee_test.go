package venice_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/venice"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func modelPubKeyHex(t *testing.T) string {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate model key: %v", err)
	}
	return hex.EncodeToString(priv.PubKey().SerializeUncompressed())
}

func chatBody(t *testing.T) []byte {
	t.Helper()
	body := map[string]any{
		"model": "venice-model",
		"messages": []map[string]string{
			{"role": "user", "content": "Hello"},
			{"role": "assistant", "content": "Hi there"},
		},
		"stream": false,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal chat body: %v", err)
	}
	return b
}

func TestVeniceE2EE_EncryptRequest(t *testing.T) {
	pubHex := modelPubKeyHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}

	enc := venice.NewE2EE()
	encBody, decryptor, chutesE2EE, err := enc.EncryptRequest(chatBody(t), raw)
	if err != nil {
		t.Fatalf("EncryptRequest: %v", err)
	}
	defer decryptor.Zero()

	if decryptor == nil {
		t.Fatal("expected non-nil Decryptor")
	}
	if chutesE2EE != nil {
		t.Fatal("expected nil ChutesE2EE for Venice")
	}

	// Verify output JSON structure.
	var out map[string]json.RawMessage
	if err := json.Unmarshal(encBody, &out); err != nil {
		t.Fatalf("unmarshal encrypted body: %v", err)
	}
	t.Logf("encrypted body keys: %v", mapKeys(out))

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
		t.Logf("message[%d]: role=%q content_len=%d content_prefix=%q", i, msg.Role, len(msg.Content), safePrefix(msg.Content, 20))

		// Content should be hex-encoded encrypted data, not plaintext.
		if msg.Content == "Hello" || msg.Content == "Hi there" {
			t.Errorf("message[%d]: content appears unencrypted: %q", i, msg.Content)
		}
		// Venice encrypted chunks are hex strings starting with "04" and length >= 186.
		if len(msg.Content) < 186 {
			t.Errorf("message[%d]: content too short for encrypted chunk: len=%d", i, len(msg.Content))
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

func TestVeniceE2EE_EncryptRequest_InvalidSigningKey(t *testing.T) {
	raw := &attestation.RawAttestation{SigningKey: "not-a-valid-key"}
	enc := venice.NewE2EE()
	_, _, _, err := enc.EncryptRequest(chatBody(t), raw)
	if err == nil {
		t.Fatal("expected error for invalid signing key")
	}
	t.Logf("error (expected): %v", err)
}

func TestVeniceE2EE_EncryptRequest_InvalidBody(t *testing.T) {
	pubHex := modelPubKeyHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}
	enc := venice.NewE2EE()
	_, _, _, err := enc.EncryptRequest([]byte("not json"), raw)
	if err == nil {
		t.Fatal("expected error for invalid body")
	}
	t.Logf("error (expected): %v", err)
}

func TestVeniceE2EE_EncryptRequest_InvalidMessages(t *testing.T) {
	pubHex := modelPubKeyHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}
	enc := venice.NewE2EE()
	body := []byte(`{"model":"m","messages":"not-an-array"}`)
	_, _, _, err := enc.EncryptRequest(body, raw)
	if err == nil {
		t.Fatal("expected error for invalid messages")
	}
	t.Logf("error (expected): %v", err)
}

func mapKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
