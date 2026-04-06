package venice_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
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
	encBody, decryptor, chutesE2EE, err := enc.EncryptRequest(chatBody(t), raw, "/v1/chat/completions")
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
	_, _, _, err := enc.EncryptRequest(chatBody(t), raw, "/v1/chat/completions")
	if err == nil {
		t.Fatal("expected error for invalid signing key")
	}
	t.Logf("error (expected): %v", err)
}

func TestVeniceE2EE_EncryptRequest_InvalidBody(t *testing.T) {
	pubHex := modelPubKeyHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}
	enc := venice.NewE2EE()
	_, _, _, err := enc.EncryptRequest([]byte("not json"), raw, "/v1/chat/completions")
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
	_, _, _, err := enc.EncryptRequest(body, raw, "/v1/chat/completions")
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

// modelKeyPair returns a secp256k1 key pair for testing — the public key hex
// for the attestation and the private key for decryption verification.
func modelKeyPair(t *testing.T) (pubHex string, priv *secp256k1.PrivateKey) {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate model key: %v", err)
	}
	return hex.EncodeToString(priv.PubKey().SerializeUncompressed()), priv
}

// TestVeniceE2EE_ToolCallConversation verifies that EncryptRequest preserves
// all message fields in a multi-turn tool calling conversation, including
// null content and tool_calls/tool_call_id fields.
func TestVeniceE2EE_ToolCallConversation(t *testing.T) {
	pubHex, modelPriv := modelKeyPair(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}

	body := []byte(`{
		"model": "venice-model",
		"messages": [
			{"role": "user", "content": "What is the weather in Paris?"},
			{"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{\"location\":\"Paris\"}"}}]},
			{"role": "tool", "tool_call_id": "call_1", "name": "get_weather", "content": "{\"temp\": 22}"},
			{"role": "assistant", "content": "The weather in Paris is 22 degrees."}
		],
		"tools": [{"type": "function", "function": {"name": "get_weather"}}],
		"stream": false
	}`)

	enc := venice.NewE2EE()
	encBody, decryptor, _, err := enc.EncryptRequest(body, raw, "/v1/chat/completions")
	if err != nil {
		t.Fatalf("EncryptRequest: %v", err)
	}
	defer decryptor.Zero()

	var out map[string]json.RawMessage
	if err := json.Unmarshal(encBody, &out); err != nil {
		t.Fatalf("unmarshal encrypted body: %v", err)
	}

	// tools must be preserved at top level.
	if _, ok := out["tools"]; !ok {
		t.Error("top-level 'tools' field was stripped")
	}

	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(out["messages"], &messages); err != nil {
		t.Fatalf("unmarshal messages: %v", err)
	}
	if len(messages) != 4 {
		t.Fatalf("message count = %d, want 4", len(messages))
	}

	// Message 0: user — content encrypted.
	assertRole(t, messages[0], "user")
	assertContentEncrypted(t, messages[0], "What is the weather in Paris?", modelPriv)

	// Message 1: assistant with null content + tool_calls preserved.
	assertRole(t, messages[1], "assistant")
	assertContentNull(t, messages[1])
	assertFieldPresent(t, messages[1], "tool_calls")

	// Message 2: tool — tool_call_id and name preserved, content encrypted.
	assertRole(t, messages[2], "tool")
	assertFieldPresent(t, messages[2], "tool_call_id")
	assertFieldPresent(t, messages[2], "name")
	assertContentEncrypted(t, messages[2], `{"temp": 22}`, modelPriv)

	// Message 3: assistant — content encrypted.
	assertRole(t, messages[3], "assistant")
	assertContentEncrypted(t, messages[3], "The weather in Paris is 22 degrees.", modelPriv)
}

// TestVeniceE2EE_PreservesExtraFields verifies that non-message fields
// (tools, temperature) and message-level fields (name) are preserved.
func TestVeniceE2EE_PreservesExtraFields(t *testing.T) {
	pubHex, _ := modelKeyPair(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}

	body := []byte(`{
		"model": "venice-model",
		"messages": [
			{"role": "system", "name": "instructor", "content": "You are helpful."},
			{"role": "user", "content": "Hello"}
		],
		"temperature": 0.7,
		"tools": [{"type": "function"}]
	}`)

	enc := venice.NewE2EE()
	encBody, decryptor, _, err := enc.EncryptRequest(body, raw, "/v1/chat/completions")
	if err != nil {
		t.Fatalf("EncryptRequest: %v", err)
	}
	defer decryptor.Zero()

	var out map[string]json.RawMessage
	if err := json.Unmarshal(encBody, &out); err != nil {
		t.Fatalf("unmarshal encrypted body: %v", err)
	}

	// Top-level fields preserved.
	for _, field := range []string{"model", "temperature", "tools"} {
		if _, ok := out[field]; !ok {
			t.Errorf("top-level field %q was stripped", field)
		}
	}

	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(out["messages"], &messages); err != nil {
		t.Fatalf("unmarshal messages: %v", err)
	}

	// Message-level "name" field preserved.
	assertFieldPresent(t, messages[0], "name")
	var name string
	if err := json.Unmarshal(messages[0]["name"], &name); err != nil {
		t.Fatalf("unmarshal name: %v", err)
	}
	if name != "instructor" {
		t.Errorf("name = %q, want instructor", name)
	}
}

// TestVeniceE2EE_NullContentVariants verifies that messages with explicit null
// and absent content both pass through without error.
func TestVeniceE2EE_NullContentVariants(t *testing.T) {
	pubHex, _ := modelKeyPair(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}

	t.Run("explicit null", func(t *testing.T) {
		body := []byte(`{"model":"m","messages":[{"role":"assistant","content":null}]}`)
		enc := venice.NewE2EE()
		_, decryptor, _, err := enc.EncryptRequest(body, raw, "/v1/chat/completions")
		if err != nil {
			t.Fatalf("EncryptRequest with null content: %v", err)
		}
		decryptor.Zero()
	})

	t.Run("absent content", func(t *testing.T) {
		body := []byte(`{"model":"m","messages":[{"role":"assistant"}]}`)
		enc := venice.NewE2EE()
		_, decryptor, _, err := enc.EncryptRequest(body, raw, "/v1/chat/completions")
		if err != nil {
			t.Fatalf("EncryptRequest with absent content: %v", err)
		}
		decryptor.Zero()
	})
}

// Test helpers for message assertion.

func assertRole(t *testing.T, msg map[string]json.RawMessage, want string) {
	t.Helper()
	var got string
	if err := json.Unmarshal(msg["role"], &got); err != nil {
		t.Fatalf("unmarshal role: %v", err)
	}
	if got != want {
		t.Errorf("role = %q, want %q", got, want)
	}
}

func assertContentEncrypted(t *testing.T, msg map[string]json.RawMessage, wantPlaintext string, modelPriv *secp256k1.PrivateKey) {
	t.Helper()
	raw, ok := msg["content"]
	if !ok {
		t.Fatal("content field missing")
	}
	var ct string
	if err := json.Unmarshal(raw, &ct); err != nil {
		t.Fatalf("unmarshal content: %v", err)
	}
	// Venice encrypted chunks are hex starting with "04" and at least 186 chars.
	if len(ct) < 186 {
		t.Fatalf("content too short for encrypted chunk: len=%d", len(ct))
	}
	// Decrypt and verify.
	pt, err := e2ee.DecryptVenice(ct, modelPriv)
	if err != nil {
		t.Fatalf("decrypt content: %v", err)
	}
	if string(pt) != wantPlaintext {
		t.Errorf("decrypted content = %q, want %q", string(pt), wantPlaintext)
	}
}

func assertContentNull(t *testing.T, msg map[string]json.RawMessage) {
	t.Helper()
	raw, ok := msg["content"]
	if !ok {
		t.Fatal("content field missing — expected null")
	}
	if !e2ee.IsJSONNull(raw) {
		t.Fatalf("content = %s, want null", raw)
	}
}

func assertFieldPresent(t *testing.T, msg map[string]json.RawMessage, field string) {
	t.Helper()
	if _, ok := msg[field]; !ok {
		t.Errorf("field %q missing from message", field)
	}
}

// TestVeniceE2EE_VLArrayContent verifies that multimodal/VL content (array
// format) is encrypted successfully, matching NearCloud's handling.
func TestVeniceE2EE_VLArrayContent(t *testing.T) {
	pubHex, modelPriv := modelKeyPair(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}

	body := []byte(`{
		"model": "venice-vision",
		"messages": [
			{"role": "user", "content": [
				{"type": "text", "text": "What is in this image?"},
				{"type": "image_url", "image_url": {"url": "https://example.com/img.png"}}
			]}
		]
	}`)

	enc := venice.NewE2EE()
	encBody, decryptor, _, err := enc.EncryptRequest(body, raw, "/v1/chat/completions")
	if err != nil {
		t.Fatalf("EncryptRequest with VL array content: %v", err)
	}
	defer decryptor.Zero()

	var out map[string]json.RawMessage
	if err := json.Unmarshal(encBody, &out); err != nil {
		t.Fatalf("unmarshal encrypted body: %v", err)
	}

	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(out["messages"], &messages); err != nil {
		t.Fatalf("unmarshal messages: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("message count = %d, want 1", len(messages))
	}

	assertRole(t, messages[0], "user")

	// Content should be encrypted — decrypt to verify.
	var ct string
	if err := json.Unmarshal(messages[0]["content"], &ct); err != nil {
		t.Fatalf("unmarshal encrypted content: %v", err)
	}
	pt, err := e2ee.DecryptVenice(ct, modelPriv)
	if err != nil {
		t.Fatalf("decrypt VL content: %v", err)
	}

	// Decrypted plaintext should be a valid JSON array.
	var arr []json.RawMessage
	if err := json.Unmarshal(pt, &arr); err != nil {
		t.Fatalf("decrypted content is not a JSON array: %v", err)
	}
	if len(arr) != 2 {
		t.Errorf("decrypted array length = %d, want 2", len(arr))
	}
}

// TestVeniceE2EE_UnsupportedContentType verifies that content with an
// unsupported type (e.g. object) fails closed.
func TestVeniceE2EE_UnsupportedContentType(t *testing.T) {
	pubHex := modelPubKeyHex(t)
	raw := &attestation.RawAttestation{SigningKey: pubHex}

	body := []byte(`{
		"model": "venice-model",
		"messages": [{"role": "user", "content": {"invalid": "object"}}]
	}`)

	enc := venice.NewE2EE()
	_, _, _, err := enc.EncryptRequest(body, raw, "/v1/chat/completions")
	if err == nil {
		t.Fatal("expected error for unsupported content type (object)")
	}
	t.Logf("error (expected): %v", err)
}
