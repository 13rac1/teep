package e2ee

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func ed25519KeyPairHex(t *testing.T) (pubHex string, seed []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return hex.EncodeToString(pub), priv.Seed()
}

func TestNewNearCloudSession(t *testing.T) {
	session, err := NewNearCloudSession()
	if err != nil {
		t.Fatalf("NewNearCloudSession: %v", err)
	}
	defer session.Zero()

	pubHex := session.ClientEd25519PubHex()
	t.Logf("client Ed25519 pub hex: %s", pubHex)

	if len(pubHex) != 64 {
		t.Errorf("pub hex length = %d, want 64", len(pubHex))
	}
	// Verify it's valid hex.
	if _, err := hex.DecodeString(pubHex); err != nil {
		t.Errorf("pub hex is not valid hex: %v", err)
	}
	if session.x25519Priv == nil {
		t.Error("x25519Priv is nil")
	}
}

func TestSetModelKeyEd25519(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"valid_key", pubHex, false},
		{"too_short", pubHex[:63], true},
		{"too_long", pubHex + "a", true},
		{"non_hex", strings.Repeat("zz", 32), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, err := NewNearCloudSession()
			if err != nil {
				t.Fatalf("NewNearCloudSession: %v", err)
			}
			defer session.Zero()

			err = session.SetModelKeyEd25519(tt.key)
			t.Logf("SetModelKeyEd25519(%q[:20]...): err=%v", tt.key[:min(20, len(tt.key))], err)

			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr && session.ModelX25519Pub() == nil {
				t.Error("ModelX25519Pub() is nil after successful SetModelKeyEd25519")
			}
		})
	}
}

func TestEncryptDecryptXChaCha20_RoundTrip(t *testing.T) {
	// Generate an X25519 key pair (via Ed25519 seed conversion, like the real code does).
	_, seed := ed25519KeyPairHex(t)
	x25519Priv, err := ed25519SeedToX25519(seed)
	if err != nil {
		t.Fatalf("ed25519SeedToX25519: %v", err)
	}

	plaintext := []byte("hello nearcloud e2ee")
	ct, err := EncryptXChaCha20(plaintext, x25519Priv.PublicKey())
	if err != nil {
		t.Fatalf("EncryptXChaCha20: %v", err)
	}
	t.Logf("ciphertext hex length: %d", len(ct))

	decrypted, err := DecryptXChaCha20(ct, x25519Priv)
	if err != nil {
		t.Fatalf("DecryptXChaCha20: %v", err)
	}
	t.Logf("decrypted: %q", decrypted)

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptXChaCha20_WrongKey(t *testing.T) {
	_, seed1 := ed25519KeyPairHex(t)
	priv1, err := ed25519SeedToX25519(seed1)
	if err != nil {
		t.Fatalf("ed25519SeedToX25519 (key 1): %v", err)
	}

	_, seed2 := ed25519KeyPairHex(t)
	priv2, err := ed25519SeedToX25519(seed2)
	if err != nil {
		t.Fatalf("ed25519SeedToX25519 (key 2): %v", err)
	}

	ct, err := EncryptXChaCha20([]byte("secret"), priv1.PublicKey())
	if err != nil {
		t.Fatalf("EncryptXChaCha20: %v", err)
	}

	_, err = DecryptXChaCha20(ct, priv2)
	t.Logf("wrong key error: %v", err)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("error = %q, want 'authentication failed'", err)
	}
}

func TestDecryptXChaCha20_TooShort(t *testing.T) {
	// 143 hex chars = 71.5 bytes, below minimum 72 bytes (144 hex chars).
	shortHex := strings.Repeat("ab", 71)
	_, err := DecryptXChaCha20(shortHex, nil)
	t.Logf("too short error: %v", err)
	if err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}

func TestDecryptXChaCha20_InvalidHex(t *testing.T) {
	_, err := DecryptXChaCha20("not-valid-hex!", nil)
	t.Logf("invalid hex error: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestIsEncryptedChunkXChaCha20(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"valid_144_hex", strings.Repeat("ab", 72), true},
		{"valid_200_hex", strings.Repeat("0f", 100), true},
		{"too_short_143", strings.Repeat("ab", 71) + "a", false},
		{"non_hex_chars", strings.Repeat("zz", 72), false},
		{"empty", "", false},
		{"uppercase_hex", strings.Repeat("AB", 72), true},
		{"mixed_case_hex", strings.Repeat("aB", 72), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsEncryptedChunkXChaCha20(tt.s)
			t.Logf("IsEncryptedChunkXChaCha20(len=%d) = %v", len(tt.s), got)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncryptChatMessagesNearCloud(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)

	body := map[string]any{
		"model":    "nearcloud-model",
		"messages": []map[string]string{{"role": "user", "content": "Hello"}, {"role": "assistant", "content": "Hi"}},
		"stream":   false,
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	encBody, session, err := EncryptChatMessagesNearCloud(bodyJSON, pubHex)
	if err != nil {
		t.Fatalf("EncryptChatMessagesNearCloud: %v", err)
	}
	defer session.Zero()

	t.Logf("encrypted body length: %d", len(encBody))

	if session == nil {
		t.Fatal("expected non-nil session")
	}

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
		t.Logf("message[%d]: role=%q content_len=%d content_prefix=%q", i, msg.Role, len(msg.Content), SafePrefix(msg.Content, 20))

		if msg.Content == "Hello" || msg.Content == "Hi" {
			t.Errorf("message[%d]: content appears unencrypted: %q", i, msg.Content)
		}
		if !IsEncryptedChunkXChaCha20(msg.Content) {
			t.Errorf("message[%d]: content does not look like encrypted chunk", i)
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

func TestNearCloudSessionIsResponseFieldEncrypted_NestedPaths(t *testing.T) {
	s := &NearCloudSession{}
	tests := []struct {
		name     string
		field    string
		endpoint EndpointType
		want     bool
	}{
		{name: "content encrypted", field: "content", endpoint: EndpointChat, want: true},
		{name: "tool function name encrypted", field: "tool_calls[].function.name", endpoint: EndpointChat, want: true},
		{name: "tool function args encrypted", field: "tool_calls[].function.arguments", endpoint: EndpointChat, want: true},
		{name: "audio data encrypted", field: "audio.data", endpoint: EndpointChat, want: true},
		{name: "tool id plaintext", field: "tool_calls[].id", endpoint: EndpointChat, want: false},
		{name: "tool type plaintext", field: "tool_calls[].type", endpoint: EndpointChat, want: false},
		{name: "score plaintext on score endpoint", field: "score", endpoint: EndpointScore, want: false},
		{name: "usage container plaintext", field: "usage", endpoint: EndpointChat, want: false},
		{name: "usage total_tokens plaintext", field: "usage.total_tokens", endpoint: EndpointChat, want: false},
		{name: "usage completion_tokens plaintext", field: "usage.completion_tokens", endpoint: EndpointChat, want: false},
		// Structural container paths must return false so callers can distinguish
		// containers from encrypted leaf candidates.
		{name: "tool_calls container plaintext", field: "tool_calls", endpoint: EndpointChat, want: false},
		{name: "tool_calls[] element container plaintext", field: "tool_calls[]", endpoint: EndpointChat, want: false},
		{name: "tool_calls[].function container plaintext", field: "tool_calls[].function", endpoint: EndpointChat, want: false},
		{name: "audio container plaintext", field: "audio", endpoint: EndpointChat, want: false},
		{name: "function_call container plaintext", field: "function_call", endpoint: EndpointChat, want: false},
		{name: "content[] element container plaintext", field: "content[]", endpoint: EndpointChat, want: false},
		{name: "logprobs container plaintext", field: "logprobs", endpoint: EndpointChat, want: false},
		{name: "logprobs.content array plaintext", field: "logprobs.content", endpoint: EndpointChat, want: false},
		{name: "logprobs.content[] element container plaintext", field: "logprobs.content[]", endpoint: EndpointChat, want: false},
		{name: "logprobs.refusal array plaintext", field: "logprobs.refusal", endpoint: EndpointChat, want: false},
		{name: "logprobs.refusal[] element container plaintext", field: "logprobs.refusal[]", endpoint: EndpointChat, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := s.IsResponseFieldEncrypted(tc.field, tc.endpoint)
			if got != tc.want {
				t.Fatalf("IsResponseFieldEncrypted(%q, %q)=%v want %v", tc.field, tc.endpoint, got, tc.want)
			}
		})
	}
}

func TestEncryptChatMessagesNearCloud_InvalidKey(t *testing.T) {
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`)
	_, _, err := EncryptChatMessagesNearCloud(body, "bad-key")
	t.Logf("invalid key error: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid signing key")
	}
}

func TestEncryptChatMessagesNearCloud_InvalidBody(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	_, _, err := EncryptChatMessagesNearCloud([]byte("not json"), pubHex)
	t.Logf("invalid body error: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid body")
	}
}

func TestEncryptChatMessagesNearCloud_InvalidMessages(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	_, _, err := EncryptChatMessagesNearCloud([]byte(`{"model":"m","messages":"not-an-array"}`), pubHex)
	t.Logf("invalid messages error: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid messages")
	}
}

func TestValidateModelKeyEd25519(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"valid", pubHex, false},
		{"wrong_length_63", pubHex[:63], true},
		{"wrong_length_65", pubHex + "a", true},
		{"non_hex", strings.Repeat("zz", 32), true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateModelKeyEd25519(tt.key)
			t.Logf("ValidateModelKeyEd25519(%q[:16]...): err=%v", SafePrefix(tt.key, 16), err)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestNearCloudSessionZero(t *testing.T) {
	session, err := NewNearCloudSession()
	if err != nil {
		t.Fatalf("NewNearCloudSession: %v", err)
	}

	pubHex, _ := ed25519KeyPairHex(t)
	if err := session.SetModelKeyEd25519(pubHex); err != nil {
		t.Fatalf("SetModelKeyEd25519: %v", err)
	}

	t.Logf("before Zero: x25519Priv=%v, modelX25519=%v", session.x25519Priv != nil, session.modelX25519 != nil)
	session.Zero()
	t.Logf("after Zero: x25519Priv=%v, modelX25519=%v", session.x25519Priv != nil, session.modelX25519 != nil)

	if session.x25519Priv != nil {
		t.Error("x25519Priv not nil after Zero()")
	}
	if session.modelX25519 != nil {
		t.Error("modelX25519 not nil after Zero()")
	}
}

func TestNearCloudSession_IsEncryptedChunk(t *testing.T) {
	session, err := NewNearCloudSession()
	if err != nil {
		t.Fatalf("NewNearCloudSession: %v", err)
	}
	defer session.Zero()

	validChunk := strings.Repeat("ab", 72)
	if !session.IsEncryptedChunk(validChunk) {
		t.Error("expected true for valid encrypted chunk")
	}
	if session.IsEncryptedChunk("short") {
		t.Error("expected false for short string")
	}
}

func TestNearCloudSession_Decrypt(t *testing.T) {
	session, err := NewNearCloudSession()
	if err != nil {
		t.Fatalf("NewNearCloudSession: %v", err)
	}
	defer session.Zero()

	// Encrypt for the session's own X25519 public key.
	plaintext := []byte("round-trip via session")
	ct, err := EncryptXChaCha20(plaintext, session.x25519Priv.PublicKey())
	if err != nil {
		t.Fatalf("EncryptXChaCha20: %v", err)
	}

	decrypted, err := session.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	t.Logf("decrypted via session: %q", decrypted)

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEd25519SeedToX25519(t *testing.T) {
	// Valid seed.
	_, seed := ed25519KeyPairHex(t)
	priv, err := ed25519SeedToX25519(seed)
	if err != nil {
		t.Fatalf("ed25519SeedToX25519: %v", err)
	}
	t.Logf("x25519 private key: %d bytes", len(priv.Bytes()))

	if priv.PublicKey() == nil {
		t.Error("public key is nil")
	}

	// Wrong length.
	_, err = ed25519SeedToX25519([]byte("short"))
	t.Logf("wrong length error: %v", err)
	if err == nil {
		t.Fatal("expected error for wrong seed length")
	}
}

func TestEd25519PubToX25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Valid pub.
	x25519Pub, err := Ed25519PubToX25519(pub)
	if err != nil {
		t.Fatalf("Ed25519PubToX25519: %v", err)
	}
	t.Logf("x25519 pub key: %d bytes", len(x25519Pub.Bytes()))

	// Wrong length.
	_, err = Ed25519PubToX25519([]byte("short"))
	t.Logf("wrong length error: %v", err)
	if err == nil {
		t.Fatal("expected error for wrong pub length")
	}

	// All zeros (not a valid Ed25519 point on the curve for most purposes,
	// but edwards25519.Point.SetBytes accepts it as the identity).
	// The identity point converts to all-zero Montgomery, which X25519 accepts.
	// Use a known-bad point instead: flip high bits.
	badPub := make([]byte, 32)
	badPub[31] = 0xFF // invalid: y coordinate too large
	_, err = Ed25519PubToX25519(badPub)
	t.Logf("bad point error: %v", err)
	// This may or may not error depending on edwards25519 validation;
	// the key thing is it doesn't panic.
}

func TestDeriveKeyEd25519(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	key := deriveKeyEd25519(secret)
	t.Logf("derived key: %d bytes, hex=%s", len(key), hex.EncodeToString(key[:8]))

	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}

	// Same input should produce same output (deterministic).
	key2 := deriveKeyEd25519(secret)
	if !bytes.Equal(key, key2) {
		t.Error("expected deterministic output from HKDF")
	}
}

func TestIsHexRune(t *testing.T) {
	tests := []struct {
		r    rune
		want bool
	}{
		{'0', true}, {'9', true}, {'a', true}, {'f', true},
		{'A', true}, {'F', true}, {'g', false}, {'z', false},
		{' ', false}, {'!', false},
	}
	for _, tt := range tests {
		if got := isHexRune(tt.r); got != tt.want {
			t.Errorf("isHexRune(%q) = %v, want %v", tt.r, got, tt.want)
		}
	}
}

// Verify NearCloudSession implements Decryptor interface.
var _ Decryptor = (*NearCloudSession)(nil)

func TestNearCloudSession_DecryptorInterface(t *testing.T) {
	session, err := NewNearCloudSession()
	if err != nil {
		t.Fatalf("NewNearCloudSession: %v", err)
	}
	defer session.Zero()

	var d Decryptor = session
	t.Logf("NearCloudSession implements Decryptor: %T", d)

	// Encrypt something for this session and decrypt via the Decryptor interface.
	ct, err := EncryptXChaCha20([]byte("interface test"), session.x25519Priv.PublicKey())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	plain, err := d.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt via interface: %v", err)
	}
	if string(plain) != "interface test" {
		t.Errorf("decrypted = %q, want 'interface test'", plain)
	}

	if !d.IsEncryptedChunk(ct) {
		t.Error("expected IsEncryptedChunk to return true for valid ciphertext")
	}
}

func TestEncryptChatMessagesNearCloud_VLContent(t *testing.T) {
	pubHex, seed := ed25519KeyPairHex(t)

	// VL content: array of [text, image_url] parts.
	body := map[string]any{
		"model": "vl-model",
		"messages": []map[string]any{
			{
				"role": "user",
				"content": []map[string]any{
					{"type": "text", "text": "What is this?"},
					{"type": "image_url", "image_url": map[string]string{"url": "data:image/png;base64,iVBOR"}},
				},
			},
		},
		"stream": false,
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	encBody, session, err := EncryptChatMessagesNearCloud(bodyJSON, pubHex)
	if err != nil {
		t.Fatalf("EncryptChatMessagesNearCloud VL: %v", err)
	}
	defer session.Zero()

	// Parse output.
	var out map[string]json.RawMessage
	if err := json.Unmarshal(encBody, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(out["messages"], &messages); err != nil {
		t.Fatalf("unmarshal messages: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("message count = %d, want 1", len(messages))
	}

	// Content must be a single encrypted string (not array).
	if !IsEncryptedChunkXChaCha20(messages[0].Content) {
		t.Fatalf("VL content not encrypted: %q", SafePrefix(messages[0].Content, 40))
	}

	// Decrypt and verify the serialized array is valid JSON.
	x25519Priv, err := ed25519SeedToX25519(seed)
	if err != nil {
		t.Fatalf("derive x25519: %v", err)
	}
	pt, err := DecryptXChaCha20(messages[0].Content, x25519Priv)
	if err != nil {
		t.Fatalf("decrypt VL content: %v", err)
	}
	t.Logf("decrypted VL content: %s", pt)

	// Must be a valid JSON array.
	var parts []map[string]any
	if err := json.Unmarshal(pt, &parts); err != nil {
		t.Fatalf("decrypted VL content is not a JSON array: %v", err)
	}
	if len(parts) != 2 {
		t.Fatalf("expected 2 parts, got %d", len(parts))
	}
	if parts[0]["type"] != "text" {
		t.Errorf("part[0].type = %v, want text", parts[0]["type"])
	}
}

// TestEncryptChatMessagesNearCloud_ToolCallConversation verifies that
// EncryptChatMessagesNearCloud correctly handles multi-turn tool calling
// conversations:
//   - assistant messages with null content pass through unchanged
//   - tool_call_id metadata is preserved
//   - tool/function sensitive fields are encrypted
//   - content is encrypted
func TestEncryptChatMessagesNearCloud_ToolCallConversation(t *testing.T) {
	pubHex, seed := ed25519KeyPairHex(t)

	body := map[string]any{
		"model": "test-model",
		"messages": []map[string]any{
			{
				"role":    "user",
				"content": "What's the weather in NYC?",
			},
			{
				"role":    "assistant",
				"content": nil,
				"tool_calls": []map[string]any{
					{
						"id":   "call_123",
						"type": "function",
						"function": map[string]string{
							"name":      "get_weather",
							"arguments": `{"location":"New York City"}`,
						},
					},
				},
			},
			{
				"role":         "tool",
				"tool_call_id": "call_123",
				"name":         "get_weather",
				"content":      "72°F and sunny",
			},
			{
				"role":    "user",
				"content": "Thanks! What about tomorrow?",
			},
		},
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	encBody, session, err := EncryptChatMessagesNearCloud(bodyJSON, pubHex)
	if err != nil {
		t.Fatalf("EncryptChatMessagesNearCloud: %v", err)
	}
	defer session.Zero()

	// Parse output.
	var out map[string]json.RawMessage
	if err := json.Unmarshal(encBody, &out); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(out["messages"], &messages); err != nil {
		t.Fatalf("unmarshal messages: %v", err)
	}
	if len(messages) != 4 {
		t.Fatalf("message count = %d, want 4", len(messages))
	}

	x25519Priv, err := ed25519SeedToX25519(seed)
	if err != nil {
		t.Fatalf("derive x25519: %v", err)
	}

	// Message 0: user — content encrypted, role preserved.
	assertRole(t, messages[0], "user")
	assertContentEncrypted(t, messages[0], x25519Priv, "What's the weather in NYC?")

	// Message 1: assistant with null content and tool_calls.
	assertRole(t, messages[1], "assistant")
	assertContentNull(t, messages[1])
	assertFieldPresent(t, messages[1], "tool_calls")
	var toolCalls []map[string]json.RawMessage
	if err := json.Unmarshal(messages[1]["tool_calls"], &toolCalls); err != nil {
		t.Fatalf("unmarshal tool_calls: %v", err)
	}
	if len(toolCalls) != 1 {
		t.Fatalf("tool_calls count = %d, want 1", len(toolCalls))
	}
	var tcID string
	if err := json.Unmarshal(toolCalls[0]["id"], &tcID); err != nil {
		t.Fatalf("unmarshal tool_calls[0].id: %v", err)
	}
	if tcID != "call_123" {
		t.Errorf("tool_calls[0].id = %q, want call_123", tcID)
	}
	assertToolCallFunctionEncrypted(t, toolCalls[0], x25519Priv, "get_weather", `{"location":"New York City"}`)

	// Message 2: tool — content encrypted, tool_call_id preserved, name encrypted.
	assertRole(t, messages[2], "tool")
	assertContentEncrypted(t, messages[2], x25519Priv, "72°F and sunny")
	assertFieldPresent(t, messages[2], "tool_call_id")
	assertFieldPresent(t, messages[2], "name")
	var toolCallID string
	if err := json.Unmarshal(messages[2]["tool_call_id"], &toolCallID); err != nil {
		t.Fatalf("unmarshal tool_call_id: %v", err)
	}
	if toolCallID != "call_123" {
		t.Errorf("tool_call_id = %q, want call_123", toolCallID)
	}
	assertStringFieldEncrypted(t, messages[2], "name", x25519Priv, "get_weather")

	// Message 3: user — content encrypted.
	assertRole(t, messages[3], "user")
	assertContentEncrypted(t, messages[3], x25519Priv, "Thanks! What about tomorrow?")
}

// TestEncryptChatMessagesNearCloud_PreservesExtraFields verifies that
// EncryptChatMessagesNearCloud preserves ALL message fields, not just
// role and content.
func TestEncryptChatMessagesNearCloud_PreservesExtraFields(t *testing.T) {
	pubHex, seed := ed25519KeyPairHex(t)

	body := map[string]any{
		"model": "test-model",
		"messages": []map[string]any{
			{
				"role":    "user",
				"content": "hello",
				"name":    "test_user",
			},
		},
		"tools": []map[string]any{
			{
				"type": "function",
				"function": map[string]string{
					"name":        "get_weather",
					"description": "Get weather",
				},
			},
		},
		"temperature": 0.7,
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	encBody, session, err := EncryptChatMessagesNearCloud(bodyJSON, pubHex)
	if err != nil {
		t.Fatalf("EncryptChatMessagesNearCloud: %v", err)
	}
	defer session.Zero()

	var out map[string]json.RawMessage
	if err := json.Unmarshal(encBody, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	x25519Priv, err := ed25519SeedToX25519(seed)
	if err != nil {
		t.Fatalf("derive x25519: %v", err)
	}

	// Top-level fields must be preserved.
	for _, field := range []string{"model", "tools", "temperature", "stream"} {
		if _, ok := out[field]; !ok {
			t.Errorf("top-level field %q missing — was stripped", field)
		}
	}

	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(out["messages"], &messages); err != nil {
		t.Fatalf("unmarshal messages: %v", err)
	}

	// Message-level name field must be encrypted.
	assertFieldPresent(t, messages[0], "name")
	assertStringFieldEncrypted(t, messages[0], "name", x25519Priv, "test_user")

	// Tool function name/description must be encrypted.
	var tools []map[string]json.RawMessage
	if err := json.Unmarshal(out["tools"], &tools); err != nil {
		t.Fatalf("unmarshal tools: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("tools len = %d, want 1", len(tools))
	}
	var fn map[string]json.RawMessage
	if err := json.Unmarshal(tools[0]["function"], &fn); err != nil {
		t.Fatalf("unmarshal tools[0].function: %v", err)
	}
	assertStringFieldEncrypted(t, fn, "name", x25519Priv, "get_weather")
	assertStringFieldEncrypted(t, fn, "description", x25519Priv, "Get weather")
}

// TestEncryptChatMessagesNearCloud_NullContentVariants tests handling of
// null and absent content in various message configurations.
func TestEncryptChatMessagesNearCloud_NullContentVariants(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)

	tests := []struct {
		name    string
		content any // nil for JSON null, missing for absent
		absent  bool
	}{
		{"explicit null", nil, false},
		{"absent content", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := map[string]any{
				"role": "assistant",
				"tool_calls": []map[string]any{
					{
						"id":   "call_1",
						"type": "function",
						"function": map[string]string{
							"name":      "test_fn",
							"arguments": `{}`,
						},
					},
				},
			}
			if !tt.absent {
				msg["content"] = tt.content
			}

			body := map[string]any{
				"model":    "test-model",
				"messages": []any{msg},
			}
			bodyJSON, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			encBody, session, err := EncryptChatMessagesNearCloud(bodyJSON, pubHex)
			if err != nil {
				t.Fatalf("EncryptChatMessagesNearCloud: %v", err)
			}
			defer session.Zero()

			var out map[string]json.RawMessage
			if err := json.Unmarshal(encBody, &out); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			var messages []map[string]json.RawMessage
			if err := json.Unmarshal(out["messages"], &messages); err != nil {
				t.Fatalf("unmarshal messages: %v", err)
			}

			if tt.absent {
				if _, ok := messages[0]["content"]; ok {
					t.Error("absent content should remain absent")
				}
			} else {
				assertContentNull(t, messages[0])
			}
			assertFieldPresent(t, messages[0], "tool_calls")
		})
	}
}

func TestIsJSONNull(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"null", true},
		{`"hello"`, false},
		{"42", false},
		{"[]", false},
		{"{}", false},
		{"", true},
		{"  null  ", true},
		{"\tnull\n", true},
		{" \r\n null \t", true},
		{`""`, false},
		{"true", false},
		{"false", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsJSONNull(json.RawMessage(tt.input))
			if got != tt.want {
				t.Errorf("IsJSONNull(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
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

func assertContentEncrypted(t *testing.T, msg map[string]json.RawMessage, x25519Priv *ecdh.PrivateKey, wantPlaintext string) {
	t.Helper()
	var ct string
	if err := json.Unmarshal(msg["content"], &ct); err != nil {
		t.Fatalf("unmarshal content: %v", err)
	}
	if !IsEncryptedChunkXChaCha20(ct) {
		t.Fatalf("content not encrypted: %q", SafePrefix(ct, 40))
	}
	pt, err := DecryptXChaCha20(ct, x25519Priv)
	if err != nil {
		t.Fatalf("decrypt content: %v", err)
	}
	if string(pt) != wantPlaintext {
		t.Errorf("decrypted = %q, want %q", pt, wantPlaintext)
	}
}

func assertContentNull(t *testing.T, msg map[string]json.RawMessage) {
	t.Helper()
	raw, ok := msg["content"]
	if !ok {
		t.Fatal("content field missing — expected null")
	}
	if !IsJSONNull(raw) {
		t.Fatalf("content = %s, want null", raw)
	}
}

func assertFieldPresent(t *testing.T, msg map[string]json.RawMessage, field string) {
	t.Helper()
	if _, ok := msg[field]; !ok {
		t.Errorf("field %q missing from message", field)
	}
}

func assertStringFieldEncrypted(t *testing.T, obj map[string]json.RawMessage, field string, x25519Priv *ecdh.PrivateKey, wantPlaintext string) {
	t.Helper()
	raw, ok := obj[field]
	if !ok {
		t.Fatalf("field %q missing", field)
	}
	var ct string
	if err := json.Unmarshal(raw, &ct); err != nil {
		t.Fatalf("unmarshal %s: %v", field, err)
	}
	if !IsEncryptedChunkXChaCha20(ct) {
		t.Fatalf("field %q not encrypted: %q", field, SafePrefix(ct, 40))
	}
	pt, err := DecryptXChaCha20(ct, x25519Priv)
	if err != nil {
		t.Fatalf("decrypt %s: %v", field, err)
	}
	if string(pt) != wantPlaintext {
		t.Errorf("decrypted %s = %q, want %q", field, pt, wantPlaintext)
	}
}

func assertToolCallFunctionEncrypted(t *testing.T, toolCall map[string]json.RawMessage, x25519Priv *ecdh.PrivateKey, wantName, wantArguments string) {
	t.Helper()
	var fn map[string]json.RawMessage
	if err := json.Unmarshal(toolCall["function"], &fn); err != nil {
		t.Fatalf("unmarshal tool_call.function: %v", err)
	}
	assertStringFieldEncrypted(t, fn, "name", x25519Priv, wantName)
	assertStringFieldEncrypted(t, fn, "arguments", x25519Priv, wantArguments)
}

func TestEncryptImagePromptNearCloud(t *testing.T) {
	pubHex, seed := ed25519KeyPairHex(t)

	body := map[string]any{
		"model":  "flux-model",
		"prompt": "A cat sitting on a rainbow",
		"n":      1,
		"size":   "1024x1024",
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	encBody, session, err := EncryptImagePromptNearCloud(bodyJSON, pubHex)
	if err != nil {
		t.Fatalf("EncryptImagePromptNearCloud: %v", err)
	}
	defer session.Zero()

	// Parse and verify structure.
	var out map[string]json.RawMessage
	if err := json.Unmarshal(encBody, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Other fields must be preserved.
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
	if prompt == "A cat sitting on a rainbow" {
		t.Error("prompt appears unencrypted")
	}
	if !IsEncryptedChunkXChaCha20(prompt) {
		t.Fatalf("prompt does not look encrypted: %q", SafePrefix(prompt, 40))
	}

	// Decrypt and verify.
	x25519Priv, err := ed25519SeedToX25519(seed)
	if err != nil {
		t.Fatalf("derive x25519: %v", err)
	}
	pt, err := DecryptXChaCha20(prompt, x25519Priv)
	if err != nil {
		t.Fatalf("decrypt prompt: %v", err)
	}
	if string(pt) != "A cat sitting on a rainbow" {
		t.Errorf("decrypted prompt = %q, want 'A cat sitting on a rainbow'", pt)
	}
}

func TestEncryptImagePromptNearCloud_InvalidKey(t *testing.T) {
	_, _, err := EncryptImagePromptNearCloud([]byte(`{"model":"m","prompt":"test"}`), "bad-key")
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
}

func TestEncryptImagePromptNearCloud_MissingPrompt(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	_, _, err := EncryptImagePromptNearCloud([]byte(`{"model":"m"}`), pubHex)
	if err == nil {
		t.Fatal("expected error for missing prompt")
	}
}

func TestEncryptImagePromptNearCloud_InvalidBody(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	_, _, err := EncryptImagePromptNearCloud([]byte("not json"), pubHex)
	if err == nil {
		t.Fatal("expected error for invalid body")
	}
}

func TestEncryptEmbeddingsNearCloud_StringArray(t *testing.T) {
	pubHex, seed := ed25519KeyPairHex(t)
	body := []byte(`{"model":"m","input":["hello","world"]}`)

	encBody, session, err := EncryptEmbeddingsNearCloud(body, pubHex)
	if err != nil {
		t.Fatalf("EncryptEmbeddingsNearCloud: %v", err)
	}
	defer session.Zero()

	var out map[string]json.RawMessage
	if err := json.Unmarshal(encBody, &out); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	var arr []string
	if err := json.Unmarshal(out["input"], &arr); err != nil {
		t.Fatalf("unmarshal input array: %v", err)
	}
	if len(arr) != 2 {
		t.Fatalf("input length = %d, want 2", len(arr))
	}
	x25519Priv, err := ed25519SeedToX25519(seed)
	if err != nil {
		t.Fatalf("derive x25519: %v", err)
	}
	for i, want := range []string{"hello", "world"} {
		if !IsEncryptedChunkXChaCha20(arr[i]) {
			t.Fatalf("input[%d] is not encrypted: %q", i, SafePrefix(arr[i], 20))
		}
		pt, err := DecryptXChaCha20(arr[i], x25519Priv)
		if err != nil {
			t.Fatalf("decrypt input[%d]: %v", i, err)
		}
		if string(pt) != want {
			t.Errorf("decrypted input[%d] = %q, want %q", i, pt, want)
		}
	}
}

func TestEncryptEmbeddingsNearCloud_UnsupportedArrayElementType(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	body := []byte(`{"model":"m","input":["hello",123]}`)

	_, _, err := EncryptEmbeddingsNearCloud(body, pubHex)
	if err == nil {
		t.Fatal("expected error for non-string input array element")
	}
	if !strings.Contains(err.Error(), "unsupported embeddings input element type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncryptEmbeddingsNearCloud_UnsupportedInputType(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	body := []byte(`{"model":"m","input":123}`)

	_, _, err := EncryptEmbeddingsNearCloud(body, pubHex)
	if err == nil {
		t.Fatal("expected error for unsupported input type")
	}
	if !strings.Contains(err.Error(), "unsupported embeddings input type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncryptRerankNearCloud_ObjectDocuments(t *testing.T) {
	pubHex, seed := ed25519KeyPairHex(t)
	body := []byte(`{"model":"m","query":"hello","documents":[{"text":"first","title":"doc-1"},"second"]}`)

	encBody, session, err := EncryptRerankNearCloud(body, pubHex)
	if err != nil {
		t.Fatalf("EncryptRerankNearCloud: %v", err)
	}
	defer session.Zero()

	var out map[string]json.RawMessage
	if err := json.Unmarshal(encBody, &out); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}

	x25519Priv, err := ed25519SeedToX25519(seed)
	if err != nil {
		t.Fatalf("derive x25519: %v", err)
	}

	var query string
	if err := json.Unmarshal(out["query"], &query); err != nil {
		t.Fatalf("unmarshal query: %v", err)
	}
	queryPlaintext, err := DecryptXChaCha20(query, x25519Priv)
	if err != nil {
		t.Fatalf("decrypt query: %v", err)
	}
	if string(queryPlaintext) != "hello" {
		t.Fatalf("decrypted query = %q, want hello", queryPlaintext)
	}

	var rawDocs []json.RawMessage
	if err := json.Unmarshal(out["documents"], &rawDocs); err != nil {
		t.Fatalf("unmarshal raw documents: %v", err)
	}
	if len(rawDocs) != 2 {
		t.Fatalf("documents length = %d, want 2", len(rawDocs))
	}
	var firstDoc map[string]json.RawMessage
	if err := json.Unmarshal(rawDocs[0], &firstDoc); err != nil {
		t.Fatalf("unmarshal documents[0] object: %v", err)
	}
	var textCipher string
	if err := json.Unmarshal(firstDoc["text"], &textCipher); err != nil {
		t.Fatalf("unmarshal documents[0].text: %v", err)
	}
	textPlaintext, err := DecryptXChaCha20(textCipher, x25519Priv)
	if err != nil {
		t.Fatalf("decrypt documents[0].text: %v", err)
	}
	if string(textPlaintext) != "first" {
		t.Fatalf("decrypted documents[0].text = %q, want first", textPlaintext)
	}
	var title string
	if err := json.Unmarshal(firstDoc["title"], &title); err != nil {
		t.Fatalf("unmarshal documents[0].title: %v", err)
	}
	if title != "doc-1" {
		t.Fatalf("documents[0].title = %q, want doc-1", title)
	}
	var stringCipher string
	if err := json.Unmarshal(rawDocs[1], &stringCipher); err != nil {
		t.Fatalf("unmarshal documents[1]: %v", err)
	}
	stringPlaintext, err := DecryptXChaCha20(stringCipher, x25519Priv)
	if err != nil {
		t.Fatalf("decrypt documents[1]: %v", err)
	}
	if string(stringPlaintext) != "second" {
		t.Fatalf("decrypted documents[1] = %q, want second", stringPlaintext)
	}
}

func TestEncryptRerankNearCloud_UnsupportedDocumentType(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	body := []byte(`{"model":"m","query":"hello","documents":[123]}`)

	_, _, err := EncryptRerankNearCloud(body, pubHex)
	if err == nil {
		t.Fatal("expected error for unsupported rerank document type")
	}
	if !strings.Contains(err.Error(), "unsupported rerank document type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestContentPlaintext(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{
			name: "string content",
			raw:  `"Hello world"`,
			want: "Hello world",
		},
		{
			name: "VL array content",
			raw:  `[{"type":"text","text":"What?"},{"type":"image_url","image_url":{"url":"data:..."}}]`,
			want: `[{"type":"text","text":"What?"},{"type":"image_url","image_url":{"url":"data:..."}}]`,
		},
		{
			name:    "empty content",
			raw:     ``,
			wantErr: true,
		},
		{
			name:    "number content",
			raw:     `42`,
			wantErr: true,
		},
		{
			name:    "object content",
			raw:     `{"key":"value"}`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pt, err := contentPlaintext(json.RawMessage(tt.raw))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(pt) != tt.want {
				t.Errorf("got %q, want %q", pt, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EncryptScoreNearCloud
// ---------------------------------------------------------------------------

func TestEncryptScoreNearCloud(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	body := []byte(`{"model":"m","text_1":"hello","text_2":"world"}`)
	enc, session, err := EncryptScoreNearCloud(body, pubHex)
	if err != nil {
		t.Fatalf("EncryptScoreNearCloud: %v", err)
	}
	defer session.Zero()

	// Verify that the encrypted body is valid JSON and the model is preserved.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(enc, &obj); err != nil {
		t.Fatalf("unmarshal encrypted: %v", err)
	}
	if _, ok := obj["text_1"]; !ok {
		t.Error("encrypted body missing text_1 field")
	}
	if _, ok := obj["text_2"]; !ok {
		t.Error("encrypted body missing text_2 field")
	}
}

func TestEncryptScoreNearCloud_NoTextField(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	body := []byte(`{"model":"m"}`)
	enc, session, err := EncryptScoreNearCloud(body, pubHex)
	if err != nil {
		t.Fatalf("EncryptScoreNearCloud: %v", err)
	}
	defer session.Zero()
	// Body should still be valid JSON.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(enc, &obj); err != nil {
		t.Fatalf("unmarshal encrypted: %v", err)
	}
}

// ---------------------------------------------------------------------------
// EncryptEmbeddingsNearCloud — single string input
// ---------------------------------------------------------------------------

func TestEncryptEmbeddingsNearCloud_SingleString(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	body := []byte(`{"model":"m","input":"hello world"}`)
	enc, session, err := EncryptEmbeddingsNearCloud(body, pubHex)
	if err != nil {
		t.Fatalf("EncryptEmbeddingsNearCloud: %v", err)
	}
	defer session.Zero()

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(enc, &obj); err != nil {
		t.Fatalf("unmarshal encrypted: %v", err)
	}
	if _, ok := obj["input"]; !ok {
		t.Error("encrypted body missing input field")
	}
	// The input should now be an encrypted string, not the original.
	var input string
	if err := json.Unmarshal(obj["input"], &input); err != nil {
		t.Fatalf("input not a string: %v", err)
	}
	if input == "hello world" {
		t.Error("input was not encrypted")
	}
}

func TestEncryptEmbeddingsNearCloud_NullInput(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	body := []byte(`{"model":"m","input":null}`)
	enc, session, err := EncryptEmbeddingsNearCloud(body, pubHex)
	if err != nil {
		t.Fatalf("EncryptEmbeddingsNearCloud(null input): %v", err)
	}
	defer session.Zero()
	// Null input is passed through unchanged.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(enc, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(obj["input"]) != "null" {
		t.Errorf("expected null input passthrough, got %s", obj["input"])
	}
}

// ---------------------------------------------------------------------------
// encryptMessageFields — reasoning/refusal/audio/function_call sub-fields
// ---------------------------------------------------------------------------

func testNearCloudSession(t *testing.T) *NearCloudSession {
	t.Helper()
	session, err := NewNearCloudSession()
	if err != nil {
		t.Fatalf("NewNearCloudSession: %v", err)
	}
	t.Cleanup(session.Zero)
	pubHex, _ := ed25519KeyPairHex(t)
	if err := session.SetModelKeyEd25519(pubHex); err != nil {
		t.Fatalf("SetModelKeyEd25519: %v", err)
	}
	return session
}

func TestEncryptMessageFields_ReasoningContent(t *testing.T) {
	session := testNearCloudSession(t)
	msg := map[string]json.RawMessage{
		"role":              json.RawMessage(`"assistant"`),
		"reasoning_content": json.RawMessage(`"thinking about it"`),
	}
	if err := encryptMessageFields(msg, 0, session); err != nil {
		t.Fatalf("encryptMessageFields: %v", err)
	}
	var rc string
	if err := json.Unmarshal(msg["reasoning_content"], &rc); err != nil {
		t.Fatalf("unmarshal reasoning_content: %v", err)
	}
	if rc == "thinking about it" {
		t.Error("reasoning_content was not encrypted")
	}
}

func TestEncryptMessageFields_Reasoning(t *testing.T) {
	session := testNearCloudSession(t)
	msg := map[string]json.RawMessage{
		"role":      json.RawMessage(`"assistant"`),
		"reasoning": json.RawMessage(`"step by step"`),
	}
	if err := encryptMessageFields(msg, 0, session); err != nil {
		t.Fatalf("encryptMessageFields: %v", err)
	}
	var r string
	if err := json.Unmarshal(msg["reasoning"], &r); err != nil {
		t.Fatalf("unmarshal reasoning: %v", err)
	}
	if r == "step by step" {
		t.Error("reasoning was not encrypted")
	}
}

func TestEncryptMessageFields_Refusal(t *testing.T) {
	session := testNearCloudSession(t)
	msg := map[string]json.RawMessage{
		"role":    json.RawMessage(`"assistant"`),
		"refusal": json.RawMessage(`"I cannot help with that"`),
	}
	if err := encryptMessageFields(msg, 0, session); err != nil {
		t.Fatalf("encryptMessageFields: %v", err)
	}
	var ref string
	if err := json.Unmarshal(msg["refusal"], &ref); err != nil {
		t.Fatalf("unmarshal refusal: %v", err)
	}
	if ref == "I cannot help with that" {
		t.Error("refusal was not encrypted")
	}
}

func TestEncryptMessageFields_AudioData(t *testing.T) {
	session := testNearCloudSession(t)
	msg := map[string]json.RawMessage{
		"role":  json.RawMessage(`"user"`),
		"audio": json.RawMessage(`{"data":"base64audiodata","format":"wav"}`),
	}
	if err := encryptMessageFields(msg, 0, session); err != nil {
		t.Fatalf("encryptMessageFields: %v", err)
	}
	var audio map[string]json.RawMessage
	if err := json.Unmarshal(msg["audio"], &audio); err != nil {
		t.Fatalf("unmarshal audio: %v", err)
	}
	var data string
	if err := json.Unmarshal(audio["data"], &data); err != nil {
		t.Fatalf("unmarshal audio data: %v", err)
	}
	if data == "base64audiodata" {
		t.Error("audio data was not encrypted")
	}
}

func TestEncryptMessageFields_FunctionCall(t *testing.T) {
	session := testNearCloudSession(t)
	msg := map[string]json.RawMessage{
		"role":          json.RawMessage(`"assistant"`),
		"function_call": json.RawMessage(`{"name":"get_weather","arguments":"{\"city\":\"SF\"}"}`),
	}
	if err := encryptMessageFields(msg, 0, session); err != nil {
		t.Fatalf("encryptMessageFields: %v", err)
	}
	var fc map[string]json.RawMessage
	if err := json.Unmarshal(msg["function_call"], &fc); err != nil {
		t.Fatalf("unmarshal function_call: %v", err)
	}
	var name string
	if err := json.Unmarshal(fc["name"], &name); err != nil {
		t.Fatalf("unmarshal function_call name: %v", err)
	}
	if name == "get_weather" {
		t.Error("function_call name was not encrypted")
	}
}

func TestEncryptMessageFields_FunctionCallString(t *testing.T) {
	session := testNearCloudSession(t)
	msg := map[string]json.RawMessage{
		"role":          json.RawMessage(`"user"`),
		"content":       json.RawMessage(`"hello"`),
		"function_call": json.RawMessage(`"auto"`),
	}
	if err := encryptMessageFields(msg, 0, session); err != nil {
		t.Fatalf("encryptMessageFields: %v", err)
	}
	// String "auto" should be left unchanged.
	var fc string
	if err := json.Unmarshal(msg["function_call"], &fc); err != nil {
		t.Fatalf("unmarshal function_call: %v", err)
	}
	if fc != "auto" {
		t.Errorf("string function_call changed: got %q, want auto", fc)
	}
}

// ---------------------------------------------------------------------------
// encryptTopLevelFields — tool_choice and function_call
// ---------------------------------------------------------------------------

func TestEncryptTopLevelFields_ToolChoice(t *testing.T) {
	session := testNearCloudSession(t)
	full := map[string]json.RawMessage{
		"tool_choice": json.RawMessage(`{"type":"function","function":{"name":"get_weather"}}`),
	}
	if err := encryptTopLevelFields(full, session); err != nil {
		t.Fatalf("encryptTopLevelFields: %v", err)
	}
	var tc map[string]json.RawMessage
	if err := json.Unmarshal(full["tool_choice"], &tc); err != nil {
		t.Fatalf("unmarshal tool_choice: %v", err)
	}
	var fn map[string]json.RawMessage
	if err := json.Unmarshal(tc["function"], &fn); err != nil {
		t.Fatalf("unmarshal tool_choice function: %v", err)
	}
	var name string
	if err := json.Unmarshal(fn["name"], &name); err != nil {
		t.Fatalf("unmarshal function name: %v", err)
	}
	if name == "get_weather" {
		t.Error("tool_choice function name was not encrypted")
	}
}

func TestEncryptTopLevelFields_ToolChoiceString(t *testing.T) {
	session := testNearCloudSession(t)
	full := map[string]json.RawMessage{
		"tool_choice": json.RawMessage(`"auto"`),
	}
	if err := encryptTopLevelFields(full, session); err != nil {
		t.Fatalf("encryptTopLevelFields: %v", err)
	}
	var tc string
	if err := json.Unmarshal(full["tool_choice"], &tc); err != nil {
		t.Fatalf("unmarshal tool_choice: %v", err)
	}
	if tc != "auto" {
		t.Errorf("string tool_choice changed: got %q, want auto", tc)
	}
}

func TestEncryptTopLevelFields_FunctionCall(t *testing.T) {
	session := testNearCloudSession(t)
	full := map[string]json.RawMessage{
		"function_call": json.RawMessage(`{"name":"my_func"}`),
	}
	if err := encryptTopLevelFields(full, session); err != nil {
		t.Fatalf("encryptTopLevelFields: %v", err)
	}
	var fc map[string]json.RawMessage
	if err := json.Unmarshal(full["function_call"], &fc); err != nil {
		t.Fatalf("unmarshal function_call: %v", err)
	}
	var name string
	if err := json.Unmarshal(fc["name"], &name); err != nil {
		t.Fatalf("unmarshal function_call name: %v", err)
	}
	if name == "my_func" {
		t.Error("function_call name was not encrypted")
	}
}

func TestEncryptTopLevelFields_FunctionCallString(t *testing.T) {
	session := testNearCloudSession(t)
	full := map[string]json.RawMessage{
		"function_call": json.RawMessage(`"none"`),
	}
	if err := encryptTopLevelFields(full, session); err != nil {
		t.Fatalf("encryptTopLevelFields: %v", err)
	}
	var fc string
	if err := json.Unmarshal(full["function_call"], &fc); err != nil {
		t.Fatalf("unmarshal function_call: %v", err)
	}
	if fc != "none" {
		t.Errorf("string function_call changed: got %q, want none", fc)
	}
}

// ---------------------------------------------------------------------------
// EncryptChatMessagesNearCloud — stream forcing and content encryption
// ---------------------------------------------------------------------------

func TestEncryptChatMessagesNearCloud_StreamForcing(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"hello"}],"stream":false}`)
	enc, session, err := EncryptChatMessagesNearCloud(body, pubHex)
	if err != nil {
		t.Fatalf("EncryptChatMessagesNearCloud: %v", err)
	}
	defer session.Zero()

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(enc, &obj); err != nil {
		t.Fatalf("unmarshal encrypted: %v", err)
	}
	// stream should be forced to true
	if string(obj["stream"]) != "true" {
		t.Errorf("stream not set to true: %s", obj["stream"])
	}
	// messages should be present and encrypted
	var msgs []map[string]json.RawMessage
	if err := json.Unmarshal(obj["messages"], &msgs); err != nil {
		t.Fatalf("unmarshal messages: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	var content string
	if err := json.Unmarshal(msgs[0]["content"], &content); err != nil {
		t.Fatalf("unmarshal content: %v", err)
	}
	if content == "hello" {
		t.Error("content was not encrypted")
	}
}

func TestEncryptChatMessagesNearCloud_WithTools(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	body := []byte(`{
		"model":"m",
		"messages":[{"role":"user","content":"hi"}],
		"tools":[{"type":"function","function":{"name":"get_weather","description":"Get weather","parameters":{"type":"object"}}}]
	}`)
	enc, session, err := EncryptChatMessagesNearCloud(body, pubHex)
	if err != nil {
		t.Fatalf("EncryptChatMessagesNearCloud: %v", err)
	}
	defer session.Zero()

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(enc, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// tools should be present
	if _, ok := obj["tools"]; !ok {
		t.Fatal("tools field missing from output")
	}
}

func TestEncryptChatMessagesNearCloud_WithToolCalls(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	body := []byte(`{
		"model":"m",
		"messages":[{"role":"assistant","tool_calls":[{"id":"tc1","type":"function","function":{"name":"fn","arguments":"{}"}}]}]
	}`)
	enc, session, err := EncryptChatMessagesNearCloud(body, pubHex)
	if err != nil {
		t.Fatalf("EncryptChatMessagesNearCloud: %v", err)
	}
	defer session.Zero()

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(enc, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var msgs []map[string]json.RawMessage
	if err := json.Unmarshal(obj["messages"], &msgs); err != nil {
		t.Fatalf("unmarshal messages: %v", err)
	}
	if _, ok := msgs[0]["tool_calls"]; !ok {
		t.Fatal("tool_calls field missing")
	}
}

func TestEncryptChatMessagesNearCloud_NullContent(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	// Null content is standard for tool-call assistant messages.
	body := []byte(`{"model":"m","messages":[{"role":"assistant","content":null}]}`)
	enc, session, err := EncryptChatMessagesNearCloud(body, pubHex)
	if err != nil {
		t.Fatalf("EncryptChatMessagesNearCloud: %v", err)
	}
	defer session.Zero()

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(enc, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var msgs []map[string]json.RawMessage
	if err := json.Unmarshal(obj["messages"], &msgs); err != nil {
		t.Fatalf("unmarshal messages: %v", err)
	}
	if string(msgs[0]["content"]) != "null" {
		t.Errorf("null content should pass through, got %s", msgs[0]["content"])
	}
}

func TestEncryptChatMessagesNearCloud_WithName(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"hi","name":"alice"}]}`)
	enc, session, err := EncryptChatMessagesNearCloud(body, pubHex)
	if err != nil {
		t.Fatalf("EncryptChatMessagesNearCloud: %v", err)
	}
	defer session.Zero()

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(enc, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var msgs []map[string]json.RawMessage
	if err := json.Unmarshal(obj["messages"], &msgs); err != nil {
		t.Fatalf("unmarshal messages: %v", err)
	}
	var name string
	if err := json.Unmarshal(msgs[0]["name"], &name); err != nil {
		t.Fatalf("unmarshal name: %v", err)
	}
	if name == "alice" {
		t.Error("name field was not encrypted")
	}
}

func TestEncryptImagePromptNearCloud_NonStringPrompt(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	body := []byte(`{"model":"m","prompt":123}`)
	_, _, err := EncryptImagePromptNearCloud(body, pubHex)
	if err == nil {
		t.Fatal("expected error for non-string prompt")
	}
}

// ---------------------------------------------------------------------------
// EncryptRerankNearCloud
// ---------------------------------------------------------------------------

func TestEncryptRerankNearCloud_StringDocuments(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	body := []byte(`{"model":"m","query":"search","documents":["doc1","doc2"]}`)
	enc, session, err := EncryptRerankNearCloud(body, pubHex)
	if err != nil {
		t.Fatalf("EncryptRerankNearCloud: %v", err)
	}
	defer session.Zero()

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(enc, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Query should be encrypted
	var query string
	if err := json.Unmarshal(obj["query"], &query); err != nil {
		t.Fatalf("unmarshal query: %v", err)
	}
	if query == "search" {
		t.Error("query was not encrypted")
	}
}

func TestEncryptRerankNearCloud_UnsupportedDocType(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	body := []byte(`{"model":"m","query":"q","documents":[123]}`)
	_, _, err := EncryptRerankNearCloud(body, pubHex)
	if err == nil {
		t.Fatal("expected error for unsupported document type")
	}
}

// ---------------------------------------------------------------------------
// EncryptEmbeddingsNearCloud — array input
// ---------------------------------------------------------------------------

func TestEncryptEmbeddingsNearCloud_ArrayInput(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	body := []byte(`{"model":"m","input":["hello","world"]}`)
	enc, session, err := EncryptEmbeddingsNearCloud(body, pubHex)
	if err != nil {
		t.Fatalf("EncryptEmbeddingsNearCloud: %v", err)
	}
	defer session.Zero()

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(enc, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var arr []string
	if err := json.Unmarshal(obj["input"], &arr); err != nil {
		t.Fatalf("unmarshal input array: %v", err)
	}
	if len(arr) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(arr))
	}
	if arr[0] == "hello" || arr[1] == "world" {
		t.Error("array elements were not encrypted")
	}
}

func TestEncryptEmbeddingsNearCloud_ArrayNonStringElement(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	body := []byte(`{"model":"m","input":["hello",123]}`)
	_, _, err := EncryptEmbeddingsNearCloud(body, pubHex)
	if err == nil {
		t.Fatal("expected error for non-string array element")
	}
}

// ---------------------------------------------------------------------------
// encryptToolsDefinitions — nested parsing
// ---------------------------------------------------------------------------

func TestEncryptToolsDefinitions(t *testing.T) {
	session := testNearCloudSession(t)
	full := map[string]json.RawMessage{
		"tools": json.RawMessage(`[
			{"type":"function","function":{"name":"fn1","description":"desc1","parameters":{"type":"object","properties":{}}}},
			{"type":"function","function":{"name":"fn2","description":"desc2"}}
		]`),
	}
	if err := encryptToolsDefinitions(full, session); err != nil {
		t.Fatalf("encryptToolsDefinitions: %v", err)
	}
	var tools []map[string]json.RawMessage
	if err := json.Unmarshal(full["tools"], &tools); err != nil {
		t.Fatalf("unmarshal tools: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}
	// Check first tool function fields were encrypted
	var fn map[string]json.RawMessage
	if err := json.Unmarshal(tools[0]["function"], &fn); err != nil {
		t.Fatalf("unmarshal function: %v", err)
	}
	var name string
	if err := json.Unmarshal(fn["name"], &name); err != nil {
		t.Fatalf("unmarshal name: %v", err)
	}
	if name == "fn1" {
		t.Error("tool function name was not encrypted")
	}
}

func TestEncryptToolsDefinitions_NullTools(t *testing.T) {
	session := testNearCloudSession(t)
	full := map[string]json.RawMessage{
		"tools": json.RawMessage("null"),
	}
	if err := encryptToolsDefinitions(full, session); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncryptToolsDefinitions_InvalidToolsJSON(t *testing.T) {
	session := testNearCloudSession(t)
	full := map[string]json.RawMessage{
		"tools": json.RawMessage(`not-json`),
	}
	if err := encryptToolsDefinitions(full, session); err == nil {
		t.Fatal("expected error for invalid tools JSON")
	}
}

func TestEncryptToolsDefinitions_InvalidFunctionJSON(t *testing.T) {
	session := testNearCloudSession(t)
	full := map[string]json.RawMessage{
		"tools": json.RawMessage(`[{"type":"function","function":"not-an-object"}]`),
	}
	if err := encryptToolsDefinitions(full, session); err == nil {
		t.Fatal("expected error for non-object function")
	}
}

// ---------------------------------------------------------------------------
// encryptToolChoiceFunctionName — parse errors
// ---------------------------------------------------------------------------

func TestEncryptToolChoiceFunctionName_InvalidJSON(t *testing.T) {
	session := testNearCloudSession(t)
	full := map[string]json.RawMessage{
		"tool_choice": json.RawMessage(`{bad`),
	}
	if err := encryptToolChoiceFunctionName(full, session); err == nil {
		t.Fatal("expected error for invalid tool_choice JSON")
	}
}

func TestEncryptToolChoiceFunctionName_InvalidFunctionJSON(t *testing.T) {
	session := testNearCloudSession(t)
	full := map[string]json.RawMessage{
		"tool_choice": json.RawMessage(`{"type":"function","function":"bad"}`),
	}
	if err := encryptToolChoiceFunctionName(full, session); err == nil {
		t.Fatal("expected error for non-object function in tool_choice")
	}
}

// ---------------------------------------------------------------------------
// encryptParametersField
// ---------------------------------------------------------------------------

func TestEncryptParametersField_StringParam(t *testing.T) {
	session := testNearCloudSession(t)
	fn := map[string]json.RawMessage{
		"parameters": json.RawMessage(`"stringified-json"`),
	}
	if err := encryptParametersField(fn, session); err != nil {
		t.Fatalf("encryptParametersField: %v", err)
	}
	var param string
	if err := json.Unmarshal(fn["parameters"], &param); err != nil {
		t.Fatalf("unmarshal parameters: %v", err)
	}
	if param == "stringified-json" {
		t.Error("string parameters was not encrypted")
	}
}

func TestEncryptParametersField_ObjectParam(t *testing.T) {
	session := testNearCloudSession(t)
	fn := map[string]json.RawMessage{
		"parameters": json.RawMessage(`{"type":"object"}`),
	}
	if err := encryptParametersField(fn, session); err != nil {
		t.Fatalf("encryptParametersField: %v", err)
	}
	var param string
	if err := json.Unmarshal(fn["parameters"], &param); err != nil {
		t.Fatalf("unmarshal parameters: %v", err)
	}
	if param == `{"type":"object"}` {
		t.Error("object parameters was not encrypted")
	}
}

func TestEncryptParametersField_Null(t *testing.T) {
	session := testNearCloudSession(t)
	fn := map[string]json.RawMessage{
		"parameters": json.RawMessage("null"),
	}
	if err := encryptParametersField(fn, session); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(fn["parameters"]) != "null" {
		t.Error("null parameters should be unchanged")
	}
}
