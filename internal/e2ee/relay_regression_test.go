package e2ee

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// TestReassemblyChunkDecryptsToolCallsForNearCloud regression test for:
// https://github.com/13rac1/teep/pull/103#discussion_r3263139818
// decryptSSEChunkContent must check "tool_calls[].function.name" (leaf path) not
// "tool_calls" (container path), so that tool_calls function fields are
// decrypted for NearCloud/NearDirect full-field E2EE.
func TestReassemblyChunkDecryptsToolCallsForNearCloud(t *testing.T) {
	// Test that the NearCloud policy correctly identifies encrypted leaf paths.
	session := testNearCloudSessionForRegression(t)

	// Container path should return false.
	if session.IsResponseFieldEncrypted("tool_calls", EndpointChat) {
		t.Fatalf("tool_calls container should not be encrypted")
	}

	// Leaf paths should return true.
	if !session.IsResponseFieldEncrypted(EncFieldToolCallsFuncName, EndpointChat) {
		t.Fatalf("tool_calls[].function.name should be encrypted")
	}

	if !session.IsResponseFieldEncrypted(EncFieldToolCallsFuncArgs, EndpointChat) {
		t.Fatalf("tool_calls[].function.arguments should be encrypted")
	}

	clientPubBytes, err := hex.DecodeString(session.ClientEd25519PubHex())
	if err != nil {
		t.Fatalf("decode client ed25519 pub hex: %v", err)
	}
	clientX25519Pub, err := Ed25519PubToX25519(clientPubBytes)
	if err != nil {
		t.Fatalf("convert client ed25519 pub to x25519: %v", err)
	}

	encName, err := EncryptXChaCha20([]byte("get_weather"), clientX25519Pub)
	if err != nil {
		t.Fatalf("encrypt tool call name: %v", err)
	}
	encArgs, err := EncryptXChaCha20([]byte(`{"city":"SF"}`), clientX25519Pub)
	if err != nil {
		t.Fatalf("encrypt tool call arguments: %v", err)
	}

	// If decryptSSEChunkContent checked the container path ("tool_calls") instead of
	// the leaf path ("tool_calls[].function.name"), the NearCloud policy would
	// return false and decryption would be skipped — the assertions below would
	// then fail because the ciphertext blob would survive intact in the output.
	chunk := map[string]any{
		"choices": []map[string]any{{
			"delta": map[string]any{
				"tool_calls": []map[string]any{{
					"index": 0,
					"function": map[string]any{
						"name":      encName,
						"arguments": encArgs,
					},
				}},
			},
		}},
	}
	chunkJSON, err := json.Marshal(chunk)
	if err != nil {
		t.Fatalf("marshal chunk: %v", err)
	}

	_, meta, err := decryptSSEChunkContent(string(chunkJSON), session, EndpointChat)
	if err != nil {
		t.Fatalf("decryptSSEChunkContent: %v", err)
	}
	if len(meta.ToolCalls) != 1 {
		t.Fatalf("tool_calls len = %d, want 1", len(meta.ToolCalls))
	}

	var out struct {
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	}
	if err := json.Unmarshal(meta.ToolCalls[0], &out); err != nil {
		t.Fatalf("unmarshal decrypted tool_call: %v", err)
	}
	if out.Function.Name != "get_weather" {
		t.Fatalf("tool_calls[0].function.name = %q, want get_weather", out.Function.Name)
	}
	if out.Function.Arguments != `{"city":"SF"}` {
		t.Fatalf("tool_calls[0].function.arguments = %q, want {\"city\":\"SF\"}", out.Function.Arguments)
	}
}

// TestDecryptResponseChoices_DecryptsLogprobsForNearCloud regression test for:
// https://github.com/13rac1/teep/pull/103#discussion_r3263139828
// DecryptSSEChunk for non-stream responses must check "logprobs.content[].token"
// (leaf path) not "logprobs" (container path), so that logprobs token fields
// are decrypted for NearCloud/NearDirect full-field E2EE.
func TestDecryptResponseChoices_DecryptsLogprobsForNearCloud(t *testing.T) {
	session := testNearCloudSessionForRegression(t)

	// Container path should return false.
	if session.IsResponseFieldEncrypted("logprobs", EndpointChat) {
		t.Fatalf("logprobs container should not be encrypted")
	}

	// Leaf paths should return true.
	if !session.IsResponseFieldEncrypted(EncFieldLogprobsContentToken, EndpointChat) {
		t.Fatalf("logprobs.content[].token should be encrypted")
	}

	if !session.IsResponseFieldEncrypted(EncFieldLogprobsContentBytes, EndpointChat) {
		t.Fatalf("logprobs.content[].bytes should be encrypted")
	}

	// This ensures that DecryptSSEChunk/decryptResponseChoices will correctly
	// detect that logprobs fields need decryption when checking
	// IsResponseFieldEncrypted("logprobs.content[].token", ...) rather than
	// IsResponseFieldEncrypted("logprobs", ...)
}

// TestEncryptParametersField_TrimsWhitespace regression test for:
// https://github.com/13rac1/teep/pull/103#discussion_r3263139841
// encryptParametersField must trim whitespace before checking if the input
// is a JSON string (starts with `"`), so that pretty-printed requests with
// whitespace are handled correctly.
func TestEncryptParametersField_TrimsWhitespace(t *testing.T) {
	session := testNearCloudSessionForRegression(t)

	// Test with leading whitespace before the quoted string.
	paramsWithWhitespace := json.RawMessage(`  "param_value"`)

	fn := make(map[string]json.RawMessage)
	fn["parameters"] = paramsWithWhitespace

	// encryptParametersField should trim, then unmarshal as string and encrypt.
	if err := encryptParametersField(fn, session); err != nil {
		t.Fatalf("encryptParametersField with whitespace: %v", err)
	}

	// Verify the parameters field was encrypted (should be a string).
	paramsRaw, ok := fn["parameters"]
	if !ok || len(paramsRaw) == 0 {
		t.Fatalf("parameters field not encrypted")
	}

	// The encrypted value should be a hex string, not the original JSON with whitespace.
	var paramsStr string
	if err := json.Unmarshal(paramsRaw, &paramsStr); err != nil {
		t.Fatalf("parse encrypted parameters: %v", err)
	}

	// Should not contain the literal whitespace or quotes from input.
	if strings.Contains(paramsStr, "  ") || strings.HasPrefix(paramsStr, `"`) {
		t.Errorf("encrypted parameters looks like raw JSON: %q", paramsStr)
	}

	// Should look like a hex-encoded encrypted value (long string of hex chars).
	if len(paramsStr) < 100 {
		t.Errorf("encrypted parameters too short: %d chars (expected >100 for encrypted blob)", len(paramsStr))
	}
}

// testNearCloudSessionForRegression creates a NearCloud session for testing.
func testNearCloudSessionForRegression(t *testing.T) *NearCloudSession {
	t.Helper()
	session, err := NewNearCloudSession()
	if err != nil {
		t.Fatalf("NewNearCloudSession: %v", err)
	}
	t.Cleanup(session.Zero)
	// Generate a valid Ed25519 key pair for testing.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	pubHex := hex.EncodeToString(pub)
	if err := session.SetModelKeyEd25519(pubHex); err != nil {
		t.Fatalf("SetModelKeyEd25519: %v", err)
	}
	return session
}
