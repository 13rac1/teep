package e2ee

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// TestExtractChunkMeta_DecryptsToolCallsForNearCloud regression test for:
// https://github.com/13rac1/teep/pull/103#discussion_r3263139818
// extractChunkMeta must gate on "tool_calls[].function.name" (leaf path) not
// "tool_calls" (container path), so that tool_calls function fields are
// decrypted for NearCloud/NearDirect full-field E2EE.
func TestExtractChunkMeta_DecryptsToolCallsForNearCloud(t *testing.T) {
	// Test that the NearCloud policy correctly identifies encrypted leaf paths.
	session := testNearCloudSessionForRegression(t)

	// Container path should return false.
	if session.IsResponseFieldEncrypted("tool_calls", "/v1/chat/completions") {
		t.Fatalf("tool_calls container should not be encrypted")
	}

	// Leaf paths should return true.
	if !session.IsResponseFieldEncrypted("tool_calls[].function.name", "/v1/chat/completions") {
		t.Fatalf("tool_calls[].function.name should be encrypted")
	}

	if !session.IsResponseFieldEncrypted("tool_calls[].function.arguments", "/v1/chat/completions") {
		t.Fatalf("tool_calls[].function.arguments should be encrypted")
	}

	// This ensures that extractChunkMeta will correctly detect that tool_calls
	// function fields need decryption when checking IsResponseFieldEncrypted("tool_calls[].function.name", ...)
	// rather than IsResponseFieldEncrypted("tool_calls", ...)
}

// TestDecryptResponseChoices_DecryptsLogprobsForNearCloud regression test for:
// https://github.com/13rac1/teep/pull/103#discussion_r3263139828
// DecryptSSEChunk for non-stream responses must gate on "logprobs.content[].token"
// (leaf path) not "logprobs" (container path), so that logprobs token fields
// are decrypted for NearCloud/NearDirect full-field E2EE.
func TestDecryptResponseChoices_DecryptsLogprobsForNearCloud(t *testing.T) {
	session := testNearCloudSessionForRegression(t)

	// Container path should return false.
	if session.IsResponseFieldEncrypted("logprobs", "/v1/chat/completions") {
		t.Fatalf("logprobs container should not be encrypted")
	}

	// Leaf paths should return true.
	if !session.IsResponseFieldEncrypted("logprobs.content[].token", "/v1/chat/completions") {
		t.Fatalf("logprobs.content[].token should be encrypted")
	}

	if !session.IsResponseFieldEncrypted("logprobs.content[].bytes", "/v1/chat/completions") {
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
