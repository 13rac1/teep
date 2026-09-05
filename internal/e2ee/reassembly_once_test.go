package e2ee

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/jsonstrict"
)

type countedDecryptor struct {
	Decryptor
	calls int
}

func (d *countedDecryptor) Decrypt(ciphertext string) ([]byte, error) {
	d.calls++
	return d.Decryptor.Decrypt(ciphertext)
}

func TestReassemblyDecryptsToolCallsOnce(t *testing.T) {
	session := testNearCloudSessionForRegression(t)
	defer session.Zero()
	public, err := hex.DecodeString(session.ClientEd25519PubHex())
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := Ed25519PubToX25519(public)
	if err != nil {
		t.Fatal(err)
	}
	encrypt := func(value string) string {
		encrypted, err := EncryptXChaCha20([]byte(value), recipient)
		if err != nil {
			t.Fatal(err)
		}
		return encrypted
	}
	chunk, err := json.Marshal(map[string]any{"choices": []any{map[string]any{
		"delta": map[string]any{"content": encrypt("answer"), "tool_calls": []any{map[string]any{
			"index": 0, "id": "call_1", "type": "function", "function": map[string]string{"name": encrypt("weather"), "arguments": encrypt(`{"city":"SF"}`)},
		}}}, "finish_reason": "tool_calls",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	counted := &countedDecryptor{Decryptor: session}
	result, _, err := ReassembleNonStream(strings.NewReader("data: "+string(chunk)+"\n\ndata: [DONE]\n\n"), counted, EndpointChat)
	if err != nil {
		t.Fatal(err)
	}
	if counted.calls != 3 {
		t.Fatalf("decrypt calls=%d want=3", counted.calls)
	}
	var response struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content   string                `json:"content"`
				ToolCalls []reassembledToolCall `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if _, _, err := jsonstrict.Unmarshal(result, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Choices) != 1 {
		t.Fatal("missing choice")
	}
	choice := response.Choices[0]
	if choice.FinishReason != "tool_calls" || choice.Message.Content != "answer" || len(choice.Message.ToolCalls) != 1 {
		t.Fatal("reassembled response lost content or metadata")
	}
	call := choice.Message.ToolCalls[0]
	if call.Function.Name != "weather" || call.Function.Arguments != `{"city":"SF"}` {
		t.Fatal("reassembled tool call lost decrypted fields")
	}
}
