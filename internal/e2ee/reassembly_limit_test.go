package e2ee

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func reassemblyEncryptedStream(t *testing.T, size int, tools bool) (string, *NearCloudSession) {
	t.Helper()
	session := testNearCloudSessionForRegression(t)
	t.Cleanup(session.Zero)
	public, err := hex.DecodeString(session.ClientEd25519PubHex())
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := Ed25519PubToX25519(public)
	if err != nil {
		t.Fatal(err)
	}
	var stream strings.Builder
	for size > 0 {
		n := min(size, 128<<10)
		ciphertext, err := EncryptXChaCha20([]byte(strings.Repeat("x", n)), recipient)
		if err != nil {
			t.Fatal(err)
		}
		delta := map[string]any{"content": ciphertext}
		if tools {
			delta = map[string]any{"tool_calls": []any{map[string]any{"index": 0, "function": map[string]string{"arguments": ciphertext}}}}
		}
		chunk, err := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": delta}}})
		if err != nil {
			t.Fatal(err)
		}
		stream.WriteString("data: " + string(chunk) + "\n\n")
		size -= n
	}
	stream.WriteString("data: [DONE]\n\n")
	return stream.String(), session
}

func TestReassemblyResponseLimit(t *testing.T) {
	for _, tools := range []bool{false, true} {
		name := "content"
		if tools {
			name = "tool_arguments"
		}
		t.Run(name, func(t *testing.T) {
			small, session := reassemblyEncryptedStream(t, 1, tools)
			result, _, err := ReassembleNonStream(strings.NewReader(small), session, EndpointChat)
			if err != nil {
				t.Fatal(err)
			}
			overhead := len(result) - 1
			for _, extra := range []int{0, 1} {
				stream, session := reassemblyEncryptedStream(t, maxNonStreamResponseBytes-overhead+extra, tools)
				result, _, err := ReassembleNonStream(strings.NewReader(stream), session, EndpointChat)
				if extra == 0 {
					if err != nil || len(result) != maxNonStreamResponseBytes {
						t.Fatalf("exact limit: bytes=%d error=%v", len(result), err)
					}
				} else if err == nil || result != nil || errors.Is(err, ErrDecryptionFailed) {
					t.Fatalf("overflow: bytes=%d error=%v", len(result), err)
				}
			}
		})
	}
}

func TestReassemblyInputLimit(t *testing.T) {
	stream, session := reassemblyEncryptedStream(t, 1, false)
	// Comments exercise the aggregate bound independently of decrypted output.
	for _, extra := range []int{0, 1} {
		padding := maxReassemblyInputBytes - len(stream) + extra
		comments := strings.Repeat(":"+strings.Repeat(" ", 1022)+"\n", padding/1024) + strings.Repeat("\n", padding%1024)
		body := &io.LimitedReader{R: strings.NewReader(comments + stream), N: int64(maxReassemblyInputBytes + 100)}
		result, _, err := ReassembleNonStream(body, session, EndpointChat)
		if (err != nil) != (extra != 0) {
			t.Fatalf("extra=%d error=%v", extra, err)
		}
		if extra != 0 && (result != nil || errors.Is(err, ErrDecryptionFailed)) {
			t.Fatal("input overflow returned output or invalidated keys")
		}
	}
}
