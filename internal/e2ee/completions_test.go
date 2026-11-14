package e2ee

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// The prompt of a completions request is encrypted to the model key, as a
// string or each string of an array.
func TestEncryptCompletionsNearCloud(t *testing.T) {
	pubHex, seed := ed25519KeyPairHex(t)
	x25519Priv, err := ed25519SeedToX25519(seed)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body string
		want       []string
	}{
		{"string", `{"model":"m","prompt":"hello","max_tokens":5}`, []string{"hello"}},
		{"array", `{"model":"m","prompt":["hello","world"]}`, []string{"hello", "world"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encBody, session, err := EncryptCompletionsNearCloud([]byte(tc.body), testNearModelKey(t, pubHex))
			if err != nil {
				t.Fatal(err)
			}
			defer session.Zero()
			var out map[string]json.RawMessage
			if err := json.Unmarshal(encBody, &out); err != nil {
				t.Fatal(err)
			}
			var got []string
			if len(tc.want) == 1 {
				var s string
				if err := json.Unmarshal(out["prompt"], &s); err != nil {
					t.Fatal(err)
				}
				got = []string{s}
			} else if err := json.Unmarshal(out["prompt"], &got); err != nil {
				t.Fatal(err)
			}
			for i, want := range tc.want {
				pt, err := DecryptXChaCha20(got[i], x25519Priv)
				if err != nil || string(pt) != want {
					t.Errorf("prompt[%d] = %q, %v; want %q", i, pt, err, want)
				}
			}
			if strings.Contains(string(encBody), `"hello"`) {
				t.Error("the plaintext prompt is in the body")
			}
		})
	}
}

// A request shape that NEAR's E2EE cannot carry fails with
// ErrCompletionsShape before it is sent: a field outside the allowlist, or a
// content field with a value that is not "off". An integer 0 still turns
// logprobs on, so only null is off for logprobs.
func TestEncryptCompletionsNearCloudRefuses(t *testing.T) {
	pubHex, _ := ed25519KeyPairHex(t)
	for _, body := range []string{
		`{"model":"m","prompt":[1,2,3]}`,
		`{"model":"m","prompt":["hello",7]}`,
		`{"model":"m","prompt":12}`,
		`{"model":"m"}`,
		`{"model":"m","prompt":null}`,
		`{"model":"m","prompt":"hello","suffix":"end"}`,
		`{"model":"m","prompt":"hello","logprobs":5}`,
		`{"model":"m","prompt":"hello","echo":true}`,
		`{"model":"m","prompt":"hello","prompt_logprobs":1}`,
		`{"model":"m","prompt":"hello","prompt_embeds":"AAAA"}`,
		`{"model":"m","prompt":"hello","logprobs":0}`,
		`{"model":"m","prompt":"hello","logprobs":false}`,
		`{"model":"m","prompt":"hello","prompt_logprobs":0}`,
		`{"model":"m","prompt":"hello","return_token_ids":true}`,
		`{"model":"m","prompt":"hello","echo":0}`,
		`{"model":"m","prompt":"hello","some_new_field":1}`,
		`{"model":"m","prompt":[]}`,
	} {
		_, session, err := EncryptCompletionsNearCloud([]byte(body), testNearModelKey(t, pubHex))
		if !errors.Is(err, ErrCompletionsShape) || session != nil {
			t.Errorf("%s: err %v, session %v; want ErrCompletionsShape and no session", body, err, session)
		}
	}
	for _, body := range []string{
		`{"model":"m","prompt":"hello","logprobs":null,"echo":false,"suffix":null,"return_token_ids":false,"prompt_logprobs":null}`,
		`{"model":"m","prompt":"hello","max_tokens":5,"temperature":0.2,"stop":["x"],"n":1,"stream":true,"stream_options":{"include_usage":true},"seed":3}`,
	} {
		_, session, err := EncryptCompletionsNearCloud([]byte(body), testNearModelKey(t, pubHex))
		if err != nil {
			t.Errorf("%s: %v", body, err)
			continue
		}
		session.Zero()
	}
}

// A NEAR completions stream must end with [DONE], as a chat stream must.
func TestCompletionsStreamEndMarker(t *testing.T) {
	session, err := NewNearCloudSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Zero()
	if err := CheckSSEEndMarker(session, EndpointCompletions, false); err == nil {
		t.Error("a completions stream without [DONE] was accepted")
	}
	if err := CheckSSEEndMarker(session, EndpointCompletions, true); err != nil {
		t.Errorf("a completions stream with [DONE]: %v", err)
	}
}

// choices[].text of a completions response is decrypted, and a plaintext
// text fails closed, for a JSON response and for an SSE chunk.
func TestDecryptCompletionsResponse(t *testing.T) {
	session, err := NewNearCloudSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Zero()
	pub, err := hex.DecodeString(session.ClientEd25519PubHex())
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := Ed25519PubToX25519(pub)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := EncryptXChaCha20([]byte(" hello"), recipient)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := `{"id":"x","object":"text_completion","choices":[{"index":0,"text":"` + ct + `","finish_reason":"stop"}]}`
	plain := `{"id":"x","object":"text_completion","choices":[{"index":0,"text":" hello","finish_reason":"stop"}]}`

	out, err := DecryptNonStreamResponseForEndpoint([]byte(encrypted), session, EndpointCompletions)
	if err != nil || !strings.Contains(string(out), `"text":" hello"`) {
		t.Fatalf("non-stream: %s, %v", out, err)
	}
	chunk, err := DecryptSSEChunk(encrypted, session, EndpointCompletions)
	if err != nil || !strings.Contains(chunk, `"text":" hello"`) {
		t.Fatalf("SSE chunk: %s, %v", chunk, err)
	}
	if _, err := DecryptNonStreamResponseForEndpoint([]byte(plain), session, EndpointCompletions); !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("plaintext non-stream text: %v, want ErrDecryptionFailed", err)
	}
	if _, err := DecryptSSEChunk(plain, session, EndpointCompletions); !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("plaintext SSE text: %v, want ErrDecryptionFailed", err)
	}
	empty := `{"choices":[{"index":0,"text":"","finish_reason":"length","logprobs":null,"matched_stop":null}]}`
	if _, err := DecryptSSEChunk(empty, session, EndpointCompletions); err != nil {
		t.Errorf("empty text chunk: %v", err)
	}
	// A choice without text, a content key with a value, or an unknown key
	// fails closed: its content would pass outside the decrypted text.
	for _, bad := range []string{
		`{"choices":[{"index":0,"finish_reason":"stop"}]}`,
		`{"choices":[{"index":0,"text":"` + ct + `","logprobs":{"tokens":[" hello"]}}]}`,
		`{"choices":[{"index":0,"text":"` + ct + `","token_ids":[1,2,3]}]}`,
		`{"choices":[{"index":0,"text":"` + ct + `","prompt_token_ids":[4]}]}`,
		`{"choices":[{"index":0,"text":"` + ct + `","new_field":"x"}]}`,
	} {
		if _, err := DecryptNonStreamResponseForEndpoint([]byte(bad), session, EndpointCompletions); !errors.Is(err, ErrDecryptionFailed) {
			t.Errorf("non-stream %s: %v, want ErrDecryptionFailed", bad, err)
		}
		if _, err := DecryptSSEChunk(bad, session, EndpointCompletions); !errors.Is(err, ErrDecryptionFailed) {
			t.Errorf("SSE %s: %v, want ErrDecryptionFailed", bad, err)
		}
	}
}
