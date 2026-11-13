package e2ee

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const aciv2TestModel = "TEE/test-model"

// aciv2Gateway plays the gateway side of E2EE v2 for one session: it holds
// the attested service key and uses the production field functions.
type aciv2Gateway struct {
	t   *testing.T
	key *secp256k1.PrivateKey
}

func newACIv2Gateway(t *testing.T) *aciv2Gateway {
	t.Helper()
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &aciv2Gateway{t: t, key: key}
}

func (g *aciv2Gateway) pubHex() string {
	return hex.EncodeToString(g.key.PubKey().SerializeUncompressed())
}

func (g *aciv2Gateway) session() *ACIv2Session {
	g.t.Helper()
	s, err := NewACIv2Session(g.pubHex(), aciv2TestModel, time.Unix(1750000000, 0))
	if err != nil {
		g.t.Fatal(err)
	}
	g.t.Cleanup(s.Zero)
	return s
}

// encryptResponse encrypts plaintext for the session's client key under the
// response AAD of field and responseID.
func (g *aciv2Gateway) encryptResponse(s *ACIv2Session, responseID, field, plaintext string) string {
	g.t.Helper()
	aad, err := s.aad(aciv2ResponsePurpose, field, &responseID)
	if err != nil {
		g.t.Fatal(err)
	}
	ct, err := sealACIv2([]byte(plaintext), s.privateKey.PubKey(), aad)
	if err != nil {
		g.t.Fatal(err)
	}
	return ct
}

// decryptRequest decrypts a request field under the request AAD of field.
func (g *aciv2Gateway) decryptRequest(s *ACIv2Session, field, ct string) ([]byte, error) {
	g.t.Helper()
	aad, err := s.aad(aciv2RequestPurpose, field, nil)
	if err != nil {
		g.t.Fatal(err)
	}
	return openACIv2(ct, g.key, aad)
}

// The AAD bytes match the byte-exact vectors of spec/e2ee-v2-test-vectors.md
// of the private-ai-gateway.
func TestACIv2AADTestVectors(t *testing.T) {
	const nonce = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	const algo = "x25519-aes-256-gcm-hkdf-sha256"
	id := "chatcmpl-123"
	for _, tc := range []struct {
		name string
		in   aciv2AADInput
		want string
	}{
		{"request", aciv2AADInput{purpose: aciv2RequestPurpose, algo: algo, model: "demo-model", field: "messages.0.content", nonce: nonce, ts: 1750000000},
			`{"algo":"x25519-aes-256-gcm-hkdf-sha256","field":"messages.0.content","model":"demo-model","nonce":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","purpose":"aci.e2ee.request.v2","ts":1750000000}`},
		{"response", aciv2AADInput{purpose: aciv2ResponsePurpose, algo: algo, model: "demo-model", field: "choices.0.message.content", nonce: nonce, ts: 1750000000, responseID: &id},
			`{"algo":"x25519-aes-256-gcm-hkdf-sha256","field":"choices.0.message.content","id":"chatcmpl-123","model":"demo-model","nonce":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","purpose":"aci.e2ee.response.v2","ts":1750000000}`},
	} {
		got, err := aciv2AAD(&tc.in)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tc.want {
			t.Errorf("%s AAD:\n got %s\nwant %s", tc.name, got, tc.want)
		}
	}
}

func TestACIv2Headers(t *testing.T) {
	g := newACIv2Gateway(t)
	s := g.session()
	h := s.Headers()
	if len(h) != 5 || h["X-E2EE-Version"] != "2" || h["X-Model-Pub-Key"] != g.pubHex() || h["X-E2EE-Timestamp"] != "1750000000" {
		t.Fatalf("headers = %v", h)
	}
	if n := h["X-E2EE-Nonce"]; len(n) != 64 || strings.Trim(n, "0123456789abcdef") != "" {
		t.Errorf("nonce = %q, want 64 lowercase hex", n)
	}
	if _, err := parseUncompressedSecp256k1(h["X-Client-Pub-Key"]); err != nil {
		t.Errorf("client key: %v", err)
	}
	if other := g.session(); other.Headers()["X-E2EE-Nonce"] == h["X-E2EE-Nonce"] {
		t.Error("two sessions share a request nonce")
	}
}

func TestNewACIv2SessionRejectsInput(t *testing.T) {
	g := newACIv2Gateway(t)
	if _, err := NewACIv2Session(g.pubHex(), "", time.Now()); err == nil {
		t.Error("empty model accepted")
	}
	for _, key := range []string{"", g.pubHex()[2:], "02" + g.pubHex()[2:], "04" + strings.Repeat("zz", 64), "04" + strings.Repeat("00", 64)} {
		if _, err := NewACIv2Session(key, aciv2TestModel, time.Now()); err == nil {
			t.Errorf("model key %q accepted", key)
		}
	}
}

// A request field decrypts only under its own field path and request context.
func TestACIv2RequestField(t *testing.T) {
	g := newACIv2Gateway(t)
	s := g.session()
	ct, err := s.EncryptRequestField("messages.0.content", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := g.decryptRequest(s, "messages.0.content", ct); err != nil || string(got) != "hello" {
		t.Fatalf("decrypt = %q, %v", got, err)
	}
	if _, err := g.decryptRequest(s, "messages.1.content", ct); err == nil {
		t.Error("ciphertext moved to another field decrypted")
	}
	if _, err := g.decryptRequest(g.session(), "messages.0.content", ct); err == nil {
		t.Error("ciphertext decrypted under another request nonce")
	}
}

func chunkJSON(t *testing.T, v any) map[string]json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestACIv2DecryptChunk(t *testing.T) {
	g := newACIv2Gateway(t)
	s := g.session()
	full := chunkJSON(t, map[string]any{
		"id": "chatcmpl-1",
		"choices": []any{
			map[string]any{"index": 0, "delta": map[string]any{
				"role":              "assistant",
				"content":           g.encryptResponse(s, "chatcmpl-1", "choices.0.delta.content", "Hello"),
				"reasoning_content": g.encryptResponse(s, "chatcmpl-1", "choices.0.delta.reasoning_content", "think"),
				"refusal":           nil,
				"tool_calls":        []any{},
			}},
		},
	})
	if err := s.DecryptChunk(full); err != nil {
		t.Fatalf("DecryptChunk: %v", err)
	}
	var choices []struct {
		Delta map[string]any `json:"delta"`
	}
	if err := json.Unmarshal(full["choices"], &choices); err != nil {
		t.Fatal(err)
	}
	if choices[0].Delta["content"] != "Hello" || choices[0].Delta["reasoning_content"] != "think" {
		t.Fatalf("decrypted choices = %+v", choices)
	}
	if s.DecryptedFields() != 2 {
		t.Errorf("DecryptedFields = %d, want 2", s.DecryptedFields())
	}
}

// The first chunk with a choice fixes the response id of the stream: a
// later chunk with another id fails, also when its fields decrypt under
// that id.
func TestACIv2DecryptChunkPinsResponseID(t *testing.T) {
	g := newACIv2Gateway(t)
	s := g.session()
	chunk := func(id string) map[string]json.RawMessage {
		return chunkJSON(t, map[string]any{"id": id, "choices": []any{map[string]any{"index": 0, "delta": map[string]any{
			"content": g.encryptResponse(s, id, "choices.0.delta.content", "x"),
		}}}})
	}
	if err := s.DecryptChunk(chunkJSON(t, map[string]any{"id": "usage-only", "choices": []any{}})); err != nil {
		t.Fatalf("chunk without a choice: %v", err)
	}
	if err := s.DecryptChunk(chunk("id-1")); err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	if err := s.DecryptChunk(chunk("id-1")); err != nil {
		t.Fatalf("second chunk with the same id: %v", err)
	}
	if err := s.DecryptChunk(chunk("id-2")); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("chunk with another id: err = %v, want ErrDecryptionFailed", err)
	}
}

// Every chunk that is not fully E2EE v2 protected fails with
// ErrDecryptionFailed.
func TestACIv2DecryptChunkFailsClosed(t *testing.T) {
	g := newACIv2Gateway(t)
	s := g.session()
	ct := g.encryptResponse(s, "id-1", "choices.0.delta.content", "secret")
	for _, tc := range []struct {
		name  string
		chunk map[string]any
	}{
		{"plaintext content", map[string]any{"id": "id-1", "choices": []any{map[string]any{"delta": map[string]any{"content": "plain"}}}}},
		{"content of another choice", map[string]any{"id": "id-1", "choices": []any{map[string]any{"index": 1, "delta": map[string]any{"content": ct}}}}},
		{"other response id", map[string]any{"id": "id-2", "choices": []any{map[string]any{"delta": map[string]any{"content": ct}}}}},
		{"content as reasoning", map[string]any{"id": "id-1", "choices": []any{map[string]any{"delta": map[string]any{"reasoning": ct}}}}},
		{"tool calls", map[string]any{"id": "id-1", "choices": []any{map[string]any{"delta": map[string]any{"tool_calls": []any{map[string]any{"index": 0}}}}}}},
		{"refusal", map[string]any{"id": "id-1", "choices": []any{map[string]any{"delta": map[string]any{"refusal": "no"}}}}},
		{"logprobs", map[string]any{"id": "id-1", "choices": []any{map[string]any{"delta": map[string]any{}, "logprobs": map[string]any{"content": []any{}}}}}},
		{"non-stream message", map[string]any{"id": "id-1", "choices": []any{map[string]any{"message": map[string]any{"content": "plain"}}}}},
		{"completion text", map[string]any{"id": "id-1", "choices": []any{map[string]any{"text": "plain"}}}},
		{"content not a string", map[string]any{"id": "id-1", "choices": []any{map[string]any{"delta": map[string]any{"content": []any{"x"}}}}}},
		{"id not a string", map[string]any{"id": 7, "choices": []any{}}},
		{"negative index", map[string]any{"choices": []any{map[string]any{"index": -1, "delta": map[string]any{}}}}},
		{"null index", map[string]any{"id": "id-1", "choices": []any{map[string]any{"index": nil, "delta": map[string]any{"content": ct}}}}},
		{"two choices", map[string]any{"id": "id-1", "choices": []any{
			map[string]any{"index": 0, "delta": map[string]any{"content": ct}},
			map[string]any{"index": 0, "delta": map[string]any{"content": ct}},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.DecryptChunk(chunkJSON(t, tc.chunk))
			if !errors.Is(err, ErrDecryptionFailed) {
				t.Fatalf("err = %v, want ErrDecryptionFailed", err)
			}
		})
	}
	s.Zero()
	full := chunkJSON(t, map[string]any{"id": "id-1", "choices": []any{map[string]any{"delta": map[string]any{"content": ct}}}})
	if err := s.DecryptChunk(full); !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("zeroed session: err = %v", err)
	}
}

// Relay paths that do not know E2EE v2 fail instead of passing fields through.
func TestACIv2GenericPathsFailClosed(t *testing.T) {
	g := newACIv2Gateway(t)
	s := g.session()
	if _, err := s.Decrypt(g.encryptResponse(s, "", "choices.0.delta.content", "x")); err == nil {
		t.Error("Decrypt without field context succeeded")
	}
	if _, err := DecryptNonStreamResponseForEndpoint([]byte(`{"choices":[]}`), s, EndpointChat); !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("non-stream: err = %v", err)
	}
	if _, err := DecryptSSEChunk(`{"choices":[]}`, s, EndpointEmbeddings); !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("embeddings chunk: err = %v", err)
	}
	if err := CheckSSEEndMarker(s, EndpointChat, false); !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("missing [DONE]: err = %v", err)
	}
	if err := CheckSSEEndMarker(s, EndpointChat, true); err != nil {
		t.Errorf("with [DONE]: err = %v", err)
	}
	if !s.IsResponseFieldEncrypted(EncFieldContent, EndpointChat) || s.IsResponseFieldEncrypted(EncFieldContent, EndpointEmbeddings) || s.IsResponseFieldEncrypted(EncFieldRefusal, EndpointChat) {
		t.Error("IsResponseFieldEncrypted policy")
	}
}

func aciv2Stream(t *testing.T, g *aciv2Gateway, s *ACIv2Session, done bool) string {
	t.Helper()
	var b strings.Builder
	for i, word := range []string{"Hel", "lo"} {
		chunk := map[string]any{"id": "chatcmpl-9", "object": "chat.completion.chunk", "choices": []any{map[string]any{
			"index": 0, "delta": map[string]any{"content": g.encryptResponse(s, "chatcmpl-9", "choices.0.delta.content", word)},
		}}}
		if i == 1 {
			chunk["choices"].([]any)[0].(map[string]any)["finish_reason"] = "stop"
		}
		raw, err := json.Marshal(chunk)
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString("data: " + string(raw) + "\n\n")
	}
	if done {
		b.WriteString("data: [DONE]\n\n")
	}
	return b.String()
}

func TestACIv2RelayStream(t *testing.T) {
	g := newACIv2Gateway(t)
	s := g.session()
	w := httptest.NewRecorder()
	if _, err := RelayStream(context.Background(), w, strings.NewReader(aciv2Stream(t, g, s, true)), s, EndpointChat); err != nil {
		t.Fatalf("RelayStream: %v", err)
	}
	if body := w.Body.String(); !strings.Contains(body, `"content":"Hel"`) || !strings.Contains(body, `"content":"lo"`) {
		t.Fatalf("relayed body = %s", body)
	}

	s2 := g.session()
	if _, err := RelayStream(context.Background(), httptest.NewRecorder(), strings.NewReader(aciv2Stream(t, g, s2, false)), s2, EndpointChat); !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("stream without [DONE]: err = %v", err)
	}
}

func TestACIv2ReassembledNonStream(t *testing.T) {
	g := newACIv2Gateway(t)
	s := g.session()
	w := httptest.NewRecorder()
	if _, err := RelayReassembledNonStream(context.Background(), w, strings.NewReader(aciv2Stream(t, g, s, true)), s, EndpointChat); err != nil {
		t.Fatalf("RelayReassembledNonStream: %v", err)
	}
	var resp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse %s: %v", w.Body.String(), err)
	}
	if len(resp.Choices) != 1 || resp.Choices[0].Message.Content != "Hello" {
		t.Fatalf("reassembled = %s", w.Body.String())
	}
}
