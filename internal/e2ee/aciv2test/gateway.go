// Package aciv2test implements the gateway side of E2EE v2 of the
// private-ai-gateway (secp256k1 suite) for tests, from spec/e2ee-v2.md and
// separately from the client code in package e2ee, so that tests compare two
// implementations of the specification.
package aciv2test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/hkdf"
)

const (
	algo = "secp256k1-aes-256-gcm-hkdf-sha256"
	info = "aci.e2ee.v2.secp256k1"
)

// Gateway holds the attested service E2EE key.
type Gateway struct {
	t   testing.TB
	key *secp256k1.PrivateKey
}

// New returns a gateway with a fresh service key.
func New(tb testing.TB) *Gateway {
	tb.Helper()
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		tb.Fatal(err)
	}
	return &Gateway{t: tb, key: key}
}

// PubKeyHex returns the uncompressed service public key as hex.
func (g *Gateway) PubKeyHex() string {
	return hex.EncodeToString(g.key.PubKey().SerializeUncompressed())
}

// Request is the E2EE v2 context of one request, read from its headers and
// body, as the gateway reads it.
type Request struct {
	ClientKey *secp256k1.PublicKey
	ModelKey  string
	Model     string
	Nonce     string
	Timestamp int64
}

// ReadRequest checks the five E2EE v2 headers and returns the request
// context.
func (g *Gateway) ReadRequest(h http.Header, body []byte) Request {
	g.t.Helper()
	if h.Get("X-E2ee-Version") != "2" || h.Get("X-Signing-Algo") != "" {
		g.t.Fatalf("E2EE version headers: %v", h)
	}
	if h.Get("X-Model-Pub-Key") != g.PubKeyHex() {
		g.t.Fatalf("X-Model-Pub-Key = %q, want the service key", h.Get("X-Model-Pub-Key"))
	}
	nonce := h.Get("X-E2ee-Nonce")
	if len(nonce) != 64 {
		g.t.Fatalf("X-E2EE-Nonce = %q", nonce)
	}
	ts, err := strconv.ParseInt(h.Get("X-E2ee-Timestamp"), 10, 64)
	if err != nil {
		g.t.Fatalf("X-E2EE-Timestamp: %v", err)
	}
	clientRaw, err := hex.DecodeString(h.Get("X-Client-Pub-Key"))
	if err != nil {
		g.t.Fatal(err)
	}
	client, err := secp256k1.ParsePubKey(clientRaw)
	if err != nil {
		g.t.Fatal(err)
	}
	var b struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		g.t.Fatal(err)
	}
	return Request{ClientKey: client, ModelKey: h.Get("X-Model-Pub-Key"), Model: b.Model, Nonce: nonce, Timestamp: ts}
}

func (r Request) aad(tb testing.TB, purpose, field string, responseID *string) []byte {
	tb.Helper()
	m := map[string]any{"purpose": purpose, "algo": algo, "model": r.Model, "field": field, "nonce": r.Nonce, "ts": r.Timestamp}
	if responseID != nil {
		m["id"] = *responseID
	}
	raw, err := json.Marshal(m)
	if err != nil {
		tb.Fatal(err)
	}
	out, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		tb.Fatal(err)
	}
	return out
}

func gcmKey(priv *secp256k1.PrivateKey, pub *secp256k1.PublicKey) cipher.AEAD {
	var p, j secp256k1.JacobianPoint
	pub.AsJacobian(&j)
	secp256k1.ScalarMultNonConst(&priv.Key, &j, &p)
	p.ToAffine()
	x := p.X.Bytes()
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, x[:], nil, []byte(info)), key); err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

// DecryptRequestField decrypts one request field under its field path.
func (g *Gateway) DecryptRequestField(r Request, field, ciphertextHex string) (string, error) {
	g.t.Helper()
	raw, err := hex.DecodeString(ciphertextHex)
	if err != nil || len(raw) < 93 {
		return "", fmt.Errorf("bad field %q", field)
	}
	eph, err := secp256k1.ParsePubKey(raw[:65])
	if err != nil {
		return "", err
	}
	pt, err := gcmKey(g.key, eph).Open(nil, raw[65:77], raw[77:], r.aad(g.t, "aci.e2ee.request.v2", field, nil))
	return string(pt), err
}

// EncryptResponseField encrypts plaintext for the client key under the
// response AAD of field and responseID.
func (g *Gateway) EncryptResponseField(r Request, responseID, field, plaintext string) string {
	g.t.Helper()
	eph, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		g.t.Fatal(err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		g.t.Fatal(err)
	}
	ct := gcmKey(eph, r.ClientKey).Seal(nil, nonce, []byte(plaintext), r.aad(g.t, "aci.e2ee.response.v2", field, &responseID))
	return hex.EncodeToString(append(append(eph.PubKey().SerializeUncompressed(), nonce...), ct...))
}

// Stream returns an SSE chat stream whose delta contents are words, each
// encrypted under its field path, ending with [DONE] when done is true.
func (g *Gateway) Stream(r Request, responseID string, words []string, done bool) string {
	g.t.Helper()
	var b strings.Builder
	for _, w := range words {
		chunk := map[string]any{"id": responseID, "object": "chat.completion.chunk", "choices": []any{map[string]any{
			"index": 0, "delta": map[string]any{"content": g.EncryptResponseField(r, responseID, "choices.0.delta.content", w)},
		}}}
		raw, err := json.Marshal(chunk)
		if err != nil {
			g.t.Fatal(err)
		}
		b.WriteString("data: " + string(raw) + "\n\n")
	}
	if done {
		b.WriteString("data: [DONE]\n\n")
	}
	return b.String()
}
