package aci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/e2ee/aciv2test"
)

// The restored form of the live request is the form the gateway hashed:
// RestoredRequestHash of it equals request.received of the live receipt.
func TestRestoredRequestHashLive(t *testing.T) {
	r, c := receiptFixture(t)
	if c.RequestHash == nil {
		t.Fatal("fixture has no request hash")
	}
	if !hashEquals(r.RequestReceived, *c.RequestHash) {
		t.Fatal("fixture request hash differs from request.received")
	}
}

func TestRestoredForm(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
		ok             bool
	}{
		{"member order kept", `{"z":1, "a":{"y":true,"b":null}}`, `{"z":1,"a":{"y":true,"b":null}}`, true},
		{"no HTML escapes", `{"a":"<b> &"}`, `{"a":"<b> &"}`, true},
		{"escapes undone", `{"a":"A\/"}`, `{"a":"A/"}`, true},
		{"control characters", `{"a":"\b\f\n\r\t\u0001"}`, `{"a":"\b\f\n\r\t\u0001"}`, true},
		{"UTF-8 as is", `{"a":"été ✓"}`, `{"a":"été ✓"}`, true},
		{"arrays", `[1, [2, {}], []]`, `[1,[2,{}],[]]`, true},
		{"short fraction", `{"t":0.7,"p":1.0,"n":-2.25}`, `{"t":0.7,"p":1.0,"n":-2.25}`, true},
		{"large unsigned", `{"a":18446744073709551615}`, `{"a":18446744073709551615}`, true},
		{"beyond u64", `{"a":18446744073709551616}`, ``, false},
		{"exponent", `{"a":1e5}`, ``, false},
		{"trailing zero", `{"a":1.50}`, ``, false},
		{"integer without fraction as float", `{"a":1.00}`, ``, false},
		{"negative zero", `{"a":-0}`, ``, false},
		{"small fraction", `{"a":0.00001}`, ``, false},
		{"line separator", `{"a":"x y"}`, ``, false},
		{"invalid UTF-8", "{\"a\":\"\xff\"}", ``, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, err := restoredForm([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if ok != tc.ok || (ok && string(got) != tc.want) {
				t.Fatalf("restoredForm = %s, %v; want %s, %v", got, ok, tc.want, tc.ok)
			}
			hash, err := RestoredRequestHash([]byte(tc.in))
			if err != nil || (hash != nil) != tc.ok {
				t.Fatalf("RestoredRequestHash = %v, %v", hash, err)
			}
		})
	}
	if _, err := RestoredRequestHash([]byte(`{"a":`)); err == nil {
		t.Fatal("RestoredRequestHash accepted a truncated body")
	}
}

// EncryptRequest records the hash of the restored body: the request that
// the gateway rebuilds from the wire body, with the plaintext in place of
// each ciphertext and stream=true.
func TestEncryptRequestRestoredHash(t *testing.T) {
	gw := aciv2test.New(t)
	raw := &attestation.RawAttestation{SigningKey: gw.PubKeyHex(), BackendFormat: attestation.FormatACI1}
	body := `{"model":"m","temperature":0.7,"messages":[{"role":"user","content":"a <b> & c"},{"role":"user","content":[{"type":"text","text":"d"}]}],"provider":{"aci_session_ids":["` + strings.Repeat("ab", 32) + `"]}}`
	got, err := NewE2EE().EncryptRequest([]byte(body), raw, e2ee.EndpointChat)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Session.Zero()
	want := `{"messages":[{"content":"a <b> & c","role":"user"},{"content":[{"type":"text","text":"d"}],"role":"user"}],"model":"m","provider":{"aci_session_ids":["` + strings.Repeat("ab", 32) + `"]},"stream":true,"temperature":0.7}`
	sum := sha256.Sum256([]byte(want))
	session := got.Session.(interface{ RestoredRequestHash() *[32]byte })
	if h := session.RestoredRequestHash(); h == nil || *h != sum {
		t.Fatalf("restored hash = %v, want sha256(%s) = %s", h, want, hex.EncodeToString(sum[:]))
	}
	// The wire body has the same members in the same order.
	var wire, restored []string
	for _, b := range [][]byte{got.Body, []byte(want)} {
		dec := json.NewDecoder(strings.NewReader(string(b)))
		var keys []string
		depth := 0
		for {
			tok, err := dec.Token()
			if err != nil {
				break
			}
			if d, ok := tok.(json.Delim); ok {
				if d == '{' || d == '[' {
					depth++
				} else {
					depth--
				}
			}
			if s, ok := tok.(string); ok && depth == 1 {
				keys = append(keys, s)
			}
		}
		if wire == nil {
			wire = keys
		} else {
			restored = keys
		}
	}
	if strings.Join(wire, ",") != strings.Join(restored, ",") {
		t.Fatalf("wire members %q, restored members %q", wire, restored)
	}
}

// A request with a value that the gateway can write in another form has no
// restored hash: the receipt check then does not cover the request.
func TestEncryptRequestRestoredHashNotReproducible(t *testing.T) {
	gw := aciv2test.New(t)
	raw := &attestation.RawAttestation{SigningKey: gw.PubKeyHex(), BackendFormat: attestation.FormatACI1}
	got, err := NewE2EE().EncryptRequest([]byte(`{"model":"m","temperature":1e-1,"messages":[{"role":"user","content":"x"}]}`), raw, e2ee.EndpointChat)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Session.Zero()
	if h := got.Session.(interface{ RestoredRequestHash() *[32]byte }).RestoredRequestHash(); h != nil {
		t.Fatal("restored hash set for a request with an exponent number")
	}
}

// The gateway restores a plaintext that parses as a JSON array as
// structured content. A string whose text is a JSON array is sent as one
// text part, so the model receives it as text, and the request that the
// gateway restores is the one that teep hashes for the receipt.
func TestEncryptRequestArrayTextStaysText(t *testing.T) {
	gw := aciv2test.New(t)
	raw := &attestation.RawAttestation{SigningKey: gw.PubKeyHex(), BackendFormat: attestation.FormatACI1}
	body := `{"model":"m","messages":[{"role":"user","content":" [1, 2]"},{"role":"user","content":"[not json"},{"role":"user","content":[{"type":"text","text":"x"}]}]}`
	got, err := NewE2EE().EncryptRequest([]byte(body), raw, e2ee.EndpointChat)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Session.Zero()
	headers := http.Header{}
	for k, v := range got.Session.(*e2ee.ACIv2Session).Headers() {
		headers.Set(k, v)
	}
	r := gw.ReadRequest(headers, got.Body)
	var wire struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(got.Body, &wire); err != nil || len(wire.Messages) != 3 {
		t.Fatalf("wire body: %v", err)
	}
	restored := string(got.Body)
	want := []string{`[{"type":"text","text":" [1, 2]"}]`, `"[not json"`, `[{"type":"text","text":"x"}]`}
	for i, m := range wire.Messages {
		plaintext, err := gw.DecryptRequestField(r, fmt.Sprintf("messages.%d.content", i), m.Content)
		if err != nil {
			t.Fatal(err)
		}
		content := aciv2test.RestoreContent(plaintext)
		if string(content) != want[i] {
			t.Errorf("message %d restored as %s, want %s", i, content, want[i])
		}
		restored = strings.Replace(restored, `"`+m.Content+`"`, string(content), 1)
	}
	hash, err := RestoredRequestHash([]byte(restored))
	if err != nil || hash == nil {
		t.Fatalf("gateway restored hash: %v, %v", hash, err)
	}
	if h := got.Session.(*e2ee.ACIv2Session).RestoredRequestHash(); h == nil || *h != *hash {
		t.Fatal("teep hashed another request than the one the gateway restores")
	}
}
