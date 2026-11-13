package aci_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/e2ee/aciv2test"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/13rac1/teep/internal/provider/nanogpt"
	"github.com/13rac1/teep/internal/provider/phalacloud"
)

const e2eeTestBody = `{"model":"TEE/m","stream":false,"messages":[` +
	`{"role":"system","content":"be brief"},` +
	`{"role":"user","content":[ {"type":"text","text":"hi"} ]},` +
	`{"role":"assistant","name":"bot","content":null}]}`

// A request that the production encryptor and preparer build decrypts at an
// independent gateway implementation under each field path, and the
// gateway's encrypted stream decrypts in the relay.
func TestE2EERoundTrip(t *testing.T) {
	for _, prov := range []*provider.Provider{
		{Name: "phalacloud", Preparer: phalacloud.NewPreparer("k")},
		{Name: "nanogpt", Preparer: nanogpt.NewPreparer("k")},
	} {
		t.Run(prov.Name, func(t *testing.T) {
			gw := aciv2test.New(t)
			raw := &attestation.RawAttestation{BackendFormat: attestation.FormatACI1, SigningKey: gw.PubKeyHex()}
			result, err := aci.NewE2EE().EncryptRequest([]byte(e2eeTestBody), raw, e2ee.EndpointChat)
			if err != nil {
				t.Fatalf("EncryptRequest: %v", err)
			}
			session, ok := result.Session.(*e2ee.ACIv2Session)
			if !ok {
				t.Fatalf("session = %T", result.Session)
			}
			defer session.Zero()

			req := httptest.NewRequest(http.MethodPost, "https://example.com/v1/chat/completions", http.NoBody)
			if err := provider.PrepareInferenceHeaders(req, prov, session, nil, true, "/v1/chat/completions", provider.PreparationData{}); err != nil {
				t.Fatal(err)
			}
			if req.Header.Get("Authorization") != "Bearer k" {
				t.Errorf("Authorization = %q", req.Header.Get("Authorization"))
			}
			r := gw.ReadRequest(req.Header, result.Body)

			var body struct {
				Model    string                       `json:"model"`
				Stream   bool                         `json:"stream"`
				Messages []map[string]json.RawMessage `json:"messages"`
			}
			if err := json.Unmarshal(result.Body, &body); err != nil {
				t.Fatal(err)
			}
			if body.Model != "TEE/m" || !body.Stream {
				t.Errorf("model=%q stream=%v, want the clear model and stream=true", body.Model, body.Stream)
			}
			want := map[int]string{0: "be brief", 1: `[{"type":"text","text":"hi"}]`}
			for i, plaintext := range want {
				var ct string
				if err := json.Unmarshal(body.Messages[i]["content"], &ct); err != nil {
					t.Fatalf("messages.%d.content: %v", i, err)
				}
				got, err := gw.DecryptRequestField(r, fmt.Sprintf("messages.%d.content", i), ct)
				if err != nil || got != plaintext {
					t.Errorf("messages.%d.content = %q, %v; want %q", i, got, err, plaintext)
				}
				if _, err := gw.DecryptRequestField(r, "messages.9.content", ct); err == nil {
					t.Errorf("messages.%d.content decrypted under another field path", i)
				}
			}
			if string(body.Messages[2]["content"]) != "null" || string(body.Messages[2]["name"]) != `"bot"` {
				t.Errorf("message without content changed: %s", body.Messages[2]["content"])
			}

			w := httptest.NewRecorder()
			stream := gw.Stream(r, "chatcmpl-1", []string{"Hel", "lo"}, true)
			if _, err := e2ee.RelayStream(context.Background(), w, strings.NewReader(stream), session, e2ee.EndpointChat); err != nil {
				t.Fatalf("RelayStream: %v", err)
			}
			if !strings.Contains(w.Body.String(), `"content":"Hel"`) || session.DecryptedFields() != 2 {
				t.Errorf("relayed %q, %d fields", w.Body.String(), session.DecryptedFields())
			}
		})
	}
}

// A response field encrypted under another request's context does not
// decrypt: the AAD binds the request nonce, timestamp and model.
func TestE2EEResponseOfAnotherRequestFails(t *testing.T) {
	gw := aciv2test.New(t)
	raw := &attestation.RawAttestation{BackendFormat: attestation.FormatACI1, SigningKey: gw.PubKeyHex()}
	result, err := aci.NewE2EE().EncryptRequest([]byte(e2eeTestBody), raw, e2ee.EndpointChat)
	if err != nil {
		t.Fatal(err)
	}
	session := result.Session.(*e2ee.ACIv2Session)
	defer session.Zero()
	h := http.Header{}
	for k, v := range session.Headers() {
		h.Set(k, v)
	}
	r := gw.ReadRequest(h, result.Body)
	for _, tc := range []struct {
		name   string
		change func(*aciv2test.Request)
	}{
		{"other nonce", func(r *aciv2test.Request) { r.Nonce = strings.Repeat("ab", 32) }},
		{"other timestamp", func(r *aciv2test.Request) { r.Timestamp++ }},
		{"other model", func(r *aciv2test.Request) { r.Model = "TEE/other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := r
			tc.change(&other)
			stream := gw.Stream(other, "id", []string{"x"}, true)
			if _, err := e2ee.RelayStream(context.Background(), httptest.NewRecorder(), strings.NewReader(stream), session, e2ee.EndpointChat); err == nil {
				t.Fatal("field decrypted under another request context")
			}
		})
	}
}

// A request that carries free text in a field E2EE v2 cannot encrypt is
// refused before anything is sent, and the error names the field. Short
// identifiers and empty values pass.
func TestE2EERefusesUnencryptedFreeText(t *testing.T) {
	gw := aciv2test.New(t)
	raw := &attestation.RawAttestation{BackendFormat: attestation.FormatACI1, SigningKey: gw.PubKeyHex()}
	const user = `{"role":"user","content":"hi"}`
	for _, tc := range []struct {
		field string
		body  string
	}{
		{"messages.1.tool_calls", `{"model":"m","messages":[` + user + `,{"role":"assistant","content":null,"tool_calls":[{"id":"c","type":"function","function":{"name":"f","arguments":"{\"q\":\"secret\"}"}}]}]}`},
		{"messages.1.function_call", `{"model":"m","messages":[` + user + `,{"role":"assistant","content":null,"function_call":{"name":"f","arguments":"{}"}}]}`},
		{"messages.1.refusal", `{"model":"m","messages":[` + user + `,{"role":"assistant","content":"x","refusal":"no"}]}`},
		{"messages.1.audio", `{"model":"m","messages":[` + user + `,{"role":"assistant","content":"x","audio":{"id":"a1"}}]}`},
		{"prediction", `{"model":"m","messages":[` + user + `],"prediction":{"type":"content","content":"draft"}}`},
		{"tools", `{"model":"m","messages":[` + user + `],"tools":[{"type":"function","function":{"name":"f","description":"d"}}]}`},
		{"functions", `{"model":"m","messages":[` + user + `],"functions":[{"name":"f","description":"d","parameters":{}}]}`},
		{"response_format.json_schema", `{"model":"m","messages":[` + user + `],"response_format":{"type":"json_schema","json_schema":{"name":"s","schema":{}}}}`},
	} {
		t.Run(tc.field, func(t *testing.T) {
			result, err := aci.NewE2EE().EncryptRequest([]byte(tc.body), raw, e2ee.EndpointChat)
			if err == nil {
				result.Session.Zero()
				t.Fatal("EncryptRequest succeeded")
			}
			if !strings.Contains(err.Error(), tc.field+" holds free text") || !strings.Contains(err.Error(), "defines no field path") {
				t.Fatalf("err = %v, want it to name %s", err, tc.field)
			}
		})
	}
	pass := `{"model":"m","stop":["END"],"tools":[],"functions":[],"prediction":null,"response_format":{"type":"json_object"},"tool_choice":"auto","function_call":{"name":"f"},` +
		`"messages":[{"role":"user","name":"alice","content":"hi"},{"role":"assistant","content":"x","tool_calls":[],"refusal":null}]}`
	result, err := aci.NewE2EE().EncryptRequest([]byte(pass), raw, e2ee.EndpointChat)
	if err != nil {
		t.Fatalf("identifiers and empty values: %v", err)
	}
	result.Session.Zero()
}

func TestE2EERejectsRequest(t *testing.T) {
	gw := aciv2test.New(t)
	aciRaw := &attestation.RawAttestation{BackendFormat: attestation.FormatACI1, SigningKey: gw.PubKeyHex()}
	for _, tc := range []struct {
		name     string
		body     string
		raw      *attestation.RawAttestation
		endpoint e2ee.EndpointType
	}{
		{"embeddings", e2eeTestBody, aciRaw, e2ee.EndpointEmbeddings},
		{"dstack format", e2eeTestBody, &attestation.RawAttestation{BackendFormat: attestation.FormatDstack, SigningKey: gw.PubKeyHex()}, e2ee.EndpointChat},
		{"unknown format", e2eeTestBody, &attestation.RawAttestation{SigningKey: gw.PubKeyHex()}, e2ee.EndpointChat},
		{"bad key", e2eeTestBody, &attestation.RawAttestation{BackendFormat: attestation.FormatACI1, SigningKey: "04ab"}, e2ee.EndpointChat},
		{"no model", `{"messages":[{"role":"user","content":"x"}]}`, aciRaw, e2ee.EndpointChat},
		{"model not a string", `{"model":1,"messages":[{"role":"user","content":"x"}]}`, aciRaw, e2ee.EndpointChat},
		{"no content", `{"model":"m","messages":[{"role":"assistant","content":null}]}`, aciRaw, e2ee.EndpointChat},
		{"content number", `{"model":"m","messages":[{"role":"user","content":5}]}`, aciRaw, e2ee.EndpointChat},
		{"no messages", `{"model":"m"}`, aciRaw, e2ee.EndpointChat},
		{"two choices", `{"model":"m","n":2,"messages":[{"role":"user","content":"x"}]}`, aciRaw, e2ee.EndpointChat},
		{"not json", `{`, aciRaw, e2ee.EndpointChat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if result, err := aci.NewE2EE().EncryptRequest([]byte(tc.body), tc.raw, tc.endpoint); err == nil {
				result.Session.Zero()
				t.Fatal("EncryptRequest succeeded")
			}
		})
	}
}
