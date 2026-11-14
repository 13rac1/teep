package proxy

import (
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// A NearDirect completion is end-to-end encrypted: the upstream receives no
// plaintext prompt, the encrypted choices[].text is decrypted for the client,
// and e2ee_usable is confirmed.
func TestNearDirectCompletionsE2EE(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		upstream, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if strings.Contains(string(body), "Say hello") {
				t.Error("the plaintext prompt reached the upstream")
			}
			if r.URL.Path != "/v1/completions" {
				t.Errorf("path = %s", r.URL.Path)
			}
			public, err := hex.DecodeString(r.Header.Get("X-Client-Pub-Key"))
			if err != nil {
				t.Error(err)
				return
			}
			recipient, err := e2ee.Ed25519PubToX25519(public)
			if err != nil {
				t.Error(err)
				return
			}
			ct, err := e2ee.EncryptXChaCha20([]byte(" hello"), recipient)
			if err != nil {
				t.Error(err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"c","object":"text_completion","choices":[{"index":0,"text":"`+ct+`","finish_reason":"stop"}]}`)
		}))
		server, input, first := nearCompletionAuthorization(t, "neardirect", upstream.URL, fp)
		request := *input
		request.body = []byte(`{"model":"model","prompt":"Say hello","max_tokens":5}`)
		request.path = "/v1/completions"
		request.endpoint = e2ee.EndpointCompletions
		rec := newInferenceRecorder()
		out, err := server.inferAuthorized(t.Context(), rec, &request)
		if err != nil || out.status != "ok" {
			t.Fatalf("inferAuthorized: %v, status %q", err, out.status)
		}
		if !strings.Contains(rec.Body.String(), `"text":" hello"`) {
			t.Fatalf("body = %s", rec.Body.String())
		}
		current, ok := server.authorizations.acquire(input.key)
		if !ok || current.generation != first.generation {
			t.Fatal("authorization changed")
		}
		var usable bool
		for _, f := range current.report.Factors {
			if f.Name == attestation.FactorE2EEUsable {
				usable = f.Status == attestation.Pass
			}
		}
		if !usable {
			t.Error("an E2EE completion did not confirm e2ee_usable")
		}
	})
}
