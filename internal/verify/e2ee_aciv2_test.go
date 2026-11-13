package verify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee/aciv2test"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// testE2EE sends one E2EE v2 request for Phala Cloud and NanoGPT and passes
// only when every content field of the response decrypts and the stream
// ends with [DONE]. A response that NanoGPT or the gateway returns in
// plaintext fails.
func TestTestE2EE_ACIv2(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, tc := range []struct {
			name    string
			respond func(w http.ResponseWriter, gw *aciv2test.Gateway, r aciv2test.Request)
			wantErr string
		}{
			{"encrypted stream", func(w http.ResponseWriter, gw *aciv2test.Gateway, r aciv2test.Request) {
				_, _ = io.WriteString(w, gw.Stream(r, "chatcmpl-1", []string{"Hel", "lo"}, true))
			}, ""},
			{"JSON response", func(w http.ResponseWriter, _ *aciv2test.Gateway, _ aciv2test.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"choices":[]}`)
			}, "is not text/event-stream"},
			{"plaintext stream", func(w http.ResponseWriter, _ *aciv2test.Gateway, _ aciv2test.Request) {
				_, _ = io.WriteString(w, `data: {"id":"x","choices":[{"index":0,"delta":{"content":"Hello"}}]}`+"\n\ndata: [DONE]\n\n")
			}, "expected encrypted string"},
			{"stream without [DONE]", func(w http.ResponseWriter, gw *aciv2test.Gateway, r aciv2test.Request) {
				_, _ = io.WriteString(w, gw.Stream(r, "chatcmpl-1", []string{"Hel"}, false))
			}, "without [DONE]"},
			{"no content", func(w http.ResponseWriter, _ *aciv2test.Gateway, _ aciv2test.Request) {
				_, _ = io.WriteString(w, `data: {"id":"x","choices":[{"index":0,"delta":{"role":"assistant"}}]}`+"\n\ndata: [DONE]\n\n")
			}, "no encrypted content fields"},
			{"payment required", func(w http.ResponseWriter, _ *aciv2test.Gateway, _ aciv2test.Request) {
				w.WriteHeader(http.StatusPaymentRequired)
			}, "HTTP 402"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				gw := aciv2test.New(t)
				ts := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					body, err := io.ReadAll(req.Body)
					if err != nil {
						t.Error(err)
						return
					}
					if req.URL.Path != "/v1/chat/completions" || req.Header.Get("Authorization") != "Bearer key" {
						t.Errorf("request %s, Authorization %q", req.URL.Path, req.Header.Get("Authorization"))
					}
					r := gw.ReadRequest(req.Header, body)
					var b struct {
						Stream    bool `json:"stream"`
						MaxTokens int  `json:"max_tokens"`
						Messages  []struct {
							Content string `json:"content"`
						} `json:"messages"`
					}
					if err := json.Unmarshal(body, &b); err != nil || !b.Stream || b.MaxTokens == 0 || len(b.Messages) != 1 {
						t.Errorf("body %s: %v", body, err)
						return
					}
					if got, err := gw.DecryptRequestField(r, "messages.0.content", b.Messages[0].Content); err != nil || got != "Say hello" {
						t.Errorf("messages.0.content = %q, %v", got, err)
					}
					if req.Header.Get("Connection") != "" {
						t.Errorf("Connection header = %q", req.Header.Get("Connection"))
					}
					w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
					tc.respond(w, gw, r)
				}))
				defer ts.Close()
				raw := &attestation.RawAttestation{BackendFormat: attestation.FormatACI1, SigningKey: gw.PubKeyHex()}
				got := testE2EE(context.Background(), raw, "phalacloud", &config.Provider{APIKey: "key", BaseURL: ts.URL}, "TEE/m", false)
				if got == nil || !got.Attempted {
					t.Fatalf("testE2EE = %+v", got)
				}
				if tc.wantErr == "" {
					if got.Err != nil || !strings.Contains(got.Detail, "E2EE v2 secp256k1: 2 encrypted fields") {
						t.Fatalf("result = %+v", got)
					}
					return
				}
				if got.Err == nil || !strings.Contains(got.Err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", got.Err, tc.wantErr)
				}
			})
		}
	})
}
