package proxy

import (
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestAuthorizedEHBPStreamCompletion(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, test := range []struct {
			name    string
			suffix  []byte
			corrupt bool
			wantErr bool
		}{
			{name: "complete"},
			{name: "comments", suffix: []byte(": finished\n\n")},
			{name: "truncated_prefix", suffix: []byte{0, 0}, wantErr: true},
			{name: "invalid_tag", corrupt: true, wantErr: true},
			{name: "extra_data", suffix: []byte("data: {}\n\n"), wantErr: true},
			{name: "over_limit", suffix: []byte(strings.Repeat("\n", (64<<10)+1)), wantErr: true},
		} {
			t.Run(test.name, func(t *testing.T) {
				private := authorizedTestKey(t)
				upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					encap, err := hex.DecodeString(r.Header.Get("Ehbp-Encapsulated-Key"))
					if err != nil {
						t.Error(err)
						return
					}
					_ = decryptAuthorizedTestRequest(t, private, encap, io.LimitReader(r.Body, 1<<20))
					frames := [][]byte{[]byte("data: {\"choices\":[]}\n\ndata: [DONE]\n\n")}
					if test.name != "truncated_prefix" && len(test.suffix) > 0 {
						frames = append(frames, test.suffix)
					}
					if test.corrupt {
						frames = append(frames, []byte("\n"))
					}
					body, nonce := encryptAuthorizedTestResponse(t, private, encap, frames)
					if test.name == "truncated_prefix" {
						body = append(body, test.suffix...)
					}
					if test.corrupt {
						body[len(body)-1] ^= 1
					}
					w.Header().Set("Ehbp-Response-Nonce", nonce)
					_, _ = w.Write(body)
				}))
				server, input, first := authorizedFailureFixture(t, upstream, private)
				input.stream = true
				rec := newInferenceRecorder()
				out, err := server.inferAuthorized(t.Context(), rec, input)
				if (err != nil) != test.wantErr {
					t.Fatalf("status=%s error=%v", out.status, err)
				}
				if strings.Contains(rec.Body.String(), "data: [DONE]") == test.wantErr {
					t.Fatal("completion marker does not reflect validated response completion")
				}
				if test.corrupt != errors.Is(err, e2ee.ErrDecryptionFailed) {
					t.Fatalf("authentication error classification: %v", err)
				}
				value, ok := server.authorizations.acquire(input.key)
				if test.corrupt {
					if ok {
						t.Fatal("failed authentication retained authorization")
					}
					return
				}
				if !ok || value.generation != first.generation {
					t.Fatal("response framing changed authenticated authorization")
				}
				for _, factor := range value.report.Factors {
					if factor.Name == attestation.FactorE2EEUsable && (factor.Status == attestation.Pass) == test.wantErr {
						t.Fatal("report promotion does not reflect response completion")
					}
				}
			})
		}
	})
}
