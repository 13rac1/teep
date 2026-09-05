package proxy

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"testing"

	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestAuthorizedEHBPResponseBoundary(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, tc := range []struct {
			name    string
			size    int
			corrupt bool
			media   string
		}{
			{"exact_limit", 10 << 20, false, "application/json"},
			{"over_limit", (10 << 20) + 1, false, "application/json"},
			{"bad_frame_after_limit", 10 << 20, true, "application/json"},
			{"speech", 128, false, "audio/mpeg"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				private := authorizedTestKey(t)
				upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					encap, err := hex.DecodeString(r.Header.Get("Ehbp-Encapsulated-Key"))
					if err != nil {
						t.Error(err)
						return
					}
					_ = decryptAuthorizedTestRequest(t, private, encap, io.LimitReader(r.Body, 1<<20))
					plaintext := bytes.Repeat([]byte(" "), tc.size)
					copy(plaintext, `{}`)
					chunks := [][]byte{plaintext}
					if tc.corrupt {
						chunks = append(chunks, []byte("tail"))
					}
					encrypted, nonce := encryptAuthorizedTestResponse(t, private, encap, chunks)
					if tc.corrupt {
						encrypted[len(encrypted)-1] ^= 1
					}
					w.Header().Set("Ehbp-Response-Nonce", nonce)
					w.Header().Set("Content-Type", tc.media)
					_, _ = w.Write(encrypted)
				}))
				defer upstream.Close()
				server, input, _ := authorizedFailureFixture(t, upstream, private)
				if tc.media == "audio/mpeg" {
					input.endpoint = e2ee.EndpointSpeech
					input.path = "/v1/audio/speech"
				}
				rec := newInferenceRecorder()
				_, err := server.inferAuthorized(t.Context(), rec, input)
				invalid := tc.corrupt || tc.size > 10<<20
				if (err != nil) != invalid {
					t.Fatalf("error=%v, want failure=%v", err, invalid)
				}
				if invalid {
					if rec.Code != http.StatusBadGateway {
						t.Fatalf("status=%d", rec.Code)
					}
				} else {
					if rec.Code != http.StatusOK || rec.Body.Len() != tc.size {
						t.Fatalf("status=%d length=%d", rec.Code, rec.Body.Len())
					}
					if rec.Header().Get("Content-Type") != tc.media {
						t.Fatal("response media type changed")
					}
				}
				_, retained := server.authorizations.acquire(input.key)
				if retained == tc.corrupt {
					t.Fatalf("authorization retained=%v", retained)
				}
			})
		}
	})
}
