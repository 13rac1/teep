package proxy

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// delayedResponseWriter models a write that returns only when its installed
// deadline expires. Subsequent buffered writes must not reach this writer.
type delayedResponseWriter struct {
	*inferenceRecorder
	writes int
}

func (w *delayedResponseWriter) Write([]byte) (int, error) {
	w.writes++
	if !w.deadline.IsZero() {
		<-time.After(time.Until(w.deadline) + time.Millisecond)
	}
	return 0, context.DeadlineExceeded
}

func TestCallerDeadlineStopsBufferedResponses(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, tc := range []struct {
			name   string
			stream bool
			status int
		}{
			{"stream", true, http.StatusOK},
			{"nonstream", false, http.StatusOK},
			{"encrypted_error", false, http.StatusUnprocessableEntity},
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
					plain := []byte(`{"choices":[]}`)
					if tc.stream {
						plain = []byte("data: {}\n\ndata: {}\n\ndata: [DONE]\n\n")
					}
					body, nonce := encryptAuthorizedTestResponse(t, private, encap, [][]byte{plain})
					w.Header().Set("Ehbp-Response-Nonce", nonce)
					w.WriteHeader(tc.status)
					_, _ = w.Write(body)
				}))
				defer upstream.Close()
				server, input, _ := authorizedFailureFixture(t, upstream, private)
				input.stream = tc.stream
				expires := time.Now().Add(300 * time.Millisecond)
				ctx, cancel := context.WithDeadline(t.Context(), expires)
				defer cancel()
				writer := &delayedResponseWriter{inferenceRecorder: newInferenceRecorder()}
				out := server.handleAuthorizedEndpoint(ctx, writer, input)
				if out.status != "deadline_exceeded" || writer.writes != 1 || !writer.deadline.Equal(expires) {
					t.Fatalf("status=%s writes=%d deadline=%v", out.status, writer.writes, writer.deadline)
				}
				if out.report != nil {
					for _, factor := range out.report.Factors {
						if factor.Name == attestation.FactorE2EEUsable && factor.Status == attestation.Pass {
							t.Fatal("timed out response promoted E2EE success")
						}
					}
				}
			})
		}
	})
}
