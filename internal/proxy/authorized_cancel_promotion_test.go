package proxy

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// signalRecorder closes written when a downstream write holds want.
type signalRecorder struct {
	*inferenceRecorder
	want    string
	once    sync.Once
	written chan struct{}
}

func (r *signalRecorder) Write(body []byte) (int, error) {
	n, err := r.inferenceRecorder.Write(body)
	if strings.Contains(string(body), r.want) {
		r.once.Do(func() { close(r.written) })
	}
	return n, err
}

// A client that ends a streamed NEAR request after it has a decrypted field,
// before teep reads the end of the upstream stream, leaves the request
// "canceled" but promotes E2EE usability. A client that ends it before any
// field is decrypted promotes nothing.
func TestAuthorizedNearCallerCancelPromotion(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, tc := range []struct {
			name        string
			sendContent bool
			wantUsable  bool
		}{
			{"cancel after a decrypted chunk", true, true},
			{"cancel before any decrypted chunk", false, false},
		} {
			for _, name := range []string{"nearcloud", "neardirect"} {
				t.Run(name+"/"+tc.name, func(t *testing.T) {
					release := make(chan struct{})
					sent := make(chan struct{})
					upstream, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
						w.Header().Set("Content-Type", "text/event-stream")
						if tc.sendContent {
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
							encrypted, err := e2ee.EncryptXChaCha20([]byte("answer"), recipient)
							if err != nil {
								t.Error(err)
								return
							}
							_, _ = fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q},\"finish_reason\":\"stop\"}]}\n\n", encrypted)
						} else {
							_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n")
						}
						w.(http.Flusher).Flush()
						close(sent)
						select {
						case <-release:
						case <-r.Context().Done():
						}
					}))
					server, input, first := nearCompletionAuthorization(t, name, upstream.URL, fp)
					defer close(release)
					request := *input
					request.stream = true
					want := "answer"
					if !tc.sendContent {
						want = "assistant"
					}
					rec := &signalRecorder{inferenceRecorder: newInferenceRecorder(), want: want, written: make(chan struct{})}
					ctx, cancel := context.WithCancel(t.Context())
					go func() {
						<-sent
						<-rec.written
						cancel()
					}()
					out, err := server.inferAuthorized(ctx, rec, &request)
					if err == nil {
						t.Fatal("canceled request reported no error")
					}
					if !callerCanceledOnly(ctx, err) {
						t.Fatalf("error is not the caller's cancellation alone: %v", err)
					}
					if out.status == "ok" {
						t.Error("canceled request reported status ok")
					}
					current, ok := server.authorizations.acquire(input.key)
					if !ok || current.generation != first.generation {
						t.Fatal("caller cancellation changed the authorization generation")
					}
					var usable bool
					for _, factor := range current.report.Factors {
						if factor.Name == attestation.FactorE2EEUsable {
							usable = factor.Status == attestation.Pass
						}
					}
					if usable != tc.wantUsable {
						t.Fatalf("e2ee_usable passed = %v, want %v", usable, tc.wantUsable)
					}
				})
			}
		}
	})
}
