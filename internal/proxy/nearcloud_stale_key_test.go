package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

const cloudStaleKeyBody = `{"error":{"type":"provider_error","message":"The encryption key is no longer valid. Please refresh your attestation report and retry.","param":null,"code":null}}`

func TestNearCloudTLSOnlyStaleKeyInvalidation(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, late := range []bool{false, true} {
			var calls atomic.Int32
			entered, release := make(chan struct{}), make(chan struct{})
			upstream, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if len(r.Header.Values("X-Model-Pub-Key")) != 1 || r.Header.Get("X-Encryption-Version") != "" {
					t.Error("TLS-only request lacks its single routing hint or enables encryption")
				}
				close(entered)
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusMisdirectedRequest)
				_, _ = io.WriteString(w, cloudStaleKeyBody)
			}))
			server, input, first := nearCompletionAuthorization(t, "nearcloud", upstream.URL, fp)
			input.provider.E2EE = false
			done := make(chan error, 1)
			recorder := newInferenceRecorder()
			go func() { _, err := server.inferAuthorized(t.Context(), recorder, input); done <- err }()
			<-entered
			replacement := first
			if late {
				public, private, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				clear(private)
				candidate, err := newAuthorization(first.key, first.report, hex.EncodeToString(public), false, false)
				if err != nil {
					t.Fatal(err)
				}
				server.authorizations.invalidate(first.key)
				replacement = loadTestAuthorization(t, server.authorizations, first.key, candidate)
			}
			close(release)
			<-done // The ordinary upstream-error path returns the original HTTP status.
			if calls.Load() != 1 || recorder.Code != http.StatusMisdirectedRequest {
				t.Fatalf("TLS-only rejection replayed or lost its status: calls=%d status=%d", calls.Load(), recorder.Code)
			}
			current, ok := server.authorizations.acquire(first.key)
			if late {
				if !ok || current.generation != replacement.generation || subtle.ConstantTimeCompare([]byte(current.signingKey), []byte(replacement.signingKey)) != 1 {
					t.Fatal("late rejection removed replacement")
				}
			} else if ok {
				t.Fatal("stale TLS-only routing key remained authorized")
			}
		}
	})
}

func TestNearCloudE2EEStaleKeyUsesPublishedReplacement(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		model, err := e2ee.NewNearCloudSession()
		if err != nil {
			t.Fatal(err)
		}
		defer model.Zero()
		var calls atomic.Int32
		var publish func()
		ready := make(chan struct{})
		var firstClientKey atomic.Value
		upstream, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-ready
			attempt := calls.Add(1)
			if attempt == 1 {
				firstClientKey.Store(r.Header.Get("X-Client-Pub-Key"))
				publish()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusMisdirectedRequest)
				_, _ = io.WriteString(w, cloudStaleKeyBody)
				return
			}
			if attempt != 2 {
				t.Error("more than one retry")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Model-Pub-Key")), []byte(model.ClientEd25519PubHex())) != 1 {
				t.Error("retry did not use replacement routing key")
			}
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Client-Pub-Key")), []byte(firstClientKey.Load().(string))) == 1 {
				t.Error("retry reused encryption session")
			}
			data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				t.Error(err)
				return
			}
			var request struct {
				Messages []struct {
					Content string `json:"content"`
				} `json:"messages"`
			}
			if _, _, err := jsonstrict.Unmarshal(data, &request); err != nil || len(request.Messages) != 1 {
				t.Error("invalid encrypted retry request")
				return
			}
			plain, err := model.Decrypt(request.Messages[0].Content)
			if err != nil || string(plain) != "test" {
				t.Error("retry was not encrypted to replacement backend")
			}
			writeNearPolicyChat(t, w, r)
		}))
		server, input, first := nearCompletionAuthorization(t, "nearcloud", upstream.URL, fp)
		var replacement atomic.Pointer[authorization]
		publish = func() {
			candidate, err := newAuthorization(first.key, first.report, model.ClientEd25519PubHex(), true, false)
			if err != nil {
				t.Error(err)
				return
			}
			server.authorizations.invalidate(first.key)
			replacement.Store(loadTestAuthorization(t, server.authorizations, first.key, candidate))
		}
		close(ready)
		if _, err := server.inferAuthorized(t.Context(), newInferenceRecorder(), input); err != nil {
			t.Fatal(err)
		}
		current, ok := server.authorizations.acquire(first.key)
		if calls.Load() != 2 || replacement.Load() == nil || !ok || current.generation != replacement.Load().generation {
			t.Fatal("retry did not preserve already-published replacement")
		}
	})
}
