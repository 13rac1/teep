package proxy

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestNearCloudImageErrorsRetainSharedAuthorization(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, encrypted := range []bool{false, true} {
			for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError} {
				var calls atomic.Int32
				var connections sync.Map
				upstream, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					connections.Store(r.RemoteAddr, true)
					if r.URL.Path == "/v1/images/generations" {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(status)
						_, _ = io.WriteString(w, cloudStaleKeyBody)
						return
					}
					writeNearPolicyChat(t, w, r)
				}))
				server, input, first := nearCompletionAuthorization(t, "nearcloud", upstream.URL, fp)
				input.provider.E2EE = encrypted
				image := *input
				image.path = "/v1/images/generations"
				image.endpoint = e2ee.EndpointImages
				image.body = []byte(`{"model":"model","prompt":"test image"}`)
				for range 2 {
					recorder := newInferenceRecorder()
					outcome := server.handleAuthorizedEndpoint(t.Context(), recorder, &image)
					if recorder.Code != status || outcome.status == "ok" {
						t.Fatal("image failure reported success or changed status")
					}
				}
				current, ok := server.authorizations.acquire(first.key)
				if !ok || current.generation != first.generation || server.negCache.Len() != 0 {
					t.Fatal("generic image errors invalidated or delayed authorization")
				}
				recorder := newInferenceRecorder()
				if _, err := server.inferAuthorized(t.Context(), recorder, input); err != nil {
					t.Fatalf("same-model chat did not reuse authorization: %v", err)
				}
				count := 0
				connections.Range(func(_, _ any) bool { count++; return true })
				if calls.Load() != 3 || count != 1 {
					t.Fatalf("image errors replayed or replaced gateway pool: calls=%d connections=%d", calls.Load(), count)
				}
			}
		}
	})
}

func writeNearPolicyChat(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	if r.Header.Get("X-Encryption-Version") == "" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"answer"}}]}`)
		return
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
	encrypted, err := e2ee.EncryptXChaCha20([]byte("answer"), recipient)
	if err != nil {
		t.Error(err)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	_, _ = fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\ndata: [DONE]\n\n", encrypted)
}

func TestNearCloudMalformedImageErrorsRetainAuthorization(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, body := range []string{"invalid JSON", strings.Repeat("x", (10<<20)+1)} {
			upstream, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = io.WriteString(w, body)
			}))
			server, input, first := nearCompletionAuthorization(t, "nearcloud", upstream.URL, fp)
			input.path = "/v1/images/generations"
			input.endpoint = e2ee.EndpointImages
			input.body = []byte(`{"model":"model","prompt":"test"}`)
			recorder := newInferenceRecorder()
			outcome := server.handleAuthorizedEndpoint(t.Context(), recorder, input)
			if outcome.status == "ok" || recorder.Body.Len() > 10<<20 {
				t.Fatal("unbounded or successful malformed image failure")
			}
			current, ok := server.authorizations.acquire(first.key)
			if !ok || current.generation != first.generation || server.negCache.Len() != 0 {
				t.Fatal("malformed image error changed authorization")
			}
		}
	})
}

func TestNearCloudImageFailuresDoNotInterruptOtherRequests(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		var calls atomic.Int32
		entered, release := make(chan struct{}), make(chan struct{})
		upstream, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			if r.URL.Path == "/v1/images/generations" {
				close(entered)
				<-release
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			writeNearPolicyChat(t, w, r)
		}))
		server, input, first := nearCompletionAuthorization(t, "nearcloud", upstream.URL, fp)
		other := *input
		var err error
		other.key, err = input.route.AuthorizationKey("nearcloud", "other")
		if err != nil {
			t.Fatal(err)
		}
		report := *first.report
		report.Model = "other"
		candidate, err := newAuthorization(other.key, &report, first.signingKey, true, false)
		if err != nil {
			t.Fatal(err)
		}
		second := loadTestAuthorization(t, server.authorizations, other.key, candidate)
		other.body = []byte(`{"model":"other","messages":[{"role":"user","content":"test"}]}`)
		image := *input
		image.path, image.endpoint = "/v1/images/generations", e2ee.EndpointImages
		image.body = []byte(`{"model":"model","prompt":"test"}`)
		var pending sync.WaitGroup
		pending.Go(func() {
			if out := server.handleAuthorizedEndpoint(t.Context(), newInferenceRecorder(), &image); out.status == "ok" {
				t.Error("image failure reported success")
			}
		})
		<-entered
		var traffic sync.WaitGroup
		for _, request := range []*authorizedRequest{input, &other} {
			traffic.Go(func() {
				if _, err := server.inferAuthorized(t.Context(), newInferenceRecorder(), request); err != nil {
					t.Errorf("concurrent chat failed: %v", err)
				}
			})
		}
		traffic.Wait()
		close(release)
		pending.Wait()
		for _, expected := range []*authorization{first, second} {
			current, ok := server.authorizations.acquire(expected.key)
			if !ok || current.generation != expected.generation {
				t.Fatal("image failure changed shared authorization")
			}
		}
		if calls.Load() != 3 || server.negCache.Len() != 0 {
			t.Fatal("image failure replayed or imposed cooldown")
		}
	})
}

func TestNearCloudImageInterruptedErrorsRetainAuthorization(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, cancelRequest := range []bool{false, true} {
			ctx, cancel := context.WithCancel(t.Context())
			var calls atomic.Int32
			upstream, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Length", "100")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = io.WriteString(w, "partial")
				if cancelRequest {
					w.(http.Flusher).Flush()
					cancel()
					<-r.Context().Done()
				}
				// Returning less than Content-Length produces a real body read error.
			}))
			server, input, first := nearCompletionAuthorization(t, "nearcloud", upstream.URL, fp)
			input.path, input.endpoint = "/v1/images/generations", e2ee.EndpointImages
			input.body = []byte(`{"model":"model","prompt":"test"}`)
			out := server.handleAuthorizedEndpoint(ctx, newInferenceRecorder(), input)
			cancel()
			current, ok := server.authorizations.acquire(first.key)
			if out.status == "ok" || calls.Load() != 1 || !ok || current.generation != first.generation || server.negCache.Len() != 0 {
				t.Fatal("interrupted image error succeeded, replayed, or invalidated authorization")
			}
		}
	})
}
