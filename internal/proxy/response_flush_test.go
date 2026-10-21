package proxy

import (
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

type failedFlushWriter struct{ *inferenceRecorder }

func (w failedFlushWriter) FlushError() error { return io.ErrClosedPipe }
func (w failedFlushWriter) Flush()            { _ = w.FlushError() }

func TestResponseInterceptorPreservesFlushFailure(t *testing.T) {
	interceptor, writer := newResponseInterceptor(&statusRecorder{ResponseWriter: failedFlushWriter{newInferenceRecorder()}})
	if err := http.NewResponseController(writer).Flush(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("flush error = %v, want closed pipe", err)
	}
	if !interceptor.headerSent {
		t.Fatal("flush did not record committed headers")
	}
}

func TestStatusRecorderPreservesFlushFailure(t *testing.T) {
	recorder := &statusRecorder{ResponseWriter: failedFlushWriter{newInferenceRecorder()}}
	if err := http.NewResponseController(recorder).Flush(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("flush error = %v, want closed pipe", err)
	}
}

func TestAuthorizedFlushFailurePreventsSuccess(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		private := authorizedTestKey(t)
		upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			encap, err := hex.DecodeString(r.Header.Get("Ehbp-Encapsulated-Key"))
			if err != nil {
				t.Error(err)
				return
			}
			_ = decryptAuthorizedTestRequest(t, private, encap, io.LimitReader(r.Body, 1<<20))
			body, nonce := encryptAuthorizedTestResponse(t, private, encap, [][]byte{[]byte("data: {}\n\ndata: [DONE]\n\n")})
			w.Header().Set("Ehbp-Response-Nonce", nonce)
			_, _ = w.Write(body)
		}))
		defer upstream.Close()
		server, input, first := authorizedFailureFixture(t, upstream, private)
		input.stream = true
		out := server.handleAuthorizedEndpoint(t.Context(), &statusRecorder{ResponseWriter: failedFlushWriter{newInferenceRecorder()}}, input)
		if out.status != "upstream_failed" {
			t.Fatalf("status = %s, want upstream_failed", out.status)
		}
		current, ok := server.authorizations.acquire(input.key)
		if !ok || current.generation != first.generation {
			t.Fatal("downstream failure invalidated authorization")
		}
		for _, factor := range current.report.Factors {
			if factor.Name == attestation.FactorE2EEUsable && factor.Status == attestation.Pass {
				t.Fatal("failed flush promoted E2EE success")
			}
		}
	})
}
