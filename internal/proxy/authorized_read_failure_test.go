package proxy

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

type authorizedReadFailure struct{ err error }

func (r authorizedReadFailure) Read([]byte) (int, error) { return 0, r.err }

func TestAuthorizedNearReadFailureRetainsAuthorization(t *testing.T) {
	for _, readErr := range []error{context.Canceled, context.DeadlineExceeded, io.ErrUnexpectedEOF} {
		t.Run(readErr.Error(), func(t *testing.T) {
			server := newTLSBindingTestServerHandle()
			server.authorizations = newAuthorizationStore(10, 2, time.Second)
			defer server.Close()
			key, candidate := testAuthorizationCandidate(t, "model", time.Time{}, false)
			value := loadTestAuthorization(t, server.authorizations, key, candidate)
			session, err := e2ee.NewNearCloudSession()
			if err != nil {
				t.Fatal(err)
			}
			defer session.Zero()
			input := &authorizedRequest{provider: &provider.Provider{Name: "neardirect", E2EE: true}, key: key, endpoint: e2ee.EndpointChat}
			result := authorizedResponse{authorization: value, upstream: &upstreamResult{Session: session, Resp: &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(authorizedReadFailure{readErr})}}}
			err = server.relayAuthorized(t.Context(), newInferenceRecorder(), input, result)
			if !errors.Is(err, readErr) {
				t.Fatalf("lost read error: %v", err)
			}
			if errors.Is(err, e2ee.ErrDecryptionFailed) {
				t.Fatal("ordinary read failure classified as a cryptographic failure")
			}
			if _, ok := server.authorizations.acquire(key); !ok {
				t.Fatal("ordinary body read failure invalidated shared authorization")
			}
		})
	}
}

func TestAuthorizedEHBPPartialPrefixFailsClosed(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, afterFrame := range []bool{false, true} {
			for prefix := range 4 {
				t.Run(fmt.Sprintf("after_frame_%v_prefix_%d", afterFrame, prefix), func(t *testing.T) {
					private := authorizedTestKey(t)
					upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						encap, err := hex.DecodeString(r.Header.Get("Ehbp-Encapsulated-Key"))
						if err != nil {
							t.Error(err)
							return
						}
						_ = decryptAuthorizedTestRequest(t, private, encap, io.LimitReader(r.Body, 1<<20))
						body, nonce := encryptAuthorizedTestResponse(t, private, encap, [][]byte{[]byte(`{"choices":[]}`)})
						if afterFrame {
							body = append(body, body[:prefix]...)
						} else {
							body = body[:prefix]
						}
						w.Header().Set("Ehbp-Response-Nonce", nonce)
						_, _ = w.Write(body)
					}))
					defer upstream.Close()
					server, input, first := authorizedFailureFixture(t, upstream, private)
					outcome, err := server.inferAuthorized(t.Context(), newInferenceRecorder(), input)
					complete := afterFrame && prefix == 0
					if complete != (err == nil) {
						t.Fatalf("complete=%v status=%s error=%v", complete, outcome.status, err)
					}
					if !complete && !errors.Is(err, io.ErrUnexpectedEOF) {
						t.Fatalf("truncation error lost: %v", err)
					}
					value, ok := server.authorizations.acquire(input.key)
					if !ok || value.generation != first.generation {
						t.Fatal("truncation invalidated authenticated keys")
					}
					for _, factor := range value.report.Factors {
						if factor.Name == attestation.FactorE2EEUsable && (factor.Status == attestation.Pass) != complete {
							t.Fatal("E2EE report does not reflect response completion")
						}
					}
				})
			}
		}
	})
}
