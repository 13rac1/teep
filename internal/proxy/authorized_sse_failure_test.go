package proxy

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
)

func TestAuthorizedSSEFailureClassification(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, kind := range []string{"json", "choices", "delta", "authentication", "plaintext"} {
			t.Run(fmt.Sprintf("stream_%v_%s", stream, kind), func(t *testing.T) {
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
				data := `{`
				switch kind {
				case "choices":
					data = `{"choices":42}`
				case "delta":
					data = `{"choices":[{"delta":42}]}`
				case "plaintext":
					data = `{"choices":[{"delta":{"content":"plaintext"}}]}`
				case "authentication":
					public, err := hex.DecodeString(session.ClientEd25519PubHex())
					if err != nil {
						t.Fatal(err)
					}
					recipient, err := e2ee.Ed25519PubToX25519(public)
					if err != nil {
						t.Fatal(err)
					}
					ciphertext, err := e2ee.EncryptXChaCha20([]byte("answer"), recipient)
					if err != nil {
						t.Fatal(err)
					}
					// Another genuine session cannot authenticate this ciphertext.
					other, err := e2ee.NewNearCloudSession()
					if err != nil {
						t.Fatal(err)
					}
					defer other.Zero()
					session = other
					data = fmt.Sprintf(`{"choices":[{"delta":{"content":%q}}]}`, ciphertext)
				}
				input := &authorizedRequest{provider: &provider.Provider{Name: "neardirect", E2EE: true}, key: key, endpoint: e2ee.EndpointChat, stream: stream}
				response := authorizedResponse{authorization: value, upstream: &upstreamResult{Session: session, Resp: &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("data: " + data + "\n\n"))}}}
				err = server.relayAuthorized(t.Context(), newInferenceRecorder(), input, response)
				if err == nil {
					t.Fatal("invalid response succeeded")
				}
				cryptoFailure := kind == "authentication" || kind == "plaintext"
				if errors.Is(err, e2ee.ErrDecryptionFailed) != cryptoFailure {
					t.Fatalf("incorrect error classification: %v", err)
				}
				current, retained := server.authorizations.acquire(key)
				if retained == cryptoFailure {
					t.Fatalf("authorization retained=%v", retained)
				}
				if retained && current.generation != value.generation {
					t.Fatal("protocol error changed authorization generation")
				}
			})
		}
	}
}
