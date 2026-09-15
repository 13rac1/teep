package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/e2ee"
)

func TestAuthorizedHTTPFailurePreservesBodyReadError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"complete", nil},
		{"truncated", io.ErrUnexpectedEOF},
		{"canceled", context.Canceled},
		{"deadline", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newTLSBindingTestServerHandle()
			defer server.Close()
			key, value := testAuthorizationCandidate(t, "model")
			input := &authorizedRequest{key: key, endpoint: e2ee.EndpointChat}
			var body io.Reader = strings.NewReader("upstream unavailable")
			if tc.err != nil {
				body = io.MultiReader(body, authorizedReadFailure{tc.err})
			}
			// Exercise copying an HTTP error response, without network or encryption.
			result := authorizedResponse{authorization: value, upstream: &upstreamResult{Resp: &http.Response{
				StatusCode: http.StatusServiceUnavailable, Header: make(http.Header), Body: io.NopCloser(body),
			}}}
			writer := newInferenceRecorder()
			err := server.relayAuthorized(t.Context(), writer, input, &result)
			if err == nil || !strings.Contains(err.Error(), "upstream returned HTTP 503") || writer.Code != http.StatusServiceUnavailable {
				t.Fatalf("HTTP failure lost: status=%d error=%v", writer.Code, err)
			}
			if tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatalf("body read failure lost: %v", err)
			}
			if strings.Contains(err.Error(), "upstream unavailable") {
				t.Fatal("response content included in diagnostic")
			}
		})
	}
}
