package proxy

import (
	"context"
	"errors"
	"fmt"
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

func TestAuthorizedNonStreamFailureDiagnostics(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		for _, writeFailure := range []bool{false, true} {
			t.Run(fmt.Sprintf("status=%d/write_failure=%t", status, writeFailure), func(t *testing.T) {
				server := newTLSBindingTestServerHandle()
				defer server.Close()
				key, value := testAuthorizationCandidate(t, "model")
				input := &authorizedRequest{key: key, endpoint: e2ee.EndpointChat}
				const response = "private response"
				var body io.Reader = strings.NewReader(response)
				var writer http.ResponseWriter = newInferenceRecorder()
				wantOperation, wantErr := "response_body_read", io.ErrUnexpectedEOF
				if writeFailure {
					writer = partialDiagnosticWriter{newInferenceRecorder()}
					wantOperation, wantErr = "downstream_write", io.ErrClosedPipe
				} else {
					body = io.MultiReader(body, authorizedReadFailure{io.ErrUnexpectedEOF})
				}
				// Exercise response I/O without replacing a cryptographic pathway.
				result := authorizedResponse{authorization: value, upstream: &upstreamResult{Resp: &http.Response{
					StatusCode: status, Header: make(http.Header), Body: io.NopCloser(body),
				}}}
				err := server.relayAuthorized(t.Context(), writer, input, &result)
				if !errors.Is(err, wantErr) {
					t.Fatalf("lost response failure: %v", err)
				}
				fields := diagnosticFields(t, result.relayDiagnostics)
				if fields["response_io_failure"] != wantOperation || fields["response_body_read_failed"] != !writeFailure || fields["response_body_bytes_read"] != int64(len(response)) || fields["response_last_read_ago"] == nil {
					t.Fatalf("incorrect response diagnostics: %v", fields)
				}
				if fields["stream_chunks_processed"] != nil || strings.Contains(fmt.Sprint(result.relayDiagnostics), response) {
					t.Fatalf("unexpected response diagnostics: %v", fields)
				}
			})
		}
	}
}
