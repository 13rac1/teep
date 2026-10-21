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

type cancelFailedResponseWriter struct {
	*inferenceRecorder
	cancel context.CancelFunc
	flush  bool
}

func (w cancelFailedResponseWriter) Write(p []byte) (int, error) {
	if w.flush {
		return w.inferenceRecorder.Write(p)
	}
	w.cancel()
	return 0, io.ErrClosedPipe
}

func (w cancelFailedResponseWriter) FlushError() error {
	w.cancel()
	return io.ErrClosedPipe
}

func TestAuthorizedDownstreamFailureSurvivesCancellation(t *testing.T) {
	for _, flush := range []bool{false, true} {
		name := "write"
		if flush {
			name = "flush"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			server := newTLSBindingTestServerHandle()
			defer server.Close()
			key, value := testAuthorizationCandidate(t, "model")
			input := &authorizedRequest{key: key, stream: flush, endpoint: e2ee.EndpointChat}
			body := "{}"
			if flush {
				body = "data: {}\n\ndata: [DONE]\n\n"
			}
			// Exercise response I/O only; no network or cryptographic failure is simulated.
			result := authorizedResponse{authorization: value, upstream: &upstreamResult{Resp: &http.Response{
				StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)),
			}}}
			writer := cancelFailedResponseWriter{newInferenceRecorder(), cancel, flush}
			err := server.relayAuthorized(ctx, writer, input, &result)
			if !errors.Is(err, context.Canceled) || !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("lost downstream failure or cancellation: %v", err)
			}
			if strings.Count(err.Error(), io.ErrClosedPipe.Error()) != 1 || strings.Count(err.Error(), context.Canceled.Error()) != 1 {
				t.Fatalf("duplicate downstream failure or cancellation: %v", err)
			}
			out := authorizedOutcome{status: "upstream_failed"}
			if !classifyAuthorizedFailure(ctx, err, &out) || out.status != "upstream_failed" {
				t.Fatalf("downstream failure suppressed: %s", out.status)
			}
		})
	}
}

func TestReassemblyReadFailureDiagnosticOwnership(t *testing.T) {
	for _, readErr := range []error{context.Canceled, io.ErrUnexpectedEOF} {
		t.Run(readErr.Error(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cancel()
			session, err := e2ee.NewNearCloudSession()
			if err != nil {
				t.Fatal(err)
			}
			defer session.Zero()
			_, err = relayResponse(ctx, newInferenceRecorder(), authorizedReadFailure{readErr}, session, nil, false, e2ee.EndpointChat)
			if !errors.Is(err, readErr) || !errors.Is(err, e2ee.ErrRelayFailed) {
				t.Fatalf("lost reassembly failure: %v", err)
			}
			out := authorizedOutcome{status: "upstream_failed"}
			if warn := classifyAuthorizedFailure(ctx, err, &out); warn != !errors.Is(readErr, context.Canceled) {
				t.Fatalf("incorrect reassembly warning: %v", warn)
			}
		})
	}
}
