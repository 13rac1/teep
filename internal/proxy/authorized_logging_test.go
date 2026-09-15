package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/tlsct"
)

type nilCauseError struct{}

func (nilCauseError) Error() string { return "failure without cause" }
func (nilCauseError) Unwrap() error { return nil }

func TestAuthorizedFailureLoggingClassification(t *testing.T) {
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, stop := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer stop()
	for _, tc := range []struct {
		name           string
		ctx            func() context.Context
		err            error
		warn           bool
		status, source string
	}{
		{"caller_cancel", func() context.Context { return canceled }, context.Canceled, false, "canceled", "caller"},
		{"operation_cancel", t.Context, context.Canceled, true, "canceled", "operation"},
		{"caller_deadline", func() context.Context { return expired }, context.DeadlineExceeded, true, "deadline_exceeded", "caller"},
		{"operation_deadline", t.Context, context.DeadlineExceeded, true, "deadline_exceeded", "operation"},
		{"spki_and_cancel", func() context.Context { return canceled }, errors.Join(tlsct.ErrSPKIMismatch, context.Canceled), true, "upstream_failed", "caller"},
		{"decryption_and_cancel", func() context.Context { return canceled }, errors.Join(e2ee.ErrDecryptionFailed, context.Canceled), true, "upstream_failed", "caller"},
		{"wrapped_cancel", func() context.Context { return canceled }, fmt.Errorf("relay: %w: %w", e2ee.ErrRelayFailed, context.Canceled), false, "canceled", "caller"},
		{"io_and_cancel", func() context.Context { return canceled }, errors.Join(io.ErrUnexpectedEOF, context.Canceled), true, "upstream_failed", "caller"},
		{"io_and_deadline", func() context.Context { return expired }, errors.Join(io.ErrUnexpectedEOF, context.DeadlineExceeded), true, "upstream_failed", "caller"},
		{"io_and_operation_cancel", t.Context, errors.Join(io.ErrUnexpectedEOF, context.Canceled), true, "upstream_failed", "operation"},
		{"io_and_operation_deadline", t.Context, errors.Join(io.ErrUnexpectedEOF, context.DeadlineExceeded), true, "upstream_failed", "operation"},
		{"wrapper_without_cause_and_cancel", func() context.Context { return canceled }, errors.Join(nilCauseError{}, context.Canceled), true, "upstream_failed", "caller"},
		{"nested_failure", func() context.Context { return canceled }, fmt.Errorf("relay: %w", errors.Join(context.Canceled, errors.New("invalid SSE completion"))), true, "upstream_failed", "caller"},
		{"io_after_cancel", func() context.Context { return canceled }, errors.New("unexpected EOF"), true, "upstream_failed", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := authorizedOutcome{status: "upstream_failed"}
			warn := classifyAuthorizedFailure(tc.ctx(), tc.err, &out)
			source, _ := diagnosticFields(t, out.summary)["cancellation_source"].(string)
			if warn != tc.warn || out.status != tc.status || source != tc.source {
				t.Fatalf("warn=%v status=%s source=%s", warn, out.status, source)
			}
		})
	}
}

// These input failures have a diagnostic on the ErrRelayFailed wrapper rather
// than a second wrapped cause. Cancellation while sending the error must not
// hide the input failure. No cryptography is involved in these input checks.
func TestRelayInputFailureRetainsWarningAfterCancellation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		stream     bool
		body       string
		diagnostic string
	}{
		{"empty_stream", true, "", "empty upstream stream"},
		{"response_size_limit", false, strings.Repeat("x", (10<<20)+1), "upstream response exceeds 10 MiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			writer, err := newResponseLifetime(ctx, cancelResponseWriter{newInferenceRecorder(), cancel})
			if err != nil {
				t.Fatal(err)
			}
			_, relayErr := relayResponse(ctx, writer, strings.NewReader(tc.body), nil, nil, tc.stream, e2ee.EndpointChat)
			if relayErr == nil || !strings.Contains(relayErr.Error(), tc.diagnostic) {
				t.Fatalf("missing input failure: %v", relayErr)
			}
			if !errors.Is(writer.check(), context.Canceled) {
				t.Fatal("error response did not cancel caller")
			}
			out := authorizedOutcome{status: "upstream_failed"}
			if !classifyAuthorizedFailure(ctx, errors.Join(relayErr, writer.check()), &out) || out.status != "upstream_failed" {
				t.Fatalf("input failure hidden by cancellation: %s", out.status)
			}
		})
	}
}
