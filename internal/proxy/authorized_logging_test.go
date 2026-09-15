package proxy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/tlsct"
)

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
		{"spki_and_cancel", func() context.Context { return canceled }, errors.Join(tlsct.ErrSPKIMismatch, context.Canceled), true, "upstream_failed", ""},
		{"decryption_and_cancel", func() context.Context { return canceled }, errors.Join(e2ee.ErrDecryptionFailed, context.Canceled), true, "upstream_failed", ""},
		{"io_after_cancel", func() context.Context { return canceled }, errors.New("unexpected EOF"), true, "upstream_failed", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := authorizedOutcome{status: "upstream_failed"}
			warn := classifyAuthorizedFailure(tc.ctx(), tc.err, &out)
			source := ""
			if len(out.summary) != 0 {
				source = out.summary[1].(string)
			}
			if warn != tc.warn || out.status != tc.status || source != tc.source {
				t.Fatalf("warn=%v status=%s source=%s", warn, out.status, source)
			}
		})
	}
}
