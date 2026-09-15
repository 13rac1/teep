package proxy

import (
	"context"
	"errors"
	"log/slog"
	"slices"

	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/tlsct"
)

// classifyAuthorizedFailure suppresses warnings only for caller cancellation.
// Trust failures retain their failure status even if the caller also cancels.
func classifyAuthorizedFailure(ctx context.Context, err error, out *authorizedOutcome) bool {
	var status string
	source := "operation"
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		status = "deadline_exceeded"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			source = "caller"
		}
	case errors.Is(err, context.Canceled):
		status = "canceled"
		if errors.Is(ctx.Err(), context.Canceled) {
			source = "caller"
		}
	default:
		return true
	}
	out.summary = append(out.summary, slog.String("cancellation_source", source))
	if tlsct.IsTrustFailure(err) || errors.Is(err, e2ee.ErrDecryptionFailed) || hasIndependentFailure(err) {
		return true
	}
	out.status = status
	return out.status != "canceled" || source != "caller"
}

// hasIndependentFailure checks every cause so a joined cancellation cannot hide
// another failure. ErrRelayFailed classifies a relay error; its sibling cause
// identifies the failure. A wrapper with only that marker supplies its own
// failure description, such as an empty stream, and retains its warning. A
// wrapper without a cause reports its own failure.
func hasIndependentFailure(err error) bool {
	switch wrapped := err.(type) { //nolint:errorlint // Traverse immediate children, not a matching descendant.
	case interface{ Unwrap() []error }:
		return slices.ContainsFunc(wrapped.Unwrap(), hasIndependentFailure)
	case interface{ Unwrap() error }:
		cause := wrapped.Unwrap()
		if cause == nil {
			return true
		}
		if cause == e2ee.ErrRelayFailed { //nolint:errorlint // Only the direct marker lacks a separate cause to classify.
			return true
		}
		return hasIndependentFailure(cause)
	default:
		return err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, e2ee.ErrRelayFailed)
	}
}
