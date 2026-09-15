package proxy

import (
	"context"
	"errors"

	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/tlsct"
)

// classifyAuthorizedFailure suppresses warnings only for caller cancellation.
// Trust failures retain their failure status even if the caller also cancels.
func classifyAuthorizedFailure(ctx context.Context, err error, out *authorizedOutcome) bool {
	if tlsct.IsTrustFailure(err) || errors.Is(err, e2ee.ErrDecryptionFailed) {
		return true
	}
	source := "operation"
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		out.status = "deadline_exceeded"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			source = "caller"
		}
	case errors.Is(err, context.Canceled):
		out.status = "canceled"
		if errors.Is(ctx.Err(), context.Canceled) {
			source = "caller"
		}
	default:
		return true
	}
	out.summary = append(out.summary, "cancellation_source", source)
	return out.status != "canceled" || source != "caller"
}
