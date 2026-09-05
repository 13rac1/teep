package tlsct

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http/httptrace"
	"sync/atomic"
	"time"
)

// InferenceAttempt records whether any connection was assigned to an attempt.
// The flag remains set across any transport-internal retry.
type InferenceAttempt struct{ assigned atomic.Bool }

// Context attaches the per-attempt connection assignment trace.
func (a *InferenceAttempt) Context(ctx context.Context) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { a.assigned.Store(true) }})
}

// RetryConnectionFailure accepts only typed establishment failures before
// GotConn. TLS verification errors and ambiguous EOF/reset errors do not match.
func (a *InferenceAttempt) RetryConnectionFailure(ctx context.Context, err error) bool {
	if err == nil || errors.Is(err, ErrConnectionCapacity) || ctx.Err() != nil || a.assigned.Load() || IsTrustFailure(err) {
		return false
	}
	if dns, ok := errors.AsType[*net.DNSError](err); ok {
		return dns.IsTemporary || dns.IsTimeout
	}
	if op, ok := errors.AsType[*net.OpError](err); ok {
		return op.Op == "dial"
	}
	return false
}

// RunInferenceAttempts permits at most one application retry under one caller
// deadline. The callback cleans up a rejected attempt before requesting retry.
func RunInferenceAttempts[T any](ctx context.Context, attempt func(context.Context) (T, bool, error)) (T, error) {
	var result T
	for n := range 2 {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		value, retry, err := attempt(ctx)
		result = value
		if !retry || n == 1 {
			return result, err
		}
	}
	panic("unreachable inference attempt state")
}

// IsTrustFailure identifies handshake authentication failures without matching error text.
func IsTrustFailure(err error) bool {
	if errors.Is(err, ErrSPKIMismatch) {
		return true
	}
	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); ok {
		return true
	}
	_, ok := errors.AsType[*ctVerificationError](err)
	return ok
}

type ctVerificationError struct{ err error }

func (e *ctVerificationError) Error() string {
	return "certificate transparency check failed: " + e.err.Error()
}
func (e *ctVerificationError) Unwrap() error { return e.err }

// InferenceContext bounds an attempt by authenticated evidence without extending
// its caller's deadline. An expired bound produces an already-canceled context.
func InferenceContext(ctx context.Context, expires time.Time, present bool) (context.Context, context.CancelFunc) {
	if present {
		return context.WithDeadline(ctx, expires)
	}
	return context.WithCancel(ctx)
}
