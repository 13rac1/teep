package provider

import (
	"context"
	"errors"
	"log/slog"
	"slices"

	"github.com/13rac1/teep/internal/tlsct"
)

// MaxCandidateAttempts is the maximum number of candidates that RunFailover
// tries for one request. The caller's context deadline also applies.
const MaxCandidateAttempts = 8

// CandidateFailureRecorder skips a failed candidate authority for a period.
// It skips the authority only for model: discovery returns candidates for each
// model, and a failed enclave for one model says nothing about another model.
type CandidateFailureRecorder func(ctx context.Context, model, authority string)

// CandidateError is a failure caused by the selected candidate.
type CandidateError struct{ Err error }

func (e *CandidateError) Error() string { return e.Err.Error() }
func (e *CandidateError) Unwrap() error { return e.Err }

// IsCandidateFailure reports whether err is caused by the selected candidate,
// so that RunFailover can try the next one.
func IsCandidateFailure(err error) bool {
	// We try the next candidate only for errors that a call site marked.
	// Call sites mark errors before they know the cause, so we also exclude
	// local failures and credential rejections.
	if _, ok := errors.AsType[*CandidateError](err); !ok {
		return false
	}
	return !tlsct.IsLocalError(err) && !IsAuthFailure(err)
}

// Candidate is one enclave that RunFailover can try. It keeps the result of
// its own attempt.
type Candidate interface {
	// Attempt verifies the candidate. It reports whether an enforced factor
	// failed.
	Attempt(ctx context.Context) (blocked bool, err error)
	// Authority returns the candidate authority. RunFailover calls it after
	// Attempt, because Attempt can resolve the candidate.
	Authority() string
}

// RunFailover tries candidate. While an enforced factor fails or the error is
// a candidate failure, it records the failed authority, gets the next
// candidate from next, and tries it. It returns the last candidate that it
// tried and the error of that attempt. If record is nil, it tries only the
// first candidate.
// SEE: docs/transport/retries.md.
func RunFailover[C Candidate](ctx context.Context, candidate C, record func(ctx context.Context, authority string), next func(ctx context.Context) (C, error)) (C, error) {
	var tried []string
	for {
		blocked, err := candidate.Attempt(ctx)
		authority := candidate.Authority()
		failed := (err == nil && blocked) || IsCandidateFailure(err)
		if record == nil || authority == "" || !failed || ctx.Err() != nil {
			return candidate, err
		}
		record(ctx, authority)
		tried = append(tried, authority)
		if len(tried) >= MaxCandidateAttempts {
			return candidate, err
		}
		following, resolveErr := next(ctx)
		if resolveErr != nil {
			// The last attempt failed, so its result stays the fail-closed
			// answer.
			slog.WarnContext(ctx, "failover: cannot resolve next candidate", "authority", authority, "err", resolveErr)
			return candidate, err
		}
		if slices.Contains(tried, following.Authority()) {
			// The resolver returns a tried candidate only when no untried
			// candidate remains.
			return candidate, err
		}
		candidate = following
	}
}
