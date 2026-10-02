package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/13rac1/teep/internal/tlsct"
)

func TestIsCandidateFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unmarked", errors.New("authorization route and key differ"), false},
		{"marked", &CandidateError{Err: errors.New("connection refused")}, true},
		{"marked and wrapped", fmt.Errorf("fetch: %w", &CandidateError{Err: errors.New("connection refused")}), true},
		{"marked capacity", &CandidateError{Err: tlsct.ErrConnectionCapacity}, false},
		{"marked cancellation", &CandidateError{Err: context.Canceled}, false},
		{"marked deadline", &CandidateError{Err: context.DeadlineExceeded}, false},
		{"marked 401", &CandidateError{Err: &HTTPStatusError{StatusCode: http.StatusUnauthorized}}, false},
		{"marked 403", &CandidateError{Err: &HTTPStatusError{StatusCode: http.StatusForbidden}}, false},
		{"marked 503", &CandidateError{Err: &HTTPStatusError{StatusCode: http.StatusServiceUnavailable}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsCandidateFailure(tc.err); got != tc.want {
				t.Errorf("IsCandidateFailure(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestCandidateErrorKeepsCause(t *testing.T) {
	cause := &HTTPStatusError{StatusCode: http.StatusBadGateway, Body: "bad gateway"}
	err := error(&CandidateError{Err: cause})
	if err.Error() != cause.Error() {
		t.Errorf("Error() = %q, want the cause's message %q", err.Error(), cause.Error())
	}
	if got, ok := errors.AsType[*HTTPStatusError](err); !ok || got != cause {
		t.Errorf("errors.AsType did not find the cause")
	}
}

type attemptOutcome struct {
	blocked bool
	err     error
}

// testCandidate is a candidate whose authority is its name. It records each
// attempt in attempted.
type testCandidate struct {
	authority string
	outcome   attemptOutcome
	attempted *[]string
}

func (c *testCandidate) Attempt(context.Context) (bool, error) {
	*c.attempted = append(*c.attempted, c.authority)
	return c.outcome.blocked, c.outcome.err
}

func (c *testCandidate) Authority() string { return c.authority }

// runFailover tries candidates in order. Candidates missing from outcomes
// pass.
func runFailover(t *testing.T, candidates []string, outcomes map[string]attemptOutcome, withRecord bool, resolveErr error) (final string, attempted, recorded []string, err error) {
	t.Helper()
	candidate := func(i int) *testCandidate {
		name := candidates[min(i, len(candidates)-1)]
		return &testCandidate{authority: name, outcome: outcomes[name], attempted: &attempted}
	}
	i := 0
	next := func(context.Context) (*testCandidate, error) {
		if resolveErr != nil {
			return nil, resolveErr
		}
		i++
		return candidate(i), nil
	}
	var record func(context.Context, string)
	if withRecord {
		record = func(_ context.Context, a string) { recorded = append(recorded, a) }
	}
	last, err := RunFailover(t.Context(), candidate(0), record, next)
	return last.authority, attempted, recorded, err
}

func TestRunFailover(t *testing.T) {
	fetchErr := &CandidateError{Err: errors.New("connection refused")}
	setupErr := errors.New("route and key differ")
	blocked := attemptOutcome{blocked: true}
	many := make([]string, 0, MaxCandidateAttempts+2)
	manyOutcomes := map[string]attemptOutcome{}
	for i := range MaxCandidateAttempts + 2 {
		c := fmt.Sprintf("c%d", i)
		many = append(many, c)
		manyOutcomes[c] = blocked
	}
	for _, tc := range []struct {
		name          string
		candidates    []string
		outcomes      map[string]attemptOutcome
		noRecord      bool
		resolveErr    error
		wantFinal     string
		wantErr       error
		wantAttempted []string
		wantRecorded  []string
	}{
		{name: "candidate error tries next", candidates: []string{"a", "b"}, outcomes: map[string]attemptOutcome{"a": {err: fetchErr}},
			wantFinal: "b", wantAttempted: []string{"a", "b"}, wantRecorded: []string{"a"}},
		{name: "failed factor tries next", candidates: []string{"a", "b"}, outcomes: map[string]attemptOutcome{"a": blocked},
			wantFinal: "b", wantAttempted: []string{"a", "b"}, wantRecorded: []string{"a"}},
		{name: "unmarked error stops", candidates: []string{"a", "b"}, outcomes: map[string]attemptOutcome{"a": {err: setupErr}},
			wantFinal: "a", wantErr: setupErr, wantAttempted: []string{"a"}},
		{name: "nil record disables failover", candidates: []string{"a", "b"}, outcomes: map[string]attemptOutcome{"a": {err: fetchErr}}, noRecord: true,
			wantFinal: "a", wantErr: fetchErr, wantAttempted: []string{"a"}},
		{name: "tried candidate stops", candidates: []string{"a", "a"}, outcomes: map[string]attemptOutcome{"a": {err: fetchErr}},
			wantFinal: "a", wantErr: fetchErr, wantAttempted: []string{"a"}, wantRecorded: []string{"a"}},
		{name: "resolve error keeps last outcome", candidates: []string{"a", "b"}, outcomes: map[string]attemptOutcome{"a": blocked}, resolveErr: errors.New("discovery down"),
			wantFinal: "a", wantAttempted: []string{"a"}, wantRecorded: []string{"a"}},
		{name: "attempt bound", candidates: many, outcomes: manyOutcomes,
			wantFinal: many[MaxCandidateAttempts-1], wantAttempted: many[:MaxCandidateAttempts], wantRecorded: many[:MaxCandidateAttempts]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			final, attempted, recorded, err := runFailover(t, tc.candidates, tc.outcomes, !tc.noRecord, tc.resolveErr)
			if final != tc.wantFinal || !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Errorf("RunFailover = %q, %v; want %q, %v", final, err, tc.wantFinal, tc.wantErr)
			}
			if !slices.Equal(attempted, tc.wantAttempted) {
				t.Errorf("attempted = %v, want %v", attempted, tc.wantAttempted)
			}
			if !slices.Equal(recorded, tc.wantRecorded) {
				t.Errorf("recorded = %v, want %v", recorded, tc.wantRecorded)
			}
		})
	}
}
