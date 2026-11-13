package proxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

// endedByClient names the client only from positive evidence: the relay
// error is the downstream write error, or the error of the client's own
// context, which has ended. teep's own deadline for the attempt, and every
// other relay error, are the gateway's.
func TestEndedByClient(t *testing.T) {
	alive := context.Background()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	broken := errors.New("broken pipe")
	for _, tc := range []struct {
		name   string
		ending relayEnding
		client func() context.Context
		want   bool
	}{
		{"downstream write failed", relayEnding{err: fmt.Errorf("relay: %w", broken), downstream: broken}, func() context.Context { return alive }, true},
		{"client hung up", relayEnding{err: fmt.Errorf("relay: %w", context.Canceled)}, func() context.Context { return cancelled }, true},
		{"client deadline", relayEnding{err: fmt.Errorf("relay: %w", context.DeadlineExceeded)}, func() context.Context { return expired }, true},
		{"teep's own deadline, client alive", relayEnding{err: fmt.Errorf("relay: %w", context.DeadlineExceeded)}, func() context.Context { return alive }, false},
		{"stream does not parse", relayEnding{err: errors.New("upstream SSE error event")}, func() context.Context { return alive }, false},
		{"stream does not parse, client gone later", relayEnding{err: errors.New("upstream SSE error event")}, func() context.Context { return cancelled }, false},
		// The downstream write deadline is the attempt deadline, which is
		// teep's own: a write that fails on it while the client is still
		// connected is not the client's.
		{"write deadline of the attempt, client alive", relayEnding{err: fmt.Errorf("relay: %w", os.ErrDeadlineExceeded), downstream: os.ErrDeadlineExceeded}, func() context.Context { return alive }, false},
		{"write deadline as context error, client alive", relayEnding{err: fmt.Errorf("relay: %w", context.DeadlineExceeded), downstream: context.DeadlineExceeded}, func() context.Context { return alive }, false},
		{"downstream error that is not the relay error", relayEnding{err: errors.New("reset"), downstream: broken}, func() context.Context { return alive }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := endedByClient(tc.client(), tc.ending); got != tc.want {
				t.Errorf("endedByClient = %v, want %v", got, tc.want)
			}
		})
	}
}
