package proxy

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// The states of a tailHold.
const (
	holdRelaying  int32 = iota // nothing reached the client yet
	holdContent                // content reached the client; teep relays
	holdTail                   // the relay failed for the gateway's reason; teep reads the rest
	holdAbandoned              // the client left before any content; the attempt stopped
	holdDraining               // the client left after content; teep reads the rest
)

// tailHold decides, once, what the end of a client's request does to the
// upstream attempt. The upstream request does not run on the client's
// context, so that teep can read the rest of a stream for its receipt
// check after the client left or after the gateway ended the stream badly.
//
//   - The client leaves before any content reached it: the attempt is
//     abandoned (onAbandon stops it), as before.
//   - The client leaves after content reached it (markContent): teep stops
//     writing downstream but keeps the attempt, and onDrain arms the drain
//     bound; the handler reads the rest of the stream (draining).
//   - The relay failed for a reason that is not the client's: the handler
//     claims the tail read first (enterTail); a later client end does not
//     touch the attempt.
//
// Compare-and-swap makes the first transition the only one.
type tailHold struct {
	state   atomic.Int32
	stop    func() bool
	mu      sync.Mutex
	onDrain func() (stop func() bool)
	drain   func() bool
}

// newTailHold calls onAbandon when clientCtx ends before any content, and
// onDrain when it ends after content. onDrain returns the function that
// stops what it armed; release calls it.
func newTailHold(clientCtx context.Context, onAbandon func(), onDrain func() (stop func() bool)) *tailHold {
	h := &tailHold{onDrain: onDrain}
	h.stop = context.AfterFunc(clientCtx, func() {
		switch {
		case h.state.CompareAndSwap(holdRelaying, holdAbandoned):
			onAbandon()
		case h.state.CompareAndSwap(holdContent, holdDraining):
			h.mu.Lock()
			if h.onDrain != nil {
				h.drain = h.onDrain()
			}
			h.mu.Unlock()
		}
	})
	return h
}

// markContent records that content reached the client.
func (h *tailHold) markContent() {
	h.state.CompareAndSwap(holdRelaying, holdContent)
}

// enterTail moves the hold to the tail read. It reports false when the
// client's end came first.
func (h *tailHold) enterTail() bool {
	return h.state.CompareAndSwap(holdRelaying, holdTail) || h.state.CompareAndSwap(holdContent, holdTail)
}

// draining reports whether the client left after content, so that teep
// reads the rest of the stream.
func (h *tailHold) draining() bool {
	return h.state.Load() == holdDraining
}

// release stops the watch of the client's context and the drain bound.
// After it, the client's end calls nothing.
func (h *tailHold) release() {
	h.stop()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onDrain = nil
	if h.drain != nil {
		h.drain()
	}
}

// drainTimer returns an onDrain that cancels the attempt when the drain
// bound passes after the client left.
func drainTimer(bound time.Duration, cancel context.CancelFunc) func() (stop func() bool) {
	return func() (stop func() bool) {
		return time.AfterFunc(bound, cancel).Stop
	}
}
