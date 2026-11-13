package proxy

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The first of the client's end and the tail read wins, once. A released
// hold calls nothing when the client's context ends later, and leaves no
// goroutine behind.
func TestTailHold(t *testing.T) {
	t.Run("client leaves first", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		abandoned := make(chan struct{})
		h := newTailHold(ctx, func() { close(abandoned) }, nil)
		defer h.release()
		cancel()
		select {
		case <-abandoned:
		case <-time.After(5 * time.Second):
			t.Fatal("the client's end did not abandon the attempt")
		}
		if h.enterTail() {
			t.Fatal("the tail read was claimed after the client's end abandoned the attempt")
		}
	})
	t.Run("relay error first", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		var abandoned atomic.Int32
		h := newTailHold(ctx, func() { abandoned.Add(1) }, nil)
		defer h.release()
		if !h.enterTail() {
			t.Fatal("the tail read was not claimed")
		}
		cancel()
		time.Sleep(50 * time.Millisecond)
		if abandoned.Load() != 0 {
			t.Fatal("the client's end stopped the attempt during the tail read")
		}
	})
	t.Run("released", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		var abandoned atomic.Int32
		h := newTailHold(ctx, func() { abandoned.Add(1) }, nil)
		h.release()
		cancel()
		time.Sleep(50 * time.Millisecond)
		if abandoned.Load() != 0 {
			t.Fatal("a released hold called onAbandon")
		}
	})
}

// Concurrent ends and claims decide each hold once: never both.
func TestTailHoldConcurrent(t *testing.T) {
	before := runtime.NumGoroutine()
	var wg sync.WaitGroup
	for range 200 {
		ctx, cancel := context.WithCancel(t.Context())
		var abandoned atomic.Int32
		h := newTailHold(ctx, func() { abandoned.Add(1) }, nil)
		var claimed atomic.Bool
		wg.Go(func() { claimed.Store(h.enterTail()) })
		wg.Go(cancel)
		wg.Wait()
		// The watch runs in its own goroutine; wait until it decided.
		deadline := time.Now().Add(5 * time.Second)
		for !claimed.Load() && abandoned.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if claimed.Load() == (abandoned.Load() == 1) {
			t.Fatalf("claimed = %v, abandoned = %d: exactly one must win", claimed.Load(), abandoned.Load())
		}
		h.release()
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		t.Errorf("%d goroutines after the holds, %d before", n, before)
	}
}

// A client that leaves after content reached it does not abandon the
// attempt: the hold drains, onDrain arms the bound, and release stops it.
// A tail claim after content still wins over a later client end.
func TestTailHoldDrain(t *testing.T) {
	t.Run("client leaves after content", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		var abandoned, stopped atomic.Int32
		armed := make(chan struct{})
		h := newTailHold(ctx, func() { abandoned.Add(1) }, func() func() bool {
			close(armed)
			return func() bool { stopped.Add(1); return true }
		})
		h.markContent()
		cancel()
		select {
		case <-armed:
		case <-time.After(5 * time.Second):
			t.Fatal("the drain bound was not armed")
		}
		if !h.draining() || abandoned.Load() != 0 {
			t.Fatalf("draining = %v, abandoned = %d", h.draining(), abandoned.Load())
		}
		if h.enterTail() {
			t.Fatal("the tail read was claimed during a drain")
		}
		h.release()
		if stopped.Load() != 1 {
			t.Fatalf("release stopped the drain bound %d times, want 1", stopped.Load())
		}
	})
	t.Run("tail claimed after content, client leaves later", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		var drained atomic.Int32
		h := newTailHold(ctx, func() {}, func() func() bool { drained.Add(1); return func() bool { return true } })
		defer h.release()
		h.markContent()
		if !h.enterTail() {
			t.Fatal("the tail read was not claimed after content")
		}
		cancel()
		time.Sleep(50 * time.Millisecond)
		if drained.Load() != 0 || h.draining() {
			t.Fatal("a client end after the tail claim started a drain")
		}
	})
}

// The handler that sees the client's end before the hold's watch runs makes
// the drain transition itself: it arms the drain bound once, and the watch
// that runs later changes nothing.
func TestTailHoldClientEnded(t *testing.T) {
	t.Run("after content, before the watch", func(t *testing.T) {
		var armed atomic.Int32
		onDrain := func() func() bool { armed.Add(1); return func() bool { return true } }
		ctx, cancel := context.WithCancel(t.Context())
		h := newTailHold(ctx, func() { t.Error("onAbandon after content") }, onDrain)
		defer h.release()
		h.markContent()
		if !h.clientEnded() {
			t.Fatal("clientEnded after content did not drain")
		}
		cancel()
		time.Sleep(50 * time.Millisecond)
		if !h.draining() || armed.Load() != 1 {
			t.Fatalf("draining=%v armed=%d, want true and 1", h.draining(), armed.Load())
		}
		if h.enterTail() {
			t.Fatal("the tail read was claimed during the drain")
		}
	})
	t.Run("after the tail claim", func(t *testing.T) {
		var armed atomic.Int32
		onDrain := func() func() bool { armed.Add(1); return func() bool { return true } }
		h := newTailHold(t.Context(), func() {}, onDrain)
		defer h.release()
		h.markContent()
		if !h.enterTail() {
			t.Fatal("the tail read was not claimed")
		}
		if h.clientEnded() || armed.Load() != 0 {
			t.Fatal("clientEnded after the tail claim started a drain")
		}
	})
	t.Run("before content", func(t *testing.T) {
		h := newTailHold(t.Context(), func() {}, func() func() bool { return func() bool { return true } })
		defer h.release()
		if h.clientEnded() {
			t.Fatal("clientEnded before content started a drain")
		}
	})
	t.Run("released", func(t *testing.T) {
		var armed atomic.Int32
		onDrain := func() func() bool { armed.Add(1); return func() bool { return true } }
		h := newTailHold(t.Context(), func() {}, onDrain)
		h.markContent()
		h.release()
		h.clientEnded()
		if armed.Load() != 0 {
			t.Fatal("a released hold armed the drain bound")
		}
	})
}
