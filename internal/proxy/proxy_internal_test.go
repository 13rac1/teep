package proxy

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func dialAndClose(addr string) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			errCh <- err
			return
		}
		errCh <- c.Close()
	}()
	return errCh
}

func waitDialResult(t *testing.T, errCh <-chan error) {
	t.Helper()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("dial helper: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dial helper timed out")
	}
}

func TestMonitoredConn_CloseIdempotent(t *testing.T) {
	base, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer base.Close()

	errCh := dialAndClose(base.Addr().String())
	_ = base.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))

	raw, err := base.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	waitDialResult(t, errCh)

	var active atomic.Int64
	active.Store(1)

	mc := &monitoredConn{Conn: raw, active: &active}

	t.Log("first Close")
	if err := mc.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if active.Load() != 0 {
		t.Errorf("active should be 0 after Close, got %d", active.Load())
	}

	t.Log("second Close (idempotent — decrements active only once)")
	_ = mc.Close()
	if active.Load() != 0 {
		t.Errorf("active should still be 0 after second Close, got %d", active.Load())
	}
}

func TestMonitoredListener_ThrottleLog(t *testing.T) {
	base, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer base.Close()

	ml := &monitoredListener{
		Listener: base,
		maxConns: 1,
	}
	// Simulate active == maxConns so each Accept evaluates the throttle check.
	ml.active.Store(1)
	now := time.Now().Unix()
	ml.lastWarn.Store(now)

	// First Accept is inside the 60-second throttle window, so lastWarn should
	// not be updated.
	errCh := dialAndClose(base.Addr().String())
	_ = base.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))

	conn, err := ml.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	waitDialResult(t, errCh)
	if got := ml.lastWarn.Load(); got != now {
		t.Errorf("lastWarn updated within throttle window: got %d, want %d", got, now)
	}
	conn.Close()
	if got := ml.active.Load(); got != 1 {
		t.Errorf("active = %d after Close, want 1", got)
	}

	// Move lastWarn outside the throttle window; next Accept should update it.
	ml.lastWarn.Store(now - 61)
	errCh2 := dialAndClose(base.Addr().String())
	_ = base.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))

	conn2, err := ml.Accept()
	if err != nil {
		t.Fatalf("second Accept: %v", err)
	}
	waitDialResult(t, errCh2)
	if got := ml.lastWarn.Load(); got < now {
		t.Errorf("lastWarn was not updated after throttle window: got %d, want >= %d", got, now)
	}
	conn2.Close()
	if got := ml.active.Load(); got != 1 {
		t.Errorf("active = %d after second Close, want 1", got)
	}
}
