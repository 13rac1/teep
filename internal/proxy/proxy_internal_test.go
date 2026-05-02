package proxy

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestMonitoredConn_CloseIdempotent(t *testing.T) {
	base, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer base.Close()

	go func() {
		c, err := net.Dial("tcp", base.Addr().String())
		if err == nil {
			c.Close()
		}
	}()

	raw, err := base.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

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
	go func() {
		c, err := net.Dial("tcp", base.Addr().String())
		if err == nil {
			c.Close()
		}
	}()

	conn, err := ml.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got := ml.lastWarn.Load(); got != now {
		t.Errorf("lastWarn updated within throttle window: got %d, want %d", got, now)
	}
	conn.Close()
	if got := ml.active.Load(); got != 1 {
		t.Errorf("active = %d after Close, want 1", got)
	}

	// Move lastWarn outside the throttle window; next Accept should update it.
	ml.lastWarn.Store(now - 61)
	go func() {
		c, err := net.Dial("tcp", base.Addr().String())
		if err == nil {
			c.Close()
		}
	}()

	conn2, err := ml.Accept()
	if err != nil {
		t.Fatalf("second Accept: %v", err)
	}
	if got := ml.lastWarn.Load(); got < now {
		t.Errorf("lastWarn was not updated after throttle window: got %d, want >= %d", got, now)
	}
	conn2.Close()
	if got := ml.active.Load(); got != 1 {
		t.Errorf("active = %d after second Close, want 1", got)
	}
}
