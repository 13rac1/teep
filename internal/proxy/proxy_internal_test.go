package proxy

import (
	"net"
	"sync/atomic"
	"testing"
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
	// Simulate active == maxConns so the next Accept triggers the throttle check.
	ml.active.Store(1)

	// Dial a connection so Accept doesn't block forever.
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

	// The warning should have fired and set lastWarn.
	if ml.lastWarn.Load() == 0 {
		t.Error("expected lastWarn to be set when active >= maxConns at Accept time")
	}

	// active is now 2 (pre-stored 1 + Accept increment). Close decrements back to 1.
	conn.Close()
	if got := ml.active.Load(); got != 1 {
		t.Errorf("active = %d after Close, want 1", got)
	}
}
