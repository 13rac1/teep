package proxy

import (
	"net"
	"testing"
	"time"
)

func TestLimitListener(t *testing.T) {
	base, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer base.Close()

	limit := 2
	ln := newLimitListener(base, limit)
	addr := ln.Addr().String()

	// Open `limit` connections and hold the server-side limitConns so the
	// semaphore slots stay occupied.
	serverConns := make([]net.Conn, 0, limit)
	for i := range limit {
		_, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("Dial %d: %v", i, err)
		}
		sc, err := ln.Accept()
		if err != nil {
			t.Fatalf("Accept %d: %v", i, err)
		}
		serverConns = append(serverConns, sc)
	}
	t.Logf("accepted %d connections; semaphore full", limit)

	// A (limit+1)th Accept accepts the connection from the OS backlog immediately
	// but then blocks on the semaphore send until a slot is freed.
	// Closing one server-side limitConn releases a slot and unblocks it.
	extraDone := make(chan struct{})
	go func() {
		sc, err := ln.Accept()
		if err != nil {
			t.Errorf("Accept extra: %v", err)
			close(extraDone)
			return
		}
		t.Logf("accepted extra connection after slot freed")
		sc.Close()
		close(extraDone)
	}()

	// Dial the extra connection so it can be accepted from the OS backlog.
	extra, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial extra: %v", err)
	}
	defer extra.Close()

	// Close a server-side limitConn to release its semaphore slot.
	serverConns[0].Close()
	t.Logf("closed server conn 0; waiting for extra accept to unblock")

	select {
	case <-extraDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for extra accept to unblock after slot freed")
	}

	for _, c := range serverConns[1:] {
		c.Close()
	}
}

func TestLimitConn_CloseIdempotent(t *testing.T) {
	sem := make(chan struct{}, 1)
	sem <- struct{}{} // occupy the slot

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

	lc := &limitConn{Conn: raw, sem: sem}

	t.Log("first Close")
	if err := lc.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	t.Logf("semaphore len after first Close: %d", len(sem))
	if len(sem) != 0 {
		t.Errorf("sem should be empty after Close, got len=%d", len(sem))
	}

	t.Log("second Close (idempotent — releases sem only once)")
	_ = lc.Close() // error expected on already-closed conn; ignore it
	if len(sem) != 0 {
		t.Errorf("sem should still be empty after second Close, got len=%d", len(sem))
	}
}
