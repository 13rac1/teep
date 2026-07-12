package proxy

import (
	"sync"
	"testing"
)

func TestNewHostGuard_InvalidListenAddr(t *testing.T) {
	if _, err := newHostGuard("not-a-host-port"); err == nil {
		t.Fatal("expected error for unparsable listen address")
	}
}

func TestHostGuard_Allow(t *testing.T) {
	g, err := newHostGuard("127.0.0.1:8337")
	if err != nil {
		t.Fatalf("newHostGuard: %v", err)
	}

	tests := []struct {
		name string
		host string
		want bool
	}{
		{"loopback v4 with port", "127.0.0.1:8337", true},
		{"loopback v6 with port", "[::1]:8337", true},
		{"localhost with port", "localhost:8337", true},
		{"localhost uppercase", "LocalHost:8337", true},
		{"loopback v4 no port", "127.0.0.1", true},
		{"localhost no port", "localhost", true},

		{"rebound hostname", "attacker.example:8337", false},
		{"rebound hostname default port", "attacker.example", false},
		{"empty host", "", false},
		{"garbage host", "!!!not a host!!!", false},
		{"port mismatch v4", "127.0.0.1:9999", false},
		{"port mismatch localhost", "localhost:1", false},
		{"unbracketed IPv6", "::1:8337", false},
		{"IPv6 bracket no port", "[::1]", true},
		{"IPv6 wrong bracket port", "[::1]:1234", false},
		{"loopback with trailing garbage", "127.0.0.1.evil.com:8337", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := g.allow(tc.host); got != tc.want {
				t.Errorf("allow(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestHostGuard_Allow_ConfiguredNonLoopbackHost(t *testing.T) {
	g, err := newHostGuard("teep-host.internal:9000")
	if err != nil {
		t.Fatalf("newHostGuard: %v", err)
	}
	if !g.allow("teep-host.internal:9000") {
		t.Error("configured non-loopback host:port should be allowed")
	}
	if !g.allow("127.0.0.1:9000") {
		t.Error("loopback should still be allowed even with a non-loopback configured host")
	}
	if g.allow("teep-host.internal:9001") {
		t.Error("configured host with wrong port should be rejected")
	}
	if g.allow("other-host.internal:9000") {
		t.Error("unrelated host should be rejected")
	}
}

func TestHostGuard_Allow_EphemeralPortWildcard(t *testing.T) {
	// Port 0 (OS-assigned) has no fixed value to compare against; used by
	// test harnesses that bind a real listener decoupled from Config.
	g, err := newHostGuard("127.0.0.1:0")
	if err != nil {
		t.Fatalf("newHostGuard: %v", err)
	}
	if !g.allow("127.0.0.1:54321") {
		t.Error("ephemeral-port guard should accept any port for an allowed host")
	}
	if g.allow("attacker.example:54321") {
		t.Error("ephemeral-port guard must still reject a rebound hostname")
	}
}

// TestHostGuard_Allow_Concurrent exercises allow() from many goroutines at
// once. hostGuard.allowedHosts is built once at construction and never
// mutated afterward, so concurrent reads must be race-free without locking.
func TestHostGuard_Allow_Concurrent(t *testing.T) {
	g, err := newHostGuard("127.0.0.1:8337")
	if err != nil {
		t.Fatalf("newHostGuard: %v", err)
	}

	hosts := []string{"127.0.0.1:8337", "[::1]:8337", "localhost:8337", "attacker.example:8337", ""}
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			g.allow(hosts[i%len(hosts)])
		}(i)
	}
	wg.Wait()
}
