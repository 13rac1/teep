package tlsct

import (
	"net"
	"sync"
)

type attemptConnections struct {
	mu     sync.Mutex
	remote string
	reused bool
}

func (a *attemptConnections) gotConn(conn net.Conn, reused bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.remote = ""
	if conn != nil {
		a.remote = conn.RemoteAddr().String()
	}
	a.reused = reused
}

// ConnectionDiagnostics reports the last assigned connection. HTTP tracing does
// not expose the socket for failed handshakes. RemoteAddr can identify a forward
// proxy rather than the origin; it does not identify a backend behind a tunnel.
func (a *InferenceAttempt) ConnectionDiagnostics() []any {
	c := &a.connections
	c.mu.Lock()
	defer c.mu.Unlock()
	attrs := []any{"connection_assigned", a.assigned.Load()}
	if c.remote != "" {
		attrs = append(attrs, "remote_addr", c.remote, "connection_reused", c.reused)
	}
	return attrs
}
