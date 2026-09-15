package tlsct

import (
	"log/slog"
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
func (a *InferenceAttempt) ConnectionDiagnostics() []slog.Attr {
	c := &a.connections
	c.mu.Lock()
	defer c.mu.Unlock()
	attrs := []slog.Attr{slog.Bool("connection_assigned", a.assigned.Load())}
	if c.remote != "" {
		attrs = append(attrs, slog.String("remote_addr", c.remote), slog.Bool("connection_reused", c.reused))
	}
	return attrs
}
