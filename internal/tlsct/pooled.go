package tlsct

import (
	"context"
	"net"
	"net/http"
	"time"
)

const (
	// MaxConnectionsPerHost bounds active connections in each transport pool.
	MaxConnectionsPerHost  = 16
	connectionSetupTimeout = 5 * time.Minute
)

// NewPooledTransport returns the common attestation and inference transport.
// Request deadlines can end operations before the connection setup budgets.
// TLS and CT configuration is installed by the HTTP client constructor.
func NewPooledTransport() *http.Transport {
	return newPooledTransport(connectionSetupTimeout, connectionSetupTimeout)
}

func newPooledTransport(dialTimeout, handshakeTimeout time.Duration) *http.Transport {
	// Keep normal HTTP/2 connection expansion. StrictMaxConcurrentRequests
	// deadlocks under contention in Go 1.26.8 and 1.27.1: stream admission
	// counts reservations queued behind the waiter holding reqHeaderMu.
	// The socket budget rejects overload instead; see docs/transport/README.md.
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: handshakeTimeout,
		ForceAttemptHTTP2:   true,
		MaxConnsPerHost:     MaxConnectionsPerHost,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
	budgets := &connectionBudgets{dialer: &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}, timeout: dialTimeout}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return budgets.dial(ctx, network, address, transport.MaxConnsPerHost)
	}
	return transport
}
