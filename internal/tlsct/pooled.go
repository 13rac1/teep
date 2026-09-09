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

// SocketBudget shares physical socket admission across independently owned pools.
// Its limit applies to each dial address, including a configured proxy address.
type SocketBudget struct {
	budgets *connectionBudgets
	limit   int
}

// NewSocketBudget constructs an immutable admission limit with synchronized state.
func NewSocketBudget(limit int) *SocketBudget {
	if limit <= 0 {
		panic("connection limit must be positive")
	}
	return &SocketBudget{budgets: newConnectionBudgets(connectionSetupTimeout), limit: limit}
}

func newConnectionBudgets(timeout time.Duration) *connectionBudgets {
	return &connectionBudgets{dialer: &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}, timeout: timeout}
}

// NewPooledTransportWithBudget creates a pool that consumes the supplied budget.
// Closing this pool releases only its own sockets, without resetting the budget.
func NewPooledTransportWithBudget(budget *SocketBudget) *http.Transport {
	if budget == nil {
		panic("socket budget is required")
	}
	transport := pooledTransport(connectionSetupTimeout)
	transport.MaxConnsPerHost = budget.limit
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return budget.budgets.dial(ctx, network, address, budget.limit)
	}
	return transport
}

func newPooledTransport(dialTimeout, handshakeTimeout time.Duration) *http.Transport {
	transport := pooledTransport(handshakeTimeout)
	budgets := newConnectionBudgets(dialTimeout)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return budgets.dial(ctx, network, address, transport.MaxConnsPerHost)
	}
	return transport
}

func pooledTransport(handshakeTimeout time.Duration) *http.Transport {
	// Keep normal HTTP/2 connection expansion. StrictMaxConcurrentRequests
	// deadlocks under contention in Go 1.26.8 and 1.27.1: stream admission
	// counts reservations queued behind the waiter holding reqHeaderMu.
	// The socket budget rejects overload instead; see docs/transport/README.md.
	return &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: handshakeTimeout,
		ForceAttemptHTTP2:   true,
		MaxConnsPerHost:     MaxConnectionsPerHost,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
}
