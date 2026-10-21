package tlsct

import (
	"context"
	"net"
	"net/http"
	"sync"
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
	budgets     *connectionBudgets
	limit       int
	pooledLimit int
}

// NewSocketBudget constructs an immutable admission limit with synchronized state.
func NewSocketBudget(limit int) *SocketBudget {
	if limit <= 0 {
		panic("connection limit must be positive")
	}
	return &SocketBudget{budgets: newConnectionBudgets(connectionSetupTimeout), limit: limit, pooledLimit: limit}
}

func newConnectionBudgets(timeout time.Duration) *connectionBudgets {
	return &connectionBudgets{dialer: &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}, timeout: timeout}
}

// NewHTTPClientWithBudget returns a client whose pool consumes the supplied
// budget. Its Transport is not an *http.Transport.
//
// CloseIdleConnections of the client cancels every dial of the pool, waits
// until the dials return, and closes every socket of the pool, so the pool
// holds no socket permit when it returns. Call it only after the last request
// through the pool, or at process shutdown: it also closes the sockets of
// active requests. The pool is not usable after cleanup; each later dial fails.
func NewHTTPClientWithBudget(timeout time.Duration, budget *SocketBudget, ctEnabled bool) *http.Client {
	pool := newBudgetedPool(budget)
	client := NewHTTPClientWithTransport(timeout, pool.Transport, ctEnabled)
	client.Transport = pool
	return client
}

// budgetedPool records the sockets of a transport that consumes a shared
// socket budget. http.Transport.CloseIdleConnections does not close an HTTP/2
// connection that a dial adds to the pool after cleanup ran. That connection
// stays open until IdleConnTimeout and keeps its socket permit.
type budgetedPool struct {
	*http.Transport
	// dialing has a read lock for each dial in progress.
	dialing sync.RWMutex
	// sockets holds each open *poolSocket of the pool.
	sockets sync.Map
	// stop ends each dial in progress and each later dial. Cleanup calls it.
	stop context.CancelFunc
}

// newBudgetedPool returns a pool whose Transport the caller configures before
// the first request.
func newBudgetedPool(budget *SocketBudget) *budgetedPool {
	if budget == nil {
		panic("socket budget is required")
	}
	transport := pooledTransport(connectionSetupTimeout)
	transport.MaxConnsPerHost = budget.limit
	if budget.pooledLimit > 0 {
		// Let this pool wait for its own connections instead of requesting
		// the slot reserved for fresh fetches. Cross-pool exhaustion still
		// fails immediately in shared physical-socket admission.
		transport.MaxConnsPerHost = min(budget.limit, budget.pooledLimit)
	}
	stopped, stop := context.WithCancel(context.Background())
	pool := &budgetedPool{Transport: transport, stop: stop}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		pool.dialing.RLock()
		defer pool.dialing.RUnlock()
		// A dial that starts after cleanup fails here, before it takes a
		// permit. AfterFunc cancels the dial context on another goroutine.
		if err := stopped.Err(); err != nil {
			return nil, err
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		defer context.AfterFunc(stopped, cancel)()
		conn, err := budget.budgets.dialWithShare(ctx, network, address, budget.limit, budget.pooledLimit)
		if err != nil {
			return nil, err
		}
		socket := &poolSocket{Conn: conn, pool: pool}
		pool.sockets.Store(socket, nil)
		return socket, nil
	}
	return pool
}

// CloseIdleConnections cancels every dial of the pool and runs the cleanup of
// the transport. Then it waits until the dials of the pool return and closes
// every socket of the pool. A socket permit is released when its dial fails or
// its socket closes.
func (p *budgetedPool) CloseIdleConnections() {
	p.stop()
	p.Transport.CloseIdleConnections()
	p.dialing.Lock()
	defer p.dialing.Unlock()
	p.sockets.Range(func(key, _ any) bool {
		if socket, ok := key.(*poolSocket); ok {
			_ = socket.Close()
		}
		return true
	})
}

// poolSocket removes itself from its pool when it closes.
type poolSocket struct {
	net.Conn
	pool *budgetedPool
}

// Close closes the socket before it removes the socket from the pool. Go can
// close a socket on another goroutine while cleanup runs. If cleanup finds the
// socket, its Close waits until the permit is released. If cleanup does not
// find the socket, the permit is already released.
func (s *poolSocket) Close() error {
	err := s.Conn.Close()
	s.pool.sockets.Delete(s)
	return err
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

// NewAttestationSocketBudget reserves one aggregate slot from long-lived pools.
func NewAttestationSocketBudget(limit int) *SocketBudget {
	if limit < 2 {
		panic("shared attestation socket limit must be at least two")
	}
	budget := NewSocketBudget(limit)
	budget.pooledLimit = limit - 1
	return budget
}

// Fresh returns an immutable admission view for operation-owned pools. It
// shares aggregate physical-socket accounting and has no pooled-share charge.
func (b *SocketBudget) Fresh() *SocketBudget {
	if b == nil {
		panic("socket budget is required")
	}
	return &SocketBudget{budgets: b.budgets, limit: b.limit}
}
