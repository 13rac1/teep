package tlsct

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// ErrConnectionCapacity identifies local socket exhaustion, not a trust failure.
// Callers must not retry inference or invalidate authorization for this error.
const ErrConnectionCapacity connectionCapacityError = "outbound connection capacity exhausted"

type connectionCapacityError string

func (e connectionCapacityError) Error() string { return string(e) }

// connectionBudgets holds physical connection permits until Close. net/http's
// HTTP/2 stream-capacity handling can remove a live connection from its own
// MaxConnsPerHost accounting before that connection closes.
type connectionBudgets struct {
	mu      sync.Mutex
	hosts   map[string]*connectionBudget
	dialer  *net.Dialer
	timeout time.Duration
}

type connectionBudget struct {
	active int
	pooled int
}

func (b *connectionBudgets) dial(ctx context.Context, network, address string, limit int) (net.Conn, error) {
	return b.dialWithShare(ctx, network, address, limit, 0)
}

func (b *connectionBudgets) dialWithShare(ctx context.Context, network, address string, limit, pooledLimit int) (net.Conn, error) {
	if limit <= 0 {
		return nil, errors.New("connection limit must be positive")
	}
	setup, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	if err := setup.Err(); err != nil {
		return nil, err
	}
	group, err := b.acquire(address, limit, pooledLimit)
	if err != nil {
		return nil, err
	}
	conn, err := b.dialer.DialContext(setup, network, address)
	if err != nil {
		b.release(address, group, pooledLimit > 0)
		return nil, err
	}
	return &budgetedConnection{Conn: conn, release: func() { b.release(address, group, pooledLimit > 0) }}, nil
}

// acquire admits aggregate and pooled-share permits atomically, without a queue.
func (b *connectionBudgets) acquire(address string, limit, pooledLimit int) (*connectionBudget, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.hosts == nil {
		b.hosts = make(map[string]*connectionBudget)
	}
	group := b.hosts[address]
	if group == nil {
		group = &connectionBudget{}
	}
	if group.active >= limit || (pooledLimit > 0 && group.pooled >= pooledLimit) {
		return nil, ErrConnectionCapacity
	}
	group.active++
	if pooledLimit > 0 {
		group.pooled++
	}
	b.hosts[address] = group
	return group, nil
}

func (b *connectionBudgets) release(address string, group *connectionBudget, pooled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	group.active--
	if pooled {
		group.pooled--
	}
	if group.active == 0 {
		delete(b.hosts, address)
	}
}

type budgetedConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *budgetedConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
