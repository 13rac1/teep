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
	slots chan struct{}
	users int
}

func (b *connectionBudgets) dial(ctx context.Context, network, address string, limit int) (net.Conn, error) {
	if limit <= 0 {
		return nil, errors.New("connection limit must be positive")
	}
	setup, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	if err := setup.Err(); err != nil {
		return nil, err
	}
	group := b.reference(address, limit)
	select {
	case group.slots <- struct{}{}:
	default:
		// A completed HTTP/2 stream does not release a socket permit. Waiting
		// here would strand the dial even after a connection can accept streams.
		b.release(address, group, false)
		return nil, ErrConnectionCapacity
	}
	conn, err := b.dialer.DialContext(setup, network, address)
	if err != nil {
		b.release(address, group, true)
		return nil, err
	}
	return &budgetedConnection{Conn: conn, release: func() { b.release(address, group, true) }}, nil
}

func (b *connectionBudgets) reference(address string, limit int) *connectionBudget {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.hosts == nil {
		b.hosts = make(map[string]*connectionBudget)
	}
	group := b.hosts[address]
	if group == nil {
		group = &connectionBudget{slots: make(chan struct{}, limit)}
		b.hosts[address] = group
	}
	group.users++
	return group
}

func (b *connectionBudgets) release(address string, group *connectionBudget, acquired bool) {
	if acquired {
		<-group.slots
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	group.users--
	if group.users == 0 {
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
