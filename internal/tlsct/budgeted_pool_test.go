package tlsct

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func heldSocketAddresses(budget *SocketBudget) int {
	budget.budgets.mu.Lock()
	defer budget.budgets.mu.Unlock()
	return len(budget.budgets.hosts)
}

// A dial can complete its TLS handshake after its request is canceled and
// before net/http adds the connection to its HTTP/2 pool. Cleanup that runs
// in this interval must close the socket and release its permit.
func TestBudgetedPoolCleanupClosesCompletedDial(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		server := authority.NewTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "ok")
		}), func(server *httptest.Server) {
			server.EnableHTTP2 = true
			server.TLS.NextProtos = []string{"h2"}
		})
		budget := NewSocketBudget(2)
		client := NewHTTPClientWithBudget(5*time.Second, budget, true)
		defer client.CloseIdleConnections()
		handshook := make(chan struct{})
		proceed := make(chan struct{})
		defer close(proceed)
		var once sync.Once
		trace := &httptrace.ClientTrace{TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				once.Do(func() {
					close(handshook)
					<-proceed
				})
			}
		}}
		ctx, cancel := context.WithCancel(httptrace.WithClientTrace(t.Context(), trace))
		defer cancel()
		result := make(chan error, 1)
		go func() { result <- admissionRequest(ctx, client, server.URL) }()
		select {
		case <-handshook:
		case err := <-result:
			t.Fatalf("request ended before its handshake completed: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("handshake did not complete")
		}
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("request should end with its context: %v", err)
		}
		if held := heldSocketAddresses(budget); held != 1 {
			t.Fatalf("completed dial holds permits for %d addresses, want 1", held)
		}
		client.CloseIdleConnections()
		if held := heldSocketAddresses(budget); held != 0 {
			t.Fatalf("cleanup retained the permit of a completed dial for %d addresses", held)
		}
	})
}

// Cleanup cancels a TCP connect that no request waits for. It must return
// only after that dial released its permit.
func TestBudgetedPoolCleanupWaitsForConnectingDial(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	budget := NewSocketBudget(1)
	connecting := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	budget.budgets.dialer = &net.Dialer{ControlContext: func(ctx context.Context, _, _ string, _ syscall.RawConn) error {
		once.Do(func() { close(connecting) })
		<-ctx.Done()
		<-release
		return ctx.Err()
	}}
	client := NewHTTPClientWithBudget(5*time.Second, budget, false)
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- admissionRequest(ctx, client, server.URL) }()
	select {
	case <-connecting:
	case <-time.After(5 * time.Second):
		t.Fatal("dial did not start")
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("request should end with its context: %v", err)
	}
	cleaned := make(chan struct{})
	go func() {
		client.CloseIdleConnections()
		close(cleaned)
	}()
	select {
	case <-cleaned:
		close(release)
		t.Fatal("cleanup returned while a dial held a permit")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-cleaned:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup did not return after the dial ended")
	}
	if held := heldSocketAddresses(budget); held != 0 {
		t.Fatalf("cleanup retained permits for %d addresses", held)
	}
}

// A request can wait on a dial to an unresponsive host. Cleanup must end that
// dial at once instead of after the dial time limit, and a later dial must
// fail before it takes a permit.
func TestBudgetedPoolCleanupEndsDialOfWaitingRequest(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	budget := NewSocketBudget(1)
	connecting := make(chan struct{})
	var once sync.Once
	var dials atomic.Int32
	budget.budgets.dialer = &net.Dialer{ControlContext: func(ctx context.Context, _, _ string, _ syscall.RawConn) error {
		dials.Add(1)
		once.Do(func() { close(connecting) })
		<-ctx.Done()
		return ctx.Err()
	}}
	client := NewHTTPClientWithBudget(time.Minute, budget, false)
	result := make(chan error, 1)
	go func() { result <- admissionRequest(t.Context(), client, server.URL) }()
	select {
	case <-connecting:
	case <-time.After(5 * time.Second):
		t.Fatal("dial did not start")
	}
	cleaned := make(chan struct{})
	go func() {
		client.CloseIdleConnections()
		close(cleaned)
	}()
	select {
	case <-cleaned:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup waited for the dial of a waiting request")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("request should end with the dial context: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not end after cleanup")
	}
	if held := heldSocketAddresses(budget); held != 0 {
		t.Fatalf("cleanup retained permits for %d addresses", held)
	}
	started := dials.Load()
	if err := admissionRequest(t.Context(), client, server.URL); !errors.Is(err, context.Canceled) {
		t.Fatalf("request after cleanup should fail with a context error: %v", err)
	}
	if dials.Load() != started {
		t.Fatal("dial after cleanup reached the network")
	}
	if held := heldSocketAddresses(budget); held != 0 {
		t.Fatalf("dial after cleanup holds permits for %d addresses", held)
	}
}

// Requests that run while cleanup runs must each end, and cleanup must leave
// no socket permit. Requests that start after cleanup must fail.
func TestBudgetedPoolConcurrentRequestsAndCleanup(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		server := authority.NewTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(time.Millisecond)
			_, _ = io.WriteString(w, "ok")
		}), func(server *httptest.Server) {
			server.EnableHTTP2 = true
		})
		budget := NewSocketBudget(4)
		client := NewHTTPClientWithBudget(5*time.Second, budget, true)
		const workers = 8
		completed := make(chan struct{}, workers)
		cleaned := make(chan struct{})
		errs := make(chan error, workers)
		var wg sync.WaitGroup
		for range workers {
			wg.Go(func() {
				errs <- requestUntilCleaned(t.Context(), client, server.URL, completed, cleaned)
			})
		}
		select {
		case <-completed:
		case <-time.After(10 * time.Second):
			t.Fatal("no request completed before cleanup")
		}
		go func() {
			client.CloseIdleConnections()
			close(cleaned)
		}()
		select {
		case <-cleaned:
		case <-time.After(10 * time.Second):
			t.Fatal("cleanup did not return")
		}
		if held := heldSocketAddresses(budget); held != 0 {
			t.Fatalf("cleanup retained permits for %d addresses", held)
		}
		finished := make(chan struct{})
		go func() {
			wg.Wait()
			close(finished)
		}()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Fatal("requests did not end after cleanup")
		}
		close(errs)
		for err := range errs {
			if err != nil {
				t.Error(err)
			}
		}
		if held := heldSocketAddresses(budget); held != 0 {
			t.Fatalf("requests after cleanup hold permits for %d addresses", held)
		}
	})
}

// requestUntilCleaned sends requests until cleaned closes, then one request
// that must fail. Each request either completes or fails with an error.
func requestUntilCleaned(ctx context.Context, client *http.Client, endpoint string, completed chan<- struct{}, cleaned <-chan struct{}) error {
	for {
		select {
		case <-cleaned:
			if err := admissionRequest(ctx, client, endpoint); err == nil {
				return errors.New("request after cleanup completed")
			}
			return nil
		default:
		}
		if err := admissionRequest(ctx, client, endpoint); err == nil {
			select {
			case completed <- struct{}{}:
			default:
			}
		}
	}
}
