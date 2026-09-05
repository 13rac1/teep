package tlsct

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http/httptrace"
	"sync"
	"syscall"
	"testing"
)

func TestInferenceRetryClassification(t *testing.T) {
	dial := &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
	a := &InferenceAttempt{}
	ctx := a.Context(context.Background())
	if !a.RetryConnectionFailure(ctx, dial) {
		t.Fatal("typed dial failure not retryable")
	}
	for _, err := range []error{io.EOF, ErrSPKIMismatch, &net.OpError{Op: "read", Err: syscall.ECONNRESET}, errors.New("PROTOCOL_ERROR")} {
		if a.RetryConnectionFailure(ctx, err) {
			t.Fatalf("ambiguous/trust failure retryable: %v", err)
		}
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() { httptrace.ContextClientTrace(ctx).GotConn(httptrace.GotConnInfo{}) })
	}
	wg.Wait()
	if a.RetryConnectionFailure(ctx, dial) {
		t.Fatal("retry permitted after connection assignment")
	}
}

func TestInferenceAttemptsBound(t *testing.T) {
	count := 0
	failure := errors.New("retry failed")
	_, err := RunInferenceAttempts(context.Background(), func(context.Context) (int, bool, error) { count++; return count, true, failure })
	if count != 2 || !errors.Is(err, failure) {
		t.Fatalf("attempts=%d err=%v", count, err)
	}
}
