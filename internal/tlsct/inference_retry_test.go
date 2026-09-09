package tlsct

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http/httptrace"
	"net/url"
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
	for _, err := range []error{ErrConnectionCapacity, &net.OpError{Op: "dial", Err: ErrConnectionCapacity}, io.EOF, ErrSPKIMismatch, &net.OpError{Op: "read", Err: syscall.ECONNRESET}, errors.New("PROTOCOL_ERROR")} {
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

func TestOriginTrustFailureClassification(t *testing.T) {
	certificate := &tls.CertificateVerificationError{Err: errors.New("certificate rejected")}
	ct := &ctVerificationError{err: errors.New("CT rejected")}
	for _, tc := range []struct {
		name          string
		err           error
		trust, origin bool
	}{
		{"origin_certificate", certificate, true, true},
		{"origin_ct", ct, true, true},
		{"origin_spki", ErrSPKIMismatch, true, true},
		{"proxy_certificate", &proxyHandshakeError{cause: certificate}, true, false},
		{"proxy_ct", &proxyHandshakeError{cause: ct}, true, false},
		{"proxy_io", &proxyHandshakeError{cause: io.EOF}, false, false},
		{"proxy_nested_dial", &proxyHandshakeError{cause: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := &url.Error{Op: "Post", URL: "https://origin.example", Err: tc.err}
			if IsTrustFailure(err) != tc.trust || IsOriginTrustFailure(err) != tc.origin {
				t.Fatal("incorrect trust failure scope")
			}
			if !errors.Is(err, tc.err) {
				t.Fatal("handshake cause was lost")
			}
			if attempt := new(InferenceAttempt); attempt.RetryConnectionFailure(t.Context(), err) {
				t.Fatal("handshake failure must not retry inference")
			}
		})
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
