package httpclient_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/httpclient"
)

// mockRT is a controllable RoundTripper for testing.
type mockRT struct {
	calls int
	fn    func(*http.Request) (*http.Response, error)
}

func (m *mockRT) RoundTrip(req *http.Request) (*http.Response, error) {
	m.calls++
	return m.fn(req)
}

func okResponse() *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader("ok")),
	}
}

func makeReq(rawURL string) *http.Request {
	u, _ := url.Parse(rawURL)
	return &http.Request{
		Method: http.MethodGet,
		URL:    u,
		Header: make(http.Header),
	}
}

func closeBody(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
}

// ---------------------------------------------------------------------------
// Logging transport
// ---------------------------------------------------------------------------

func TestLoggingTransport_Success(t *testing.T) {
	mock := &mockRT{fn: func(*http.Request) (*http.Response, error) {
		return okResponse(), nil
	}}
	lt := httpclient.WrapLogging(mock)
	resp, err := lt.RoundTrip(makeReq("https://example.com/foo"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer closeBody(t, resp)
	t.Logf("status=%d calls=%d", resp.StatusCode, mock.calls)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if mock.calls != 1 {
		t.Errorf("calls = %d, want 1", mock.calls)
	}
}

func TestLoggingTransport_Error(t *testing.T) {
	wantErr := errors.New("connection refused")
	mock := &mockRT{fn: func(*http.Request) (*http.Response, error) {
		return nil, wantErr
	}}
	lt := httpclient.WrapLogging(mock)
	resp, err := lt.RoundTrip(makeReq("https://example.com/bar"))
	defer closeBody(t, resp)
	t.Logf("err=%v", err)
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}

func TestLoggingTransport_ErrorWithResponse(t *testing.T) {
	// Some transports return both a response and an error (e.g., redirect errors).
	// WrapLogging must close the body to avoid leaking.
	wantErr := errors.New("redirect error")
	mock := &mockRT{fn: func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusMovedPermanently,
			Body:       io.NopCloser(strings.NewReader("redirected")),
		}, wantErr
	}}
	lt := httpclient.WrapLogging(mock)
	resp, err := lt.RoundTrip(makeReq("https://example.com/redir"))
	closeBody(t, resp)
	t.Logf("err=%v resp=%v", err, resp)
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
	if resp != nil {
		t.Error("expected nil response when error is returned")
	}
}

func TestLoggingTransport_ErrorPassthrough(t *testing.T) {
	wantErr := errors.New("context deadline exceeded")
	mock := &mockRT{fn: func(*http.Request) (*http.Response, error) {
		return nil, wantErr
	}}
	lt := httpclient.WrapLogging(mock, 45*time.Second)
	resp, err := lt.RoundTrip(makeReq("https://example.com/bar"))
	defer closeBody(t, resp)
	t.Logf("err=%v", err)
	if !errors.Is(err, wantErr) {
		t.Errorf("err should be original error: %v", err)
	}
	// WrapLogging logs errors but does not wrap them — annotation happens in Do.
	if err.Error() != wantErr.Error() {
		t.Errorf("err should pass through unchanged: got %q, want %q", err.Error(), wantErr.Error())
	}
}

// ---------------------------------------------------------------------------
// Counting transport
// ---------------------------------------------------------------------------

func TestCountingTransport_NilCallbacks(t *testing.T) {
	mock := &mockRT{fn: func(*http.Request) (*http.Response, error) {
		return okResponse(), nil
	}}
	ct := httpclient.WrapCounting(mock, nil, nil)
	resp, err := ct.RoundTrip(makeReq("https://example.com/foo"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	closeBody(t, resp)
	t.Logf("status=%d (nil callbacks did not panic)", resp.StatusCode)
}

func TestCountingTransport_NilCallbacksOnError(t *testing.T) {
	wantErr := errors.New("connection refused")
	mock := &mockRT{fn: func(*http.Request) (*http.Response, error) {
		return nil, wantErr
	}}
	ct := httpclient.WrapCounting(mock, nil, nil)
	resp, err := ct.RoundTrip(makeReq("https://example.com/bar"))
	closeBody(t, resp)
	t.Logf("err=%v (nil callbacks did not panic)", err)
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}

func TestCountingTransport_ErrorWithResponse(t *testing.T) {
	// Transport returns both a response and an error — body must be closed.
	wantErr := errors.New("redirect error")
	mock := &mockRT{fn: func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusMovedPermanently,
			Body:       io.NopCloser(strings.NewReader("redirected")),
		}, wantErr
	}}
	var errCount int
	ct := httpclient.WrapCounting(mock, nil, func() { errCount++ })
	resp, err := ct.RoundTrip(makeReq("https://example.com/redir"))
	closeBody(t, resp)
	t.Logf("err=%v resp=%v errCount=%d", err, resp, errCount)
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
	if resp != nil {
		t.Error("expected nil response when error is returned")
	}
	if errCount != 1 {
		t.Errorf("errCount = %d, want 1", errCount)
	}
}

func TestCountingTransport_ErrorStillCallsOnRequest(t *testing.T) {
	wantErr := errors.New("timeout")
	mock := &mockRT{fn: func(*http.Request) (*http.Response, error) {
		return nil, wantErr
	}}
	var requests, errCount int
	ct := httpclient.WrapCounting(mock, func() { requests++ }, func() { errCount++ })
	resp, err := ct.RoundTrip(makeReq("https://example.com/bar"))
	closeBody(t, resp)
	t.Logf("requests=%d errors=%d", requests, errCount)
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if requests != 1 {
		t.Errorf("requests = %d, want 1 (onRequest fires before base)", requests)
	}
	if errCount != 1 {
		t.Errorf("errors = %d, want 1", errCount)
	}
}

func TestCountingTransport_SuccessDoesNotCallOnError(t *testing.T) {
	mock := &mockRT{fn: func(*http.Request) (*http.Response, error) {
		return okResponse(), nil
	}}
	var requests, errCount int
	ct := httpclient.WrapCounting(mock, func() { requests++ }, func() { errCount++ })
	resp, err := ct.RoundTrip(makeReq("https://example.com/foo"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	closeBody(t, resp)
	t.Logf("requests=%d errors=%d", requests, errCount)
	if requests != 1 {
		t.Errorf("requests = %d, want 1", requests)
	}
	if errCount != 0 {
		t.Errorf("errors = %d, want 0 (onError should not fire on success)", errCount)
	}
}

// ---------------------------------------------------------------------------
// Retry transport
// ---------------------------------------------------------------------------

// rtFunc adapts a function to http.RoundTripper for RetryTransport tests.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestRetryTransport_SuccessFirstAttempt(t *testing.T) {
	calls := 0
	rt := &httpclient.RetryTransport{
		Base: rtFunc(func(_ *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(nil))}, nil
		}),
		MaxAttempts: 3,
		MaxDelay:    time.Millisecond,
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", http.NoBody)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	t.Logf("calls: %d", calls)
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestRetryTransport_RetriesOn5xx(t *testing.T) {
	calls := 0
	rt := &httpclient.RetryTransport{
		Base: rtFunc(func(_ *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(bytes.NewReader(nil))}, nil
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte("ok")))}, nil
		}),
		MaxAttempts: 3,
		MaxDelay:    time.Millisecond,
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", http.NoBody)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("calls: %d, body: %s", calls, body)
	if calls != 2 {
		t.Errorf("expected 2 calls, got %d", calls)
	}
}

func TestRetryTransport_ExhaustsMaxAttempts(t *testing.T) {
	calls := 0
	rt := &httpclient.RetryTransport{
		Base: rtFunc(func(_ *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Body:       io.NopCloser(bytes.NewReader(nil)),
			}, nil
		}),
		// Zero MaxAttempts exercises the default (3).
		MaxDelay: time.Millisecond,
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", http.NoBody)
	resp, err := rt.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	t.Logf("calls=%d err=%v", calls, err)
	if err == nil {
		t.Fatal("expected error after exhausting all attempts")
	}
	if calls != 3 {
		t.Errorf("expected 3 calls (default MaxAttempts), got %d", calls)
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error = %q, should mention 503", err)
	}
}

func TestRetryTransport_BodyCannotReset(t *testing.T) {
	attempts := 0
	rt := &httpclient.RetryTransport{
		Base: &mockRT{fn: func(req *http.Request) (*http.Response, error) {
			attempts++
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Body:       io.NopCloser(bytes.NewReader(nil)),
			}, nil
		}},
		MaxAttempts: 3,
		MaxDelay:    time.Millisecond,
	}

	req, _ := http.NewRequest(http.MethodPost, "https://example.com/attest", http.NoBody)
	req.Body = io.NopCloser(bytes.NewReader([]byte(`{"nonce":"abc"}`)))
	req.GetBody = nil

	resp, err := rt.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	t.Logf("BodyCannotReset: err=%v attempts=%d", err, attempts)
	if attempts != 1 {
		t.Errorf("expected 1 attempt (body cannot be reset), got %d", attempts)
	}
	if err == nil {
		t.Error("expected non-nil error when body cannot be reset")
	}
}

func TestRetryTransport_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	rt := &httpclient.RetryTransport{
		Base: &mockRT{fn: func(req *http.Request) (*http.Response, error) {
			cancel() // cancel after first attempt
			return nil, errors.New("connection refused")
		}},
		MaxAttempts: 3,
		MaxDelay:    time.Millisecond,
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", http.NoBody)
	resp, err := rt.RoundTrip(req)
	closeBody(t, resp)
	t.Logf("err=%v", err)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestRetryTransport_NetworkError(t *testing.T) {
	calls := 0
	rt := &httpclient.RetryTransport{
		Base: &mockRT{fn: func(req *http.Request) (*http.Response, error) {
			calls++
			if calls < 3 {
				return nil, errors.New("connection refused")
			}
			return okResponse(), nil
		}},
		MaxAttempts: 3,
		MaxDelay:    time.Millisecond,
	}

	req := makeReq("https://example.com/")
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer closeBody(t, resp)
	t.Logf("calls: %d, status: %d", calls, resp.StatusCode)
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
}

func TestRetryTransport_GetBodyError(t *testing.T) {
	calls := 0
	rt := &httpclient.RetryTransport{
		Base: &mockRT{fn: func(req *http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("connection refused")
		}},
		MaxAttempts: 3,
		MaxDelay:    time.Millisecond,
	}

	body := []byte(`{"nonce":"abc"}`)
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/attest", bytes.NewReader(body))
	getBodyErr := errors.New("body stream closed")
	req.GetBody = func() (io.ReadCloser, error) {
		return nil, getBodyErr
	}

	resp, err := rt.RoundTrip(req)
	closeBody(t, resp)
	t.Logf("calls=%d err=%v", calls, err)
	if !errors.Is(err, getBodyErr) {
		t.Errorf("expected GetBody error, got: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call before GetBody error, got %d", calls)
	}
}

func TestRetryTransport_RetriesWithGetBody(t *testing.T) {
	calls := 0
	rt := &httpclient.RetryTransport{
		Base: &mockRT{fn: func(req *http.Request) (*http.Response, error) {
			calls++
			if calls < 2 {
				return &http.Response{
					StatusCode: http.StatusServiceUnavailable,
					Body:       io.NopCloser(bytes.NewReader(nil)),
				}, nil
			}
			return okResponse(), nil
		}},
		MaxAttempts: 3,
		MaxDelay:    time.Millisecond,
	}

	body := []byte(`{"nonce":"abc"}`)
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/attest", bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer closeBody(t, resp)
	t.Logf("calls: %d, status: %d", calls, resp.StatusCode)
	if calls != 2 {
		t.Errorf("expected 2 calls, got %d", calls)
	}
}

// ---------------------------------------------------------------------------
// Client construction
// ---------------------------------------------------------------------------

func TestNewHTTPClientWithTransport(t *testing.T) {
	t.Run("nil base does not panic", func(t *testing.T) {
		c := httpclient.NewHTTPClientWithTransport(5*time.Second, nil)
		if c == nil {
			t.Fatal("expected non-nil client")
		}
		t.Logf("client timeout: %v", c.Timeout)
	})

	t.Run("TLS 1.2 upgraded to 1.3", func(t *testing.T) {
		base := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
		c := httpclient.NewHTTPClientWithTransport(5*time.Second, base)
		tr := c.Transport.(*http.Transport)
		t.Logf("TLS min version: %d", tr.TLSClientConfig.MinVersion)
		if tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
			t.Fatalf("expected TLS 1.3, got %d", tr.TLSClientConfig.MinVersion)
		}
	})

	t.Run("TLS 1.3 not downgraded", func(t *testing.T) {
		base := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
		c := httpclient.NewHTTPClientWithTransport(5*time.Second, base)
		tr := c.Transport.(*http.Transport)
		t.Logf("TLS min version: %d", tr.TLSClientConfig.MinVersion)
		if tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
			t.Fatalf("expected TLS 1.3, got %d", tr.TLSClientConfig.MinVersion)
		}
	})

	t.Run("nil TLSClientConfig gets TLS 1.3", func(t *testing.T) {
		base := &http.Transport{}
		c := httpclient.NewHTTPClientWithTransport(5*time.Second, base)
		tr := c.Transport.(*http.Transport)
		t.Logf("TLS config: %+v", tr.TLSClientConfig)
		if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
			t.Fatal("expected TLS 1.3 config")
		}
	})

	t.Run("timeout propagated", func(t *testing.T) {
		c := httpclient.NewHTTPClient(42 * time.Second)
		t.Logf("timeout: %v", c.Timeout)
		if c.Timeout != 42*time.Second {
			t.Fatalf("expected 42s timeout, got %v", c.Timeout)
		}
	})
}

func TestNewAttestationClient(t *testing.T) {
	client := httpclient.NewAttestationClient(config.AttestationTimeout, false)
	if client == nil {
		t.Fatal("NewAttestationClient returned nil")
	}
	t.Logf("timeout: %v", client.Timeout)
	if client.Timeout != config.AttestationTimeout {
		t.Errorf("client Timeout: got %v, want %v", client.Timeout, config.AttestationTimeout)
	}
}

func TestNewAttestationClientOffline(t *testing.T) {
	client := httpclient.NewAttestationClient(config.AttestationTimeout, true)
	if client == nil {
		t.Fatal("NewAttestationClient returned nil")
	}
	t.Logf("timeout: %v, transport type: %T", client.Timeout, client.Transport)
	if client.Timeout != config.AttestationTimeout {
		t.Errorf("client Timeout: got %v, want %v", client.Timeout, config.AttestationTimeout)
	}
}

// ---------------------------------------------------------------------------
// Do — timeout annotation
// ---------------------------------------------------------------------------

func TestDo_AnnotatesErrorWithTimeout(t *testing.T) {
	client := &http.Client{
		Timeout: 42 * time.Second,
		Transport: &mockRT{fn: func(*http.Request) (*http.Response, error) {
			return nil, errors.New("connection refused")
		}},
	}
	req := makeReq("https://example.com/test")
	resp, err := httpclient.Do(client, req)
	closeBody(t, resp)
	if err == nil {
		t.Fatal("expected error")
	}
	t.Logf("error: %v", err)
	if !strings.Contains(err.Error(), "(timeout 42s)") {
		t.Errorf("error should contain timeout annotation, got: %v", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error should contain original message, got: %v", err)
	}
}

func TestDo_NoAnnotationWithoutTimeout(t *testing.T) {
	client := &http.Client{
		Timeout: 0, // no timeout
		Transport: &mockRT{fn: func(*http.Request) (*http.Response, error) {
			return nil, errors.New("connection refused")
		}},
	}
	req := makeReq("https://example.com/test")
	resp, err := httpclient.Do(client, req)
	closeBody(t, resp)
	if err == nil {
		t.Fatal("expected error")
	}
	t.Logf("error: %v", err)
	if strings.Contains(err.Error(), "timeout") {
		t.Errorf("error should not contain timeout annotation, got: %v", err)
	}
}

func TestDo_Success(t *testing.T) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &mockRT{fn: func(*http.Request) (*http.Response, error) {
			return okResponse(), nil
		}},
	}
	req := makeReq("https://example.com/test")
	resp, err := httpclient.Do(client, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer closeBody(t, resp)
	t.Logf("status: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}
