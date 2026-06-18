package tlsct_test

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/tlsct"
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
	lt := tlsct.WrapLogging(mock)
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
	lt := tlsct.WrapLogging(mock)
	resp, err := lt.RoundTrip(makeReq("https://example.com/bar"))
	defer closeBody(t, resp)
	t.Logf("err=%v", err)
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}

// ---------------------------------------------------------------------------
// Counting transport
// ---------------------------------------------------------------------------

func TestCountingTransport_NilCallbacks(t *testing.T) {
	mock := &mockRT{fn: func(*http.Request) (*http.Response, error) {
		return okResponse(), nil
	}}
	// nil for both callbacks — must not panic.
	ct := tlsct.WrapCounting(mock, nil, nil)
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
	// nil for both callbacks — error path must not panic.
	ct := tlsct.WrapCounting(mock, nil, nil)
	resp, err := ct.RoundTrip(makeReq("https://example.com/bar"))
	closeBody(t, resp)
	t.Logf("err=%v (nil callbacks did not panic)", err)
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}

func TestCountingTransport_ErrorStillCallsOnRequest(t *testing.T) {
	wantErr := errors.New("timeout")
	mock := &mockRT{fn: func(*http.Request) (*http.Response, error) {
		return nil, wantErr
	}}
	var requests, errCount int
	ct := tlsct.WrapCounting(mock, func() { requests++ }, func() { errCount++ })
	resp, err := ct.RoundTrip(makeReq("https://example.com/bar"))
	closeBody(t, resp)
	t.Logf("requests=%d errors=%d", requests, errCount)
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	// onRequest fires before the base call; onError fires after.
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
	ct := tlsct.WrapCounting(mock, func() { requests++ }, func() { errCount++ })
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

func TestCountingTransport_CountsRequests(t *testing.T) {
	mock := &mockRT{fn: func(*http.Request) (*http.Response, error) {
		return okResponse(), nil
	}}
	var requests int
	ct := tlsct.WrapCounting(mock, func() { requests++ }, nil)
	resp, err := ct.RoundTrip(makeReq("https://example.com/foo"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	closeBody(t, resp)
	t.Logf("requests=%d", requests)
	if requests != 1 {
		t.Errorf("requests = %d, want 1", requests)
	}
}

func TestCountingTransport_CountsErrors(t *testing.T) {
	wantErr := errors.New("connection refused")
	mock := &mockRT{fn: func(*http.Request) (*http.Response, error) {
		return nil, wantErr
	}}
	var requests, errCount int
	ct := tlsct.WrapCounting(mock, func() { requests++ }, func() { errCount++ })
	resp, err := ct.RoundTrip(makeReq("https://example.com/bar"))
	closeBody(t, resp)
	t.Logf("requests=%d errors=%d err=%v", requests, errCount, err)
	if requests != 1 {
		t.Errorf("requests = %d, want 1", requests)
	}
	if errCount != 1 {
		t.Errorf("errors = %d, want 1", errCount)
	}
}

// ---------------------------------------------------------------------------
// TLS 1.2 fallback transport
// ---------------------------------------------------------------------------

func TestTLS12FallbackTransport_RoutesToFallback(t *testing.T) {
	var defaultCalls, fallbackCalls int
	defaultRT := &mockRT{fn: func(*http.Request) (*http.Response, error) {
		defaultCalls++
		return okResponse(), nil
	}}
	fallbackRT := &mockRT{fn: func(*http.Request) (*http.Response, error) {
		fallbackCalls++
		return okResponse(), nil
	}}

	// Use the testable constructor so we can verify routing without a real
	// TLS 1.2 handshake. The fallback host is registered with an explicit
	// port to confirm port-stripping in the host key.
	fb := tlsct.NewTLS12FallbackTransportWithFallback(
		defaultRT, fallbackRT, []string{"special.example.com:443"})

	// Request to the fallback host must route through fallbackRT, not default.
	resp, err := fb.RoundTrip(makeReq("https://special.example.com/path"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	closeBody(t, resp)
	if fallbackCalls != 1 {
		t.Errorf("fallbackCalls = %d, want 1 (fallback host must route through fallback transport)", fallbackCalls)
	}
	if defaultCalls != 0 {
		t.Errorf("defaultCalls = %d, want 0 (fallback host must NOT route through default transport)", defaultCalls)
	}

	// Request to an explicit default port on the fallback host must also match.
	resp, err = fb.RoundTrip(makeReq("https://special.example.com:443/path"))
	if err != nil {
		t.Fatalf("unexpected error for explicit port: %v", err)
	}
	closeBody(t, resp)
	if fallbackCalls != 2 {
		t.Errorf("fallbackCalls = %d, want 2 (explicit port must still match fallback host)", fallbackCalls)
	}

	// Request to a non-fallback host must route through defaultRT.
	resp, err = fb.RoundTrip(makeReq("https://normal.example.com/path"))
	if err != nil {
		t.Fatalf("unexpected error for normal host: %v", err)
	}
	closeBody(t, resp)
	if defaultCalls != 1 {
		t.Errorf("defaultCalls = %d, want 1 (normal host must route through default transport)", defaultCalls)
	}
	if fallbackCalls != 2 {
		t.Errorf("fallbackCalls = %d, want 2 (normal host must NOT route through fallback transport)", fallbackCalls)
	}
}

func TestTLS12FallbackTransport_NoHosts(t *testing.T) {
	defaultRT := &mockRT{fn: func(*http.Request) (*http.Response, error) {
		return okResponse(), nil
	}}

	fb := tlsct.NewTLS12FallbackTransport(defaultRT)
	resp, err := fb.RoundTrip(makeReq("https://example.com/path"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	closeBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}
