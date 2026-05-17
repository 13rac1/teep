// Package httpclient provides HTTP client construction, transport wrappers,
// and retry logic used throughout the teep codebase.
package httpclient

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
)

// --- Transport wrappers ---

// Do wraps client.Do and annotates errors with the client's configured
// timeout. Use this instead of client.Do(req) so that timeout errors
// always include the configured limit.
func Do(client *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := client.Do(req)
	if err != nil && client.Timeout > 0 {
		return resp, fmt.Errorf("%w (timeout %v)", err, client.Timeout)
	}
	return resp, err
}

// loggingTransport logs every outgoing HTTP request at DEBUG level.
// When timeout is set, it is included in log output so operators can
// correlate failures with the configured limit.
type loggingTransport struct {
	base    http.RoundTripper
	timeout time.Duration
}

// WrapLogging wraps a transport with DEBUG-level request/response logging.
// Logs method, host, path, status, content-type, content-length, and elapsed
// time. Query parameters are omitted for nonce safety.
func WrapLogging(base http.RoundTripper, timeout ...time.Duration) http.RoundTripper {
	var t time.Duration
	if len(timeout) > 0 {
		t = timeout[0]
	}
	return &loggingTransport{base: base, timeout: t}
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	elapsed := time.Since(start)

	host := req.URL.Host
	path := req.URL.Path

	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		attrs := []any{
			"method", req.Method,
			"host", host,
			"path", path,
			"elapsed", elapsed,
			"err", err,
		}
		if t.timeout > 0 {
			attrs = append(attrs, "timeout", t.timeout)
		}
		slog.DebugContext(req.Context(), "http request failed", attrs...)
		return nil, err
	}

	slog.DebugContext(req.Context(), "http request",
		"method", req.Method,
		"host", host,
		"path", path,
		"status", resp.StatusCode,
		"content_type", resp.Header.Get("Content-Type"),
		"content_length", resp.ContentLength,
		"elapsed", elapsed,
	)
	return resp, nil
}

// countingTransport wraps a transport to count requests and errors.
type countingTransport struct {
	base      http.RoundTripper
	onRequest func()
	onError   func()
}

// WrapCounting wraps a transport to call onRequest before each request and
// onError on transport failures. Nil callbacks are no-ops.
func WrapCounting(base http.RoundTripper, onRequest, onError func()) http.RoundTripper {
	return &countingTransport{base: base, onRequest: onRequest, onError: onError}
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.onRequest != nil {
		t.onRequest()
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		if t.onError != nil {
			t.onError()
		}
		return nil, err
	}
	return resp, nil
}

// --- Retry transport ---

// RetryTransport wraps a transport with automatic retry on 5xx and network errors.
type RetryTransport struct {
	Base        http.RoundTripper
	MaxAttempts int           // 0 → default 3
	MaxDelay    time.Duration // 0 → default 4s
}

// RoundTrip executes the request, retrying on 5xx and network errors.
func (t *RetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	maxAttempts := t.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	maxDelay := t.MaxDelay
	if maxDelay <= 0 {
		maxDelay = 4 * time.Second
	}
	hasBody := req.Body != nil && req.Body != http.NoBody
	var lastErr error
	for attempt := range maxAttempts {
		if attempt > 0 {
			if hasBody && req.GetBody == nil {
				// Body was consumed on the first attempt and cannot be reset.
				return nil, lastErr
			}
			exp := min(attempt-1, 30) // cap to avoid int64 overflow; 2^30s >> any realistic maxDelay
			timer := time.NewTimer(min(time.Duration(1<<exp)*time.Second, maxDelay))
			select {
			case <-req.Context().Done():
				timer.Stop()
				return nil, req.Context().Err()
			case <-timer.C:
			}
			slog.WarnContext(req.Context(), "retrying after error",
				"host", req.URL.Host, "path", req.URL.Path, "attempt", attempt+1, "err", lastErr)
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err != nil {
					return nil, err
				}
				req.Body = body
			}
		}
		resp, err := t.Base.RoundTrip(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, req.URL.Host)
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

// --- Client construction ---

// NewHTTPClient returns an HTTP client with TLS 1.3 enforcement and
// DEBUG-level request logging. The returned client uses a cloned
// http.DefaultTransport with sensible defaults.
func NewHTTPClient(timeout time.Duration) *http.Client {
	dt, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		panic("http.DefaultTransport is not *http.Transport")
	}
	client := NewHTTPClientWithTransport(timeout, dt.Clone())
	client.Transport = WrapLogging(client.Transport, timeout)
	return client
}

// NewHTTPClientWithTransport returns an HTTP client that enforces TLS 1.3
// using the provided base transport settings.
func NewHTTPClientWithTransport(timeout time.Duration, base *http.Transport) *http.Client {
	if base == nil {
		dt, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			panic("http.DefaultTransport is not *http.Transport")
		}
		base = dt.Clone()
	}
	if base.TLSClientConfig == nil {
		base.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	} else if base.TLSClientConfig.MinVersion < tls.VersionTLS13 {
		base.TLSClientConfig.MinVersion = tls.VersionTLS13
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: base,
	}
}

// NewAttestationClient returns an *http.Client configured for fetching
// attestation data from TEE provider endpoints. Wraps with Certificate
// Transparency checks unless offline.
func NewAttestationClient(timeout time.Duration, offline bool) *http.Client {
	client := NewHTTPClientWithTransport(timeout, &http.Transport{
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	})
	transport := client.Transport
	if !offline {
		transport = tlsct.WrapTransport(transport)
	}
	client.Transport = &RetryTransport{Base: WrapLogging(transport, timeout)}
	return client
}
