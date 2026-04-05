package tlsct

import (
	"log/slog"
	"net/http"
	"time"
)

// loggingTransport logs every outgoing HTTP request at DEBUG level.
type loggingTransport struct{ base http.RoundTripper }

// WrapLogging wraps a transport with DEBUG-level request/response logging.
// Logs method, host, path, status, content-type, content-length, and elapsed
// time. Query parameters are omitted for nonce safety.
func WrapLogging(base http.RoundTripper) http.RoundTripper {
	return &loggingTransport{base: base}
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
		slog.DebugContext(req.Context(), "http request failed",
			"method", req.Method,
			"host", host,
			"path", path,
			"elapsed", elapsed,
			"err", err,
		)
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
