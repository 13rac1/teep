package tlsct

import (
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"sync"
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

// tls12FallbackTransport routes requests by host. Hosts in the fallback
// map use a separate TLS 1.2 transport; everything else uses the default.
type tls12FallbackTransport struct {
	Default  http.RoundTripper
	Hosts    map[string]http.RoundTripper
	warnOnce sync.Once
}

// NewTLS12FallbackTransport wraps defaultRT with a host-dispatch layer.
// Requests to any host in tls12Hosts are routed through a separate
// http.Transport with MinVersion TLS 1.2 (no CT). All other requests use
// defaultRT unchanged.
//
// Hosts may be specified as bare hostnames ("kdsintf.amd.com") or with an
// explicit port ("kdsintf.amd.com:443"); the port is stripped before lookup
// so requests with explicit default ports still match.
//
// This exists because AMD KDS (kdsintf.amd.com) does not support TLS 1.3.
// TODO: remove when AMD KDS adds TLS 1.3 support.
func NewTLS12FallbackTransport(defaultRT http.RoundTripper, tls12Hosts ...string) http.RoundTripper {
	if len(tls12Hosts) == 0 {
		return defaultRT
	}
	fallback := &http.Transport{
		// Pin both Min and Max to TLS 1.2 so the fallback transport never
		// negotiates TLS 1.3 (which would bypass CT enforcement). This
		// keeps the workaround behavior consistent with its intent and
		// makes removal of the fallback less urgent operationally.
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12},
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	return NewTLS12FallbackTransportWithFallback(defaultRT, fallback, tls12Hosts)
}

// NewTLS12FallbackTransportWithFallback is the testable core of
// NewTLS12FallbackTransport: it accepts the fallback RoundTripper directly so
// tests can verify host routing without performing a real TLS 1.2 handshake.
// Production code should use NewTLS12FallbackTransport, which constructs a
// real TLS 1.2 transport internally.
func NewTLS12FallbackTransportWithFallback(defaultRT, fallback http.RoundTripper, tls12Hosts []string) http.RoundTripper {
	hosts := make(map[string]http.RoundTripper, len(tls12Hosts))
	for _, h := range tls12Hosts {
		hosts[hostKey(h)] = fallback
	}
	return &tls12FallbackTransport{Default: defaultRT, Hosts: hosts}
}

func (t *tls12FallbackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Strip the port from req.URL.Host so that explicit default ports
	// (e.g. "kdsintf.amd.com:443") still match the fallback map, which is
	// keyed by bare hostname.
	host := req.URL.Hostname()
	if host == "" {
		// Hostname() returns "" when Host has no port and is empty; fall
		// back to the raw Host so malformed requests still fail loudly
		// through the default transport rather than silently matching.
		host = req.URL.Host
	}
	if rt, ok := t.Hosts[host]; ok {
		// TODO: remove TLS 1.2 fallback when AMD KDS supports TLS 1.3.
		t.warnOnce.Do(func() {
			slog.Warn("using TLS 1.2 fallback for host (no TLS 1.3 support)",
				"host", host)
		})
		return rt.RoundTrip(req)
	}
	return t.Default.RoundTrip(req)
}

// hostKey normalizes a host (possibly with a port) to its bare hostname for
// use as a fallback map key. Used by NewTLS12FallbackTransport so callers may
// pass either "kdsintf.amd.com" or "kdsintf.amd.com:443".
func hostKey(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil && host != "" {
		return host
	}
	return h
}
