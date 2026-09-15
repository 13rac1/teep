package tlsct

import (
	"sync"
	"time"
)

type inferenceTiming struct {
	mu                                   sync.Mutex
	acquire, connected, written, headers time.Time
	tlsStarted                           time.Time
	tlsActive                            int
	tlsDuration                          time.Duration
	tlsSeen                              bool
	acquisitions                         int
	protocol                             string
}

func (t *inferenceTiming) getConn() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.acquire = time.Now()
	t.acquisitions++
	t.protocol = ""
	t.connected, t.written, t.headers = time.Time{}, time.Time{}, time.Time{}
}
func (t *inferenceTiming) gotConn(protocol string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.connected = time.Now()
	t.protocol = inferenceProtocol(protocol)
}
func (t *inferenceTiming) tlsStart() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.tlsActive == 0 {
		t.tlsStarted = time.Now()
	}
	t.tlsActive++
	t.tlsSeen = true
}
func (t *inferenceTiming) tlsDone() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.tlsActive > 0 {
		t.tlsActive--
		if t.tlsActive == 0 {
			t.tlsDuration += time.Since(t.tlsStarted)
		}
	}
}
func (t *inferenceTiming) wroteRequest(err error) {
	if err != nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.written = time.Now()
}

// ResponseHeadersReceived ends response-header waiting at client.Do return.
// It must be called only when a response was received successfully.
func (a *InferenceAttempt) ResponseHeadersReceived(protocol string) {
	t := &a.timing
	t.mu.Lock()
	defer t.mu.Unlock()
	t.headers = time.Now()
	t.protocol = inferenceProtocol(protocol)
}

// TimingDiagnostics reports elapsed connection acquisition (including dial and
// TLS), elapsed time with at least one active origin TLS handshake, and
// response-header waiting from the successful WroteRequest callback. With
// HTTP/1.1, that interval can include the final transport buffer flush.
// Concurrent handshakes count once. These overlapping durations must not be
// added together.
func (a *InferenceAttempt) TimingDiagnostics() []any {
	t := &a.timing
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	attrs := []any{"failure_phase", t.phase()}
	if !t.acquire.IsZero() {
		attrs = append(attrs, "connection_acquire", timingElapsed(t.acquire, t.connected, now))
	}
	if t.tlsSeen {
		duration := t.tlsDuration
		if t.tlsActive > 0 {
			duration += now.Sub(t.tlsStarted)
		}
		attrs = append(attrs, "tls_handshake", duration)
	}
	if !t.written.IsZero() {
		attrs = append(attrs, "response_header_wait", timingElapsed(t.written, t.headers, now))
	}
	if t.protocol != "" {
		attrs = append(attrs, "upstream_protocol", t.protocol)
	}
	return attrs
}

func timingElapsed(start, end, now time.Time) time.Duration {
	if end.IsZero() {
		end = now
	}
	return max(0, end.Sub(start))
}

func (t *inferenceTiming) phase() string {
	switch {
	case !t.headers.IsZero():
		return "response_body"
	case !t.written.IsZero() && t.protocol == "HTTP/2.0":
		return "response_headers"
	case !t.written.IsZero():
		// WroteRequest can precede the final HTTP/1.1 buffer flush.
		return "request_write_or_response_headers"
	case !t.connected.IsZero():
		return "request_write"
	// TLS callbacks do not identify their acquisition. After a retry, late
	// callbacks can belong to an earlier dial; report only the broader phase.
	case t.tlsSeen && t.acquisitions == 1:
		return "tls_handshake"
	case !t.acquire.IsZero():
		return "connection_acquire"
	default:
		return "prepare"
	}
}

// inferenceProtocol gives ALPN and HTTP response metadata the same spelling.
func inferenceProtocol(protocol string) string {
	switch protocol {
	case "h2":
		return "HTTP/2.0"
	case "http/1.1":
		return "HTTP/1.1"
	default:
		return protocol
	}
}
