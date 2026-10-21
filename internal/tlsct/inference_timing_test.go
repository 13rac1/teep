package tlsct

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestInferenceTimingHeaderWaitAndReuse(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		server := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/wait" {
				<-r.Context().Done()
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		for _, reuse := range []bool{false, true} {
			client, err := NewSPKIPinnedHTTPClientWithTransport(0, NewPooledTransport(), pinnedTestIdentity(t, server.URL, certificateSPKI(t, server)), false)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.CloseIdleConnections)
			if reuse {
				resp, err := client.Get(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			written := make(chan struct{})
			var once sync.Once
			ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) { once.Do(func() { close(written) }) }})
			attempt := &InferenceAttempt{}
			req, err := http.NewRequestWithContext(attempt.Context(ctx), http.MethodGet, server.URL+"/wait", http.NoBody)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				resp, err := client.Do(req)
				if resp != nil {
					resp.Body.Close()
				}
				done <- err
			}()
			select {
			case <-written:
			case <-ctx.Done():
				cancel()
				t.Fatal("request not written")
			}
			timing := diagnosticFields(attempt.TimingDiagnostics())
			connection := diagnosticFields(attempt.ConnectionDiagnostics())
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation: %v", err)
			}
			if timing["failure_phase"] != "response_headers" || timing["response_header_wait"].(time.Duration) < 0 || timing["connection_acquire"].(time.Duration) <= 0 || connection["connection_reused"] != reuse {
				t.Fatalf("incorrect wait/reuse: %v %v", timing, connection)
			}
			_, handshake := timing["tls_handshake"]
			if handshake == reuse {
				t.Fatalf("handshake=%v reused=%v", handshake, reuse)
			}
		}
	})
}

func TestInferenceTimingEarlyResponse(t *testing.T) {
	for _, failedWrite := range []bool{false, true} {
		attempt := &InferenceAttempt{}
		attempt.timing.getConn()
		attempt.timing.gotConn("h2")
		attempt.ResponseHeadersReceived("HTTP/2.0")
		if failedWrite {
			// An early rejection can stop the upload before it completes.
			attempt.timing.wroteRequest(errors.New("request body write aborted"))
		}
		fields := diagnosticFields(attempt.TimingDiagnostics())
		if fields["failure_phase"] != "response_body" || fields["upstream_protocol"] != "HTTP/2.0" {
			t.Fatalf("incorrect early response diagnostics: %v", fields)
		}
		if _, ok := fields["response_header_wait"]; ok {
			t.Fatalf("header wait without a successful write callback: %v", fields)
		}
	}
}

func TestInferenceTimingRepeatedAcquisition(t *testing.T) {
	attempt := &InferenceAttempt{}
	timing := &attempt.timing
	timing.getConn()
	timing.tlsStart()
	timing.gotConn("h2")
	timing.wroteRequest(nil)
	// The old speculative handshake can finish after the next acquisition.
	timing.getConn()
	timing.tlsDone()
	fields := diagnosticFields(attempt.TimingDiagnostics())
	if fields["failure_phase"] != "connection_acquire" || fields["upstream_protocol"] != nil || fields["response_header_wait"] != nil {
		t.Fatalf("previous acquisition contaminated timing: %v", fields)
	}
	timing.gotConn("h2")
	timing.wroteRequest(nil)
	attempt.ResponseHeadersReceived("HTTP/2.0")
	// A late callback must not replace the assigned response's protocol.
	timing.tlsDone()
	fields = diagnosticFields(attempt.TimingDiagnostics())
	if fields["failure_phase"] != "response_body" || fields["upstream_protocol"] != "HTTP/2.0" {
		t.Fatalf("late handshake changed response diagnostics: %v", fields)
	}
}

func TestInferenceTimingOverlappingHandshakes(t *testing.T) {
	attempt := &InferenceAttempt{}
	timing := &attempt.timing
	timing.tlsStart()
	// Set the start in the past to check elapsed time without sleeping.
	started := time.Now().Add(-time.Second)
	timing.tlsStarted = started
	timing.tlsStart()
	timing.tlsDone()
	if timing.tlsActive != 1 || timing.tlsDuration != 0 || !timing.tlsStarted.Equal(started) {
		t.Fatal("overlapping handshake ended the elapsed interval")
	}
	timing.tlsDone()
	elapsed := diagnosticFields(attempt.TimingDiagnostics())["tls_handshake"].(time.Duration)
	if elapsed < time.Second || elapsed > time.Since(started) {
		t.Fatalf("handshake interval counted incorrectly: %v", elapsed)
	}
	if timing.tlsActive != 0 {
		t.Fatal("completed handshakes remain active")
	}
}
