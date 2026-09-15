package tlsct

import (
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func diagnosticFields(attrs []any) map[string]any {
	fields := make(map[string]any)
	for i := 0; i < len(attrs); i += 2 {
		fields[attrs[i].(string)] = attrs[i+1]
	}
	return fields
}

func TestFailedHandshakeHasNoAssignedConnection(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		var wg sync.WaitGroup
		for range 8 {
			ts := authority.NewTLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("mismatched peer received request") }))
			client, err := NewSPKIPinnedHTTPClientWithTransport(0, NewPooledTransport(), pinnedTestIdentity(t, ts.URL, hexFingerprint([32]byte{1})), false)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.CloseIdleConnections)
			wg.Go(func() {
				attempt := &InferenceAttempt{}
				req, err := http.NewRequestWithContext(attempt.Context(t.Context()), http.MethodGet, ts.URL, http.NoBody)
				if err != nil {
					t.Error(err)
					return
				}
				resp, err := client.Do(req)
				if resp != nil {
					resp.Body.Close()
				}
				if !errors.Is(err, ErrSPKIMismatch) {
					t.Errorf("missing mismatch: %v", err)
					return
				}
				timing := diagnosticFields(attempt.TimingDiagnostics())
				if timing["failure_phase"] != "tls_handshake" {
					t.Errorf("incorrect handshake phase: %v", timing)
				}
				fields := diagnosticFields(attempt.ConnectionDiagnostics())
				if fields["connection_assigned"] != false || fields["remote_addr"] != nil {
					t.Errorf("incorrect failed handshake diagnostics: %v", fields)
				}
			})
		}
		wg.Wait()
	})
}
