package tlsct

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// A cold pool must queue behind its own connection allowance instead of
// attempting a dial that its socket budget will reject. Hold real TLS
// handshakes so HTTP/2 cannot conceal an excess dial through stream reuse.
func TestAttestationTransportAdmissionAlignment(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, h2 := range []bool{false, true} {
			for _, mode := range []string{"pooled", "fresh", "unreserved", "nested_tls12"} {
				if h2 && mode == "nested_tls12" {
					continue
				}
				t.Run(fmt.Sprintf("%s/http2=%v", mode, h2), func(t *testing.T) {
					testAttestationAdmission(t, authority, mode, h2)
				})
			}
		}
	})
}

func testAttestationAdmission(t *testing.T, authority *testtls.Authority, mode string, h2 bool) {
	t.Helper()
	budget, allowance := NewAttestationSocketBudget(3), 2
	switch mode {
	case "fresh":
		budget, allowance = budget.Fresh(), 3
	case "unreserved":
		budget, allowance = NewSocketBudget(3), 3
	}
	entered := make(chan struct{}, 64)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var requests atomic.Int32
	server := authority.NewTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if (r.ProtoMajor == 2) != h2 {
			t.Error("unexpected HTTP protocol")
		}
		_, _ = io.WriteString(w, "ok")
	}), func(server *httptest.Server) {
		server.EnableHTTP2 = h2
		server.TLS.NextProtos = []string{"http/1.1"}
		if h2 {
			server.TLS.NextProtos = []string{"h2", "http/1.1"}
		}
		if mode == "nested_tls12" {
			server.TLS.MinVersion, server.TLS.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
		}
		handshakeConfig := server.TLS.Clone()
		server.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			entered <- struct{}{}
			<-release
			return handshakeConfig, nil
		}
	})
	defer unblock()
	client := NewHTTPClientWithBudget(5*time.Second, budget, true)
	if mode == "nested_tls12" {
		client.Transport = NewTLS12FallbackTransportWithBudget(client.Transport, budget, "127.0.0.1")
	}
	defer client.CloseIdleConnections()
	results := make(chan error, allowance)
	for range allowance {
		go func() { results <- admissionRequest(t.Context(), client, server.URL) }()
	}
	for range allowance {
		select {
		case <-entered:
		case err := <-results:
			t.Fatalf("allowed dial failed: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("allowed handshakes did not start")
		}
	}
	// Cancel an excess request while the admitted connections are still
	// establishing TLS. Cancellation must not consume or release their permits.
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	err := admissionRequest(ctx, client, server.URL)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrConnectionCapacity) {
		t.Errorf("request should wait for its pool, then reach its deadline: %v", err)
	}
	if requests.Load() != 0 {
		t.Error("request bytes sent before TLS completed")
	}
	unblock()
	for range allowance {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			if err := admissionRequest(t.Context(), client, server.URL); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if requests.Load() != int32(allowance+24) {
		t.Error("request lost or replayed after queued cancellation")
	}
	// HTTP/2 can finish every request on one connection while another dial
	// completes in the background. Cleanup of an idle pool must still
	// release every permit before it returns.
	client.CloseIdleConnections()
	if remaining := heldSocketAddresses(budget); remaining != 0 {
		t.Fatalf("closed pools retained socket permits for %d addresses", remaining)
	}
}

func admissionRequest(ctx context.Context, client *http.Client, endpoint string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	return err
}
