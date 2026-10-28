package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// messageCounter is a slog handler that counts records by message. It is
// safe for concurrent use.
type messageCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func (h *messageCounter) Enabled(context.Context, slog.Level) bool { return true }

func (h *messageCounter) Handle(_ context.Context, r slog.Record) error { //nolint:gocritic // slog.Handler interface requires slog.Record by value
	h.mu.Lock()
	defer h.mu.Unlock()
	h.counts[r.Message]++
	return nil
}

func (h *messageCounter) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *messageCounter) WithGroup(string) slog.Handler      { return h }

func (h *messageCounter) count(msg string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.counts[msg]
}

// countingPool is a nonce pool that gives a new instance and nonce for each
// fetch, all with the same E2EE key.
type countingPool struct {
	key     string
	fetches atomic.Int32
}

func (p *countingPool) FetchE2EEMaterial(context.Context, string) (*provider.E2EEMaterial, error) {
	n := p.fetches.Add(1)
	return &provider.E2EEMaterial{
		E2EPubKey:  p.key,
		InstanceID: fmt.Sprintf("inst-%d", n),
		E2ENonce:   fmt.Sprintf("nonce-%d", n),
		ChuteID:    "chute-1",
	}, nil
}

func (p *countingPool) MarkFailed(_, _ string) {}
func (p *countingPool) Invalidate(string)      {}

// Concurrent Chutes requests that find the report but no signing key share one
// full verification. One request receives the verified instance and nonce.
// Each other request fails its first attempt, and the Chutes retry takes
// material from the nonce pool with the key that the verification published.
// All requests complete.
func TestChutesConcurrentKeyMissRetriesThroughNoncePool(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		const n = 8
		attester := newHeldReportAttester(nil)
		// The cache holds a passing report and no signing key.
		s, prov, enc, _ := newChutesKeyMissTestServer(t, attester, &mockE2EEMaterialFetcher{}, "")
		// The test evidence fails TDX. The force policy gives a report that passes.
		bindTestEvidence(s, prov)
		pool := &countingPool{key: "attested-key"}
		prov.E2EEMaterialFetcher = pool
		var upstreamRequests atomic.Int32
		prov.BaseURL = authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			upstreamRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","created":1,"model":"model","choices":[]}`))
		})).URL

		logs := &messageCounter{counts: make(map[string]int)}
		prev := slog.Default()
		slog.SetDefault(slog.New(logs))
		defer slog.SetDefault(prev)

		var wg sync.WaitGroup
		errs := make(chan error, n)
		for range n {
			wg.Go(func() {
				ur, err := s.doUpstreamRoundtrip(t.Context(), prov, []byte(`{}`), "model", true, nil, false,
					"/v1/chat/completions", "application/json", e2ee.EndpointChat)
				if err == nil {
					_, _ = io.Copy(io.Discard, ur.Resp.Body)
					ur.Resp.Body.Close()
					ur.Cancel()
					if ur.Resp.StatusCode != http.StatusOK {
						err = fmt.Errorf("upstream status %d", ur.Resp.StatusCode)
					}
				}
				errs <- err
			})
		}
		waitForCondition(t, "all key misses", func() bool {
			return logs.count("E2EE key exchange: no usable cached signing key; starting full verification") == n
		})
		close(attester.release)
		wg.Wait()
		close(errs)

		for err := range errs {
			if err != nil {
				t.Errorf("request failed: %v", err)
			}
		}
		if got := attester.calls.Load(); got != 1 {
			t.Errorf("attestation fetches = %d, want 1", got)
		}
		if got := upstreamRequests.Load(); got != n {
			t.Errorf("upstream requests = %d, want %d", got, n)
		}
		// Each request that did not receive the verified material needs at
		// least one retry, so n-1 retries means exactly one each.
		if got := logs.count("E2EE key exchange: verified E2EE material went to another request; request blocked"); got != n-1 {
			t.Errorf("requests without the verified material = %d, want %d", got, n-1)
		}
		if got := logs.count("chutes: E2EE body build failed, retrying"); got != n-1 {
			t.Errorf("retries = %d, want %d", got, n-1)
		}
		if got := pool.fetches.Load(); got != n-1 {
			t.Errorf("nonce pool fetches = %d, want %d", got, n-1)
		}
		keys := enc.encrypted()
		if len(keys) != n {
			t.Fatalf("encrypted requests = %d, want %d", len(keys), n)
		}
		for _, key := range keys {
			if key != "attested-key" {
				t.Fatalf("request used key %q, want the published key", key)
			}
		}
	})
}
