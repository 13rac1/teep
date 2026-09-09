package config

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestAttestationFactorySharedBudget(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		server := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
		var requests atomic.Int32
		var recordings []*capture.RecordingTransport
		factory := NewAttestationClientFactory(false, tlsct.NewSocketBudget(2), func(base http.RoundTripper) http.RoundTripper {
			recorder := capture.WrapRecording(tlsct.WrapCounting(base, func() { requests.Add(1) }, nil))
			recordings = append(recordings, recorder)
			return recorder
		})
		clients := []*http.Client{factory.NewClient(), factory.NewClient(), factory.NewClient()}
		for _, client := range clients {
			t.Cleanup(client.CloseIdleConnections)
		}
		var wg sync.WaitGroup
		for _, client := range clients[:2] {
			wg.Go(func() {
				if _, err := factoryRequest(t, client, server.URL); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if _, err := factoryRequest(t, clients[2], server.URL); !errors.Is(err, tlsct.ErrConnectionCapacity) {
			t.Fatalf("third pool: %v", err)
		}
		if requests.Load() != 3 {
			t.Fatalf("capacity failure retried: %d requests", requests.Load())
		}
		// Metadata can acquire the same address through its independent budget.
		metadata := NewAttestationClient(false)
		defer metadata.CloseIdleConnections()
		if _, err := factoryRequest(t, metadata, server.URL); err != nil {
			t.Fatal(err)
		}
		clients[0].CloseIdleConnections()
		if reused, err := factoryRequest(t, clients[1], server.URL); err != nil || !reused {
			t.Fatalf("other pool lost its connection: reused=%v err=%v", reused, err)
		}
		if _, err := factoryRequest(t, clients[2], server.URL); err != nil {
			t.Fatalf("closed permit was not released: %v", err)
		}
		for i, recorder := range recordings {
			if len(recorder.Snapshot()) == 0 {
				t.Fatalf("pool %d bypassed capture", i)
			}
		}
	})
}

func TestAttestationFactoryFullPooledAllowance(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		server := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
		factory := NewAttestationClientFactory(false, tlsct.NewSocketBudget(tlsct.MaxConnectionsPerHost), nil)
		for range tlsct.MaxConnectionsPerHost {
			client := factory.NewClient()
			t.Cleanup(client.CloseIdleConnections)
			if _, err := factoryRequest(t, client, server.URL); err != nil {
				t.Fatal(err)
			}
		}
		excess := factory.NewClient()
		defer excess.CloseIdleConnections()
		if _, err := factoryRequest(t, excess, server.URL); !errors.Is(err, tlsct.ErrConnectionCapacity) {
			t.Fatalf("excess pool: %v", err)
		}
	})
}

func factoryRequest(t *testing.T, client *http.Client, endpoint string) (bool, error) {
	t.Helper()
	var reused bool
	ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	_, err = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return reused, err
}
