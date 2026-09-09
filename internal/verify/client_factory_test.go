package verify

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/config"
)

func TestStandaloneExplicitAttestationFactory(t *testing.T) {
	for _, suppliedCollateral := range []bool{false, true} {
		t.Run(map[bool]string{false: "default_collateral", true: "supplied_collateral"}[suppliedCollateral], func(t *testing.T) {
			var factories, requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusBadRequest)
			}))
			defer server.Close()
			opts := &Options{Config: &config.Config{}, ProviderName: "neardirect", ModelName: "model", Offline: true,
				Provider:                 &config.Provider{BaseURL: server.URL},
				AttestationClientFactory: func() *http.Client { factories.Add(1); return server.Client() },
			}
			if suppliedCollateral {
				opts.Client = server.Client()
			}
			if _, err := Run(t.Context(), opts); err == nil {
				t.Fatal("attestation rejection accepted")
			}
			if factories.Load() != 1 || requests.Load() != 1 {
				t.Fatalf("factory calls=%d requests=%d; want one each", factories.Load(), requests.Load())
			}
		})
	}
}

func TestStandaloneClientOwnership(t *testing.T) {
	for _, name := range []string{"neardirect", "nearcloud", "tinfoil_v3_cloud"} {
		t.Run(name, func(t *testing.T) {
			opts := &Options{ProviderName: name, Offline: true}
			closeClients := opts.initializeClients()
			defer closeClients()
			if opts.Client == nil || (opts.MetadataClient != nil) != (name == "neardirect") {
				t.Fatal("incorrect default client ownership")
			}
			if opts.MetadataClient != nil && opts.MetadataClient == opts.Client {
				t.Fatal("metadata shares collateral client")
			}
			tracker := &clientCleanupTracker{}
			injected := &http.Client{Transport: tracker}
			opts = &Options{ProviderName: name, Client: injected, MetadataClient: injected}
			opts.initializeClients()()
			if tracker.closed.Load() != 0 || opts.Client != injected || opts.MetadataClient != injected {
				t.Fatal("injected client ownership changed")
			}
		})
	}
}

type clientCleanupTracker struct{ closed atomic.Int32 }

func (c *clientCleanupTracker) RoundTrip(*http.Request) (*http.Response, error) {
	panic("unexpected request")
}
func (c *clientCleanupTracker) CloseIdleConnections() { c.closed.Add(1) }
