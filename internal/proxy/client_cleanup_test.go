package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestServerCloseProviderConnections(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		var connections, closed atomic.Int32
		upstream := authority.NewTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/models") {
				_, _ = io.WriteString(w, `{"data":[]}`)
				return
			}
			// Invalid evidence exercises attester transport ownership without claiming
			// that mocked evidence passes provider authentication.
			_, _ = io.WriteString(w, `{`)
		}), func(server *httptest.Server) {
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateClosed {
					closed.Add(1)
				}
			}
		})
		server, err := New(&config.Config{Providers: map[string]*config.Provider{
			"tinfoil_v3_cloud": {Name: "tinfoil_v3_cloud", BaseURL: upstream.URL},
			"venice":           {Name: "venice", BaseURL: upstream.URL},
		}})
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
			if !info.Reused {
				connections.Add(1)
			}
		}})
		fetch := func() {
			for _, prov := range server.providers {
				if _, err := prov.Attester.FetchAttestation(ctx, "model", attestation.NewNonce()); err == nil {
					t.Fatal("malformed JSON accepted")
				}
				if _, err := prov.ModelLister.ListModels(ctx); err != nil {
					t.Fatal(err)
				}
			}
		}
		fetch()
		if connections.Load() != 4 {
			t.Fatalf("connections=%d; want four owned pools", connections.Load())
		}
		fetch()
		if connections.Load() != 4 {
			t.Fatal("provider clients did not reuse idle connections")
		}
		if closed.Load() != 0 {
			t.Fatalf("closed=%d before cleanup", closed.Load())
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(server.Close)
		}
		wg.Wait()
		deadline := time.Now().Add(5 * time.Second)
		for closed.Load() != 4 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if closed.Load() != 4 {
			t.Fatalf("closed=%d; cleanup did not close all provider pools", closed.Load())
		}
	})
}
