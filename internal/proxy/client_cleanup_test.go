package proxy

import (
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestServerCloseProviderConnections(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		var connections atomic.Int32
		upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/models") {
				_, _ = io.WriteString(w, `{"data":[]}`)
				return
			}
			// Invalid evidence exercises attester transport ownership without claiming
			// that mocked evidence passes provider authentication.
			_, _ = io.WriteString(w, `{`)
		}))
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
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(server.Close)
		}
		wg.Wait()
		fetch()
		if connections.Load() != 8 {
			t.Fatalf("connections=%d; cleanup did not close all provider pools", connections.Load())
		}
	})
}
