package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestAuthorizationExpiryStopsConnectionWait(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		release := make(chan struct{})
		var inference atomic.Int32
		upstream := authority.NewTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/hold" {
				inference.Add(1)
				return
			}
			_, _ = io.WriteString(w, "held")
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Error(err)
				return
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}), func(ts *httptest.Server) {
			ts.EnableHTTP2 = false
			ts.TLS.NextProtos = []string{"http/1.1"}
		})
		defer upstream.Close()
		defer close(release)
		server := newTLSBindingTestServerHandle()
		server.authorizations = newAuthorizationStore(10, 2, time.Second)
		defer server.Close()
		route, err := provider.NewResolvedRoute(upstream.URL, "")
		if err != nil {
			t.Fatal(err)
		}
		key, err := route.AuthorizationKey("neardirect", "model")
		if err != nil {
			t.Fatal(err)
		}
		fp := sha256.Sum256(upstream.Certificate().RawSubjectPublicKeyInfo)
		identity, err := tlsct.NewTransportIdentity(route.Authority(), hex.EncodeToString(fp[:]))
		if err != nil {
			t.Fatal(err)
		}
		client, err := server.pinnedClientForIdentity(key.ProviderName(), identity)
		if err != nil {
			t.Fatal(err)
		}
		server.pinnedUpstreams.entries[pinnedUpstreamKey{provider: key.ProviderName(), authority: route.Authority()}].transport.MaxConnsPerHost = 1
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream.URL+"/hold", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		held, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Body.Close()
		report := &attestation.VerificationReport{Provider: key.ProviderName(), Model: key.Model(), TLSAuthority: route.Authority(), TLSKeyFP: identity.Fingerprint()}
		candidate, err := newAuthorization(key, report, "", false, false, time.Now().Add(200*time.Millisecond), true, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		loadTestAuthorization(t, server.authorizations, key, candidate)
		// E2EE is explicitly disabled: this test isolates authorization expiry
		// while the production TLS pool has no available physical connection.
		prov := &provider.Provider{Name: key.ProviderName(), BaseURL: upstream.URL, StaticRoute: route, UsesTLSBinding: true}
		result, err := server.authorizedRoundtrip(ctx, &authorizedRequest{provider: prov, route: route, key: key, body: []byte(`{}`), path: "/inference", endpoint: e2ee.EndpointChat, contentType: "application/json"})
		if result.upstream != nil {
			cleanupAuthorized(result.upstream)
		}
		if !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			t.Fatalf("authenticated expiry did not stop wait: %v", err)
		}
		if inference.Load() != 0 {
			t.Fatal("expired authorization sent inference")
		}
		if _, ok := server.authorizations.acquire(key); ok {
			t.Fatal("expired authorization remains selectable")
		}
	})
}
