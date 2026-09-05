package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// ---------------------------------------------------------------------------
// Regression coverage for attested upstream TLS binding. Every new connection
// must match the attested SPKI during its TLS handshake, before request data is
// transmitted. Reused connections remain within the attested pool scope.
// ---------------------------------------------------------------------------

// newTLSBindingTestServer starts a locally CA-signed server whose CA is a
// system fallback root only inside testtls.RunWithFallbackRoot's subprocess.
// Production transports retain nil RootCAs and full WebPKI verification.
func newTLSBindingTestServer(t *testing.T, authority *testtls.Authority) (server *httptest.Server, spkiFP string) {
	t.Helper()
	return newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
}

func newTLSBindingTestServerWithHandler(t *testing.T, authority *testtls.Authority, handler http.Handler) (server *httptest.Server, spkiFP string) {
	t.Helper()
	ts := authority.NewTLSServer(t, handler)
	sum := sha256.Sum256(ts.Certificate().RawSubjectPublicKeyInfo)
	return ts, hex.EncodeToString(sum[:])
}

// newTLSBindingTestServerHandle builds a minimal Server with real,
// independently-locking caches and production-equivalent upstream transports.
func newTLSBindingTestServerHandle() *Server {
	return &Server{
		cfg:             &config.Config{},
		cache:           attestation.NewCache(time.Minute),
		negCache:        attestation.NewNegativeCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(time.Minute),
		upstreamClient:  tlsct.NewHTTPClientWithTransport(0, newUpstreamTransport(), false),
		pinnedUpstreams: newPinnedUpstreamPools(),
		stats:           stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}
}

// TLS authorization tests explicitly disable body encryption to isolate the
// production attested TLS handshake, cache acquisition, and pool boundaries.
func tlsAuthorizationInput(t *testing.T, server *Server, name, model, origin, fingerprint string) *authorizedRequest {
	t.Helper()
	route, err := provider.NewResolvedRoute(origin, "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := route.AuthorizationKey(name, model)
	if err != nil {
		t.Fatal(err)
	}
	prov := &provider.Provider{Name: name, BaseURL: origin, StaticRoute: route, UsesTLSBinding: true,
		Attester: &mockAttester{err: errors.New("test attestation unavailable after invalidation")}}
	report := &attestation.VerificationReport{Provider: name, Model: model, TLSAuthority: route.Authority(), TLSKeyFP: fingerprint}
	candidate, err := newAuthorization(key, report, "", false, false, time.Time{}, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	loadTestAuthorization(t, server.authorizations, key, candidate)
	return &authorizedRequest{provider: prov, route: route, key: key, body: []byte(`{}`), path: "/inference", endpoint: e2ee.EndpointChat, contentType: "application/json"}
}

func TestAuthorizedTLSSequentialReuse(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		var mu sync.Mutex
		connections := make(map[string]bool)
		upstream, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			connections[r.RemoteAddr] = true
			mu.Unlock()
			if r.ProtoMajor != 2 || r.Header.Get("Connection") != "" {
				t.Error("unexpected inference protocol or connection header")
			}
			_, _ = io.WriteString(w, `{}`)
		}))
		server := newTLSBindingTestServerHandle()
		server.authorizations = newAuthorizationStore(10, 2, time.Second)
		defer server.Close()
		input := tlsAuthorizationInput(t, server, "neardirect", "model", upstream.URL, fp)
		for range 2 {
			result, err := server.authorizedRoundtrip(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, result.upstream.Resp.Body)
			cleanupAuthorized(result.upstream)
			if err != nil {
				t.Fatal(err)
			}
		}
		mu.Lock()
		count := len(connections)
		mu.Unlock()
		if count != 1 {
			t.Fatalf("connections=%d, want 1", count)
		}
	})
}

func TestAuthorizedTLSConcurrentIsolation(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		good, fp := newTLSBindingTestServer(t, authority)
		var badRequests atomic.Int32
		bad, _ := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { badRequests.Add(1) }))
		server := newTLSBindingTestServerHandle()
		server.authorizations = newAuthorizationStore(16, 4, time.Second)
		defer server.Close()
		goodInputs := make([]*authorizedRequest, 0, 4)
		badInputs := make([]*authorizedRequest, 0, 4)
		for _, name := range []string{"nearcloud", "neardirect"} {
			for _, model := range []string{"one", "two"} {
				goodInputs = append(goodInputs, tlsAuthorizationInput(t, server, name, model, good.URL, fp))
				badInputs = append(badInputs, tlsAuthorizationInput(t, server, name, model, bad.URL, fp))
			}
		}
		var wg sync.WaitGroup
		for i := range 32 {
			wg.Go(func() {
				inputs := goodInputs
				badPin := i%2 != 0
				if badPin {
					inputs = badInputs
				}
				result, err := server.authorizedRoundtrip(t.Context(), inputs[(i/2)%len(inputs)])
				if result.upstream != nil {
					_, _ = io.Copy(io.Discard, result.upstream.Resp.Body)
					cleanupAuthorized(result.upstream)
				}
				if badPin == (err == nil) {
					t.Errorf("mismatched pin=%v error=%v", badPin, err)
				}
			})
		}
		wg.Wait()
		if badRequests.Load() != 0 {
			t.Fatal("mismatched peer received inference bytes")
		}
		for _, input := range goodInputs {
			if _, ok := server.authorizations.acquire(input.key); !ok {
				t.Error("another route's failure removed valid authorization")
			}
		}
		for _, input := range badInputs {
			if _, ok := server.authorizations.acquire(input.key); ok {
				t.Error("TLS failure retained its authorization")
			}
		}
	})
}

func TestNonBindingTransportRequest(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		upstream, _ := newTLSBindingTestServer(t, authority)
		server := newTLSBindingTestServerHandle()
		defer server.Close()
		prov := &provider.Provider{Name: "venice", BaseURL: upstream.URL}
		result, err := server.doUpstreamRoundtrip(t.Context(), prov, []byte(`{}`), "model", false, nil, false, "/inference", "application/json", e2ee.EndpointChat)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanupAuthorized(result)
		if result.Resp.StatusCode != http.StatusOK {
			t.Fatal("ordinary TLS inference failed")
		}
	})
}

func TestAttestedPoolsRespectProviderAuthorityAndKey(t *testing.T) {
	server := newTLSBindingTestServerHandle()
	defer server.Close()
	a, err := tlsct.NewTransportIdentity("a.near.ai", strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	b, err := tlsct.NewTransportIdentity("a.near.ai", strings.Repeat("cd", 32))
	if err != nil {
		t.Fatal(err)
	}
	other, err := tlsct.NewTransportIdentity("b.near.ai", strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	var previous *http.Client
	for _, name := range []string{"tinfoil_v3_cloud", "nearcloud", "neardirect"} {
		first, err := server.pinnedClientForIdentity(name, a)
		if err != nil {
			t.Fatal(err)
		}
		same, err := server.pinnedClientForIdentity(name, a)
		if err != nil || same != first {
			t.Fatal("unchanged identity replaced its pool")
		}
		if previous == first {
			t.Fatal("providers shared a pool")
		}
		previous = first
		rotated, err := server.pinnedClientForIdentity(name, b)
		if err != nil || rotated == first {
			t.Fatal("changed key reused a pool")
		}
		restored, err := server.pinnedClientForIdentity(name, a)
		if err != nil || restored == rotated {
			t.Fatal("valid earlier key could not select a pool")
		}
		isolated, err := server.pinnedClientForIdentity(name, other)
		if err != nil || isolated == restored {
			t.Fatal("authorities shared a pool")
		}
	}
}
