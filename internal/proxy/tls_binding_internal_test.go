package proxy

import (
	"context"
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
// transmitted. The response SPKI is checked again on cache hits and misses as
// defense in depth.
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
		spkiCache:       attestation.NewSPKICache(),
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

// tlsBindingTestProvider returns a TLS-binding provider (mirrors
// tinfoil_v3_cloud/direct) pointed at baseURL.
func tlsBindingTestProvider(baseURL string) *provider.Provider {
	return &provider.Provider{Name: "tinfoil_test", UsesTLSBinding: true, BaseURL: baseURL}
}

func TestSetUpstreamConnectionHeaders_DoesNotSetConnectionHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://example.com", http.NoBody)
	provider.SetEHBPHeaders(req, nil)
	if got := req.Header.Get("Connection"); got != "" {
		t.Fatalf("Connection = %q, want empty", got)
	}
}

func TestNewUpstreamTransportAttemptsHTTP2(t *testing.T) {
	if !newUpstreamTransport().ForceAttemptHTTP2 {
		t.Fatal("upstream transport does not attempt HTTP/2")
	}
}

// closeUpstream releases resources returned by a successful doUpstreamRoundtrip.
func closeUpstream(ur *upstreamResult) {
	if ur == nil {
		return
	}
	if ur.Resp != nil {
		_ = ur.Resp.Body.Close()
	}
	if ur.Cancel != nil {
		ur.Cancel()
	}
}

func drainAndCloseUpstream(t *testing.T, ur *upstreamResult) {
	t.Helper()
	if ur == nil {
		return
	}
	if ur.Resp != nil {
		if _, err := io.Copy(io.Discard, ur.Resp.Body); err != nil {
			t.Errorf("drain upstream response: %v", err)
		}
		if err := ur.Resp.Body.Close(); err != nil {
			t.Errorf("close upstream response: %v", err)
		}
	}
	if ur.Cancel != nil {
		ur.Cancel()
	}
}

// asHTTPError unwraps err as *httpError, failing the test if it is not one.
func asHTTPError(t *testing.T, err error) *httpError {
	t.Helper()
	var he *httpError
	if !errors.As(err, &he) {
		t.Fatalf("error type = %T, want *httpError (err=%v)", err, err)
	}
	return he
}

// ---------------------------------------------------------------------------
// Cache miss: SPKI verified (existing behavior preserved).
// ---------------------------------------------------------------------------

func TestDoUpstreamRoundtrip_TLSBinding_CacheMissVerifies(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		ts, fp := newTLSBindingTestServer(t, authority)
		s := newTLSBindingTestServerHandle()
		prov := tlsBindingTestProvider(ts.URL)

		// Cache miss: raw is populated with the just-attested fingerprint,
		// mirroring attestAndCache's miss branch.
		raw := &attestation.RawAttestation{TinfoilTLSKeyFP: fp}

		ur, err := s.doUpstreamRoundtrip(context.Background(), prov, []byte(`{}`), "model",
			false, raw, fp, false, "", "application/json", e2ee.EndpointChat)
		defer closeUpstream(ur)
		if err != nil {
			t.Fatalf("doUpstreamRoundtrip: unexpected error: %v", err)
		}
		if ur.Resp == nil || ur.Resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK response, got %+v", ur.Resp)
		}
	})
}

// ---------------------------------------------------------------------------
// THE regression test: cache hit must still verify SPKI. Prime the cache
// with a fingerprint attested against server A, then serve the "hit" request
// from server B (different cert/SPKI, simulating a mis-issued cert served
// during the cache TTL). The request must be rejected.
// ---------------------------------------------------------------------------

func TestDoUpstreamRoundtrip_TLSBinding_CacheHitDetectsCertSwap(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		_, fpA := newTLSBindingTestServer(t, authority) // originally-attested server
		var received atomic.Int64
		tsB, fpB := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			received.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		if tlsct.SPKIFingerprintsEqual(fpA, fpB) {
			t.Fatal("test servers unexpectedly share an SPKI fingerprint")
		}

		s := newTLSBindingTestServerHandle()
		prov := tlsBindingTestProvider(tsB.URL) // upstream connection now lands on server B

		// Prime caches as attestAndCache would after a real miss against server A.
		s.cache.Put(prov.Name, "model", &attestation.VerificationReport{TLSKeyFP: fpA})
		s.signingKeyCache.Put(prov.Name, "model", "some-signing-key")

		// Cache hit: raw is nil (no fresh attestation this request); the cached
		// fingerprint from the prior miss (fpA) is what attestAndCache would
		// have returned as attestResult.TLSKeyFP.
		ur, err := s.doUpstreamRoundtrip(context.Background(), prov, []byte(`{}`), "model",
			false, nil, fpA, false, "", "application/json", e2ee.EndpointChat)
		defer closeUpstream(ur)
		if err == nil {
			t.Fatal("expected upstream TLS SPKI mismatch to be rejected on a cache-hit request, got nil error")
		}
		he := asHTTPError(t, err)
		if he.status != "tls_binding_failed" {
			t.Errorf("status = %q, want tls_binding_failed", he.status)
		}
		if he.code != http.StatusBadGateway {
			t.Errorf("code = %d, want %d", he.code, http.StatusBadGateway)
		}
		if got := received.Load(); got != 0 {
			t.Errorf("mismatched server received %d HTTP requests, want 0", got)
		}

		// Caches must be invalidated to force full re-attestation on next request.
		if _, ok := s.cache.Get(prov.Name, "model"); ok {
			t.Error("expected attestation cache entry to be deleted after SPKI mismatch")
		}
		if _, ok := s.signingKeyCache.Get(prov.Name, "model"); ok {
			t.Error("expected signing key cache entry to be deleted after SPKI mismatch")
		}
	})
}

func TestPinnedUpstreamClientRotatesPoolWhenAttestedFingerprintChanges(t *testing.T) {
	s := newTLSBindingTestServerHandle()
	prov := tlsBindingTestProvider("https://example.com")
	first := sha256.Sum256([]byte("first SPKI"))
	second := sha256.Sum256([]byte("second SPKI"))
	firstFP := hex.EncodeToString(first[:])
	secondFP := hex.EncodeToString(second[:])

	firstClient, err := s.pinnedUpstreamClient(prov, prov.BaseURL, firstFP)
	if err != nil {
		t.Fatalf("first pinnedUpstreamClient: %v", err)
	}
	secondClient, err := s.pinnedUpstreamClient(prov, prov.BaseURL, secondFP)
	if err != nil {
		t.Fatalf("second pinnedUpstreamClient: %v", err)
	}
	if firstClient == secondClient {
		t.Fatal("fingerprint change reused the old pinned client")
	}
	uppercaseSecondClient, err := s.pinnedUpstreamClient(prov, prov.BaseURL, strings.ToUpper(secondFP))
	if err != nil {
		t.Fatalf("uppercase pinnedUpstreamClient: %v", err)
	}
	if uppercaseSecondClient != secondClient {
		t.Fatal("equivalent uppercase fingerprint rotated the pinned client")
	}
	again, err := s.pinnedUpstreamClient(prov, prov.BaseURL, secondFP)
	if err != nil {
		t.Fatalf("reused pinnedUpstreamClient: %v", err)
	}
	if again != secondClient {
		t.Fatal("unchanged fingerprint did not reuse the pinned client")
	}
}

func TestDoUpstreamRoundtrip_TLSBinding_ReusesHandshakePinnedConnection(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		var mu sync.Mutex
		connections := make(map[string]struct{})
		ts, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			connections[r.RemoteAddr] = struct{}{}
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		s := newTLSBindingTestServerHandle()
		prov := tlsBindingTestProvider(ts.URL)

		for i := range 2 {
			var raw *attestation.RawAttestation
			if i == 0 {
				raw = &attestation.RawAttestation{TinfoilTLSKeyFP: fp}
			}
			ur, err := s.doUpstreamRoundtrip(context.Background(), prov, []byte(`{}`), "model",
				false, raw, fp, false, "", "application/json", e2ee.EndpointChat)
			if err != nil {
				t.Fatalf("request %d: %v", i+1, err)
			}
			drainAndCloseUpstream(t, ur)
		}

		mu.Lock()
		got := len(connections)
		mu.Unlock()
		if got != 1 {
			t.Fatalf("unique TLS connections = %d, want 1", got)
		}
	})
}

// ---------------------------------------------------------------------------
// Cache hit with a matching SPKI proceeds normally.
// ---------------------------------------------------------------------------

func TestDoUpstreamRoundtrip_TLSBinding_CacheHitMatchingProceeds(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		ts, fp := newTLSBindingTestServer(t, authority)
		s := newTLSBindingTestServerHandle()
		prov := tlsBindingTestProvider(ts.URL)

		s.cache.Put(prov.Name, "model", &attestation.VerificationReport{TLSKeyFP: fp})

		ur, err := s.doUpstreamRoundtrip(context.Background(), prov, []byte(`{}`), "model",
			false, nil, fp, false, "", "application/json", e2ee.EndpointChat)
		defer closeUpstream(ur)
		if err != nil {
			t.Fatalf("doUpstreamRoundtrip: unexpected error on matching cache-hit SPKI: %v", err)
		}
		if ur.Resp == nil || ur.Resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK response, got %+v", ur.Resp)
		}
	})
}

// ---------------------------------------------------------------------------
// A TLS-binding provider with an empty cached fingerprint must fail closed
// (cache entry predating the field, or attestation that failed to produce
// one) rather than silently skipping the check.
// ---------------------------------------------------------------------------

func TestDoUpstreamRoundtrip_TLSBinding_EmptyFingerprintFailsClosed(t *testing.T) {
	s := newTLSBindingTestServerHandle()
	prov := tlsBindingTestProvider("https://example.com")

	ur, err := s.doUpstreamRoundtrip(context.Background(), prov, []byte(`{}`), "model",
		false, nil, "", false, "", "application/json", e2ee.EndpointChat)
	defer closeUpstream(ur)
	if err == nil {
		t.Fatal("expected empty attested fingerprint to fail closed, got nil error")
	}
	he := asHTTPError(t, err)
	if he.status != "tls_binding_failed" {
		t.Errorf("status = %q, want tls_binding_failed", he.status)
	}
}

// A provider that does not use TLS binding is unaffected by an empty
// fingerprint (the check does not apply to it at all).
func TestDoUpstreamRoundtrip_TLSBinding_NotRequiredForNonBindingProvider(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		ts, _ := newTLSBindingTestServer(t, authority)
		s := newTLSBindingTestServerHandle()
		prov := &provider.Provider{Name: "venice_test", UsesTLSBinding: false, BaseURL: ts.URL}

		ur, err := s.doUpstreamRoundtrip(context.Background(), prov, []byte(`{}`), "model",
			false, nil, "", false, "", "application/json", e2ee.EndpointChat)
		defer closeUpstream(ur)
		if err != nil {
			t.Fatalf("non-TLS-binding provider should not require a fingerprint: %v", err)
		}
		if ur.Resp == nil || ur.Resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK response, got %+v", ur.Resp)
		}
	})
}

// ---------------------------------------------------------------------------
// Concurrent requests across hit/miss transitions and matching/mismatching
// fingerprints exercise the shared attestation/signing-key caches under
// -race. TLS-binding failure handling mutates the pinned transport registry
// and the attestation/signing-key caches, so this must be safe when many
// goroutines race through both the success and failure paths simultaneously.
// ---------------------------------------------------------------------------

func TestDoUpstreamRoundtrip_TLSBinding_Concurrent(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		tsGood, fpGood := newTLSBindingTestServer(t, authority)
		tsBad, fpBad := newTLSBindingTestServer(t, authority)
		if tlsct.SPKIFingerprintsEqual(fpGood, fpBad) {
			t.Fatal("test servers unexpectedly share an SPKI fingerprint")
		}

		s := newTLSBindingTestServerHandle()
		provGood := tlsBindingTestProvider(tsGood.URL)
		provBad := tlsBindingTestProvider(tsBad.URL) // same model key, mismatched live cert

		const workers = 40
		var wg sync.WaitGroup
		wg.Add(workers)
		for i := range workers {
			go func(i int) {
				defer wg.Done()
				ctx := context.Background()
				switch i % 4 {
				case 0:
					// Simulated miss against the matching server: succeeds.
					raw := &attestation.RawAttestation{TinfoilTLSKeyFP: fpGood}
					ur, err := s.doUpstreamRoundtrip(ctx, provGood, []byte(`{}`), "model",
						false, raw, fpGood, false, "", "application/json", e2ee.EndpointChat)
					closeUpstream(ur)
					if err != nil {
						t.Errorf("worker %d: matching miss unexpectedly failed: %v", i, err)
					}
				case 1:
					// Simulated hit against the matching server: succeeds.
					ur, err := s.doUpstreamRoundtrip(ctx, provGood, []byte(`{}`), "model",
						false, nil, fpGood, false, "", "application/json", e2ee.EndpointChat)
					closeUpstream(ur)
					if err != nil {
						t.Errorf("worker %d: matching hit unexpectedly failed: %v", i, err)
					}
				case 2:
					// Simulated hit against the mismatched server: must be rejected.
					ur, err := s.doUpstreamRoundtrip(ctx, provBad, []byte(`{}`), "model",
						false, nil, fpGood, false, "", "application/json", e2ee.EndpointChat)
					closeUpstream(ur)
					if err == nil {
						t.Errorf("worker %d: expected SPKI mismatch to be rejected", i)
					}
				default:
					// Empty attested fingerprint: must fail closed.
					ur, err := s.doUpstreamRoundtrip(ctx, provGood, []byte(`{}`), "model",
						false, nil, "", false, "", "application/json", e2ee.EndpointChat)
					closeUpstream(ur)
					if err == nil {
						t.Errorf("worker %d: expected empty fingerprint to fail closed", i)
					}
				}
			}(i)
		}
		wg.Wait()
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
