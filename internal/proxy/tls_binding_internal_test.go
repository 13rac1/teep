package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
)

// ---------------------------------------------------------------------------
// Regression coverage for the M3 finding: the attested upstream TLS leaf
// SPKI fingerprint must be verified against the live upstream peer on EVERY
// response — cache hit or miss — not only immediately after a fresh
// attestation fetch. Before the fix, doUpstreamRoundtrip only ran
// verifyUpstreamTLSBinding when `raw != nil` (cache miss), so a mis-issued
// but CA-valid cert served during the ~1h attestation cache TTL went
// undetected.
// ---------------------------------------------------------------------------

// newSelfSignedCert generates a fresh, uniquely-keyed self-signed
// certificate so that distinct calls to newTLSBindingTestServer produce
// distinct SPKI fingerprints. httptest.NewTLSServer's default behavior
// reuses a single hardcoded cert across all servers in the process, which
// would make cert-swap scenarios indistinguishable from no swap at all.
func newSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// newTLSBindingTestServer starts an httptest TLS server (per AGENTS.md,
// httptest.NewTLSServer/NewUnstartedServer+StartTLS is required for tests
// needing an HTTP server) with a freshly-generated certificate, so it
// answers any request with 200 OK. Returns the server plus its leaf
// certificate's SPKI fingerprint computed the same way as tlsct.PeerSPKI:
// hex(sha256(leaf.RawSubjectPublicKeyInfo)).
func newTLSBindingTestServer(t *testing.T) (server *httptest.Server, spkiFP string) {
	t.Helper()
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	cert := newSelfSignedCert(t)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse generated certificate: %v", err)
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return ts, hex.EncodeToString(sum[:])
}

// tlsBindingInsecureClient returns an http.Client that completes the TLS
// handshake with any server certificate (self-signed or otherwise), so that
// tests exercise the proxy's own SPKI-pinning check in
// verifyUpstreamTLSBinding rather than Go's CA trust validation. This
// mirrors the real-world threat model for this finding: a mis-issued cert
// can be CA-valid (and thus pass normal TLS validation) while still failing
// the attested SPKI pin.
func tlsBindingInsecureClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			// test-only: SPKI pinning (verifyUpstreamTLSBinding) is what's
			// under test here, not CA trust validation.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// newTLSBindingTestServerHandle builds a minimal Server with real,
// independently-locking caches (needed because verifyUpstreamTLSBinding
// deletes from them on mismatch, and the concurrent test below exercises
// that from multiple goroutines) and an upstream client that will complete
// the handshake against any test server's certificate.
func newTLSBindingTestServerHandle() *Server {
	return &Server{
		cfg:             &config.Config{},
		cache:           attestation.NewCache(time.Minute),
		negCache:        attestation.NewNegativeCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(time.Minute),
		spkiCache:       attestation.NewSPKICache(),
		upstreamClient:  tlsBindingInsecureClient(),
		stats:           stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}
}

// tlsBindingTestProvider returns a TLS-binding provider (mirrors
// tinfoil_v3_cloud/direct) pointed at baseURL.
func tlsBindingTestProvider(baseURL string) *provider.Provider {
	return &provider.Provider{Name: "tinfoil_test", UsesTLSBinding: true, BaseURL: baseURL}
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
	ts, fp := newTLSBindingTestServer(t)
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
}

// ---------------------------------------------------------------------------
// THE regression test: cache hit must still verify SPKI. Prime the cache
// with a fingerprint attested against server A, then serve the "hit" request
// from server B (different cert/SPKI, simulating a mis-issued cert served
// during the cache TTL). The request must be rejected.
// ---------------------------------------------------------------------------

func TestDoUpstreamRoundtrip_TLSBinding_CacheHitDetectsCertSwap(t *testing.T) {
	_, fpA := newTLSBindingTestServer(t) // originally-attested server
	tsB, fpB := newTLSBindingTestServer(t)
	if fpA == fpB {
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

	// Caches must be invalidated to force full re-attestation on next request.
	if _, ok := s.cache.Get(prov.Name, "model"); ok {
		t.Error("expected attestation cache entry to be deleted after SPKI mismatch")
	}
	if _, ok := s.signingKeyCache.Get(prov.Name, "model"); ok {
		t.Error("expected signing key cache entry to be deleted after SPKI mismatch")
	}
}

// ---------------------------------------------------------------------------
// Cache hit with a matching SPKI proceeds normally.
// ---------------------------------------------------------------------------

func TestDoUpstreamRoundtrip_TLSBinding_CacheHitMatchingProceeds(t *testing.T) {
	ts, fp := newTLSBindingTestServer(t)
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
}

// ---------------------------------------------------------------------------
// A TLS-binding provider with an empty cached fingerprint must fail closed
// (cache entry predating the field, or attestation that failed to produce
// one) rather than silently skipping the check.
// ---------------------------------------------------------------------------

func TestDoUpstreamRoundtrip_TLSBinding_EmptyFingerprintFailsClosed(t *testing.T) {
	ts, _ := newTLSBindingTestServer(t)
	s := newTLSBindingTestServerHandle()
	prov := tlsBindingTestProvider(ts.URL)

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
	ts, _ := newTLSBindingTestServer(t)
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
}

// ---------------------------------------------------------------------------
// Concurrent requests across hit/miss transitions and matching/mismatching
// fingerprints exercise the shared attestation/signing-key caches under
// -race. verifyUpstreamTLSBinding mutates s.cache/s.signingKeyCache on
// mismatch, so this must be safe when many goroutines race through both the
// success and failure paths simultaneously.
// ---------------------------------------------------------------------------

func TestDoUpstreamRoundtrip_TLSBinding_Concurrent(t *testing.T) {
	tsGood, fpGood := newTLSBindingTestServer(t)
	tsBad, fpBad := newTLSBindingTestServer(t)
	if fpGood == fpBad {
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
}
