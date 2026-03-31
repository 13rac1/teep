package tlsct_test

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
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist3"
	cttls "github.com/google/certificate-transparency-go/tls"
)

// selfSignedCert generates a throwaway self-signed certificate for tests.
func selfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

// mockRoundTripper is an in-process RoundTripper that serves canned responses.
type mockRoundTripper struct {
	handler func(req *http.Request) (*http.Response, error)
	calls   int
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	m.calls++
	return m.handler(req)
}

func handlerResponse(code int, body string) func(*http.Request) (*http.Response, error) {
	return func(_ *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		rec.WriteHeader(code)
		rec.WriteString(body)
		return rec.Result(), nil
	}
}

// ---------- Group 1: isPrivateHost ----------

func TestIsPrivateHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"", true},
		{"   ", true},
		{"localhost", true},
		{"localhost:443", true},
		{"127.0.0.1", true},
		{"127.0.0.1:8080", true},
		{"::1", true},
		{"[::1]:443", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"192.168.1.100", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"169.254.1.1", true}, // link-local unicast
		{"fe80::1", true},     // link-local unicast IPv6
		{"ff02::1", true},     // link-local multicast IPv6
		{"google.com", false},
		{"google.com:443", false},
		{"8.8.8.8", false},
		{"8.8.8.8:53", false},
		{"2001:4860:4860::8888", false},
		{"example.com", false},
		{"1.1.1.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := tlsct.IsPrivateHost(tt.host)
			if got != tt.want {
				t.Errorf("isPrivateHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

// ---------- Group 2: toCTChain ----------

func TestToCTChain(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		chain, err := tlsct.ToCTChain(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(chain) != 0 {
			t.Fatalf("expected empty chain, got %d", len(chain))
		}
	})

	t.Run("empty", func(t *testing.T) {
		chain, err := tlsct.ToCTChain([]*x509.Certificate{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(chain) != 0 {
			t.Fatalf("expected empty chain, got %d", len(chain))
		}
	})

	t.Run("nil entries skipped", func(t *testing.T) {
		chain, err := tlsct.ToCTChain([]*x509.Certificate{nil, nil})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(chain) != 0 {
			t.Fatalf("expected empty chain, got %d", len(chain))
		}
	})

	t.Run("valid cert", func(t *testing.T) {
		cert := selfSignedCert(t)
		chain, err := tlsct.ToCTChain([]*x509.Certificate{cert})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(chain) != 1 {
			t.Fatalf("expected 1 cert, got %d", len(chain))
		}
	})

	t.Run("invalid raw bytes", func(t *testing.T) {
		bad := &x509.Certificate{Raw: []byte("not a certificate")}
		_, err := tlsct.ToCTChain([]*x509.Certificate{bad})
		if err == nil {
			t.Fatal("expected error for invalid cert")
		}
		if !strings.Contains(err.Error(), "parse cert 0:") {
			t.Fatalf("expected 'parse cert 0:' in error, got: %v", err)
		}
	})
}

// ---------- Group 3: ctEnabledFromOpt ----------

func TestCtEnabledFromOpt(t *testing.T) {
	tests := []struct {
		name string
		args []bool
		want bool
	}{
		{"no args defaults to true", nil, true},
		{"explicit true", []bool{true}, true},
		{"explicit false", []bool{false}, false},
		{"multiple args uses first", []bool{false, true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tlsct.CtEnabledFromOpt(tt.args...)
			if got != tt.want {
				t.Errorf("ctEnabledFromOpt(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

// ---------- Group 4: SetEnabled nil safety ----------

func TestSetEnabled_NilSafe(t *testing.T) {
	var c *tlsct.Checker
	c.SetEnabled(true)  // must not panic
	c.SetEnabled(false) // must not panic
}

// ---------- Group 5: CheckTLSState early returns ----------

func TestCheckTLSState_EarlyReturns(t *testing.T) {
	ctx := context.Background()

	t.Run("nil checker", func(t *testing.T) {
		var c *tlsct.Checker
		if err := c.CheckTLSState(ctx, "example.com", &tls.ConnectionState{}); err != nil {
			t.Fatalf("expected nil, got: %v", err)
		}
	})

	t.Run("disabled checker", func(t *testing.T) {
		c := tlsct.NewChecker()
		c.SetEnabled(false)
		if err := c.CheckTLSState(ctx, "example.com", &tls.ConnectionState{}); err != nil {
			t.Fatalf("expected nil, got: %v", err)
		}
	})

	t.Run("private host localhost", func(t *testing.T) {
		c := tlsct.NewChecker()
		if err := c.CheckTLSState(ctx, "localhost", &tls.ConnectionState{}); err != nil {
			t.Fatalf("expected nil, got: %v", err)
		}
	})

	t.Run("private host loopback", func(t *testing.T) {
		c := tlsct.NewChecker()
		if err := c.CheckTLSState(ctx, "127.0.0.1", &tls.ConnectionState{}); err != nil {
			t.Fatalf("expected nil, got: %v", err)
		}
	})

	t.Run("nil state", func(t *testing.T) {
		c := tlsct.NewChecker()
		err := c.CheckTLSState(ctx, "example.com", nil)
		if err == nil || err.Error() != "missing peer certificate" {
			t.Fatalf("expected 'missing peer certificate', got: %v", err)
		}
	})

	t.Run("empty PeerCertificates", func(t *testing.T) {
		c := tlsct.NewChecker()
		err := c.CheckTLSState(ctx, "example.com", &tls.ConnectionState{})
		if err == nil || err.Error() != "missing peer certificate" {
			t.Fatalf("expected 'missing peer certificate', got: %v", err)
		}
	})
}

// ---------- Group 6: cache hit ----------

func TestCheckTLSState_CacheHit(t *testing.T) {
	c := tlsct.NewChecker()
	cert := selfSignedCert(t)
	key := tlsct.CertCacheKey("example.com", cert)
	c.InjectCacheEntry(key, time.Now()) // fresh entry

	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	err := c.CheckTLSState(context.Background(), "example.com", state)
	if err != nil {
		t.Fatalf("expected nil (cache hit), got: %v", err)
	}
}

// ---------- Group 7: cache expired ----------

func TestCheckTLSState_CacheExpired(t *testing.T) {
	c := tlsct.NewChecker()
	cert := selfSignedCert(t)
	key := tlsct.CertCacheKey("example.com", cert)
	c.InjectCacheEntry(key, time.Now().Add(-2*time.Hour)) // expired

	// Inject a failing log list HTTP so we can detect that it proceeded past cache.
	mock := &mockRoundTripper{handler: handlerResponse(http.StatusInternalServerError, "broken")} //nolint:bodyclose // closed by loadLogList
	c.SetLogListHTTP(&http.Client{Transport: mock})

	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	err := c.CheckTLSState(context.Background(), "example.com", state)
	if err == nil {
		t.Fatal("expected error after cache miss")
	}
	if !strings.Contains(err.Error(), "load CT log list:") {
		t.Fatalf("expected 'load CT log list:' error, got: %v", err)
	}
	if mock.calls == 0 {
		t.Fatal("expected log list HTTP call after cache miss")
	}
	t.Logf("cache expired → loadLogList called (%d calls), error: %v", mock.calls, err)
}

// ---------- Group 8: loadLogList error ----------

func TestCheckTLSState_LoadLogListError(t *testing.T) {
	c := tlsct.NewChecker()
	mock := &mockRoundTripper{handler: handlerResponse(http.StatusInternalServerError, "server error")} //nolint:bodyclose // closed by loadLogList
	c.SetLogListHTTP(&http.Client{Transport: mock})

	cert := selfSignedCert(t)
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	err := c.CheckTLSState(context.Background(), "example.com", state)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "load CT log list:") {
		t.Fatalf("expected 'load CT log list:' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected '500' in error, got: %v", err)
	}
	t.Logf("loadLogList error: %v", err)
}

// ---------- Group 9: no SCTs ----------

func TestCheckTLSState_NoSCTs(t *testing.T) {
	c := tlsct.NewChecker()
	c.InjectLogList(emptyLogList(t))

	cert := selfSignedCert(t)
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		// No SignedCertificateTimestamps, self-signed has no embedded SCTs.
	}
	err := c.CheckTLSState(context.Background(), "example.com", state)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "no SCTs found") {
		t.Fatalf("expected 'no SCTs found' in error, got: %v", err)
	}
	t.Logf("no SCTs error: %v", err)
}

// emptyLogList creates a minimal valid LogList with no operators/logs.
func emptyLogList(t *testing.T) *loglist3.LogList {
	t.Helper()
	ll, err := loglist3.NewFromJSON([]byte(`{"operators":[]}`))
	if err != nil {
		t.Fatalf("create empty log list: %v", err)
	}
	return ll
}

// ---------- Group 10: SCT log ID not found ----------

func TestCheckTLSState_SCTLogNotFound(t *testing.T) {
	c := tlsct.NewChecker()
	c.InjectLogList(emptyLogList(t))

	cert := selfSignedCert(t)

	// Fabricate a TLS handshake SCT with a random log ID.
	sctBytes := fabricateHandshakeSCT(t)

	state := &tls.ConnectionState{
		PeerCertificates:            []*x509.Certificate{cert},
		SignedCertificateTimestamps: [][]byte{sctBytes},
	}
	err := c.CheckTLSState(context.Background(), "example.com", state)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "no valid SCTs") {
		t.Fatalf("expected 'no valid SCTs' in error, got: %v", err)
	}
	t.Logf("SCT not found error: %v", err)
}

// fabricateHandshakeSCT creates a TLS-marshalled SCT with a random LogID.
func fabricateHandshakeSCT(t *testing.T) []byte {
	t.Helper()
	sct := ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		Timestamp:  uint64(time.Now().UnixMilli()),
		Signature: ct.DigitallySigned{
			Algorithm: cttls.SignatureAndHashAlgorithm{
				Hash:      cttls.SHA256,
				Signature: cttls.ECDSA,
			},
			Signature: []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, // minimal DER ECDSA sig
		},
	}
	// Random log ID
	if _, err := rand.Read(sct.LogID.KeyID[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	raw, err := cttls.Marshal(sct)
	if err != nil {
		t.Fatalf("marshal SCT: %v", err)
	}
	return raw
}

// ---------- Group 11: cache eviction ----------

func TestCacheEviction(t *testing.T) {
	t.Run("TTL sweep evicts expired entries", func(t *testing.T) {
		c := tlsct.NewChecker()
		// Fill 1025 entries with expired timestamps.
		for i := range 1025 {
			key := "host" + strconv.Itoa(i) + "\x00" + hex.EncodeToString(make([]byte, 32))
			c.InjectCacheEntry(key, time.Now().Add(-2*time.Hour))
		}
		if n := c.CacheLen(); n != 1025 {
			t.Fatalf("expected 1025 entries, got %d", n)
		}

		// Adding one more triggers eviction: all expired entries should be swept.
		tlsct.AddCacheEntry(c, "new-key")
		n := c.CacheLen()
		t.Logf("after TTL sweep: %d entries", n)
		if n > 2 {
			// Only the new entry (and maybe a few that raced) should survive.
			// All 1025 expired entries should have been evicted.
			t.Fatalf("expected ≤2 entries after TTL sweep, got %d", n)
		}
	})

	t.Run("hard cap evicts oldest when all fresh", func(t *testing.T) {
		c := tlsct.NewChecker()
		// Fill 1025 entries with fresh timestamps.
		for i := range 1025 {
			h := sha256.Sum256([]byte(strconv.Itoa(i)))
			key := "host\x00" + hex.EncodeToString(h[:])
			c.InjectCacheEntry(key, time.Now())
		}
		if n := c.CacheLen(); n != 1025 {
			t.Fatalf("expected 1025 entries, got %d", n)
		}

		// Adding one more triggers hard cap eviction.
		tlsct.AddCacheEntry(c, "brand-new-key")
		n := c.CacheLen()
		t.Logf("after hard cap eviction: %d entries", n)
		if n > 1025 {
			t.Fatalf("expected ≤1025 entries, got %d", n)
		}
	})
}

// ---------- Group 12: ctRoundTripper ----------

func TestCTRoundTripper(t *testing.T) {
	t.Run("base error propagated", func(t *testing.T) {
		base := &mockRoundTripper{handler: func(_ *http.Request) (*http.Response, error) {
			return nil, errors.New("connection refused")
		}}
		rt := tlsct.WrapTransport(base)
		req := httptest.NewRequest(http.MethodGet, "https://example.com/", http.NoBody)
		_, err := rt.RoundTrip(req) //nolint:bodyclose // error path, no body
		if err == nil || !strings.Contains(err.Error(), "connection refused") {
			t.Fatalf("expected 'connection refused', got: %v", err)
		}
	})

	t.Run("HTTP skips CT check", func(t *testing.T) {
		base := &mockRoundTripper{handler: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}}
		rt := tlsct.WrapTransport(base)
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", http.NoBody)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		t.Log("HTTP request passed through without CT check")
	})

	t.Run("HTTPS with nil TLS state", func(t *testing.T) {
		base := &mockRoundTripper{handler: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("ok")),
				TLS:        nil, // no TLS state
			}, nil
		}}
		rt := tlsct.WrapTransport(base)
		req := httptest.NewRequest(http.MethodGet, "https://example.com/", http.NoBody)
		_, err := rt.RoundTrip(req) //nolint:bodyclose // body closed by RoundTrip on error
		if err == nil || !strings.Contains(err.Error(), "missing TLS connection state") {
			t.Fatalf("expected 'missing TLS connection state', got: %v", err)
		}
	})

	t.Run("HTTPS with disabled checker passes through", func(t *testing.T) {
		// WrapTransport uses defaultChecker. Disable it for this test.
		tlsct.DefaultChecker().SetEnabled(false)
		defer tlsct.DefaultChecker().SetEnabled(true)

		cert := selfSignedCert(t)
		base := &mockRoundTripper{handler: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("ok")),
				TLS: &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{cert},
				},
			}, nil
		}}
		rt := tlsct.WrapTransport(base)
		req := httptest.NewRequest(http.MethodGet, "https://example.com/", http.NoBody)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		t.Log("disabled checker → HTTPS passed through")
	})

	t.Run("nil base uses DefaultTransport", func(t *testing.T) {
		rt := tlsct.WrapTransport(nil)
		if rt == nil {
			t.Fatal("expected non-nil RoundTripper")
		}
	})
}

// ---------- Group 13: NewHTTPClientWithTransport ----------

func TestNewHTTPClientWithTransport(t *testing.T) {
	t.Run("nil base does not panic", func(t *testing.T) {
		c := tlsct.NewHTTPClientWithTransport(5*time.Second, nil, false)
		if c == nil {
			t.Fatal("expected non-nil client")
		}
	})

	t.Run("TLS 1.2 upgraded to 1.3", func(t *testing.T) {
		base := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
		c := tlsct.NewHTTPClientWithTransport(5*time.Second, base, false)
		tr := c.Transport.(*http.Transport)
		if tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
			t.Fatalf("expected TLS 1.3, got %d", tr.TLSClientConfig.MinVersion)
		}
	})

	t.Run("TLS 1.3 not downgraded", func(t *testing.T) {
		base := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
		c := tlsct.NewHTTPClientWithTransport(5*time.Second, base, false)
		tr := c.Transport.(*http.Transport)
		if tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
			t.Fatalf("expected TLS 1.3, got %d", tr.TLSClientConfig.MinVersion)
		}
	})

	t.Run("nil TLSClientConfig gets TLS 1.3", func(t *testing.T) {
		base := &http.Transport{}
		c := tlsct.NewHTTPClientWithTransport(5*time.Second, base, false)
		tr := c.Transport.(*http.Transport)
		if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
			t.Fatal("expected TLS 1.3 config")
		}
	})

	t.Run("CT disabled returns plain transport", func(t *testing.T) {
		c := tlsct.NewHTTPClientWithTransport(5*time.Second, nil, false)
		if _, ok := c.Transport.(*http.Transport); !ok {
			t.Fatalf("expected *http.Transport when CT disabled, got %T", c.Transport)
		}
	})

	t.Run("CT enabled wraps transport", func(t *testing.T) {
		c := tlsct.NewHTTPClientWithTransport(5*time.Second, nil, true)
		if _, ok := c.Transport.(*http.Transport); ok {
			t.Fatal("expected wrapped transport when CT enabled")
		}
	})

	t.Run("timeout propagated", func(t *testing.T) {
		c := tlsct.NewHTTPClient(42*time.Second, false)
		if c.Timeout != 42*time.Second {
			t.Fatalf("expected 42s timeout, got %v", c.Timeout)
		}
	})
}

// ---------- Group 14: loadLogList ----------

func TestLoadLogList(t *testing.T) {
	// Minimal valid log list JSON.
	const validJSON = `{"operators":[]}`

	t.Run("successful fetch and caching", func(t *testing.T) {
		mock := &mockRoundTripper{handler: handlerResponse(http.StatusOK, validJSON)} //nolint:bodyclose // closed by loadLogList
		c := tlsct.NewChecker()
		c.SetLogListHTTP(&http.Client{Transport: mock})

		ll, err := tlsct.LoadLogList(context.Background(), c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ll == nil {
			t.Fatal("expected non-nil log list")
		}
		if mock.calls != 1 {
			t.Fatalf("expected 1 HTTP call, got %d", mock.calls)
		}
		t.Logf("first call: log list fetched")

		// Second call should use cache.
		ll2, err := tlsct.LoadLogList(context.Background(), c)
		if err != nil {
			t.Fatalf("unexpected error on cached call: %v", err)
		}
		if ll2 == nil {
			t.Fatal("expected non-nil cached log list")
		}
		if mock.calls != 1 {
			t.Fatalf("expected 1 HTTP call (cached), got %d", mock.calls)
		}
		t.Logf("second call: served from cache (calls=%d)", mock.calls)
	})

	t.Run("HTTP 500 error", func(t *testing.T) {
		mock := &mockRoundTripper{handler: handlerResponse(http.StatusInternalServerError, "server error")} //nolint:bodyclose // closed by loadLogList
		c := tlsct.NewChecker()
		c.SetLogListHTTP(&http.Client{Transport: mock})

		_, err := tlsct.LoadLogList(context.Background(), c)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "HTTP 500") {
			t.Fatalf("expected 'HTTP 500' in error, got: %v", err)
		}
		t.Logf("HTTP error: %v", err)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		mock := &mockRoundTripper{handler: handlerResponse(http.StatusOK, "not json {")} //nolint:bodyclose // closed by loadLogList
		c := tlsct.NewChecker()
		c.SetLogListHTTP(&http.Client{Transport: mock})

		_, err := tlsct.LoadLogList(context.Background(), c)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
		t.Logf("invalid JSON error: %v", err)
	})

	t.Run("pre-populated cache returns without HTTP", func(t *testing.T) {
		mock := &mockRoundTripper{handler: handlerResponse(http.StatusOK, validJSON)} //nolint:bodyclose // closed by loadLogList
		c := tlsct.NewChecker()
		c.SetLogListHTTP(&http.Client{Transport: mock})

		// Pre-populate.
		ll0, err := tlsct.LoadLogList(context.Background(), c)
		if err != nil {
			t.Fatalf("setup: %v", err)
		}
		if mock.calls != 1 {
			t.Fatalf("setup: expected 1 call, got %d", mock.calls)
		}

		// Now inject directly and reset mock.
		c.InjectLogList(ll0)
		mock.calls = 0

		ll, err := tlsct.LoadLogList(context.Background(), c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ll == nil {
			t.Fatal("expected non-nil log list")
		}
		if mock.calls != 0 {
			t.Fatalf("expected 0 HTTP calls with injected cache, got %d", mock.calls)
		}
		t.Logf("injected cache: no HTTP calls")
	})
}

// ---------- Group 15: live integration test ----------

func TestLiveCheckTLSState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live CT check in short mode")
	}

	c := tlsct.NewChecker()
	conn, err := tls.Dial("tcp", "google.com:443", &tls.Config{MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("TLS dial google.com:443: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	t.Logf("peer certs: %d, handshake SCTs: %d",
		len(state.PeerCertificates), len(state.SignedCertificateTimestamps))

	err = c.CheckTLSState(context.Background(), "google.com", &state)
	if err != nil {
		t.Fatalf("CheckTLSState: %v", err)
	}
	t.Logf("CT check passed, cache entries: %d", c.CacheLen())

	// Second call should hit cache.
	err = c.CheckTLSState(context.Background(), "google.com", &state)
	if err != nil {
		t.Fatalf("CheckTLSState (cached): %v", err)
	}
	t.Log("second call: cache hit")
}
