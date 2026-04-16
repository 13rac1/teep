package neardirect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
)

func TestWriteHTTPRequest_GET(t *testing.T) {
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)

	headers := make(http.Header)
	headers.Set("Authorization", "Bearer key")
	headers.Set("Connection", "keep-alive")

	headers.Set("Host", "example.com")

	if err := WriteHTTPRequest(bw, "GET", "/v1/attestation/report?nonce=abc", headers, nil); err != nil {
		t.Fatalf("WriteHTTPRequest: %v", err)
	}

	got := buf.String()
	if !strings.HasPrefix(got, "GET /v1/attestation/report?nonce=abc HTTP/1.1\r\n") {
		t.Errorf("request line incorrect: %q", got[:80])
	}
	if !strings.Contains(got, "Host: example.com\r\n") {
		t.Error("missing Host header")
	}
	if !strings.Contains(got, "Authorization: Bearer key\r\n") {
		t.Error("missing Authorization header")
	}
	if strings.Contains(got, "Content-Length") {
		t.Error("GET should not have Content-Length")
	}
	if !strings.HasSuffix(got, "\r\n\r\n") {
		t.Error("missing header terminator")
	}
}

func TestWriteHTTPRequest_POST(t *testing.T) {
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)

	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")

	headers.Set("Host", "api.near.ai")

	body := []byte(`{"model":"test"}`)
	if err := WriteHTTPRequest(bw, "POST", "/v1/chat/completions", headers, body); err != nil {
		t.Fatalf("WriteHTTPRequest: %v", err)
	}

	got := buf.String()
	if !strings.HasPrefix(got, "POST /v1/chat/completions HTTP/1.1\r\n") {
		t.Errorf("request line incorrect: %q", got[:60])
	}
	if !strings.Contains(got, fmt.Sprintf("Content-Length: %d\r\n", len(body))) {
		t.Error("missing or wrong Content-Length")
	}
	if !strings.HasSuffix(got, string(body)) {
		t.Error("body not written correctly")
	}
}

func TestWriteHTTPRequest_ValidHTTP(t *testing.T) {
	// Verify the output can be parsed by http.ReadRequest.
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)

	headers := make(http.Header)
	headers.Set("Authorization", "Bearer test")
	headers.Set("Content-Type", "application/json")

	headers.Set("Host", "host.com")

	body := []byte(`{"model":"x"}`)
	if err := WriteHTTPRequest(bw, "POST", "/v1/chat", headers, body); err != nil {
		t.Fatalf("WriteHTTPRequest: %v", err)
	}

	req, err := http.ReadRequest(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	defer req.Body.Close()

	if req.Method != http.MethodPost {
		t.Errorf("Method = %q, want POST", req.Method)
	}
	if req.URL.Path != "/v1/chat" {
		t.Errorf("Path = %q, want /v1/chat", req.URL.Path)
	}
	if req.Host != "host.com" {
		t.Errorf("Host = %q, want host.com", req.Host)
	}
	reqBody, _ := io.ReadAll(req.Body)
	if !bytes.Equal(reqBody, body) {
		t.Errorf("body = %q, want %q", reqBody, body)
	}
}

func TestWriteHTTPRequest_MissingHost(t *testing.T) {
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)

	headers := make(http.Header)
	headers.Set("Authorization", "Bearer key")
	// No Host header set.

	err := WriteHTTPRequest(bw, "GET", "/path", headers, nil)
	if err == nil {
		t.Fatal("expected error for missing Host header")
	}
	if !strings.Contains(err.Error(), "Host") {
		t.Errorf("error should mention Host: %v", err)
	}
}

func TestWriteHTTPRequest_RejectsCRLFInHeaderValue(t *testing.T) {
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)

	headers := make(http.Header)
	headers.Set("Host", "example.com")
	headers.Set("Authorization", "Bearer good\r\nX-Injected: bad")

	err := WriteHTTPRequest(bw, "GET", "/path", headers, nil)
	if err == nil {
		t.Fatal("expected error for CRLF header injection")
	}
	if !strings.Contains(err.Error(), "CR/LF") {
		t.Fatalf("error should mention CR/LF characters, got: %v", err)
	}
}

func TestWriteHTTPRequest_RejectsCRLFInMethodAndPath(t *testing.T) {
	headers := make(http.Header)
	headers.Set("Host", "example.com")

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"method with CR", "GET\r", "/path"},
		{"method with LF", "GET\n", "/path"},
		{"path with CR", "GET", "/path\r\nX-Injected: bad"},
		{"path with LF", "GET", "/path\nX-Injected: bad"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			bw := bufio.NewWriter(&buf)
			err := WriteHTTPRequest(bw, tt.method, tt.path, headers, nil)
			if err == nil {
				t.Fatal("expected error for CRLF injection")
			}
			if !strings.Contains(err.Error(), "CR/LF") {
				t.Fatalf("error should mention CR/LF, got: %v", err)
			}
		})
	}
}

func TestExtractSPKI(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	conn := dialTestTLSCT(t, srv)
	defer conn.Close()

	spki := conn.SPKI()
	if spki == "" {
		t.Fatal("SPKI hash is empty")
	}
	t.Logf("SPKI hash: %s", spki)

	// Verify it's deterministic — same cert should produce same hash.
	conn2 := dialTestTLSCT(t, srv)
	defer conn2.Close()

	spki2 := conn2.SPKI()
	if spki != spki2 {
		t.Errorf("SPKI mismatch: %q vs %q", spki, spki2)
	}
}

// TestPinnedHandler_SPKICacheHit verifies that when the SPKI is already cached,
// no attestation request is made and the chat request goes through directly.
func TestPinnedHandler_SPKICacheHit(t *testing.T) {
	// Set up a TLS server that serves a chat response.
	requestPaths := []string{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPaths = append(requestPaths, r.URL.Path)
		if r.URL.Path == "/v1/chat/completions" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"hello"}}]}`))
			return
		}
		http.Error(w, "unexpected path: "+r.URL.Path, http.StatusBadRequest)
	}))
	defer srv.Close()

	// Extract the server's SPKI hash and pre-populate the cache.
	spkiCache := attestation.NewSPKICache()
	spkiHash := computeTestServerSPKI(t, srv)

	// The endpoint resolver maps to the test server's address.
	domain := hostFromURL(t, srv.URL)
	endpointSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"endpoints":[{"domain":"%s","models":["test-model"]}]}`, domain)
	}))
	defer endpointSrv.Close()

	resolver := newEndpointResolverForTest(endpointSrv.URL)

	// Pre-add the SPKI to the cache.
	spkiCache.Add(domain, spkiHash)

	handler := &PinnedHandler{
		resolver:   resolver,
		spkiCache:  spkiCache,
		apiKey:     "test-key",
		offline:    true,
		allowFail:  []string{},
		rdVerifier: ReportDataVerifier{},
	}

	// Override tlsDial to connect to the test server.
	resp, err := handlePinnedWithTestDial(t, handler, srv, &provider.PinnedRequest{
		Method:  "POST",
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Content-Type": {"application/json"}},
		Body:    []byte(`{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`),
		Model:   "test-model",
	})
	if err != nil {
		t.Fatalf("HandlePinned: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "hello") {
		t.Errorf("body = %q, want to contain 'hello'", body)
	}

	// No attestation endpoint should have been hit.
	for _, p := range requestPaths {
		if strings.Contains(p, "attestation") {
			t.Errorf("unexpected attestation request: %s", p)
		}
	}

	// Report should be nil (SPKI cache hit).
	if resp.Report != nil {
		t.Error("Report should be nil on SPKI cache hit")
	}
}

// handlePinnedWithTestDial works around the fact that test TLS servers use
// localhost addresses, not real domains. It patches the handler's tlsDial
// to connect to the test server directly.
func handlePinnedWithTestDial(t *testing.T, h *PinnedHandler, srv *httptest.Server, req *provider.PinnedRequest) (_ *provider.PinnedResponse, err error) {
	t.Helper()

	// We can't use the handler's tlsDial because it resolves domain:443.
	// Instead, manually do what HandlePinned does but with a test connection.
	ctx := context.Background()

	domain, err := h.resolver.Resolve(ctx, req.Model)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}

	// Connect to test server using the server's own CA cert pool.
	tc, err := tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	conn, err := tlsct.NewConn(tc)
	if err != nil {
		tc.Close()
		return nil, fmt.Errorf("tlsct.NewConn: %w", err)
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	liveSPKI := conn.SPKI()

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	var report *attestation.VerificationReport
	if !h.spkiCache.Contains(domain, liveSPKI) {
		return nil, errors.New("SPKI not in cache (test expects cache hit)")
	}

	headers := req.Headers.Clone()
	headers.Set("Host", domain)
	headers.Set("Authorization", "Bearer "+h.apiKey)
	headers.Set("Connection", "close")

	if err := WriteHTTPRequest(bw, req.Method, req.Path, headers, req.Body); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	resp, err := http.ReadResponse(br, nil) //nolint:bodyclose // body is closed via ConnClosingReader wrapping below
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	wrappedBody := NewConnClosingReader(resp.Body, conn)
	return &provider.PinnedResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       wrappedBody,
		Report:     report,
	}, nil
}

func testTLSConfig(srv *httptest.Server) *tls.Config {
	certPool := x509.NewCertPool()
	certPool.AddCert(srv.Certificate())
	return &tls.Config{RootCAs: certPool, MinVersion: tls.VersionTLS13}
}

// dialTestTLSCT dials a test TLS server and wraps the connection as a tlsct.Conn.
func dialTestTLSCT(t *testing.T, srv *httptest.Server) *tlsct.Conn {
	t.Helper()
	tc, err := tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	conn, err := tlsct.NewConn(tc)
	if err != nil {
		tc.Close()
		t.Fatalf("tlsct.NewConn: %v", err)
	}
	return conn
}

func computeTestServerSPKI(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	conn := dialTestTLSCT(t, srv)
	defer conn.Close()
	return conn.SPKI()
}

func hostFromURL(t *testing.T, rawURL string) string {
	t.Helper()
	// httptest.Server.URL is like "https://127.0.0.1:PORT"
	_, addr, ok := strings.Cut(rawURL, "://")
	if !ok {
		t.Fatalf("bad URL: %s", rawURL)
	}
	// Validate it looks like host:port.
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	return addr
}

// allFactorsExcept returns KnownFactors minus the given names — useful for
// building an allow_fail list that enforces only the excluded factors.
func allFactorsExcept(exclude ...string) []string {
	ex := make(map[string]bool, len(exclude))
	for _, n := range exclude {
		ex[n] = true
	}
	var out []string
	for _, n := range attestation.KnownFactors {
		if !ex[n] {
			out = append(out, n)
		}
	}
	return out
}

// TestNewPinnedHandler verifies constructor sets all fields correctly.
func TestNewPinnedHandler(t *testing.T) {
	spkiCache := attestation.NewSPKICache()
	resolver := newEndpointResolverForTest("http://localhost")
	rdVerifier := ReportDataVerifier{}
	allowFail := []string{"nonce_match", "tdx_debug_disabled"}

	h := NewPinnedHandler(resolver, spkiCache, "test-api-key", true, allowFail, attestation.MeasurementPolicy{}, rdVerifier, nil, attestation.DefaultNVIDIAVerifier(), nil)

	if h.apiKey != "test-api-key" {
		t.Errorf("apiKey = %q, want %q", h.apiKey, "test-api-key")
	}
	if !h.offline {
		t.Error("offline = false, want true")
	}
	if len(h.allowFail) != 2 {
		t.Errorf("allowFail len = %d, want 2", len(h.allowFail))
	}
	if h.spkiCache == nil {
		t.Error("spkiCache is nil")
	}
	if h.resolver == nil {
		t.Error("resolver is nil")
	}
}

// TestSetDialer verifies setDialer installs a custom dial function.
func TestSetDialer(t *testing.T) {
	h := &PinnedHandler{}
	if h.dialFn != nil {
		t.Fatal("dialFn should be nil by default")
	}

	called := false
	h.setDialer(func(_ context.Context, _ string) (*tlsct.Conn, error) {
		called = true
		return nil, errors.New("test dialer")
	})

	if h.dialFn == nil {
		t.Fatal("dialFn should be set after setDialer")
	}

	_, err := h.dialFn(context.Background(), "example.com")
	if err == nil || !called {
		t.Error("custom dialer was not invoked")
	}
}

// --------------------------------------------------------------------------
// HandlePinned end-to-end tests
// --------------------------------------------------------------------------

// nearaiAttestationJSON builds a minimal NEAR AI attestation response JSON
// with the given SPKI hash as TLS fingerprint and the given nonce.
func nearaiAttestationJSON(spkiHash, nonceHex string) string {
	return fmt.Sprintf(`{
		"verified": true,
		"model": "test-model",
		"model_name": "test-model",
		"nonce": %q,
		"signing_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"signing_address": "0xtest",
		"signing_algo": "ed25519",
		"intel_quote": "",
		"nvidia_payload": "",
		"tls_cert_fingerprint": %q
	}`, nonceHex, spkiHash)
}

func TestHandlePinned_CacheMiss(t *testing.T) {
	// TLS server handles both attestation and chat.
	var spkiHash string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("server received: %s %s", r.Method, r.URL.String())
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			nonceHex := r.URL.Query().Get("nonce")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(nearaiAttestationJSON(spkiHash, nonceHex)))
			return
		}
		if r.URL.Path == "/v1/chat/completions" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"hello from pinned"}}]}`))
			return
		}
		http.Error(w, "unexpected: "+r.URL.String(), http.StatusBadRequest)
	}))
	defer srv.Close()

	// Compute the server's SPKI hash.
	spkiHash = computeTestServerSPKI(t, srv)
	t.Logf("test server SPKI: %s", spkiHash)

	domain := hostFromURL(t, srv.URL)
	endpointSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"endpoints":[{"domain":"%s","models":["test-model"]}]}`, domain)
	}))
	defer endpointSrv.Close()

	handler := NewPinnedHandler(
		newEndpointResolverForTest(endpointSrv.URL),
		attestation.NewSPKICache(),
		"test-key",
		true, // offline — skip Sigstore/Rekor
		attestation.KnownFactors,
		attestation.MeasurementPolicy{},
		ReportDataVerifier{}, nil, attestation.DefaultNVIDIAVerifier(),
		nil,
	)

	// Inject dialer that connects to our test TLS server.
	handler.setDialer(func(_ context.Context, _ string) (*tlsct.Conn, error) {
		tc, err := tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
		if err != nil {
			return nil, err
		}
		return tlsct.NewConn(tc)
	})

	resp, err := handler.HandlePinned(context.Background(), &provider.PinnedRequest{
		Method:  "POST",
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Content-Type": {"application/json"}},
		Body:    []byte(`{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`),
		Model:   "test-model",
	})
	if err != nil {
		t.Fatalf("HandlePinned: %v", err)
	}
	defer resp.Body.Close()

	t.Logf("status: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}

	body, _ := io.ReadAll(resp.Body)
	t.Logf("body: %s", body)
	if !strings.Contains(string(body), "hello from pinned") {
		t.Errorf("body = %q, want to contain 'hello from pinned'", body)
	}

	// Report should be non-nil (attestation was fetched).
	if resp.Report == nil {
		t.Error("Report should be non-nil on cache miss (attestation was fetched)")
	}
}

func TestHandlePinned_CacheHitViaSetDialer(t *testing.T) {
	var requestPaths []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPaths = append(requestPaths, r.URL.Path)
		t.Logf("server received: %s %s", r.Method, r.URL.String())
		if r.URL.Path == "/v1/chat/completions" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"cached"}}]}`))
			return
		}
		http.Error(w, "unexpected: "+r.URL.Path, http.StatusBadRequest)
	}))
	defer srv.Close()

	spkiHash := computeTestServerSPKI(t, srv)
	domain := hostFromURL(t, srv.URL)

	endpointSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"endpoints":[{"domain":"%s","models":["test-model"]}]}`, domain)
	}))
	defer endpointSrv.Close()

	spkiCache := attestation.NewSPKICache()
	spkiCache.Add(domain, spkiHash)

	handler := NewPinnedHandler(
		newEndpointResolverForTest(endpointSrv.URL),
		spkiCache,
		"test-key",
		true,
		[]string{},
		attestation.MeasurementPolicy{},
		ReportDataVerifier{}, nil, attestation.DefaultNVIDIAVerifier(),
		nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tlsct.Conn, error) {
		tc, err := tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
		if err != nil {
			return nil, err
		}
		return tlsct.NewConn(tc)
	})

	resp, err := handler.HandlePinned(context.Background(), &provider.PinnedRequest{
		Method:  "POST",
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Content-Type": {"application/json"}},
		Body:    []byte(`{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`),
		Model:   "test-model",
	})
	if err != nil {
		t.Fatalf("HandlePinned: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	t.Logf("body: %s", body)
	if !strings.Contains(string(body), "cached") {
		t.Errorf("body = %q, want to contain 'cached'", body)
	}

	// No attestation request should have been made.
	for _, p := range requestPaths {
		if strings.Contains(p, "attestation") {
			t.Errorf("unexpected attestation request: %s", p)
		}
	}

	// Report should be nil on cache hit.
	if resp.Report != nil {
		t.Error("Report should be nil on SPKI cache hit")
	}
}

func TestHandlePinned_MismatchedFingerprint(t *testing.T) {
	// Server returns a wrong TLS fingerprint in attestation.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("server received: %s %s", r.Method, r.URL.String())
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			nonceHex := r.URL.Query().Get("nonce")
			w.Header().Set("Content-Type", "application/json")
			// Return a wrong fingerprint.
			_, _ = w.Write([]byte(nearaiAttestationJSON("sha256:wrong_fingerprint_value", nonceHex)))
			return
		}
		http.Error(w, "should not reach chat", http.StatusInternalServerError)
	}))
	defer srv.Close()

	domain := hostFromURL(t, srv.URL)
	endpointSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"endpoints":[{"domain":"%s","models":["test-model"]}]}`, domain)
	}))
	defer endpointSrv.Close()

	handler := NewPinnedHandler(
		newEndpointResolverForTest(endpointSrv.URL),
		attestation.NewSPKICache(),
		"test-key",
		true,
		[]string{},
		attestation.MeasurementPolicy{},
		ReportDataVerifier{}, nil, attestation.DefaultNVIDIAVerifier(),
		nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tlsct.Conn, error) {
		tc, err := tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
		if err != nil {
			return nil, err
		}
		return tlsct.NewConn(tc)
	})

	_, err := handler.HandlePinned(context.Background(), &provider.PinnedRequest{
		Method:  "POST",
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Content-Type": {"application/json"}},
		Body:    []byte(`{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`),
		Model:   "test-model",
	})

	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for mismatched TLS fingerprint")
	}
	if !strings.Contains(err.Error(), "SPKI") && !strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("error should mention SPKI/fingerprint mismatch: %v", err)
	}
}

func TestHandlePinned_BlockedReportDoesNotPopulateSPKICache(t *testing.T) {
	attestCalls := 0
	var spkiHash string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			attestCalls++
			w.Header().Set("Content-Type", "application/json")
			// Force nonce mismatch so nonce_match fails when not in allow_fail.
			_, _ = w.Write([]byte(nearaiAttestationJSON(spkiHash, "0000000000000000000000000000000000000000000000000000000000000000")))
			return
		}
		http.Error(w, "chat should not be reached", http.StatusInternalServerError)
	}))
	defer srv.Close()

	spkiHash = computeTestServerSPKI(t, srv)
	domain := hostFromURL(t, srv.URL)
	endpointSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"endpoints":[{"domain":"%s","models":["test-model"]}]}`, domain)
	}))
	defer endpointSrv.Close()

	handler := NewPinnedHandler(
		newEndpointResolverForTest(endpointSrv.URL),
		attestation.NewSPKICache(),
		"test-key",
		true,
		[]string{}, // empty allow_fail → all factors enforced, including nonce_match
		attestation.MeasurementPolicy{},
		ReportDataVerifier{}, nil, attestation.DefaultNVIDIAVerifier(),
		nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tlsct.Conn, error) {
		tc, err := tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
		if err != nil {
			return nil, err
		}
		return tlsct.NewConn(tc)
	})

	for i := range 2 {
		resp, err := handler.HandlePinned(context.Background(), &provider.PinnedRequest{
			Method:  "POST",
			Path:    "/v1/chat/completions",
			Headers: http.Header{"Content-Type": {"application/json"}},
			Body:    []byte(`{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`),
			Model:   "test-model",
		})
		if err != nil {
			t.Fatalf("HandlePinned call %d: %v", i+1, err)
		}
		if resp.Report == nil {
			t.Fatalf("HandlePinned call %d: expected non-nil report", i+1)
		}
		if !resp.Report.Blocked() {
			t.Fatalf("HandlePinned call %d: report should be blocked", i+1)
		}
		_ = resp.Body.Close()
	}

	if attestCalls != 2 {
		t.Fatalf("attestation calls = %d, want 2", attestCalls)
	}

	if handler.spkiCache.Contains(domain, spkiHash) {
		t.Fatal("SPKI cache should remain empty when report is blocked")
	}
}

func TestHandlePinned_DomainResolveError(t *testing.T) {
	// Endpoint server returns an error.
	endpointSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer endpointSrv.Close()

	handler := NewPinnedHandler(
		newEndpointResolverForTest(endpointSrv.URL),
		attestation.NewSPKICache(),
		"test-key",
		true,
		[]string{},
		attestation.MeasurementPolicy{},
		ReportDataVerifier{}, nil, attestation.DefaultNVIDIAVerifier(),
		nil,
	)

	_, err := handler.HandlePinned(context.Background(), &provider.PinnedRequest{
		Method:  "POST",
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Content-Type": {"application/json"}},
		Body:    []byte(`{"model":"unknown-model","messages":[]}`),
		Model:   "unknown-model",
	})

	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for domain resolution failure")
	}
	if !strings.Contains(err.Error(), "resolve") {
		t.Errorf("error should mention 'resolve': %v", err)
	}
}

// --------------------------------------------------------------------------
// ConnClosingReader tests
// --------------------------------------------------------------------------

type mockReadCloser struct {
	closeErr error
}

func (m *mockReadCloser) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (m *mockReadCloser) Close() error {
	return m.closeErr
}

type mockConn struct {
	net.Conn
	closeErr error
}

func (m *mockConn) Close() error {
	return m.closeErr
}

func TestConnClosingReader_BothSucceed(t *testing.T) {
	r := NewConnClosingReader(&mockReadCloser{}, &mockConn{})
	err := r.Close()
	t.Logf("Close error: %v", err)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestConnClosingReader_ReaderFails(t *testing.T) {
	readerErr := errors.New("reader close failed")
	r := NewConnClosingReader(&mockReadCloser{closeErr: readerErr}, &mockConn{})
	err := r.Close()
	t.Logf("Close error: %v", err)
	if !errors.Is(err, readerErr) {
		t.Errorf("expected reader error, got %v", err)
	}
}

func TestConnClosingReader_ConnFails(t *testing.T) {
	connErr := errors.New("conn close failed")
	r := NewConnClosingReader(&mockReadCloser{}, &mockConn{closeErr: connErr})
	err := r.Close()
	t.Logf("Close error: %v", err)
	if !errors.Is(err, connErr) {
		t.Errorf("expected conn error, got %v", err)
	}
}

func TestConnClosingReader_BothFail(t *testing.T) {
	readerErr := errors.New("reader close failed")
	connErr := errors.New("conn close failed")
	r := NewConnClosingReader(&mockReadCloser{closeErr: readerErr}, &mockConn{closeErr: connErr})
	err := r.Close()
	t.Logf("Close error: %v", err)
	// ReadCloser error takes priority.
	if !errors.Is(err, readerErr) {
		t.Errorf("expected reader error (first error wins), got %v", err)
	}
}

// --------------------------------------------------------------------------
// Singleflight & concurrency tests
// --------------------------------------------------------------------------

// TestHandlePinned_ConcurrentRequests_SingleflightDedup verifies that N
// concurrent requests for the same domain+SPKI produce exactly one
// attestation fetch (singleflight deduplication). All goroutines should
// see the result.
func TestHandlePinned_ConcurrentRequests_SingleflightDedup(t *testing.T) {
	var spkiHash string
	var attestCalls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			attestCalls.Add(1)
			// Hold the attestation response long enough for all goroutines
			// to pile into singleflight before the winner returns.
			time.Sleep(100 * time.Millisecond)
			nonceHex := r.URL.Query().Get("nonce")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(nearaiAttestationJSON(spkiHash, nonceHex)))
			return
		}
		if r.URL.Path == "/v1/chat/completions" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
			return
		}
		http.Error(w, "unexpected", http.StatusBadRequest)
	}))
	defer srv.Close()

	spkiHash = computeTestServerSPKI(t, srv)
	domain := hostFromURL(t, srv.URL)
	endpointSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"endpoints":[{"domain":"%s","models":["test-model"]}]}`, domain)
	}))
	defer endpointSrv.Close()

	handler := NewPinnedHandler(
		newEndpointResolverForTest(endpointSrv.URL),
		attestation.NewSPKICache(),
		"test-key",
		true,
		attestation.KnownFactors,
		attestation.MeasurementPolicy{},
		ReportDataVerifier{}, nil, attestation.DefaultNVIDIAVerifier(),
		nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tlsct.Conn, error) {
		tc, err := tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
		if err != nil {
			return nil, err
		}
		return tlsct.NewConn(tc)
	})

	const n = 5
	// Barrier ensures all goroutines enter HandlePinned concurrently.
	var ready sync.WaitGroup
	ready.Add(n)
	errs := make(chan error, n)
	for range n {
		go func() {
			ready.Done()
			ready.Wait()
			resp, err := handler.HandlePinned(context.Background(), &provider.PinnedRequest{
				Method:  "POST",
				Path:    "/v1/chat/completions",
				Headers: http.Header{"Content-Type": {"application/json"}},
				Body:    []byte(`{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`),
				Model:   "test-model",
			})
			if err != nil {
				errs <- err
				return
			}
			resp.Body.Close()
			errs <- nil
		}()
	}

	for range n {
		if err := <-errs; err != nil {
			t.Errorf("goroutine error: %v", err)
		}
	}

	// All goroutines share the same singleflight key (domain+SPKI) so
	// exactly one attestation fetch should occur; the rest either join the
	// in-flight call or find the SPKI already cached.
	calls := attestCalls.Load()
	t.Logf("attestation calls: %d", calls)
	if calls != 1 {
		t.Errorf("attestation calls = %d, want exactly 1 (singleflight dedup)", calls)
	}
}

// TestHandlePinned_AttestationTimeout verifies that a slow attestation endpoint
// respects context cancellation and does not hang.
func TestHandlePinned_AttestationTimeout(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			// Block until context cancelled — simulates unresponsive server.
			<-r.Context().Done()
			return
		}
		http.Error(w, "unexpected", http.StatusBadRequest)
	}))
	defer srv.Close()

	domain := hostFromURL(t, srv.URL)
	endpointSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"endpoints":[{"domain":"%s","models":["test-model"]}]}`, domain)
	}))
	defer endpointSrv.Close()

	handler := NewPinnedHandler(
		newEndpointResolverForTest(endpointSrv.URL),
		attestation.NewSPKICache(),
		"test-key",
		true,
		[]string{},
		attestation.MeasurementPolicy{},
		ReportDataVerifier{}, nil, attestation.DefaultNVIDIAVerifier(),
		nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tlsct.Conn, error) {
		tc, err := tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
		if err != nil {
			return nil, err
		}
		return tlsct.NewConn(tc)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := handler.HandlePinned(ctx, &provider.PinnedRequest{
		Method:  "POST",
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Content-Type": {"application/json"}},
		Body:    []byte(`{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`),
		Model:   "test-model",
	})

	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for attestation timeout")
	}

	// SPKI cache should NOT be populated.
	spkiHash := computeTestServerSPKI(t, srv)
	if handler.spkiCache.Contains(domain, spkiHash) {
		t.Error("SPKI cache should not be populated after timeout")
	}
}

// TestHandlePinned_MalformedAttestationResponse verifies that invalid JSON
// from the attestation endpoint results in an error with no SPKI cache population.
func TestHandlePinned_MalformedAttestationResponse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{{{not valid json`))
			return
		}
		http.Error(w, "unexpected", http.StatusBadRequest)
	}))
	defer srv.Close()

	domain := hostFromURL(t, srv.URL)
	endpointSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"endpoints":[{"domain":"%s","models":["test-model"]}]}`, domain)
	}))
	defer endpointSrv.Close()

	handler := NewPinnedHandler(
		newEndpointResolverForTest(endpointSrv.URL),
		attestation.NewSPKICache(),
		"test-key",
		true,
		[]string{},
		attestation.MeasurementPolicy{},
		ReportDataVerifier{}, nil, attestation.DefaultNVIDIAVerifier(),
		nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tlsct.Conn, error) {
		tc, err := tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
		if err != nil {
			return nil, err
		}
		return tlsct.NewConn(tc)
	})

	_, err := handler.HandlePinned(context.Background(), &provider.PinnedRequest{
		Method:  "POST",
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Content-Type": {"application/json"}},
		Body:    []byte(`{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`),
		Model:   "test-model",
	})

	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for malformed attestation JSON")
	}

	// SPKI cache should NOT be populated.
	spkiHash := computeTestServerSPKI(t, srv)
	if handler.spkiCache.Contains(domain, spkiHash) {
		t.Error("SPKI cache should not be populated after malformed attestation")
	}
}

// TestHandlePinned_BlockedThenRecovery verifies that after a blocked
// attestation, a subsequent successful attestation populates the SPKI cache.
func TestHandlePinned_BlockedThenRecovery(t *testing.T) {
	var spkiHash string
	echoNonce := false
	attestCalls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			attestCalls++
			nonceHex := r.URL.Query().Get("nonce")
			w.Header().Set("Content-Type", "application/json")
			if echoNonce {
				// Return correct nonce using request_nonce field (parsed field).
				_, _ = fmt.Fprintf(w, `{
					"verified": true,
					"model_name": "test-model",
					"request_nonce": %q,
					"signing_public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					"signing_address": "0xtest",
					"signing_algo": "ed25519",
					"intel_quote": "",
					"nvidia_payload": "",
					"tls_cert_fingerprint": %q
				}`, nonceHex, spkiHash)
			} else {
				// Return wrong nonce to trigger nonce_match failure.
				_, _ = w.Write([]byte(nearaiAttestationJSON(spkiHash, "0000000000000000000000000000000000000000000000000000000000000000")))
			}
			return
		}
		if r.URL.Path == "/v1/chat/completions" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"recovered"}}]}`))
			return
		}
		http.Error(w, "unexpected", http.StatusBadRequest)
	}))
	defer srv.Close()

	spkiHash = computeTestServerSPKI(t, srv)
	domain := hostFromURL(t, srv.URL)
	endpointSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"endpoints":[{"domain":"%s","models":["test-model"]}]}`, domain)
	}))
	defer endpointSrv.Close()

	handler := NewPinnedHandler(
		newEndpointResolverForTest(endpointSrv.URL),
		attestation.NewSPKICache(),
		"test-key",
		true,
		allFactorsExcept("nonce_match"), // only nonce_match is enforced
		attestation.MeasurementPolicy{},
		ReportDataVerifier{}, nil, attestation.DefaultNVIDIAVerifier(),
		nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tlsct.Conn, error) {
		tc, err := tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
		if err != nil {
			return nil, err
		}
		return tlsct.NewConn(tc)
	})

	// Request 1: blocked (nonce mismatch — nonce_match is the only enforced factor).
	resp, err := handler.HandlePinned(context.Background(), &provider.PinnedRequest{
		Method:  "POST",
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Content-Type": {"application/json"}},
		Body:    []byte(`{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`),
		Model:   "test-model",
	})
	if err != nil {
		t.Fatalf("request 1: %v", err)
	}
	if resp.Report == nil || !resp.Report.Blocked() {
		t.Fatal("request 1 should be blocked")
	}
	resp.Body.Close()

	// SPKI cache should NOT be populated.
	if handler.spkiCache.Contains(domain, spkiHash) {
		t.Fatal("SPKI cache should be empty after blocked attestation")
	}

	// Request 2: server now echoes nonce correctly.
	echoNonce = true
	resp, err = handler.HandlePinned(context.Background(), &provider.PinnedRequest{
		Method:  "POST",
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Content-Type": {"application/json"}},
		Body:    []byte(`{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`),
		Model:   "test-model",
	})
	if err != nil {
		t.Fatalf("request 2: %v", err)
	}
	defer resp.Body.Close()

	if resp.Report != nil && resp.Report.Blocked() {
		t.Fatal("request 2 should not be blocked")
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "recovered") {
		t.Errorf("body = %q, want to contain 'recovered'", body)
	}

	// SPKI cache should now be populated.
	if !handler.spkiCache.Contains(domain, spkiHash) {
		t.Error("SPKI cache should be populated after successful attestation")
	}

	if attestCalls != 2 {
		t.Errorf("attestation calls = %d, want 2", attestCalls)
	}
}

// --------------------------------------------------------------------------
// Direct unit tests for extracted verification helpers
// --------------------------------------------------------------------------

func readRealTDXQuoteHex(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../attestation/testdata/tdx_prod_quote_SPR_E4.dat")
	if err != nil {
		t.Fatalf("read TDX quote testdata: %v", err)
	}
	return hex.EncodeToString(raw)
}

func TestVerifyTDX(t *testing.T) {
	t.Run("EmptyQuote", func(t *testing.T) {
		h := &PinnedHandler{offline: true}
		raw := &attestation.RawAttestation{IntelQuote: ""}
		nonce := attestation.NewNonce()

		result := h.verifyTDX(context.Background(), raw, nonce)
		t.Logf("result: %v", result)
		if result != nil {
			t.Error("expected nil for empty quote")
		}
	})

	t.Run("InvalidQuote", func(t *testing.T) {
		h := &PinnedHandler{offline: true, verifyQuote: attestation.VerifyTDXQuoteOffline}
		raw := &attestation.RawAttestation{IntelQuote: "aabbccdd"}
		nonce := attestation.NewNonce()

		result := h.verifyTDX(context.Background(), raw, nonce)
		t.Logf("result: %+v", result)
		if result == nil {
			t.Fatal("expected non-nil result for invalid quote")
		}
		if result.ParseErr == nil {
			t.Error("expected ParseErr for invalid quote")
		}
		t.Logf("ParseErr: %v", result.ParseErr)
	})

	t.Run("RealQuoteWithVerifier", func(t *testing.T) {
		quoteHex := readRealTDXQuoteHex(t)
		h := &PinnedHandler{
			offline:     true,
			rdVerifier:  ReportDataVerifier{},
			verifyQuote: attestation.VerifyTDXQuoteOffline,
		}
		raw := &attestation.RawAttestation{
			IntelQuote:     quoteHex,
			SigningAddress: "0xtest",
			TLSFingerprint: "aabb",
		}
		nonce := attestation.NewNonce()

		result := h.verifyTDX(context.Background(), raw, nonce)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		t.Logf("result: ParseErr=%v, MRTD len=%d", result.ParseErr, len(result.MRTD))
		if result.ParseErr != nil {
			t.Fatalf("unexpected ParseErr: %v", result.ParseErr)
		}
		// rdVerifier was called (nonce won't match, so binding should fail).
		t.Logf("ReportDataBindingErr: %v", result.ReportDataBindingErr)
		t.Logf("ReportDataBindingDetail: %s", result.ReportDataBindingDetail)
	})
}

func TestVerifyNVIDIA(t *testing.T) {
	t.Run("EmptyPayload", func(t *testing.T) {
		h := &PinnedHandler{offline: true}
		raw := &attestation.RawAttestation{NvidiaPayload: ""}
		nonce := attestation.NewNonce()

		eat, nras := h.verifyNVIDIA(context.Background(), raw, nonce)
		t.Logf("eat=%v nras=%v", eat, nras)
		if eat != nil {
			t.Error("expected nil eat for empty payload")
		}
		if nras != nil {
			t.Error("expected nil nras for empty payload")
		}
	})

	t.Run("NonJSONPayload", func(t *testing.T) {
		h := &PinnedHandler{offline: true}
		raw := &attestation.RawAttestation{NvidiaPayload: "not-a-json-payload"}
		nonce := attestation.NewNonce()

		eat, nras := h.verifyNVIDIA(context.Background(), raw, nonce)
		t.Logf("eat=%+v nras=%v", eat, nras)
		if eat == nil {
			t.Fatal("expected non-nil eat for non-JSON payload")
		}
		if eat.SignatureErr == nil {
			t.Error("expected SignatureErr for non-JSON payload")
		}
		t.Logf("eat.SignatureErr: %v", eat.SignatureErr)
		// NRAS not attempted: payload doesn't start with '{' and offline=true.
		if nras != nil {
			t.Error("expected nil nras for non-JSON payload")
		}
	})

	t.Run("JSONPayloadOffline", func(t *testing.T) {
		h := &PinnedHandler{offline: true}
		raw := &attestation.RawAttestation{NvidiaPayload: `{"invalid":"jwt"}`}
		nonce := attestation.NewNonce()

		eat, nras := h.verifyNVIDIA(context.Background(), raw, nonce)
		t.Logf("eat=%+v nras=%v", eat, nras)
		if eat == nil {
			t.Fatal("expected non-nil eat for JSON payload")
		}
		// NRAS skipped because offline=true.
		if nras != nil {
			t.Error("expected nil nras when offline")
		}
	})
}

func TestCheckPoC(t *testing.T) {
	t.Run("Offline", func(t *testing.T) {
		h := &PinnedHandler{offline: true}
		result := h.checkPoC(context.Background(), "some-quote-hex")
		t.Logf("result: %v", result)
		if result != nil {
			t.Error("expected nil when offline")
		}
	})

	t.Run("EmptyQuote", func(t *testing.T) {
		h := &PinnedHandler{offline: false}
		result := h.checkPoC(context.Background(), "")
		t.Logf("result: %v", result)
		if result != nil {
			t.Error("expected nil for empty quote")
		}
	})
}

// testComposeWithDigest returns a compose JSON and matching MRConfigID for testing.
func testComposeWithDigest(t *testing.T) (appCompose string, mrConfigID []byte) {
	t.Helper()
	appCompose = `{"docker_compose_file":"services:\n  app:\n    image: ghcr.io/org/repo@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234\n"}`
	hash := sha256.Sum256([]byte(appCompose))
	mrConfigID = make([]byte, 48)
	mrConfigID[0] = 0x01
	copy(mrConfigID[1:], hash[:])
	return appCompose, mrConfigID
}

func TestVerifySupplyChain(t *testing.T) {
	t.Run("EmptyCompose", func(t *testing.T) {
		h := &PinnedHandler{offline: true}
		raw := &attestation.RawAttestation{AppCompose: ""}
		tdx := &attestation.TDXVerifyResult{}

		compose, repos, d2r, sig, rek := h.verifySupplyChain(context.Background(), raw, tdx)
		t.Logf("compose=%v repos=%v d2r=%v sig=%v rek=%v", compose, repos, d2r, sig, rek)
		if compose != nil {
			t.Error("expected nil compose for empty AppCompose")
		}
	})

	t.Run("NilTDX", func(t *testing.T) {
		h := &PinnedHandler{offline: true}
		raw := &attestation.RawAttestation{AppCompose: "something"}

		compose, repos, d2r, sig, rek := h.verifySupplyChain(context.Background(), raw, nil)
		t.Logf("compose=%v repos=%v d2r=%v sig=%v rek=%v", compose, repos, d2r, sig, rek)
		if compose != nil {
			t.Error("expected nil compose for nil TDX result")
		}
	})

	t.Run("TDXParseError", func(t *testing.T) {
		h := &PinnedHandler{offline: true}
		raw := &attestation.RawAttestation{AppCompose: "something"}
		tdx := &attestation.TDXVerifyResult{ParseErr: errors.New("bad quote")}

		compose, repos, d2r, sig, rek := h.verifySupplyChain(context.Background(), raw, tdx)
		t.Logf("compose=%v repos=%v d2r=%v sig=%v rek=%v", compose, repos, d2r, sig, rek)
		if compose != nil {
			t.Error("expected nil compose when TDX has ParseErr")
		}
	})

	t.Run("BindingMismatch", func(t *testing.T) {
		h := &PinnedHandler{offline: true}
		appCompose, _ := testComposeWithDigest(t)
		wrongMRConfigID := make([]byte, 48)
		wrongMRConfigID[0] = 0x01 // correct prefix, but wrong hash (zeros)

		raw := &attestation.RawAttestation{AppCompose: appCompose}
		tdx := &attestation.TDXVerifyResult{MRConfigID: wrongMRConfigID}

		compose, repos, d2r, sig, rek := h.verifySupplyChain(context.Background(), raw, tdx)
		t.Logf("compose=%+v repos=%v d2r=%v sig=%v rek=%v", compose, repos, d2r, sig, rek)
		if compose == nil {
			t.Fatal("expected non-nil compose result")
		}
		if !compose.Checked {
			t.Error("expected Checked=true")
		}
		if compose.Err == nil {
			t.Error("expected compose binding error for mismatched MRConfigID")
		}
		t.Logf("compose.Err: %v", compose.Err)
		if repos != nil {
			t.Error("expected nil repos on binding failure")
		}
		if sig != nil {
			t.Error("expected nil sigstore on binding failure")
		}
	})

	t.Run("BindingPass", func(t *testing.T) {
		h := &PinnedHandler{offline: true}
		appCompose, mrConfigID := testComposeWithDigest(t)

		raw := &attestation.RawAttestation{AppCompose: appCompose}
		tdx := &attestation.TDXVerifyResult{MRConfigID: mrConfigID}

		compose, repos, d2r, sig, rek := h.verifySupplyChain(context.Background(), raw, tdx)
		t.Logf("compose=%+v repos=%v d2r=%v sig=%v rek=%v", compose, repos, d2r, sig, rek)
		if compose == nil {
			t.Fatal("expected non-nil compose result")
		}
		if compose.Err != nil {
			t.Fatalf("unexpected compose binding error: %v", compose.Err)
		}
		if len(repos) == 0 {
			t.Error("expected non-empty imageRepos")
		}
		t.Logf("imageRepos: %v", repos)
		if len(d2r) == 0 {
			t.Error("expected non-empty digestToRepo")
		}
		t.Logf("digestToRepo: %v", d2r)
		// Sigstore/rekor not attempted: offline=true, rekorClient=nil.
		if sig != nil {
			t.Error("expected nil sigstore when offline")
		}
		if rek != nil {
			t.Error("expected nil rekor when offline")
		}
	})
}

// --------------------------------------------------------------------------
// encryptBody tests
// --------------------------------------------------------------------------

func TestEncryptBody_NoE2EE(t *testing.T) {
	h := &PinnedHandler{}
	body := []byte(`{"messages":[]}`)
	chatBody, session, headers, err := h.encryptBody(
		&provider.PinnedRequest{Body: body},
		nil, "",
	)
	if err != nil {
		t.Fatalf("encryptBody: %v", err)
	}
	t.Logf("chatBody len: %d, session: %v, headers: %v", len(chatBody), session, headers)

	if !bytes.Equal(chatBody, body) {
		t.Errorf("chatBody = %q, want %q", chatBody, body)
	}
	if session != nil {
		t.Error("session should be nil when E2EE is off")
	}
	if headers != nil {
		t.Error("headers should be nil when E2EE is off")
	}
}

func TestEncryptBody_NoSigningKey(t *testing.T) {
	h := &PinnedHandler{}
	_, _, _, err := h.encryptBody(
		&provider.PinnedRequest{E2EE: true, Path: "/v1/chat/completions", Body: []byte(`{}`)},
		nil, "",
	)
	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error when E2EE requested but no signing key")
	}
	if !strings.Contains(err.Error(), "no signing key") {
		t.Errorf("error should mention signing key: %v", err)
	}
}

func TestEncryptBody_UsesRequestSigningKey(t *testing.T) {
	h := &PinnedHandler{}

	// A valid 64-hex-char Ed25519 public key.
	sigKey := "04aaaa0000000000000000000000000000000000000000000000000000000000"

	chatBody, session, headers, err := h.encryptBody(
		&provider.PinnedRequest{
			E2EE:       true,
			SigningKey: sigKey,
			Path:       "/v1/chat/completions",
			Body:       []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
		},
		nil, "", // no report, no attestation signing key — uses req.SigningKey
	)
	t.Logf("err: %v", err)
	t.Logf("chatBody len: %d", len(chatBody))
	if session != nil {
		if nc, ok := session.(*e2ee.NearCloudSession); ok {
			t.Logf("session: Ed25519PubHex=%s", nc.ClientEd25519PubHex()[:16]+"...")
		}
	}
	if headers != nil {
		t.Logf("headers: %v", headers)
	}

	if err != nil {
		t.Fatalf("encryptBody: %v", err)
	}
	if session == nil {
		t.Fatal("session should be non-nil with E2EE")
	}
	defer session.Zero()
	if headers == nil {
		t.Fatal("headers should be non-nil with E2EE")
	}
	if headers.Get("X-Signing-Algo") != "ed25519" {
		t.Errorf("X-Signing-Algo = %q, want ed25519", headers.Get("X-Signing-Algo"))
	}
	if headers.Get("X-Encryption-Version") != "2" {
		t.Errorf("X-Encryption-Version = %q, want 2", headers.Get("X-Encryption-Version"))
	}
}

func TestEncryptBody_FailsOnBadBinding(t *testing.T) {
	h := &PinnedHandler{}

	// Report with tdx_reportdata_binding failed.
	report := &attestation.VerificationReport{
		Provider: "neardirect",
		Model:    "test-model",
		Factors: []attestation.FactorResult{
			{Name: "nonce_match", Status: attestation.Pass, Detail: "match"},
			{Name: "tdx_reportdata_binding", Status: attestation.Fail, Detail: "binding failed"},
		},
	}

	_, _, _, err := h.encryptBody(
		&provider.PinnedRequest{
			E2EE: true,
			Path: "/v1/chat/completions",
			Body: []byte(`{"messages":[]}`),
		},
		report, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error when REPORTDATA binding not passed")
	}
	if !strings.Contains(err.Error(), "tdx_reportdata_binding") {
		t.Errorf("error should mention tdx_reportdata_binding: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ConstantTimeHexEqual
// ---------------------------------------------------------------------------

func TestConstantTimeHexEqual_Equal(t *testing.T) {
	ok, err := ConstantTimeHexEqual("deadbeef", "deadbeef")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("equal hex strings should be equal")
	}
}

func TestConstantTimeHexEqual_NotEqual(t *testing.T) {
	ok, err := ConstantTimeHexEqual("deadbeef", "cafebabe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("different hex strings should not be equal")
	}
}

func TestConstantTimeHexEqual_DifferentLengths(t *testing.T) {
	ok, err := ConstantTimeHexEqual("deadbeef", "dead")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("different-length hex should not be equal")
	}
}

func TestConstantTimeHexEqual_InvalidFirst(t *testing.T) {
	_, err := ConstantTimeHexEqual("not-hex!", "deadbeef")
	if err == nil {
		t.Error("expected error for invalid first hex string")
	}
	t.Logf("error: %v", err)
}

func TestConstantTimeHexEqual_InvalidSecond(t *testing.T) {
	_, err := ConstantTimeHexEqual("deadbeef", "not-hex!")
	if err == nil {
		t.Error("expected error for invalid second hex string")
	}
	t.Logf("error: %v", err)
}
