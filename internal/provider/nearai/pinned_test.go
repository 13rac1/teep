package nearai

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
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

func TestExtractSPKI(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	conn, err := tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	handler := &PinnedHandler{}
	spki, err := handler.extractSPKI(conn)
	if err != nil {
		t.Fatalf("extractSPKI: %v", err)
	}
	if spki == "" {
		t.Fatal("SPKI hash is empty")
	}
	t.Logf("SPKI hash: %s", spki)

	// Verify it's deterministic — same cert should produce same hash.
	conn2, err := tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer conn2.Close()

	spki2, err := handler.extractSPKI(conn2)
	if err != nil {
		t.Fatalf("extractSPKI 2: %v", err)
	}
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
		enforced:   []string{},
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

	// Connect to test server with InsecureSkipVerify (self-signed cert).
	conn, err := tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	liveSPKI, err := h.extractSPKI(conn)
	if err != nil {
		return nil, fmt.Errorf("extractSPKI: %w", err)
	}

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

func testTLSConfig(_ *httptest.Server) *tls.Config {
	// httptest.NewTLSServer provides a TLS config with the server's cert pool
	// but we need InsecureSkipVerify for direct dialing.
	return &tls.Config{InsecureSkipVerify: true}
}

func computeTestServerSPKI(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	conn, err := tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	if err != nil {
		t.Fatalf("dial for SPKI: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificates")
	}
	hash, err := attestation.ComputeSPKIHash(state.PeerCertificates[0].Raw)
	if err != nil {
		t.Fatalf("ComputeSPKIHash: %v", err)
	}
	return hash
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

// TestNewPinnedHandler verifies constructor sets all fields correctly.
func TestNewPinnedHandler(t *testing.T) {
	spkiCache := attestation.NewSPKICache()
	resolver := newEndpointResolverForTest("http://localhost")
	rdVerifier := ReportDataVerifier{}
	enforced := []string{"nonce_match", "tdx_debug_disabled"}

	h := NewPinnedHandler(resolver, spkiCache, "test-api-key", true, enforced, attestation.MeasurementPolicy{}, rdVerifier)

	if h.apiKey != "test-api-key" {
		t.Errorf("apiKey = %q, want %q", h.apiKey, "test-api-key")
	}
	if !h.offline {
		t.Error("offline = false, want true")
	}
	if len(h.enforced) != 2 {
		t.Errorf("enforced len = %d, want 2", len(h.enforced))
	}
	if h.spkiCache == nil {
		t.Error("spkiCache is nil")
	}
	if h.resolver == nil {
		t.Error("resolver is nil")
	}
}

// TestSetDialer verifies SetDialer installs a custom dial function.
func TestSetDialer(t *testing.T) {
	h := &PinnedHandler{}
	if h.dialFn != nil {
		t.Fatal("dialFn should be nil by default")
	}

	called := false
	h.SetDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		called = true
		return nil, errors.New("test dialer")
	})

	if h.dialFn == nil {
		t.Fatal("dialFn should be set after SetDialer")
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
		"signing_key": "04aaaa",
		"signing_address": "0xtest",
		"signing_algo": "ecdsa",
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
		[]string{},
		attestation.MeasurementPolicy{},
		ReportDataVerifier{},
	)

	// Inject dialer that connects to our test TLS server.
	handler.SetDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		conn, err := tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
		return conn, err
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
		ReportDataVerifier{},
	)
	handler.SetDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		return tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
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
		ReportDataVerifier{},
	)
	handler.SetDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		return tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
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
			// Force nonce mismatch so nonce_match fails when enforced.
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
		[]string{"nonce_match"},
		attestation.MeasurementPolicy{},
		ReportDataVerifier{},
	)
	handler.SetDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		return tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
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
		ReportDataVerifier{},
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
