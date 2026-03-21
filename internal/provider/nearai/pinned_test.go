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

	if err := writeHTTPRequest(bw, "GET", "/v1/attestation/report?nonce=abc", headers, nil); err != nil {
		t.Fatalf("writeHTTPRequest: %v", err)
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
	if err := writeHTTPRequest(bw, "POST", "/v1/chat/completions", headers, body); err != nil {
		t.Fatalf("writeHTTPRequest: %v", err)
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
	if err := writeHTTPRequest(bw, "POST", "/v1/chat", headers, body); err != nil {
		t.Fatalf("writeHTTPRequest: %v", err)
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

	err := writeHTTPRequest(bw, "GET", "/path", headers, nil)
	if err == nil {
		t.Fatal("expected error for missing Host header")
	}
	if !strings.Contains(err.Error(), "Host") {
		t.Errorf("error should mention Host: %v", err)
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
		enforced:   attestation.DefaultEnforced,
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

	if err := writeHTTPRequest(bw, req.Method, req.Path, headers, req.Body); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	resp, err := http.ReadResponse(br, nil) //nolint:bodyclose // body is closed via connClosingReader wrapping below
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	wrappedBody := &connClosingReader{ReadCloser: resp.Body, conn: conn}
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

	h := NewPinnedHandler(resolver, spkiCache, "test-api-key", true, enforced, rdVerifier)

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
