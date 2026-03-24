package nearcloud

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"github.com/13rac1/teep/internal/provider/neardirect"
)

func testTLSConfig(srv *httptest.Server) *tls.Config {
	certPool := x509.NewCertPool()
	certPool.AddCert(srv.Certificate())
	return &tls.Config{RootCAs: certPool, MinVersion: tls.VersionTLS13}
}

func hostFromURL(t *testing.T, rawURL string) string {
	t.Helper()
	_, addr, ok := strings.Cut(rawURL, "://")
	if !ok {
		t.Fatalf("bad URL: %s", rawURL)
	}
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	return addr
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

// nearcloudAttestationJSON builds a combined gateway+model attestation JSON
// suitable for the nearcloud provider. Both gateway and model sections are
// present with the given SPKI hash and nonce.
func nearcloudAttestationJSON(spkiHash, nonceHex string) string {
	return fmt.Sprintf(`{
		"gateway_attestation": {
			"request_nonce": %q,
			"intel_quote": "",
			"event_log": "",
			"tls_cert_fingerprint": %q,
			"info": {
				"tcb_info": "{\"app_compose\":\"test-compose\"}"
			}
		},
		"model_attestations": [
			{
				"model": "test-model",
				"intel_quote": "",
				"nvidia_payload": "",
				"signing_key": "04aaaa",
				"signing_address": "0xtest",
				"signing_algo": "ecdsa",
				"tls_cert_fingerprint": %q,
				"nonce": %q
			}
		]
	}`, nonceHex, spkiHash, spkiHash, nonceHex)
}

func TestHandlePinned_CacheMiss(t *testing.T) {
	var spkiHash string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("server received: %s %s", r.Method, r.URL.String())
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			nonceHex := r.URL.Query().Get("nonce")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(nearcloudAttestationJSON(spkiHash, nonceHex)))
			return
		}
		if r.URL.Path == "/v1/chat/completions" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"hello from nearcloud"}}]}`))
			return
		}
		http.Error(w, "unexpected: "+r.URL.String(), http.StatusBadRequest)
	}))
	defer srv.Close()

	spkiHash = computeTestServerSPKI(t, srv)
	t.Logf("test server SPKI: %s", spkiHash)

	spkiCache := attestation.NewSPKICache()
	handler := NewPinnedHandler(
		spkiCache,
		"test-key",
		true, // offline
		[]string{},
		attestation.MeasurementPolicy{},
		nil, // no model RD verifier
	)
	handler.SetDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		return tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	})
	// Disable CT checker for test server (self-signed cert).
	handler.SetCTChecker(nil)

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
	if !strings.Contains(string(body), "hello from nearcloud") {
		t.Errorf("body = %q, want to contain 'hello from nearcloud'", body)
	}

	if resp.Report == nil {
		t.Error("Report should be non-nil on cache miss")
	}

	// SPKI should be cached after successful attestation.
	if !spkiCache.Contains(gatewayHost, spkiHash) {
		t.Error("SPKI should be cached after successful attestation")
	}
}

func TestHandlePinned_CacheHit(t *testing.T) {
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
	spkiCache := attestation.NewSPKICache()
	spkiCache.Add(gatewayHost, spkiHash)

	handler := NewPinnedHandler(
		spkiCache,
		"test-key",
		true,
		[]string{},
		attestation.MeasurementPolicy{},
		nil,
	)
	handler.SetDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		return tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	})
	handler.SetCTChecker(nil)

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

	for _, p := range requestPaths {
		if strings.Contains(p, "attestation") {
			t.Errorf("unexpected attestation request: %s", p)
		}
	}

	if resp.Report != nil {
		t.Error("Report should be nil on SPKI cache hit")
	}
}

func TestHandlePinned_MissingGatewayTLSFingerprint(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("server received: %s %s", r.Method, r.URL.String())
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			nonceHex := r.URL.Query().Get("nonce")
			// Return empty tls_cert_fingerprint for gateway.
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{
				"gateway_attestation": {
					"request_nonce": %q,
					"intel_quote": "",
					"event_log": "",
					"tls_cert_fingerprint": "",
					"info": {"tcb_info": "{}"}
				},
				"model_attestations": [
					{"model": "test-model", "nonce": %q, "signing_key": "04aaaa", "signing_address": "0x1", "signing_algo": "ecdsa", "tls_cert_fingerprint": "somefp"}
				]
			}`, nonceHex, nonceHex)
			return
		}
		http.Error(w, "should not reach chat", http.StatusInternalServerError)
	}))
	defer srv.Close()

	handler := NewPinnedHandler(
		attestation.NewSPKICache(),
		"test-key",
		true,
		[]string{},
		attestation.MeasurementPolicy{},
		nil,
	)
	handler.SetDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		return tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	})
	handler.SetCTChecker(nil)

	_, err := handler.HandlePinned(context.Background(), &provider.PinnedRequest{
		Method:  "POST",
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Content-Type": {"application/json"}},
		Body:    []byte(`{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`),
		Model:   "test-model",
	})

	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for missing gateway tls_cert_fingerprint")
	}
	if !strings.Contains(err.Error(), "tls_cert_fingerprint") {
		t.Errorf("error should mention tls_cert_fingerprint: %v", err)
	}
}

func TestHandlePinned_MismatchedGatewayFingerprint(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("server received: %s %s", r.Method, r.URL.String())
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			nonceHex := r.URL.Query().Get("nonce")
			w.Header().Set("Content-Type", "application/json")
			// Return a wrong gateway fingerprint.
			_, _ = w.Write([]byte(nearcloudAttestationJSON("sha256:wrong_gateway_fp", nonceHex)))
			return
		}
		http.Error(w, "should not reach chat", http.StatusInternalServerError)
	}))
	defer srv.Close()

	handler := NewPinnedHandler(
		attestation.NewSPKICache(),
		"test-key",
		true,
		[]string{},
		attestation.MeasurementPolicy{},
		nil,
	)
	handler.SetDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		return tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	})
	handler.SetCTChecker(nil)

	_, err := handler.HandlePinned(context.Background(), &provider.PinnedRequest{
		Method:  "POST",
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Content-Type": {"application/json"}},
		Body:    []byte(`{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`),
		Model:   "test-model",
	})

	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for mismatched gateway fingerprint")
	}
	if !strings.Contains(err.Error(), "SPKI") {
		t.Errorf("error should mention SPKI: %v", err)
	}
}

func TestHandlePinned_BlockedReport(t *testing.T) {
	var spkiHash string
	attestCalls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			attestCalls++
			w.Header().Set("Content-Type", "application/json")
			// Force nonce mismatch: return a fixed wrong nonce.
			_, _ = w.Write([]byte(nearcloudAttestationJSON(spkiHash, "0000000000000000000000000000000000000000000000000000000000000000")))
			return
		}
		http.Error(w, "chat should not be reached", http.StatusInternalServerError)
	}))
	defer srv.Close()

	spkiHash = computeTestServerSPKI(t, srv)
	spkiCache := attestation.NewSPKICache()

	handler := NewPinnedHandler(
		spkiCache,
		"test-key",
		true,
		[]string{"nonce_match"},
		attestation.MeasurementPolicy{},
		nil,
	)
	handler.SetDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		return tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	})
	handler.SetCTChecker(nil)

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
		t.Logf("call %d: status=%d, blocked=%v", i+1, resp.StatusCode, resp.Report != nil && resp.Report.Blocked())
		if resp.Report == nil {
			t.Fatalf("HandlePinned call %d: expected non-nil report", i+1)
		}
		if !resp.Report.Blocked() {
			t.Fatalf("HandlePinned call %d: report should be blocked", i+1)
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("HandlePinned call %d: status = %d, want 502", i+1, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}

	t.Logf("attestation calls: %d", attestCalls)
	if attestCalls != 2 {
		t.Fatalf("attestation calls = %d, want 2", attestCalls)
	}

	if spkiCache.Contains(gatewayHost, spkiHash) {
		t.Fatal("SPKI cache should remain empty when report is blocked")
	}
}

func TestHandlePinned_AttestationQueryParams(t *testing.T) {
	var spkiHash string
	var capturedQuery string
	var capturedAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("server received: %s %s", r.Method, r.URL.String())
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			capturedQuery = r.URL.RawQuery
			capturedAuth = r.Header.Get("Authorization")
			nonceHex := r.URL.Query().Get("nonce")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(nearcloudAttestationJSON(spkiHash, nonceHex)))
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

	handler := NewPinnedHandler(
		attestation.NewSPKICache(),
		"my-secret-key",
		true,
		[]string{},
		attestation.MeasurementPolicy{},
		nil,
	)
	handler.SetDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		return tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	})
	handler.SetCTChecker(nil)

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
	_ = resp.Body.Close()

	t.Logf("captured query: %s", capturedQuery)
	t.Logf("captured auth: %s", capturedAuth)

	if !strings.Contains(capturedQuery, "model=test-model") {
		t.Errorf("query should contain model=test-model: %s", capturedQuery)
	}
	if !strings.Contains(capturedQuery, "include_tls_fingerprint=true") {
		t.Errorf("query should contain include_tls_fingerprint=true: %s", capturedQuery)
	}
	if !strings.Contains(capturedQuery, "signing_algo=ecdsa") {
		t.Errorf("query should contain signing_algo=ecdsa: %s", capturedQuery)
	}
	if !strings.Contains(capturedQuery, "nonce=") {
		t.Errorf("query should contain nonce=: %s", capturedQuery)
	}
	if capturedAuth != "Bearer my-secret-key" {
		t.Errorf("Authorization = %q, want %q", capturedAuth, "Bearer my-secret-key")
	}
}

func TestNewPinnedHandler(t *testing.T) {
	spkiCache := attestation.NewSPKICache()
	enforced := []string{"nonce_match", "tdx_debug_disabled"}

	h := NewPinnedHandler(spkiCache, "test-key", true, enforced, attestation.MeasurementPolicy{}, nil)

	if h.apiKey != "test-key" {
		t.Errorf("apiKey = %q, want %q", h.apiKey, "test-key")
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
	t.Logf("handler created: apiKey=%q, offline=%v, enforced=%v", h.apiKey, h.offline, h.enforced)
}

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
	t.Logf("dial error: %v, called: %v", err, called)
	if err == nil || !called {
		t.Error("custom dialer was not invoked")
	}
}

func TestHandlePinned_AttestationHTTPError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("server received: %s %s", r.Method, r.URL.String())
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		http.Error(w, "unexpected", http.StatusBadRequest)
	}))
	defer srv.Close()

	handler := NewPinnedHandler(
		attestation.NewSPKICache(),
		"test-key",
		true,
		[]string{},
		attestation.MeasurementPolicy{},
		nil,
	)
	handler.SetDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		return tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	})
	handler.SetCTChecker(nil)

	_, err := handler.HandlePinned(context.Background(), &provider.PinnedRequest{
		Method:  "POST",
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Content-Type": {"application/json"}},
		Body:    []byte(`{"model":"test-model","messages":[]}`),
		Model:   "test-model",
	})

	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention 500: %v", err)
	}
}

func TestHandlePinned_InvalidAttestationJSON(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("server received: %s %s", r.Method, r.URL.String())
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{{{not valid json`))
			return
		}
		http.Error(w, "unexpected", http.StatusBadRequest)
	}))
	defer srv.Close()

	handler := NewPinnedHandler(
		attestation.NewSPKICache(),
		"test-key",
		true,
		[]string{},
		attestation.MeasurementPolicy{},
		nil,
	)
	handler.SetDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		return tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	})
	handler.SetCTChecker(nil)

	_, err := handler.HandlePinned(context.Background(), &provider.PinnedRequest{
		Method:  "POST",
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Content-Type": {"application/json"}},
		Body:    []byte(`{"model":"test-model","messages":[]}`),
		Model:   "test-model",
	})

	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestHandlePinned_DialError(t *testing.T) {
	handler := NewPinnedHandler(
		attestation.NewSPKICache(),
		"test-key",
		true,
		[]string{},
		attestation.MeasurementPolicy{},
		nil,
	)
	handler.SetDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		return nil, errors.New("connection refused")
	})
	handler.SetCTChecker(nil)

	_, err := handler.HandlePinned(context.Background(), &provider.PinnedRequest{
		Method:  "POST",
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Content-Type": {"application/json"}},
		Body:    []byte(`{"model":"test-model","messages":[]}`),
		Model:   "test-model",
	})

	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for dial failure")
	}
	if !strings.Contains(err.Error(), "TLS dial") {
		t.Errorf("error should mention TLS dial: %v", err)
	}
}

// nearcloudAttestationWithModel builds a response where the model has TLS fingerprint
// present but the model field points to a model-specific subdomain.
func nearcloudAttestationWithModelFP(gatewayFP, modelFP, nonceHex string) string {
	return fmt.Sprintf(`{
		"gateway_attestation": {
			"request_nonce": %q,
			"intel_quote": "",
			"event_log": "",
			"tls_cert_fingerprint": %q,
			"info": {
				"tcb_info": "{\"app_compose\":\"gw-compose\"}"
			}
		},
		"model_attestations": [
			{
				"model": "test-model",
				"intel_quote": "",
				"nvidia_payload": "",
				"signing_key": "04aaaa",
				"signing_address": "0xtest",
				"signing_algo": "ecdsa",
				"tls_cert_fingerprint": %q,
				"nonce": %q
			}
		]
	}`, nonceHex, gatewayFP, modelFP, nonceHex)
}

func TestHandlePinned_ModelHasDifferentFingerprint(t *testing.T) {
	// Model tls_cert_fingerprint != gateway SPKI — this is expected for nearcloud.
	var spkiHash string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("server received: %s %s", r.Method, r.URL.String())
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			nonceHex := r.URL.Query().Get("nonce")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(nearcloudAttestationWithModelFP(spkiHash, "differentmodelfp", nonceHex)))
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

	handler := NewPinnedHandler(
		attestation.NewSPKICache(),
		"test-key",
		true,
		[]string{},
		attestation.MeasurementPolicy{},
		nil,
	)
	handler.SetDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		return tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	})
	handler.SetCTChecker(nil)

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

	// Should succeed because gateway fingerprint matches.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}
}

func TestFetchAttestation_HappyPath(t *testing.T) {
	nonce := attestation.NewNonce()
	var capturedQuery string
	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		capturedAuth = r.Header.Get("Authorization")
		t.Logf("request: %s %s", r.Method, r.URL.String())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nearcloudAttestationJSON("sha256:fp", nonce.Hex())))
	}))
	defer srv.Close()

	a := NewAttester("my-api-key", true)
	// Override the client transport to redirect to our test server.
	a.client = srv.Client()
	a.client.Transport = &testTransport{target: srv.URL}

	raw, err := a.FetchAttestation(context.Background(), "test-model", nonce)
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	t.Logf("raw: nonce=%s, model=%s", raw.Nonce, raw.Model)
	t.Logf("gateway fields: nonce=%s, compose=%s, fp=%s",
		raw.GatewayNonceHex, raw.GatewayAppCompose, raw.GatewayTLSFingerprint)
	t.Logf("captured query: %s", capturedQuery)
	t.Logf("captured auth: %s", capturedAuth)

	if raw.Nonce != nonce.Hex() {
		t.Errorf("Nonce = %q, want %q", raw.Nonce, nonce.Hex())
	}
	if raw.GatewayNonceHex != nonce.Hex() {
		t.Errorf("GatewayNonceHex = %q, want %q", raw.GatewayNonceHex, nonce.Hex())
	}
	if raw.GatewayAppCompose != "test-compose" {
		t.Errorf("GatewayAppCompose = %q, want %q", raw.GatewayAppCompose, "test-compose")
	}
	if raw.GatewayTLSFingerprint != "sha256:fp" {
		t.Errorf("GatewayTLSFingerprint = %q, want %q", raw.GatewayTLSFingerprint, "sha256:fp")
	}

	// Verify query params.
	if !strings.Contains(capturedQuery, "model=test-model") {
		t.Errorf("query should contain model: %s", capturedQuery)
	}
	if !strings.Contains(capturedQuery, "nonce="+nonce.Hex()) {
		t.Errorf("query should contain nonce: %s", capturedQuery)
	}
	if !strings.Contains(capturedQuery, "include_tls_fingerprint=true") {
		t.Errorf("query should contain include_tls_fingerprint: %s", capturedQuery)
	}
	if !strings.Contains(capturedQuery, "signing_algo=ecdsa") {
		t.Errorf("query should contain signing_algo: %s", capturedQuery)
	}
	if capturedAuth != "Bearer my-api-key" {
		t.Errorf("Authorization = %q, want %q", capturedAuth, "Bearer my-api-key")
	}
}

func TestFetchAttestation_HTTP500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("request: %s %s", r.Method, r.URL.String())
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	a := NewAttester("key", true)
	a.client = srv.Client()
	a.client.Transport = &testTransport{target: srv.URL}

	_, err := a.FetchAttestation(context.Background(), "test-model", attestation.NewNonce())
	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention 500: %v", err)
	}
}

func TestFetchAttestation_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("request: %s %s", r.Method, r.URL.String())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{{{`))
	}))
	defer srv.Close()

	a := NewAttester("key", true)
	a.client = srv.Client()
	a.client.Transport = &testTransport{target: srv.URL}

	_, err := a.FetchAttestation(context.Background(), "test-model", attestation.NewNonce())
	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestFetchAttestation_LongErrorTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		// Write >512 bytes to trigger truncation.
		msg := strings.Repeat("x", 600)
		_, _ = w.Write([]byte(msg))
	}))
	defer srv.Close()

	a := NewAttester("key", true)
	a.client = srv.Client()
	a.client.Transport = &testTransport{target: srv.URL}

	_, err := a.FetchAttestation(context.Background(), "m", attestation.NewNonce())
	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("long error should be truncated: %v", err)
	}
}

func TestHandlePinned_WithGatewayComposeAndModelFingerprint(t *testing.T) {
	// This test covers branches in attestOnConn:
	// - raw.TLSFingerprint != "" (model has fingerprint → debug log branch)
	// - gwRaw.AppCompose != "" (gateway compose binding path — needs gatewayTDX)
	var spkiHash string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("server received: %s %s", r.Method, r.URL.String())
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			nonceHex := r.URL.Query().Get("nonce")
			w.Header().Set("Content-Type", "application/json")
			// Return with gateway app_compose and model tls_cert_fingerprint.
			_, _ = fmt.Fprintf(w, `{
				"gateway_attestation": {
					"request_nonce": %q,
					"intel_quote": "",
					"event_log": "",
					"tls_cert_fingerprint": %q,
					"info": {"tcb_info": "{\"app_compose\":\"gateway-compose-data\"}"}
				},
				"model_attestations": [{
					"model": "test-model",
					"intel_quote": "",
					"nvidia_payload": "",
					"signing_key": "04aaaa",
					"signing_address": "0xtest",
					"signing_algo": "ecdsa",
					"tls_cert_fingerprint": "modelfp123",
					"nonce": %q
				}]
			}`, nonceHex, spkiHash, nonceHex)
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

	handler := NewPinnedHandler(
		attestation.NewSPKICache(),
		"test-key",
		true,
		[]string{},
		attestation.MeasurementPolicy{},
		nil,
	)
	handler.SetDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		return tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	})
	handler.SetCTChecker(nil)

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

	if resp.Report == nil {
		t.Fatal("Report should be non-nil")
	}
	t.Logf("report: %d factors, %d pass, %d fail, %d skip",
		len(resp.Report.Factors), resp.Report.Passed, resp.Report.Failed, resp.Report.Skipped)
}

func TestHandlePinned_WithNonEmptyQuotesAndPayload(t *testing.T) {
	// Provide non-empty intel_quote and nvidia_payload to cover the verification
	// branches in attestOnConn, even though they won't parse successfully.
	var spkiHash string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("server received: %s %s", r.Method, r.URL.String())
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			nonceHex := r.URL.Query().Get("nonce")
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{
				"gateway_attestation": {
					"request_nonce": %q,
					"intel_quote": "AQAAAA==",
					"event_log": "",
					"tls_cert_fingerprint": %q,
					"info": {"tcb_info": "{\"app_compose\":\"gw-compose-hash\"}"}
				},
				"model_attestations": [{
					"model": "test-model",
					"intel_quote": "AQAAAA==",
					"nvidia_payload": "not-a-real-jwt",
					"signing_key": "04aaaa",
					"signing_address": "0xtest",
					"signing_algo": "ecdsa",
					"tls_cert_fingerprint": "modelfp",
					"nonce": %q,
					"info": {"tcb_info": "{\"app_compose\":\"model-compose\"}"}
				}]
			}`, nonceHex, spkiHash, nonceHex)
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

	handler := NewPinnedHandler(
		attestation.NewSPKICache(),
		"test-key",
		true, // offline — skips NRAS, PoC, Sigstore
		[]string{},
		attestation.MeasurementPolicy{},
		nil,
	)
	handler.SetDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		return tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	})
	handler.SetCTChecker(nil)

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
	if resp.Report == nil {
		t.Fatal("Report should be non-nil")
	}
	t.Logf("report: %d factors, %d pass, %d fail, %d skip",
		len(resp.Report.Factors), resp.Report.Passed, resp.Report.Failed, resp.Report.Skipped)

	// Verify TDX-related factors were emitted (even if failed due to invalid quotes).
	var foundTDXStructure, foundNvidiaPayload, foundGatewayTDX bool
	for _, f := range resp.Report.Factors {
		t.Logf("  factor: %s = %s", f.Name, f.Status)
		switch f.Name {
		case "tdx_quote_structure":
			foundTDXStructure = true
		case "nvidia_payload_present":
			foundNvidiaPayload = true
		case "gateway_tdx_quote_present":
			foundGatewayTDX = true
		}
	}
	if !foundTDXStructure {
		t.Error("expected tdx_quote_structure factor")
	}
	if !foundNvidiaPayload {
		t.Error("expected nvidia_payload_present factor")
	}
	if !foundGatewayTDX {
		t.Error("expected gateway_tdx_quote_present factor")
	}
}

// testTransport redirects all requests to a test server URL.
type testTransport struct {
	target string
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rewrite the URL to point to the test server.
	req.URL.Scheme = "http"
	req.URL.Host = strings.TrimPrefix(t.target, "http://")
	return http.DefaultTransport.RoundTrip(req)
}

// Suppress unused import warning for neardirect package.
var _ = neardirect.NewCTChecker
