package nearcloud

import (
	"bytes"
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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
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
				"model_name": "test-model",
				"intel_quote": "",
				"nvidia_payload": "",
				"signing_public_key": "04aaaa",
				"signing_address": "0xtest",
				"signing_algo": "ecdsa",
				"tls_cert_fingerprint": %q,
				"request_nonce": %q
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
		attestation.KnownFactors,
		attestation.MeasurementPolicy{},
		attestation.MeasurementPolicy{},
		nil /* no model RD verifier */, nil, /* no RekorClient */

	)
	handler.setDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
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
		attestation.MeasurementPolicy{},
		nil, nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
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
			// Return empty tls_cert_fingerprint for gateway but a non-empty
			// intel_quote so GW-M-01 zero-value check passes.
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{
				"gateway_attestation": {
					"request_nonce": %q,
					"intel_quote": "deadbeef",
					"event_log": "",
					"tls_cert_fingerprint": "",
					"info": {"tcb_info": "{}"}
				},
				"model_attestations": [
					{"model_name": "test-model", "request_nonce": %q, "signing_public_key": "04aaaa", "signing_address": "0x1", "signing_algo": "ecdsa", "tls_cert_fingerprint": "somefp"}
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
		attestation.MeasurementPolicy{},
		nil, nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
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
		attestation.MeasurementPolicy{},
		nil, nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
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
		[]string{}, // empty allow_fail → all factors enforced, including nonce_match
		attestation.MeasurementPolicy{},
		attestation.MeasurementPolicy{},
		nil, nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
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
		attestation.KnownFactors,
		attestation.MeasurementPolicy{},
		attestation.MeasurementPolicy{},
		nil, nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
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
	if !strings.Contains(capturedQuery, "signing_algo=ed25519") {
		t.Errorf("query should contain signing_algo=ed25519: %s", capturedQuery)
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
	allowFail := []string{"nonce_match", "tdx_debug_disabled"}

	h := NewPinnedHandler(spkiCache, "test-key", true, allowFail, attestation.MeasurementPolicy{}, attestation.MeasurementPolicy{}, nil, nil)

	if h.apiKey != "test-key" {
		t.Errorf("apiKey = %q, want %q", h.apiKey, "test-key")
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
	t.Logf("handler created: apiKey=%q, offline=%v, allowFail=%v", h.apiKey, h.offline, h.allowFail)
}

func TestSetDialer(t *testing.T) {
	h := &PinnedHandler{}
	if h.dialFn != nil {
		t.Fatal("dialFn should be nil by default")
	}

	called := false
	h.setDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
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
		attestation.MeasurementPolicy{},
		nil, nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
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
		attestation.MeasurementPolicy{},
		nil, nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
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
		attestation.MeasurementPolicy{},
		nil, nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
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
				"model_name": "test-model",
				"intel_quote": "",
				"nvidia_payload": "",
				"signing_public_key": "04aaaa",
				"signing_address": "0xtest",
				"signing_algo": "ecdsa",
				"tls_cert_fingerprint": %q,
				"request_nonce": %q
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
		attestation.KnownFactors,
		attestation.MeasurementPolicy{},
		attestation.MeasurementPolicy{},
		nil, nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
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
	if !strings.Contains(capturedQuery, "signing_algo=ed25519") {
		t.Errorf("query should contain signing_algo=ed25519: %s", capturedQuery)
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
	errMsg := err.Error()
	full600 := strings.Repeat("x", 600)
	if strings.Contains(errMsg, full600) {
		t.Errorf("error should be truncated, but contains all 600 bytes")
	}
	if !strings.Contains(errMsg, "...") {
		t.Errorf("truncated error should end with ...: %v", err)
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
					"model_name": "test-model",
					"intel_quote": "",
					"nvidia_payload": "",
					"signing_public_key": "04aaaa",
					"signing_address": "0xtest",
					"signing_algo": "ecdsa",
					"tls_cert_fingerprint": "modelfp123",
					"request_nonce": %q
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
		attestation.KnownFactors,
		attestation.MeasurementPolicy{},
		attestation.MeasurementPolicy{},
		nil, nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
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
					"model_name": "test-model",
					"intel_quote": "AQAAAA==",
					"nvidia_payload": "not-a-real-jwt",
					"signing_public_key": "04aaaa",
					"signing_address": "0xtest",
					"signing_algo": "ecdsa",
					"tls_cert_fingerprint": "modelfp",
					"request_nonce": %q,
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
		attestation.KnownFactors,
		attestation.MeasurementPolicy{},
		attestation.MeasurementPolicy{},
		nil, nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
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

func TestExtractComposeDigests(t *testing.T) {
	t.Run("with_docker_compose", func(t *testing.T) {
		// app_compose wrapping a docker_compose_file with image references.
		appCompose := `{"docker_compose_file":"services:\n  web:\n    image: ghcr.io/example/web@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\n  api:\n    image: ghcr.io/example/api@sha256:1111111111111111111111111111111111111111111111111111111111111111\n"}`

		cd := attestation.ExtractComposeDigests(appCompose)
		t.Logf("repos: %v", cd.Repos)
		t.Logf("digests: %v", cd.Digests)
		t.Logf("digestToRepo: %v", cd.DigestToRepo)

		if len(cd.Repos) == 0 {
			t.Error("expected non-empty repos")
		}
		if len(cd.Digests) == 0 {
			t.Error("expected non-empty digests")
		}
		if len(cd.DigestToRepo) == 0 {
			t.Error("expected non-empty digestToRepo")
		}
	})

	t.Run("plain_compose", func(t *testing.T) {
		// app_compose that is itself a compose file (no docker_compose_file wrapper).
		appCompose := "services:\n  web:\n    image: ghcr.io/example/web@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\n"

		cd := attestation.ExtractComposeDigests(appCompose)
		t.Logf("repos: %v", cd.Repos)
		t.Logf("digests: %v", cd.Digests)

		if len(cd.Repos) == 0 {
			t.Error("expected non-empty repos")
		}
		if len(cd.Digests) == 0 {
			t.Error("expected non-empty digests")
		}
	})

	t.Run("empty", func(t *testing.T) {
		cd := attestation.ExtractComposeDigests("")
		t.Logf("repos: %v, digests: %v", cd.Repos, cd.Digests)
		if len(cd.Repos) != 0 || len(cd.Digests) != 0 {
			t.Error("expected empty results for empty input")
		}
	})
}

func TestMergeComposeDigests(t *testing.T) {
	t.Run("no_overlap", func(t *testing.T) {
		model := attestation.ComposeDigests{
			Repos:        []string{"ghcr.io/a/web"},
			DigestToRepo: map[string]string{"aaa": "ghcr.io/a/web"},
			Digests:      []string{"aaa"},
		}
		gateway := attestation.ComposeDigests{
			Repos:        []string{"ghcr.io/b/gw"},
			DigestToRepo: map[string]string{"bbb": "ghcr.io/b/gw"},
			Digests:      []string{"bbb"},
		}

		allDigests, dtr := attestation.MergeComposeDigests(model, gateway)
		t.Logf("allDigests: %v", allDigests)
		t.Logf("digestToRepo: %v", dtr)

		if len(allDigests) != 2 {
			t.Errorf("allDigests len = %d, want 2", len(allDigests))
		}
		if len(dtr) != 2 {
			t.Errorf("digestToRepo len = %d, want 2", len(dtr))
		}
	})

	t.Run("duplicate_digests_deduped", func(t *testing.T) {
		model := attestation.ComposeDigests{
			Repos:        []string{"ghcr.io/a/web"},
			DigestToRepo: map[string]string{"same": "ghcr.io/a/web"},
			Digests:      []string{"same"},
		}
		gateway := attestation.ComposeDigests{
			Repos:        []string{"ghcr.io/a/web"},
			DigestToRepo: map[string]string{"same": "ghcr.io/a/web"},
			Digests:      []string{"same"},
		}

		allDigests, dtr := attestation.MergeComposeDigests(model, gateway)
		t.Logf("allDigests: %v", allDigests)

		if len(allDigests) != 1 {
			t.Errorf("allDigests len = %d, want 1 (deduplicated)", len(allDigests))
		}
		if len(dtr) != 1 {
			t.Errorf("digestToRepo len = %d, want 1", len(dtr))
		}
	})

	t.Run("conflict_first_writer_wins", func(t *testing.T) {
		model := attestation.ComposeDigests{
			DigestToRepo: map[string]string{"conflict_digest": "ghcr.io/model/img"},
			Digests:      []string{"conflict_digest"},
		}
		gateway := attestation.ComposeDigests{
			DigestToRepo: map[string]string{"conflict_digest": "ghcr.io/gateway/img"},
			Digests:      []string{"conflict_digest"},
		}

		allDigests, dtr := attestation.MergeComposeDigests(model, gateway)
		t.Logf("allDigests: %v", allDigests)
		t.Logf("digestToRepo: %v", dtr)

		// Model was first, so model's repo wins.
		if dtr["conflict_digest"] != "ghcr.io/model/img" {
			t.Errorf("digestToRepo[conflict_digest] = %q, want %q (first-writer-wins)",
				dtr["conflict_digest"], "ghcr.io/model/img")
		}
		if len(allDigests) != 1 {
			t.Errorf("allDigests len = %d, want 1", len(allDigests))
		}
	})

	t.Run("empty_inputs", func(t *testing.T) {
		allDigests, dtr := attestation.MergeComposeDigests(attestation.ComposeDigests{}, attestation.ComposeDigests{})
		t.Logf("allDigests: %v, digestToRepo: %v", allDigests, dtr)

		if len(allDigests) != 0 {
			t.Error("expected empty allDigests")
		}
		if len(dtr) != 0 {
			t.Error("expected empty digestToRepo")
		}
	})
}

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
	// Generate a valid Ed25519 key pair (64 hex chars = 32 bytes public key).
	h := &PinnedHandler{}

	// A valid 64-hex-char Ed25519 public key (from test fixtures).
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

func TestHandlePinned_GatewayBlockedModelPasses(t *testing.T) {
	// Gateway attestation returns mismatched nonce (blocked), model would pass.
	// Request must be blocked because gateway factor fails — fail-closed.
	var spkiHash string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			nonceHex := r.URL.Query().Get("nonce")
			w.Header().Set("Content-Type", "application/json")
			// Gateway returns wrong nonce, model returns correct nonce.
			// Non-empty intel_quote triggers gateway TDX evaluator inclusion.
			_, _ = fmt.Fprintf(w, `{
				"gateway_attestation": {
					"request_nonce": "0000000000000000000000000000000000000000000000000000000000000000",
					"intel_quote": "AQAAAA==",
					"event_log": "",
					"tls_cert_fingerprint": %q,
					"info": {"tcb_info": "{\"app_compose\":\"gw-compose\"}"}
				},
				"model_attestations": [{
					"model_name": "test-model",
					"intel_quote": "",
					"nvidia_payload": "",
					"signing_public_key": "04aaaa",
					"signing_address": "0xtest",
					"signing_algo": "ecdsa",
					"tls_cert_fingerprint": %q,
					"request_nonce": %q
				}]
			}`, spkiHash, spkiHash, nonceHex)
			return
		}
		http.Error(w, "chat should not be reached", http.StatusInternalServerError)
	}))
	defer srv.Close()

	spkiHash = computeTestServerSPKI(t, srv)
	spkiCache := attestation.NewSPKICache()

	handler := NewPinnedHandler(
		spkiCache, "test-key", true,
		[]string{}, // empty allow_fail → all factors enforced, including gateway_nonce_match
		attestation.MeasurementPolicy{},
		attestation.MeasurementPolicy{},
		nil, nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
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

	if resp.Report == nil {
		t.Fatal("Report should be non-nil")
	}
	if !resp.Report.Blocked() {
		t.Fatal("Report should be blocked when gateway nonce mismatches")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if spkiCache.Contains(gatewayHost, spkiHash) {
		t.Error("SPKI cache should remain empty when gateway is blocked")
	}
}

func TestHandlePinned_GatewayPassesModelBlocked(t *testing.T) {
	// Gateway attestation passes, model returns wrong nonce (blocked).
	// Request must be blocked — both must pass.
	var spkiHash string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			nonceHex := r.URL.Query().Get("nonce")
			w.Header().Set("Content-Type", "application/json")
			// Gateway returns correct nonce, model returns wrong nonce.
			_, _ = fmt.Fprintf(w, `{
				"gateway_attestation": {
					"request_nonce": %q,
					"intel_quote": "",
					"event_log": "",
					"tls_cert_fingerprint": %q,
					"info": {"tcb_info": "{\"app_compose\":\"gw-compose\"}"}
				},
				"model_attestations": [{
					"model_name": "test-model",
					"intel_quote": "",
					"nvidia_payload": "",
					"signing_public_key": "04aaaa",
					"signing_address": "0xtest",
					"signing_algo": "ecdsa",
					"tls_cert_fingerprint": %q,
					"request_nonce": "0000000000000000000000000000000000000000000000000000000000000000"
				}]
			}`, nonceHex, spkiHash, spkiHash)
			return
		}
		http.Error(w, "chat should not be reached", http.StatusInternalServerError)
	}))
	defer srv.Close()

	spkiHash = computeTestServerSPKI(t, srv)
	spkiCache := attestation.NewSPKICache()

	handler := NewPinnedHandler(
		spkiCache, "test-key", true,
		[]string{}, // empty allow_fail → all factors enforced, including nonce_match
		attestation.MeasurementPolicy{},
		attestation.MeasurementPolicy{},
		nil, nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
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

	if resp.Report == nil {
		t.Fatal("Report should be non-nil")
	}
	if !resp.Report.Blocked() {
		t.Fatal("Report should be blocked when model nonce mismatches")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if spkiCache.Contains(gatewayHost, spkiHash) {
		t.Error("SPKI cache should remain empty when model is blocked")
	}
}

func TestHandlePinned_SigningKeyCachedOnSuccess(t *testing.T) {
	// First request: SPKI miss → attestation → caches SPKI + returns signing key.
	// Second request: SPKI hit → no attestation → signing key from PinnedRequest.
	var spkiHash string
	var attestCalls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/attestation/report") {
			attestCalls.Add(1)
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
	spkiCache := attestation.NewSPKICache()

	handler := NewPinnedHandler(
		spkiCache, "test-key", true,
		attestation.KnownFactors,
		attestation.MeasurementPolicy{},
		attestation.MeasurementPolicy{},
		nil, nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		return tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	})
	handler.SetCTChecker(nil)

	// First request — triggers attestation, should return signing key.
	resp1, err := handler.HandlePinned(context.Background(), &provider.PinnedRequest{
		Method:  "POST",
		Path:    "/v1/chat/completions",
		Headers: http.Header{"Content-Type": {"application/json"}},
		Body:    []byte(`{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`),
		Model:   "test-model",
	})
	if err != nil {
		t.Fatalf("first HandlePinned: %v", err)
	}
	resp1.Body.Close()

	if resp1.Report == nil {
		t.Fatal("first request: Report should be non-nil (cache miss)")
	}
	firstKey := resp1.SigningKey
	t.Logf("first signing key: %q", firstKey)
	if firstKey == "" {
		t.Error("first request should return a signing key")
	}

	if !spkiCache.Contains(gatewayHost, spkiHash) {
		t.Fatal("SPKI should be cached after first request")
	}
	if attestCalls.Load() != 1 {
		t.Errorf("attestation calls = %d, want 1", attestCalls.Load())
	}

	// Second request — SPKI cache hit, no attestation.
	resp2, err := handler.HandlePinned(context.Background(), &provider.PinnedRequest{
		Method:     "POST",
		Path:       "/v1/chat/completions",
		Headers:    http.Header{"Content-Type": {"application/json"}},
		Body:       []byte(`{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`),
		Model:      "test-model",
		SigningKey: firstKey,
	})
	if err != nil {
		t.Fatalf("second HandlePinned: %v", err)
	}
	resp2.Body.Close()

	if resp2.Report != nil {
		t.Error("second request: Report should be nil (cache hit)")
	}
	if attestCalls.Load() != 1 {
		t.Errorf("attestation calls after second = %d, want still 1", attestCalls.Load())
	}
}

func TestHandlePinned_ConcurrentRequests_SingleflightDedup(t *testing.T) {
	// Multiple concurrent requests on SPKI cache miss should trigger only one
	// attestation via singleflight.
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
	spkiCache := attestation.NewSPKICache()

	handler := NewPinnedHandler(
		spkiCache, "test-key", true,
		attestation.KnownFactors,
		attestation.MeasurementPolicy{},
		attestation.MeasurementPolicy{},
		nil, nil,
	)
	handler.setDialer(func(_ context.Context, _ string) (*tls.Conn, error) {
		return tls.Dial("tcp", hostFromURL(t, srv.URL), testTLSConfig(srv))
	})
	handler.SetCTChecker(nil)

	const N = 5
	// Barrier ensures all goroutines enter HandlePinned concurrently.
	var ready sync.WaitGroup
	ready.Add(N)
	errs := make(chan error, N)
	for range N {
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

	for range N {
		if err := <-errs; err != nil {
			t.Errorf("concurrent request error: %v", err)
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
	if !spkiCache.Contains(gatewayHost, spkiHash) {
		t.Error("SPKI should be cached after concurrent requests")
	}
}

// Suppress unused import warning for neardirect package.
var _ = neardirect.NewCTChecker
