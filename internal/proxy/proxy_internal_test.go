package proxy

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
)

func dialAndClose(addr string) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			errCh <- err
			return
		}
		errCh <- c.Close()
	}()
	return errCh
}

func waitDialResult(t *testing.T, errCh <-chan error) {
	t.Helper()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("dial helper: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dial helper timed out")
	}
}

func TestMonitoredConn_CloseIdempotent(t *testing.T) {
	base, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer base.Close()

	errCh := dialAndClose(base.Addr().String())
	_ = base.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))

	raw, err := base.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	waitDialResult(t, errCh)

	var active atomic.Int64
	active.Store(1)

	mc := &monitoredConn{Conn: raw, active: &active}

	t.Log("first Close")
	if err := mc.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if active.Load() != 0 {
		t.Errorf("active should be 0 after Close, got %d", active.Load())
	}

	t.Log("second Close (idempotent — decrements active only once)")
	_ = mc.Close()
	if active.Load() != 0 {
		t.Errorf("active should still be 0 after second Close, got %d", active.Load())
	}
}

func TestMonitoredListener_ThrottleLog(t *testing.T) {
	base, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer base.Close()

	ml := &monitoredListener{
		Listener: base,
		maxConns: 1,
	}
	// Simulate active == maxConns so each Accept evaluates the throttle check.
	ml.active.Store(1)
	now := time.Now().Unix()
	ml.lastWarn.Store(now)

	// First Accept is inside the 60-second throttle window, so lastWarn should
	// not be updated.
	errCh := dialAndClose(base.Addr().String())
	_ = base.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))

	conn, err := ml.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	waitDialResult(t, errCh)
	if got := ml.lastWarn.Load(); got != now {
		t.Errorf("lastWarn updated within throttle window: got %d, want %d", got, now)
	}
	conn.Close()
	if got := ml.active.Load(); got != 1 {
		t.Errorf("active = %d after Close, want 1", got)
	}

	// Move lastWarn outside the throttle window; next Accept should update it.
	ml.lastWarn.Store(now - 61)
	errCh2 := dialAndClose(base.Addr().String())
	_ = base.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))

	conn2, err := ml.Accept()
	if err != nil {
		t.Fatalf("second Accept: %v", err)
	}
	waitDialResult(t, errCh2)
	if got := ml.lastWarn.Load(); got < now {
		t.Errorf("lastWarn was not updated after throttle window: got %d, want >= %d", got, now)
	}
	conn2.Close()
	if got := ml.active.Load(); got != 1 {
		t.Errorf("active = %d after second Close, want 1", got)
	}
}

// --------------------------------------------------------------------------
// inapplicableForProvider
// --------------------------------------------------------------------------

func TestInapplicableForProvider(t *testing.T) {
	tests := []struct {
		provider      string
		expectFactor  string
		expectPresent bool
	}{
		{"venice", "compose_binding", false},
		{"neardirect", "compose_binding", false},
		{"nearcloud", "compose_binding", false},
		{"nanogpt", "compose_binding", false},
		{"phalacloud", "compose_binding", false},
		{"tinfoil_v3_cloud", "compose_binding", true},
		{"tinfoil_v3_direct", "event_log_integrity", true},
		{"chutes", "compose_binding", true},
		{"unknown", "compose_binding", false}, // falls through to default
	}
	for _, tc := range tests {
		t.Run(tc.provider, func(t *testing.T) {
			result := inapplicableForProvider(tc.provider)
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			_, ok := result[tc.expectFactor]
			if ok != tc.expectPresent {
				t.Errorf("inapplicableForProvider(%q)[%q] = %v, want %v",
					tc.provider, tc.expectFactor, ok, tc.expectPresent)
			}
		})
	}
}

// --------------------------------------------------------------------------
// truncTo
// --------------------------------------------------------------------------

func TestTruncTo(t *testing.T) {
	if got := truncTo("abcdef", 4); got != "abcd" {
		t.Errorf("truncTo(abcdef,4) = %q, want abcd", got)
	}
	if got := truncTo("ab", 10); got != "ab" {
		t.Errorf("truncTo(ab,10) = %q, want ab", got)
	}
	if got := truncTo("", 5); got != "" {
		t.Errorf("truncTo('',5) = %q, want ''", got)
	}
}

// --------------------------------------------------------------------------
// unwrapEHBPResponse
// --------------------------------------------------------------------------

func TestUnwrapEHBPResponse_MissingNonce(t *testing.T) {
	s := &Server{}
	resp := &http.Response{Header: http.Header{}}
	rec := httptest.NewRecorder()
	ri := &responseInterceptor{ResponseWriter: rec}

	status, ok := s.unwrapEHBPResponse(t.Context(), resp, nil, "test", "model", ri, rec)
	if ok {
		t.Error("expected ok=false for missing nonce")
	}
	if status != "ehbp_missing_nonce" {
		t.Errorf("status = %q, want ehbp_missing_nonce", status)
	}
}

func TestUnwrapEHBPResponse_BadNonceLength(t *testing.T) {
	s := &Server{}
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Ehbp-Response-Nonce", "tooshort")
	rec := httptest.NewRecorder()
	ri := &responseInterceptor{ResponseWriter: rec}

	status, ok := s.unwrapEHBPResponse(t.Context(), resp, nil, "test", "model", ri, rec)
	if ok {
		t.Error("expected ok=false for bad nonce length")
	}
	if status != "ehbp_invalid_nonce" {
		t.Errorf("status = %q, want ehbp_invalid_nonce", status)
	}
}

func TestUnwrapEHBPResponse_ValidNonce(t *testing.T) {
	s := &Server{}
	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(bytes.NewReader([]byte("body"))),
	}
	resp.Header.Set("Ehbp-Response-Nonce", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	// Create an EHBP session — DecryptResponse wraps body lazily, so it succeeds.
	key := testX25519PubKey(t)
	session, err := e2ee.NewEHBPSession(key)
	if err != nil {
		t.Fatalf("NewEHBPSession: %v", err)
	}
	defer session.Zero()

	rec := httptest.NewRecorder()
	ri := &responseInterceptor{ResponseWriter: rec}

	status, ok := s.unwrapEHBPResponse(t.Context(), resp, session, "test", "model", ri, rec)
	if !ok {
		t.Errorf("expected ok=true, got status=%q", status)
	}
	if status != "" {
		t.Errorf("status = %q, want empty", status)
	}
	// resp.Body should now be the decrypted reader wrapper.
	if resp.Body == nil {
		t.Error("resp.Body should not be nil after successful unwrap")
	}
}

func testX25519PubKey(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	return priv.PublicKey().Bytes()
}

// --------------------------------------------------------------------------
// verifyTinfoilSupplyChain — nil guard
// --------------------------------------------------------------------------

func TestVerifyTinfoilSupplyChain_NonTinfoilFormat(t *testing.T) {
	s := &Server{}
	raw := &attestation.RawAttestation{BackendFormat: attestation.FormatDstack}
	result, _ := s.verifyTinfoilSupplyChain(t.Context(), raw, nil, nil, nil, "model")
	if result != nil {
		t.Errorf("expected nil for non-Tinfoil format, got %v", result)
	}
}

// --------------------------------------------------------------------------
// prefixModelID
// --------------------------------------------------------------------------

func TestPrefixModelID(t *testing.T) {
	tests := []struct {
		provName string
		model    json.RawMessage
		wantID   string
	}{
		{"venice", json.RawMessage(`{"id":"qwen3-32b","object":"model"}`), "venice:qwen3-32b"},
		{"tinfoil_v3_cloud", json.RawMessage(`{"id":"llama3-3-70b"}`), "tinfoil_v3_cloud:llama3-3-70b"},
	}
	for _, tc := range tests {
		result, err := prefixModelID(tc.provName, tc.model)
		if err != nil {
			t.Errorf("prefixModelID(%q, %s): %v", tc.provName, tc.model, err)
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(result, &obj); err != nil {
			t.Errorf("unmarshal result: %v", err)
			continue
		}
		var got string
		if err := json.Unmarshal(obj["id"], &got); err != nil {
			t.Errorf("unmarshal id: %v", err)
			continue
		}
		if got != tc.wantID {
			t.Errorf("prefixModelID(%q, %s) id = %q, want %q", tc.provName, tc.model, got, tc.wantID)
		}
	}
}

func TestPrefixModelID_MissingID(t *testing.T) {
	_, err := prefixModelID("test", json.RawMessage(`{"object":"model"}`))
	if err == nil {
		t.Error("expected error for missing id field")
	}
}

func TestPrefixModelID_InvalidJSON(t *testing.T) {
	_, err := prefixModelID("test", json.RawMessage(`not json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
