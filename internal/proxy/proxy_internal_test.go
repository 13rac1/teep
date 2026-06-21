package proxy

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
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

// --------------------------------------------------------------------------
// extractMultipartField — new branches not covered by relay_internal_test.go
// --------------------------------------------------------------------------

func buildMultipart(t *testing.T, fields map[string]string) (contentType string, body []byte) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("WriteField %q: %v", k, err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return mw.FormDataContentType(), buf.Bytes()
}

func TestExtractMultipartField_OversizedField(t *testing.T) {
	ct, body := buildMultipart(t, map[string]string{"model": strings.Repeat("x", 1025)})
	_, err := extractMultipartField(ct, body, "model")
	if err == nil {
		t.Fatal("expected error for oversized field")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error should mention exceeds: %v", err)
	}
}

// --------------------------------------------------------------------------
// rewriteMultipartModel
// --------------------------------------------------------------------------

func TestRewriteMultipartModel_Success(t *testing.T) {
	ct, body := buildMultipart(t, map[string]string{"model": "old-model", "file": "data"})
	result, err := rewriteMultipartModel(ct, body, "new-model")
	if err != nil {
		t.Fatalf("rewriteMultipartModel: %v", err)
	}
	// Read back the model field from the result.
	got, err := extractMultipartField(ct, result, "model")
	if err != nil {
		t.Fatalf("extract from rewritten: %v", err)
	}
	if got != "new-model" {
		t.Errorf("model = %q, want new-model", got)
	}
	// The file field should still be present.
	gotFile, err := extractMultipartField(ct, result, "file")
	if err != nil {
		t.Fatalf("extract file from rewritten: %v", err)
	}
	if gotFile != "data" {
		t.Errorf("file = %q, want data", gotFile)
	}
}

func TestRewriteMultipartModel_InvalidContentType(t *testing.T) {
	_, err := rewriteMultipartModel("application/json", []byte("{}"), "model")
	if err == nil {
		t.Fatal("expected error for non-multipart content type")
	}
}

func TestRewriteMultipartModel_MissingBoundary(t *testing.T) {
	_, err := rewriteMultipartModel("multipart/form-data", []byte("data"), "model")
	if err == nil {
		t.Fatal("expected error for missing boundary")
	}
}

// --------------------------------------------------------------------------
// rewriteModelInBody
// --------------------------------------------------------------------------

func TestRewriteModelInBody_JSON(t *testing.T) {
	body := []byte(`{"model":"old","messages":[]}`)
	result, err := rewriteModelInBody("application/json", body, "application/json", "new-model")
	if err != nil {
		t.Fatalf("rewriteModelInBody: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(result, &m); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	var got string
	if err := json.Unmarshal(m["model"], &got); err != nil {
		t.Fatalf("unmarshal model: %v", err)
	}
	if got != "new-model" {
		t.Errorf("model = %q, want new-model", got)
	}
}

func TestRewriteModelInBody_InvalidJSON(t *testing.T) {
	_, err := rewriteModelInBody("application/json", []byte("not json"), "application/json", "model")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestRewriteModelInBody_Multipart(t *testing.T) {
	ct, body := buildMultipart(t, map[string]string{"model": "old", "file": "data"})
	result, err := rewriteModelInBody(ct, body, ct, "new-model")
	if err != nil {
		t.Fatalf("rewriteModelInBody multipart: %v", err)
	}
	got, err := extractMultipartField(ct, result, "model")
	if err != nil {
		t.Fatalf("extract model: %v", err)
	}
	if got != "new-model" {
		t.Errorf("model = %q, want new-model", got)
	}
}

// --------------------------------------------------------------------------
// fetchAndVerify — nil Attester
// --------------------------------------------------------------------------

func TestFetchAndVerify_NilAttester(t *testing.T) {
	s := newTestServer(t)
	s.signingKeyCache = attestation.NewSigningKeyCache(0)

	prov := &provider.Provider{Name: "test"}
	report, raw := s.fetchAndVerify(t.Context(), prov, "model")
	if report != nil {
		t.Errorf("expected nil report, got %v", report)
	}
	if raw != nil {
		t.Errorf("expected nil raw, got %v", raw)
	}
}

// --------------------------------------------------------------------------
// pinnedPreDispatchE2EE
// --------------------------------------------------------------------------

func TestPinnedPreDispatchE2EE_BindingFailed(t *testing.T) {
	s := &Server{
		cfg:      &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:    attestation.NewCache(time.Minute),
		negCache: attestation.NewNegativeCache(0),
		stats:    stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}
	s.spkiCache = attestation.NewSPKICache()

	// Cache a report where binding is not passed.
	report := &attestation.VerificationReport{
		Provider: "test",
		Model:    "model",
		Factors: []attestation.FactorResult{
			{Name: "tee_reportdata_binding", Status: attestation.Fail, Detail: "binding failed"},
		},
	}
	s.cache.Put("test", "model", report)

	prov := &provider.Provider{Name: "test", E2EE: true}
	rec := httptest.NewRecorder()
	ok := s.pinnedPreDispatchE2EE(t.Context(), rec, prov, "model")
	if ok {
		t.Error("expected false for failed binding")
	}
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

func TestPinnedPostDispatchE2EE_StaleReportRefusesWhenPriorFailure(t *testing.T) {
	s := newTestServer(t)
	s.signingKeyCache = attestation.NewSigningKeyCache(time.Minute)

	// Simulate prior E2EE failure.
	s.e2eeFailed.Store(providerModelKey{"test", "model"}, true)

	report := &attestation.VerificationReport{
		Factors: []attestation.FactorResult{
			{Name: "tee_reportdata_binding", Status: attestation.Pass},
		},
	}
	// Put in cache so cache invalidation is exercised.
	s.cache.Put("test", "model", report)

	prov := &provider.Provider{Name: "test", E2EE: true}
	rec := httptest.NewRecorder()
	// freshReport=false → prior failure not clearable.
	ok := s.pinnedPostDispatchE2EE(t.Context(), rec, prov, "model", report, false)
	if ok {
		t.Error("expected false when prior failure exists and report is stale")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

// --------------------------------------------------------------------------
// handlePinnedChat — error path (PinnedHandler returns error)
// --------------------------------------------------------------------------

type errorPinnedHandler struct {
	err error
}

func (h *errorPinnedHandler) HandlePinned(_ context.Context, _ *provider.PinnedRequest) (*provider.PinnedResponse, error) {
	return nil, h.err
}

func TestHandlePinnedChat_PinnedHandlerError(t *testing.T) {
	s := newTestServer(t)
	s.signingKeyCache = attestation.NewSigningKeyCache(0)
	s.spkiCache = attestation.NewSPKICache()

	prov := &provider.Provider{
		Name:          "test",
		E2EE:          false,
		PinnedHandler: &errorPinnedHandler{err: errors.New("connection refused")},
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")

	s.handlePinnedChat(t.Context(), rec, r, prov, "model", []byte(`{}`), true, "/v1/chat/completions", e2ee.EndpointChat, "application/json")

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "pinned connection failed") {
		t.Errorf("body = %q, should mention pinned connection failed", rec.Body.String())
	}
}

// --------------------------------------------------------------------------
// handlePinnedChat — non-OK status forwarding
// --------------------------------------------------------------------------

type staticPinnedHandler struct {
	resp *provider.PinnedResponse
}

func (h *staticPinnedHandler) HandlePinned(_ context.Context, _ *provider.PinnedRequest) (*provider.PinnedResponse, error) {
	return h.resp, nil
}

func TestHandlePinnedChat_NonOKStatus(t *testing.T) {
	s := &Server{
		cfg:      &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:    attestation.NewCache(time.Minute),
		negCache: attestation.NewNegativeCache(time.Minute),
		stats:    stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}
	s.signingKeyCache = attestation.NewSigningKeyCache(time.Minute)
	s.spkiCache = attestation.NewSPKICache()

	passingReport := &attestation.VerificationReport{
		Provider: "test",
		Model:    "model",
		Factors: []attestation.FactorResult{
			{Name: "tee_reportdata_binding", Status: attestation.Pass},
		},
	}
	s.cache.Put("test", "model", passingReport)

	prov := &provider.Provider{
		Name: "test",
		E2EE: false,
		PinnedHandler: &staticPinnedHandler{
			resp: &provider.PinnedResponse{
				StatusCode: http.StatusBadRequest,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"error":"bad request"}`)),
				Report:     passingReport,
			},
		},
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))

	s.handlePinnedChat(t.Context(), rec, r, prov, "model", []byte(`{}`), false, "/v1/chat/completions", e2ee.EndpointChat, "application/json")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "bad request") {
		t.Errorf("body = %q, should contain upstream error", rec.Body.String())
	}
}

// --------------------------------------------------------------------------
// handlePinnedChat — OK plaintext response relayed
// --------------------------------------------------------------------------

func TestHandlePinnedChat_PlaintextStreamRelay(t *testing.T) {
	s := &Server{
		cfg:      &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:    attestation.NewCache(time.Minute),
		negCache: attestation.NewNegativeCache(time.Minute),
		stats:    stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}
	s.signingKeyCache = attestation.NewSigningKeyCache(time.Minute)
	s.spkiCache = attestation.NewSPKICache()

	passingReport := &attestation.VerificationReport{
		Provider: "test",
		Model:    "model",
		Factors: []attestation.FactorResult{
			{Name: "tee_reportdata_binding", Status: attestation.Pass},
		},
	}
	s.cache.Put("test", "model", passingReport)

	sseBody := fmt.Sprintf("data: %s\n\ndata: [DONE]\n\n",
		`{"choices":[{"delta":{"content":"hello"}}]}`)

	prov := &provider.Provider{
		Name: "test",
		E2EE: false,
		PinnedHandler: &staticPinnedHandler{
			resp: &provider.PinnedResponse{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader(sseBody)),
				Report:     passingReport,
			},
		},
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))

	s.handlePinnedChat(t.Context(), rec, r, prov, "model", []byte(`{}`), true, "/v1/chat/completions", e2ee.EndpointChat, "application/json")

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "hello") {
		t.Errorf("body = %q, should contain relayed content", rec.Body.String())
	}
}

// --------------------------------------------------------------------------
// handlePinnedNonChat — error path
// --------------------------------------------------------------------------

func TestHandlePinnedNonChat_PinnedHandlerError(t *testing.T) {
	s := newTestServer(t)
	s.signingKeyCache = attestation.NewSigningKeyCache(0)
	s.spkiCache = attestation.NewSPKICache()

	prov := &provider.Provider{
		Name:          "test",
		E2EE:          false,
		PinnedHandler: &errorPinnedHandler{err: errors.New("upstream down")},
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/embeddings", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")

	s.handlePinnedNonChat(t.Context(), rec, r, prov, "model", []byte(`{}`), "/v1/embeddings", e2ee.EndpointEmbeddings)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

// --------------------------------------------------------------------------
// handlePinnedNonChat — non-OK status forwarding
// --------------------------------------------------------------------------

func TestHandlePinnedNonChat_NonOKStatus(t *testing.T) {
	s := &Server{
		cfg:      &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:    attestation.NewCache(time.Minute),
		negCache: attestation.NewNegativeCache(time.Minute),
		stats:    stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}
	s.signingKeyCache = attestation.NewSigningKeyCache(time.Minute)
	s.spkiCache = attestation.NewSPKICache()

	passingReport := &attestation.VerificationReport{
		Factors: []attestation.FactorResult{
			{Name: "tee_reportdata_binding", Status: attestation.Pass},
		},
	}
	s.cache.Put("test", "model", passingReport)

	prov := &provider.Provider{
		Name: "test",
		E2EE: false,
		PinnedHandler: &staticPinnedHandler{
			resp: &provider.PinnedResponse{
				StatusCode: http.StatusNotFound,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("not found")),
				Report:     passingReport,
			},
		},
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/embeddings", strings.NewReader(`{}`))

	s.handlePinnedNonChat(t.Context(), rec, r, prov, "model", []byte(`{}`), "/v1/embeddings", e2ee.EndpointEmbeddings)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not found") {
		t.Errorf("body = %q, should contain upstream error", rec.Body.String())
	}
}

// --------------------------------------------------------------------------
// handlePinnedNonChat — OK plaintext response
// --------------------------------------------------------------------------

func TestHandlePinnedNonChat_PlaintextRelay(t *testing.T) {
	s := &Server{
		cfg:      &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:    attestation.NewCache(time.Minute),
		negCache: attestation.NewNegativeCache(time.Minute),
		stats:    stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}
	s.signingKeyCache = attestation.NewSigningKeyCache(time.Minute)
	s.spkiCache = attestation.NewSPKICache()

	passingReport := &attestation.VerificationReport{
		Factors: []attestation.FactorResult{
			{Name: "tee_reportdata_binding", Status: attestation.Pass},
		},
	}
	s.cache.Put("test", "model", passingReport)

	respBody := `{"data":[{"embedding":[0.1,0.2]}]}`
	prov := &provider.Provider{
		Name: "test",
		E2EE: false,
		PinnedHandler: &staticPinnedHandler{
			resp: &provider.PinnedResponse{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(respBody)),
				Report:     passingReport,
			},
		},
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/embeddings", strings.NewReader(`{}`))

	s.handlePinnedNonChat(t.Context(), rec, r, prov, "model", []byte(`{}`), "/v1/embeddings", e2ee.EndpointEmbeddings)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "embedding") {
		t.Errorf("body = %q, should contain embedding data", rec.Body.String())
	}
}

// --------------------------------------------------------------------------
// parseAudioModelRequest
// --------------------------------------------------------------------------

func TestParseAudioModelRequest_Success(t *testing.T) {
	ct, body := buildMultipart(t, map[string]string{"model": "whisper-1", "file": "audio"})
	r := httptest.NewRequest(http.MethodPost, "/v1/audio/transcriptions", bytes.NewReader(body))
	r.Header.Set("Content-Type", ct)

	model, stream, err := parseAudioModelRequest(r, body)
	if err != nil {
		t.Fatalf("parseAudioModelRequest: %v", err)
	}
	if model != "whisper-1" {
		t.Errorf("model = %q, want whisper-1", model)
	}
	if stream {
		t.Error("stream should be false for audio")
	}
}

func TestParseAudioModelRequest_EmptyModel(t *testing.T) {
	ct, body := buildMultipart(t, map[string]string{"model": "", "file": "audio"})
	r := httptest.NewRequest(http.MethodPost, "/v1/audio/transcriptions", bytes.NewReader(body))
	r.Header.Set("Content-Type", ct)

	_, _, err := parseAudioModelRequest(r, body)
	if err == nil {
		t.Fatal("expected error for empty model")
	}
}

// --------------------------------------------------------------------------
// normalizationStatusCode
// --------------------------------------------------------------------------

func TestNormalizationStatusCode_Regular(t *testing.T) {
	code := normalizationStatusCode(errors.New("regular error"))
	if code != http.StatusInternalServerError {
		t.Errorf("normalizationStatusCode(regular) = %d, want 500", code)
	}
}

func TestNormalizationStatusCode_RequestError(t *testing.T) {
	code := normalizationStatusCode(newRequestNormalizationError(errors.New("bad request")))
	if code != http.StatusBadRequest {
		t.Errorf("normalizationStatusCode(request) = %d, want 400", code)
	}
}

// --------------------------------------------------------------------------
// recordTokPerSec
// --------------------------------------------------------------------------

func TestRecordTokPerSec_Positive(t *testing.T) {
	ms := &modelStats{}
	ss := e2ee.StreamStats{Duration: 2 * time.Second, Chunks: 10}
	recordTokPerSec(ms, ss)
	if ms.lastTokDurMs.Load() != 2000 {
		t.Errorf("lastTokDurMs = %d, want 2000", ms.lastTokDurMs.Load())
	}
}

func TestRecordTokPerSec_ZeroDuration(t *testing.T) {
	ms := &modelStats{}
	ss := e2ee.StreamStats{Duration: 0, Chunks: 10}
	recordTokPerSec(ms, ss)
	if ms.lastTokDurMs.Load() != 0 {
		t.Errorf("lastTokDurMs should be 0 for zero duration, got %d", ms.lastTokDurMs.Load())
	}
}

// --------------------------------------------------------------------------
// handlePinnedPostRelay — E2EE decryption failure with cached report
// --------------------------------------------------------------------------

func TestHandlePinnedPostRelay_DecryptionFailure_DemotesCachedReport(t *testing.T) {
	s := &Server{
		cfg:             &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:           attestation.NewCache(time.Minute),
		negCache:        attestation.NewNegativeCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(time.Minute),
		stats:           stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}

	report := &attestation.VerificationReport{
		Provider: "test",
		Model:    "model",
		Factors: []attestation.FactorResult{
			{Name: "e2ee_usable", Status: attestation.Pass, Detail: "ok"},
		},
	}
	s.cache.Put("test", "model", report)
	s.signingKeyCache.Put("test", "model", "some-key")

	prov := &provider.Provider{Name: "test", E2EE: true}
	ms := &modelStats{}
	session := &noopDecryptor{}

	relayErr := fmt.Errorf("%w: bad ciphertext", e2ee.ErrDecryptionFailed)
	s.handlePinnedPostRelay(t.Context(), prov, "model", report, session, ms, relayErr)

	// e2eeFailed should be set.
	if _, failed := s.e2eeFailed.Load(providerModelKey{"test", "model"}); !failed {
		t.Error("expected e2eeFailed to be set")
	}
	// Attestation cache should be cleared after demoting.
	if _, ok := s.cache.Get("test", "model"); ok {
		t.Error("expected attestation cache to be deleted")
	}
	// Signing key cache should be cleared.
	if _, ok := s.signingKeyCache.Get("test", "model"); ok {
		t.Error("expected signing key cache to be deleted")
	}
	if ms.errors.Load() != 1 {
		t.Errorf("ms.errors = %d, want 1", ms.errors.Load())
	}
}

// --------------------------------------------------------------------------
// handlePinnedPostRelay — success promotes e2ee_usable
// --------------------------------------------------------------------------

func TestHandlePinnedPostRelay_SuccessPromotesE2EE(t *testing.T) {
	s := &Server{
		cfg:             &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:           attestation.NewCache(time.Minute),
		negCache:        attestation.NewNegativeCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(time.Minute),
		stats:           stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}

	report := &attestation.VerificationReport{
		Provider: "test",
		Model:    "model",
		Factors: []attestation.FactorResult{
			{Name: "e2ee_usable", Status: attestation.Skip, Detail: "pending"},
		},
	}
	s.cache.Put("test", "model", report)

	prov := &provider.Provider{Name: "test", E2EE: true}
	ms := &modelStats{}
	session := &noopDecryptor{}

	s.handlePinnedPostRelay(t.Context(), prov, "model", report, session, ms, nil)

	// e2ee_usable should be promoted to Pass in cache.
	cached, ok := s.cache.Get("test", "model")
	if !ok {
		t.Fatal("expected cached report")
	}
	for _, f := range cached.Factors {
		if f.Name == "e2ee_usable" {
			if f.Status != attestation.Pass {
				t.Errorf("e2ee_usable status = %v, want Pass", f.Status)
			}
			return
		}
	}
	t.Error("e2ee_usable factor not found in cached report")
}

// --------------------------------------------------------------------------
// enforceReport — blocked writes JSON body
// --------------------------------------------------------------------------

func TestEnforceReport_BlockedWritesJSONBody(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	report := &attestation.VerificationReport{
		Provider: "test",
		Model:    "model",
		Factors: []attestation.FactorResult{
			{Name: "nonce_match", Status: attestation.Fail, Enforced: true, Detail: "nonce did not match"},
		},
	}
	rec := httptest.NewRecorder()
	prov := &provider.Provider{Name: "test"}
	if s.enforceReport(t.Context(), rec, report, prov, "model") {
		t.Error("expected false for blocked report without force")
	}
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	// Response should be valid JSON containing the report.
	var decoded attestation.VerificationReport
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if decoded.Provider != "test" {
		t.Errorf("decoded.Provider = %q, want test", decoded.Provider)
	}
}

// --------------------------------------------------------------------------
// attestAndCache — cache hit
// --------------------------------------------------------------------------

func TestAttestAndCache_CacheHit(t *testing.T) {
	s := &Server{
		cfg:             &config.Config{},
		cache:           attestation.NewCache(time.Minute),
		negCache:        attestation.NewNegativeCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(time.Minute),
		stats:           stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}

	report := &attestation.VerificationReport{
		Provider: "test",
		Model:    "model",
		Factors:  []attestation.FactorResult{{Name: "nonce_match", Status: attestation.Pass}},
	}
	s.cache.Put("test", "model", report)

	prov := &provider.Provider{Name: "test", E2EE: false}
	ms := &modelStats{}
	rec := httptest.NewRecorder()

	result, failStatus := s.attestAndCache(t.Context(), rec, prov, "model", ms)
	if failStatus != "" {
		t.Errorf("failStatus = %q, want empty", failStatus)
	}
	if result.Report == nil {
		t.Fatal("expected non-nil report")
	}
	if result.E2EEActive {
		t.Error("E2EE should not be active without binding")
	}
	if s.stats.cacheHits.Load() != 1 {
		t.Errorf("cacheHits = %d, want 1", s.stats.cacheHits.Load())
	}
}

// --------------------------------------------------------------------------
// attestAndCache — cache miss, attestation fails
// --------------------------------------------------------------------------

func TestAttestAndCache_AttestFailed(t *testing.T) {
	s := &Server{
		cfg:             &config.Config{},
		cache:           attestation.NewCache(time.Minute),
		negCache:        attestation.NewNegativeCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(time.Minute),
		stats:           stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}

	// Provider with nil Attester → fetchAndVerify returns nil.
	prov := &provider.Provider{Name: "test"}
	ms := &modelStats{}
	rec := httptest.NewRecorder()

	result, failStatus := s.attestAndCache(t.Context(), rec, prov, "model", ms)
	if failStatus != "attest_failed" {
		t.Errorf("failStatus = %q, want attest_failed", failStatus)
	}
	if result == nil {
		t.Fatal("expected non-nil result even on failure")
	}
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

// --------------------------------------------------------------------------
// attestAndCache — cache miss, report blocked
// --------------------------------------------------------------------------

func TestAttestAndCache_ReportBlocked(t *testing.T) {
	s := &Server{
		cfg:             &config.Config{},
		cache:           attestation.NewCache(time.Minute),
		negCache:        attestation.NewNegativeCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(time.Minute),
		stats:           stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}

	// Use a provider with a mock attester that returns a report.
	// fetchAndVerify will run, but we need it to produce a blocked report.
	// The easiest approach: pre-populate the cache with a blocked report (cache hit)
	// and then call enforceReport which returns false.
	blockedReport := &attestation.VerificationReport{
		Provider: "test",
		Model:    "model",
		Factors: []attestation.FactorResult{
			{Name: "nonce_match", Status: attestation.Fail, Enforced: true},
		},
	}
	s.cache.Put("test", "model", blockedReport)

	prov := &provider.Provider{Name: "test"}
	ms := &modelStats{}
	rec := httptest.NewRecorder()

	result, failStatus := s.attestAndCache(t.Context(), rec, prov, "model", ms)
	if failStatus != "blocked" {
		t.Errorf("failStatus = %q, want blocked", failStatus)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

// --------------------------------------------------------------------------
// attestAndCache — cache hit with E2EE active
// --------------------------------------------------------------------------

func TestAttestAndCache_E2EEActive(t *testing.T) {
	s := &Server{
		cfg:             &config.Config{},
		cache:           attestation.NewCache(time.Minute),
		negCache:        attestation.NewNegativeCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(time.Minute),
		stats:           stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}

	report := &attestation.VerificationReport{
		Provider: "test",
		Model:    "model",
		Factors: []attestation.FactorResult{
			{Name: "tee_reportdata_binding", Status: attestation.Pass},
		},
	}
	s.cache.Put("test", "model", report)

	prov := &provider.Provider{Name: "test", E2EE: true}
	ms := &modelStats{}
	rec := httptest.NewRecorder()

	result, failStatus := s.attestAndCache(t.Context(), rec, prov, "model", ms)
	if failStatus != "" {
		t.Errorf("failStatus = %q, want empty", failStatus)
	}
	if !result.E2EEActive {
		t.Error("E2EE should be active with passing binding and E2EE enabled")
	}
	if s.stats.e2ee.Load() != 1 {
		t.Errorf("e2ee stat = %d, want 1", s.stats.e2ee.Load())
	}
}

// --------------------------------------------------------------------------
// buildDashboardData — blocked factors path
// --------------------------------------------------------------------------

func TestBuildDashboardData_BlockedFactors(t *testing.T) {
	s := &Server{
		cfg:             &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:           attestation.NewCache(time.Minute),
		negCache:        attestation.NewNegativeCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(time.Minute),
		providers: map[string]*provider.Provider{
			"test": {Name: "test"},
		},
		stats: stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}

	// Put a report with a blocked factor.
	report := &attestation.VerificationReport{
		Provider: "test",
		Model:    "model",
		Factors: []attestation.FactorResult{
			{Name: "nonce_match", Status: attestation.Fail, Enforced: true},
			{Name: attestation.FactorE2EECapable, Status: attestation.Pass},
		},
	}
	s.cache.Put("test", "model", report)

	data := s.buildDashboardData()

	if len(data.Attestations) == 0 {
		t.Fatal("expected attestations in dashboard data")
	}
	att := data.Attestations[0]
	if !att.Blocked {
		t.Error("expected Blocked=true")
	}
	if len(att.BlockedFactors) == 0 {
		t.Error("expected non-empty BlockedFactors")
	}
	if att.BlockedFactors[0] != "nonce_match" {
		t.Errorf("BlockedFactors[0] = %q, want nonce_match", att.BlockedFactors[0])
	}
	if att.E2EE != "capable" {
		t.Errorf("E2EE = %q, want capable", att.E2EE)
	}
}
