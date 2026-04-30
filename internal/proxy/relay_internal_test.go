package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/multi"
	"github.com/13rac1/teep/internal/provider"
)

// ---------------------------------------------------------------------------
// responseInterceptor
// ---------------------------------------------------------------------------

func TestResponseInterceptor_HeaderSent(t *testing.T) {
	rec := httptest.NewRecorder()
	ri := &responseInterceptor{ResponseWriter: rec}

	if ri.headerSent {
		t.Fatal("headerSent should be false before any writes")
	}

	ri.WriteHeader(http.StatusOK)
	if !ri.headerSent {
		t.Error("headerSent should be true after WriteHeader")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestResponseInterceptor_WriteSetsSent(t *testing.T) {
	rec := httptest.NewRecorder()
	ri := &responseInterceptor{ResponseWriter: rec}

	n, err := ri.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 5 {
		t.Errorf("n = %d, want 5", n)
	}
	if !ri.headerSent {
		t.Error("headerSent should be true after Write")
	}
}

func TestResponseInterceptor_Flush(t *testing.T) {
	rec := httptest.NewRecorder()
	_, riWriter := newResponseInterceptor(rec)

	// httptest.Recorder implements http.Flusher, so riWriter should too.
	flusher, ok := riWriter.(http.Flusher)
	if !ok {
		t.Fatal("riWriter should satisfy http.Flusher when underlying writer does")
	}
	flusher.Flush()
}

func TestResponseInterceptor_NoFlusher(t *testing.T) {
	// A writer that does not implement http.Flusher.
	ri, riWriter := newResponseInterceptor(nonFlushWriter{})
	_ = ri
	if _, ok := riWriter.(http.Flusher); ok {
		t.Fatal("riWriter should NOT satisfy http.Flusher when underlying writer doesn't")
	}
}

// nonFlushWriter is an http.ResponseWriter that does not implement http.Flusher.
type nonFlushWriter struct{}

func (nonFlushWriter) Header() http.Header         { return http.Header{} }
func (nonFlushWriter) Write(b []byte) (int, error) { return len(b), nil }
func (nonFlushWriter) WriteHeader(int)             {}

// ---------------------------------------------------------------------------
// classifyUpstreamError
// ---------------------------------------------------------------------------

func TestClassifyUpstreamError(t *testing.T) {
	t.Run("generic_error", func(t *testing.T) {
		status, code, msg := classifyUpstreamError(errors.New("connection refused"))
		if status != "upstream_failed" {
			t.Errorf("status = %q, want upstream_failed", status)
		}
		if code != http.StatusBadGateway {
			t.Errorf("code = %d, want 502", code)
		}
		if msg != "upstream request failed" {
			t.Errorf("msg = %q, want 'upstream request failed'", msg)
		}
	})

	t.Run("http_error", func(t *testing.T) {
		he := &httpError{code: http.StatusTooManyRequests, status: "rate_limited"}
		status, code, msg := classifyUpstreamError(he)
		if status != "rate_limited" {
			t.Errorf("status = %q, want rate_limited", status)
		}
		if code != http.StatusTooManyRequests {
			t.Errorf("code = %d, want 429", code)
		}
		if msg != "upstream request failed" {
			t.Errorf("msg = %q, want 'upstream request failed'", msg)
		}
	})

	t.Run("e2ee_failed_error", func(t *testing.T) {
		he := &httpError{code: http.StatusBadGateway, status: "e2ee_failed"}
		status, code, msg := classifyUpstreamError(he)
		if status != "e2ee_failed" {
			t.Errorf("status = %q, want e2ee_failed", status)
		}
		if code != http.StatusBadGateway {
			t.Errorf("code = %d, want 502", code)
		}
		if msg != "failed to prepare encrypted request" {
			t.Errorf("msg = %q, want 'failed to prepare encrypted request'", msg)
		}
	})
}

// ---------------------------------------------------------------------------
// e2eeFailed enforcement and recovery
// ---------------------------------------------------------------------------

func TestE2EEFailed_StoreAndRecover(t *testing.T) {
	// Simulate the e2eeFailed lifecycle: store a failure, verify it's
	// present, then clear it on successful fresh re-attestation.
	var e2eeFailed sync.Map
	key := providerModelKey{provider: "venice", model: "test-model"}

	// Initially not failed.
	if _, failed := e2eeFailed.Load(key); failed {
		t.Fatal("should not be failed initially")
	}

	// Record failure (as handleE2EEDecryptionFailure does).
	e2eeFailed.Store(key, true)
	if _, failed := e2eeFailed.Load(key); !failed {
		t.Fatal("should be failed after Store")
	}

	// Recovery: clear on successful fresh re-attestation (ar.Raw != nil).
	freshAttestation := true // simulates ar.Raw != nil
	if _, failed := e2eeFailed.Load(key); failed {
		if freshAttestation {
			e2eeFailed.Delete(key)
		}
	}
	if _, failed := e2eeFailed.Load(key); failed {
		t.Fatal("should be cleared after fresh attestation")
	}
}

func TestE2EEFailed_NotClearedOnCachedAttestation(t *testing.T) {
	// When the marker is set and attestation comes from cache (ar.Raw == nil),
	// the marker must NOT be cleared — fail closed until fresh attestation.
	var e2eeFailed sync.Map
	key := providerModelKey{provider: "venice", model: "test-model"}

	e2eeFailed.Store(key, true)

	// Simulates cached attestation (ar.Raw == nil).
	freshAttestation := false
	if _, failed := e2eeFailed.Load(key); failed {
		if freshAttestation {
			e2eeFailed.Delete(key)
		}
		// else: fail closed, marker stays
	}
	if _, failed := e2eeFailed.Load(key); !failed {
		t.Fatal("marker should NOT be cleared on cached attestation")
	}
}

func TestE2EEFailed_IsolationByKey(t *testing.T) {
	var e2eeFailed sync.Map
	key1 := providerModelKey{provider: "venice", model: "model-a"}
	key2 := providerModelKey{provider: "venice", model: "model-b"}

	e2eeFailed.Store(key1, true)

	if _, failed := e2eeFailed.Load(key1); !failed {
		t.Error("key1 should be failed")
	}
	if _, failed := e2eeFailed.Load(key2); failed {
		t.Error("key2 should NOT be failed (different model)")
	}
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// httpError.Unwrap
// ---------------------------------------------------------------------------

func TestHTTPError_Unwrap(t *testing.T) {
	cause := errors.New("underlying cause")
	he := &httpError{code: 502, status: "test_status", err: cause}
	// Verify Unwrap allows errors.Is to see the wrapped error.
	if !errors.Is(he, cause) {
		t.Error("errors.Is(httpError, cause) = false, want true")
	}
	if he.Error() != cause.Error() {
		t.Errorf("Error() = %q, want %q", he.Error(), cause.Error())
	}
}

// ---------------------------------------------------------------------------
// zeroE2EESessions
// ---------------------------------------------------------------------------

type noopDecryptor struct{ zeroed bool }

func (n *noopDecryptor) IsEncryptedChunk(string) bool   { return false }
func (n *noopDecryptor) Decrypt(string) ([]byte, error) { return nil, nil }
func (n *noopDecryptor) Zero()                          { n.zeroed = true }

func TestZeroE2EESessions_NilBoth(t *testing.T) {
	zeroE2EESessions(nil, nil) // must not panic
}

func TestZeroE2EESessions_WithSession(t *testing.T) {
	dec := &noopDecryptor{}
	zeroE2EESessions(dec, nil)
	if !dec.zeroed {
		t.Error("Zero() not called on non-nil session")
	}
}

func TestZeroE2EESessions_WithMeta(t *testing.T) {
	sess, err := e2ee.NewChutesSession()
	if err != nil {
		t.Fatalf("NewChutesSession: %v", err)
	}
	meta := &e2ee.ChutesE2EE{Session: sess}
	// Zero() should be called on meta.Session without panicking.
	zeroE2EESessions(nil, meta)
	t.Log("zeroE2EESessions with meta.Session completed without panic")
}

// ---------------------------------------------------------------------------
// verifyNVIDIA
// ---------------------------------------------------------------------------

func TestVerifyNVIDIA_EmptyPayload(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{} // no NvidiaPayload, no GPUEvidence
	result, dur := verifyNVIDIA(ctx, raw, attestation.Nonce{}, "test-provider")
	if result != nil {
		t.Errorf("expected nil result for empty raw, got %v", result)
	}
	if dur != 0 {
		t.Errorf("expected 0 duration for empty raw, got %v", dur)
	}
}

// ---------------------------------------------------------------------------
// Relay error classification
// ---------------------------------------------------------------------------

// newMinimalServer builds a Server with only the fields needed for internal unit tests.
func newMinimalServer() *Server {
	return &Server{
		cfg:             &config.Config{},
		cache:           attestation.NewCache(time.Minute),
		negCache:        attestation.NewNegativeCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(time.Minute),
		spkiCache:       attestation.NewSPKICache(),
		stats:           stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}
}

// ---------------------------------------------------------------------------
// classifyRelayOutcome
// ---------------------------------------------------------------------------

func TestClassifyRelayOutcome_NilError(t *testing.T) {
	s := newMinimalServer()
	prov := &provider.Provider{Name: "test"}
	ms := &modelStats{}
	result := s.classifyRelayOutcome(context.Background(), nil, false, prov, "model", ms, false, "")
	if result != "" {
		t.Errorf("classifyRelayOutcome(nil) = %q, want empty", result)
	}
}

func TestClassifyRelayOutcome_NonDecryptionError(t *testing.T) {
	s := newMinimalServer()
	prov := &provider.Provider{Name: "test"}
	ms := &modelStats{}
	relayErr := errors.New("upstream connection reset")
	result := s.classifyRelayOutcome(context.Background(), relayErr, false, prov, "model", ms, false, "")
	if result != "relay_failed" {
		t.Errorf("classifyRelayOutcome(non-decryption err) = %q, want relay_failed", result)
	}
}

func TestClassifyRelayOutcome_DecryptionErrorNotE2EEActive(t *testing.T) {
	s := newMinimalServer()
	prov := &provider.Provider{Name: "test"}
	ms := &modelStats{}
	// ErrDecryptionFailed but e2eeActive=false → should NOT call handleE2EEDecryptionFailure.
	result := s.classifyRelayOutcome(context.Background(), e2ee.ErrDecryptionFailed, false, prov, "model", ms, false, "")
	if result != "relay_failed" {
		t.Errorf("classifyRelayOutcome(decrypt err, not e2ee active) = %q, want relay_failed", result)
	}
}

// ---------------------------------------------------------------------------
// clearE2EEFailureIfFresh
// ---------------------------------------------------------------------------

func TestClearE2EEFailureIfFresh_NoFailure(t *testing.T) {
	s := newMinimalServer()
	prov := &provider.Provider{Name: "venice"}
	ms := &modelStats{}
	ar := &attestResult{}

	w := httptest.NewRecorder()
	proceed := s.clearE2EEFailureIfFresh(context.Background(), w, prov, "model", ar, ms)
	if !proceed {
		t.Error("expected proceed=true when no failure recorded")
	}
}

func TestClearE2EEFailureIfFresh_FailureWithFreshAttestation(t *testing.T) {
	s := newMinimalServer()
	prov := &provider.Provider{Name: "venice"}
	ms := &modelStats{}
	// Record a failure for this provider+model.
	key := providerModelKey{prov.Name, "model"}
	s.e2eeFailed.Store(key, true)
	// Fresh attestation clears the failure.
	ar := &attestResult{Raw: &attestation.RawAttestation{}}

	w := httptest.NewRecorder()
	proceed := s.clearE2EEFailureIfFresh(context.Background(), w, prov, "model", ar, ms)
	if !proceed {
		t.Error("expected proceed=true after clearing failure with fresh attestation")
	}
	if _, still := s.e2eeFailed.Load(key); still {
		t.Error("expected failure to be cleared from e2eeFailed")
	}
}

func TestClearE2EEFailureIfFresh_FailureWithCachedAttestation(t *testing.T) {
	s := newMinimalServer()
	prov := &provider.Provider{Name: "venice"}
	ms := &modelStats{}
	key := providerModelKey{prov.Name, "model"}
	s.e2eeFailed.Store(key, true)
	// Cached attestation (ar.Raw == nil) — should fail closed.
	ar := &attestResult{Raw: nil}

	w := httptest.NewRecorder()
	proceed := s.clearE2EEFailureIfFresh(context.Background(), w, prov, "model", ar, ms)
	if proceed {
		t.Error("expected proceed=false when failure recorded and attestation is cached")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

// ---------------------------------------------------------------------------
// Relay error classification
// ---------------------------------------------------------------------------

func TestRelayError_DecryptionVsRelay(t *testing.T) {
	// Verify that errors.Is correctly distinguishes the two relay sentinels.
	decErr := e2ee.ErrDecryptionFailed
	relayErr := e2ee.ErrRelayFailed

	if errors.Is(decErr, relayErr) {
		t.Error("ErrDecryptionFailed should not match ErrRelayFailed")
	}
	if errors.Is(relayErr, decErr) {
		t.Error("ErrRelayFailed should not match ErrDecryptionFailed")
	}

	// A wrapped decryption error should match ErrDecryptionFailed but not ErrRelayFailed.
	wrapped := errors.Join(decErr, errors.New("bad crypto"))
	if !errors.Is(wrapped, decErr) {
		t.Error("wrapped decryption error should match ErrDecryptionFailed")
	}
	if errors.Is(wrapped, relayErr) {
		t.Error("wrapped decryption error should NOT match ErrRelayFailed")
	}
}

// ---------------------------------------------------------------------------
// handleE2EEDecryptionFailure
// ---------------------------------------------------------------------------

// internalMockFetcher satisfies provider.E2EEMaterialFetcher for internal tests.
type internalMockFetcher struct {
	invalidated string
}

func (*internalMockFetcher) FetchE2EEMaterial(_ context.Context, _ string) (*provider.E2EEMaterial, error) {
	return nil, errors.New("mock")
}
func (*internalMockFetcher) MarkFailed(_, _ string)      {}
func (m *internalMockFetcher) Invalidate(chuteID string) { m.invalidated = chuteID }

func TestHandleE2EEDecryptionFailure_NonChutes(t *testing.T) {
	s := newMinimalServer()
	prov := &provider.Provider{Name: "venice"}
	ms := &modelStats{}
	result := s.handleE2EEDecryptionFailure(context.Background(), prov, "model", ms, false, "", errors.New("decrypt error"))
	t.Logf("result = %q, ms.errors = %d", result, ms.errors.Load())
	if result != "e2ee_decrypt_failed" {
		t.Errorf("result = %q, want %q", result, "e2ee_decrypt_failed")
	}
	if ms.errors.Load() != 1 {
		t.Errorf("ms.errors = %d, want 1", ms.errors.Load())
	}
}

func TestHandleE2EEDecryptionFailure_Chutes_WithFetcher(t *testing.T) {
	s := newMinimalServer()
	fetcher := &internalMockFetcher{}
	prov := &provider.Provider{Name: "chutes", E2EEMaterialFetcher: fetcher}
	ms := &modelStats{}
	result := s.handleE2EEDecryptionFailure(context.Background(), prov, "model", ms, true, "chute-id", errors.New("decrypt error"))
	t.Logf("result = %q, invalidated = %v", result, fetcher.invalidated)
	if result != "e2ee_decrypt_failed" {
		t.Errorf("result = %q, want %q", result, "e2ee_decrypt_failed")
	}
	if fetcher.invalidated != "chute-id" {
		t.Errorf("invalidated = %q, want %q", fetcher.invalidated, "chute-id")
	}
}

func TestHandleE2EEDecryptionFailure_Chutes_NilFetcher(t *testing.T) {
	s := newMinimalServer()
	prov := &provider.Provider{Name: "chutes", E2EEMaterialFetcher: nil}
	ms := &modelStats{}
	result := s.handleE2EEDecryptionFailure(context.Background(), prov, "model", ms, true, "", errors.New("decrypt error"))
	t.Logf("result = %q", result)
	if result != "e2ee_decrypt_failed" {
		t.Errorf("result = %q, want %q", result, "e2ee_decrypt_failed")
	}
}

// ---------------------------------------------------------------------------
// pinnedPostDispatchE2EE
// ---------------------------------------------------------------------------

// bindingPassedReport returns a minimal report where tdx_reportdata_binding passed.
func bindingPassedReport() *attestation.VerificationReport {
	return &attestation.VerificationReport{
		Factors: []attestation.FactorResult{
			{Name: "tdx_reportdata_binding", Status: attestation.Pass, Enforced: true},
		},
	}
}

func TestPinnedPostDispatchE2EE_NonE2EEProvider(t *testing.T) {
	s := newMinimalServer()
	w := httptest.NewRecorder()
	prov := &provider.Provider{Name: "venice", E2EE: false}
	proceed := s.pinnedPostDispatchE2EE(context.Background(), w, prov, "model", nil, false)
	t.Logf("proceed = %v", proceed)
	if !proceed {
		t.Error("expected proceed=true for non-E2EE provider")
	}
}

func TestPinnedPostDispatchE2EE_NilReport(t *testing.T) {
	s := newMinimalServer()
	w := httptest.NewRecorder()
	prov := &provider.Provider{Name: "venice", E2EE: true}
	proceed := s.pinnedPostDispatchE2EE(context.Background(), w, prov, "model", nil, false)
	t.Logf("proceed = %v, status = %d", proceed, w.Code)
	if proceed {
		t.Error("expected proceed=false when report is nil for E2EE provider")
	}
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
}

func TestPinnedPostDispatchE2EE_BindingNotPassed(t *testing.T) {
	s := newMinimalServer()
	w := httptest.NewRecorder()
	prov := &provider.Provider{Name: "venice", E2EE: true}
	// Report with no tdx_reportdata_binding factor → ReportDataBindingPassed() = false.
	report := &attestation.VerificationReport{}
	proceed := s.pinnedPostDispatchE2EE(context.Background(), w, prov, "model", report, false)
	t.Logf("proceed = %v, status = %d", proceed, w.Code)
	if proceed {
		t.Error("expected proceed=false when binding not passed")
	}
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
}

func TestPinnedPostDispatchE2EE_BindingPassed_NoFailureMark(t *testing.T) {
	s := newMinimalServer()
	w := httptest.NewRecorder()
	prov := &provider.Provider{Name: "venice", E2EE: true}
	proceed := s.pinnedPostDispatchE2EE(context.Background(), w, prov, "model", bindingPassedReport(), false)
	t.Logf("proceed = %v", proceed)
	if !proceed {
		t.Error("expected proceed=true when binding passed and no failure mark")
	}
}

func TestPinnedPostDispatchE2EE_E2EEFailedMark_FreshReport(t *testing.T) {
	s := newMinimalServer()
	// Set failure mark.
	s.e2eeFailed.Store(providerModelKey{"venice", "model"}, true)
	w := httptest.NewRecorder()
	prov := &provider.Provider{Name: "venice", E2EE: true}
	// freshReport=true → should clear the mark.
	proceed := s.pinnedPostDispatchE2EE(context.Background(), w, prov, "model", bindingPassedReport(), true)
	t.Logf("proceed = %v", proceed)
	if !proceed {
		t.Error("expected proceed=true after clearing failure mark on fresh report")
	}
	if _, failed := s.e2eeFailed.Load(providerModelKey{"venice", "model"}); failed {
		t.Error("failure mark should have been cleared")
	}
}

func TestPinnedPostDispatchE2EE_E2EEFailedMark_CachedReport(t *testing.T) {
	s := newMinimalServer()
	// Set failure mark.
	s.e2eeFailed.Store(providerModelKey{"venice", "model"}, true)
	w := httptest.NewRecorder()
	prov := &provider.Provider{Name: "venice", E2EE: true}
	// freshReport=false → should fail closed with 503.
	proceed := s.pinnedPostDispatchE2EE(context.Background(), w, prov, "model", bindingPassedReport(), false)
	t.Logf("proceed = %v, status = %d", proceed, w.Code)
	if proceed {
		t.Error("expected proceed=false when failure mark set and cached report only")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

// ---------------------------------------------------------------------------
// pinnedPreDispatchE2EE
// ---------------------------------------------------------------------------

func TestPinnedPreDispatchE2EE_NonE2EEProvider(t *testing.T) {
	s := newMinimalServer()
	w := httptest.NewRecorder()
	prov := &provider.Provider{Name: "venice", E2EE: false}
	proceed := s.pinnedPreDispatchE2EE(context.Background(), w, prov, "model")
	t.Logf("proceed = %v", proceed)
	if !proceed {
		t.Error("expected proceed=true for non-E2EE provider")
	}
}

func TestPinnedPreDispatchE2EE_NilSPKIDomainForModel(t *testing.T) {
	s := newMinimalServer()
	w := httptest.NewRecorder()
	// E2EE provider, cache miss, non-nil PinnedHandler, nil SPKIDomainForModel.
	prov := &provider.Provider{
		Name:               "neardirect",
		E2EE:               true,
		PinnedHandler:      &noopPinnedHandler{},
		SPKIDomainForModel: nil,
	}
	proceed := s.pinnedPreDispatchE2EE(context.Background(), w, prov, "model")
	t.Logf("proceed = %v, status = %d", proceed, w.Code)
	if proceed {
		t.Error("expected proceed=false when SPKIDomainForModel is nil")
	}
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestPinnedPreDispatchE2EE_DomainResolutionFails(t *testing.T) {
	s := newMinimalServer()
	w := httptest.NewRecorder()
	prov := &provider.Provider{
		Name:          "neardirect",
		E2EE:          true,
		PinnedHandler: &noopPinnedHandler{},
		SPKIDomainForModel: func(_ context.Context, _ string) (string, bool) {
			return "", false // resolution failed
		},
	}
	proceed := s.pinnedPreDispatchE2EE(context.Background(), w, prov, "model")
	t.Logf("proceed = %v, status = %d", proceed, w.Code)
	if proceed {
		t.Error("expected proceed=false when domain resolution fails")
	}
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestPinnedPreDispatchE2EE_CacheMissEvictsSPKI(t *testing.T) {
	s := newMinimalServer()
	w := httptest.NewRecorder()
	prov := &provider.Provider{
		Name:          "neardirect",
		E2EE:          true,
		PinnedHandler: &noopPinnedHandler{},
		SPKIDomainForModel: func(_ context.Context, _ string) (string, bool) {
			return "api.near.ai", true
		},
	}
	// Cache miss (nothing in s.cache), SPKIDomainForModel returns valid domain.
	proceed := s.pinnedPreDispatchE2EE(context.Background(), w, prov, "model")
	t.Logf("proceed = %v, status = %d", proceed, w.Code)
	if !proceed {
		t.Error("expected proceed=true after SPKI eviction")
	}
}

// noopPinnedHandler satisfies provider.PinnedHandler for tests.
type noopPinnedHandler struct{}

func (*noopPinnedHandler) HandlePinned(_ context.Context, _ *provider.PinnedRequest) (*provider.PinnedResponse, error) {
	return nil, errors.New("noop")
}

// ---------------------------------------------------------------------------
// resolveModel
// ---------------------------------------------------------------------------

func TestResolveModel_NoProviders(t *testing.T) {
	s := newMinimalServer()
	s.providers = map[string]*provider.Provider{}
	prov, model, ok := s.resolveModel("venice:qwen3-122b")
	t.Logf("resolveModel(no providers): prov=%v model=%q ok=%v", prov, model, ok)
	if ok {
		t.Error("expected ok=false when no providers configured")
	}
}

func TestResolveModel_Valid(t *testing.T) {
	s := newMinimalServer()
	s.providers = map[string]*provider.Provider{
		"venice": {Name: "venice"},
	}
	prov, model, ok := s.resolveModel("venice:qwen3-122b")
	t.Logf("resolveModel(valid): prov=%v model=%q ok=%v", prov, model, ok)
	if !ok {
		t.Error("expected ok=true for valid provider:model")
	}
	if model != "qwen3-122b" {
		t.Errorf("model = %q, want %q", model, "qwen3-122b")
	}
	if prov == nil {
		t.Fatal("prov = nil, want non-nil provider named 'venice'")
	}
	if prov.Name != "venice" {
		t.Errorf("prov.Name = %q, want 'venice'", prov.Name)
	}
}

func TestResolveModel_UnknownProvider(t *testing.T) {
	s := newMinimalServer()
	s.providers = map[string]*provider.Provider{
		"venice": {Name: "venice"},
	}
	prov, model, ok := s.resolveModel("bogus:qwen3-122b")
	t.Logf("resolveModel(unknown provider): prov=%v model=%q ok=%v", prov, model, ok)
	if ok {
		t.Error("expected ok=false for unknown provider")
	}
}

func TestResolveModel_MissingSeparator(t *testing.T) {
	s := newMinimalServer()
	s.providers = map[string]*provider.Provider{
		"venice": {Name: "venice"},
	}
	prov, model, ok := s.resolveModel("qwen3-122b")
	t.Logf("resolveModel(no separator): prov=%v model=%q ok=%v", prov, model, ok)
	if ok {
		t.Error("expected ok=false for model without provider: prefix")
	}
}

func TestResolveModel_EmptySegments(t *testing.T) {
	s := newMinimalServer()
	s.providers = map[string]*provider.Provider{
		"venice": {Name: "venice"},
	}
	cases := []string{":qwen3-122b", "venice:", ":", ""}
	for _, c := range cases {
		prov, model, ok := s.resolveModel(c)
		t.Logf("resolveModel(%q): prov=%v model=%q ok=%v", c, prov, model, ok)
		if ok {
			t.Errorf("resolveModel(%q): expected ok=false for empty segment", c)
		}
	}
}

// ---------------------------------------------------------------------------
// enforceReport
// ---------------------------------------------------------------------------

// blockedReport returns a VerificationReport with one enforced-fail factor.
func blockedReport() *attestation.VerificationReport {
	return &attestation.VerificationReport{
		Factors: []attestation.FactorResult{
			{Tier: "model", Name: "tdx_quote_present", Status: attestation.Fail, Enforced: true, Detail: "no quote"},
		},
	}
}

func TestEnforceReport_NilReport(t *testing.T) {
	s := newMinimalServer()
	s.cfg = &config.Config{}
	w := httptest.NewRecorder()
	prov := &provider.Provider{Name: "venice"}
	proceed := s.enforceReport(context.Background(), w, nil, prov, "model")
	if !proceed {
		t.Error("expected proceed=true for nil report")
	}
}

func TestEnforceReport_NotBlocked(t *testing.T) {
	s := newMinimalServer()
	s.cfg = &config.Config{}
	w := httptest.NewRecorder()
	prov := &provider.Provider{Name: "venice"}
	report := &attestation.VerificationReport{} // no blocked factors
	proceed := s.enforceReport(context.Background(), w, report, prov, "model")
	if !proceed {
		t.Error("expected proceed=true for non-blocked report")
	}
}

func TestEnforceReport_BlockedWithForce(t *testing.T) {
	s := newMinimalServer()
	s.cfg = &config.Config{Force: true}
	w := httptest.NewRecorder()
	prov := &provider.Provider{Name: "venice"}
	proceed := s.enforceReport(context.Background(), w, blockedReport(), prov, "model")
	if !proceed {
		t.Error("expected proceed=true when Force=true bypasses blocked report")
	}
}

func TestEnforceReport_BlockedWithoutForce(t *testing.T) {
	s := newMinimalServer()
	s.cfg = &config.Config{Force: false}
	w := httptest.NewRecorder()
	prov := &provider.Provider{Name: "venice"}
	proceed := s.enforceReport(context.Background(), w, blockedReport(), prov, "model")
	if proceed {
		t.Error("expected proceed=false when blocked report and Force=false")
	}
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
}

// ---------------------------------------------------------------------------
// handlePinnedPostRelay
// ---------------------------------------------------------------------------

// mockDecryptor satisfies e2ee.Decryptor for tests that need a non-nil session.
type mockDecryptor struct{}

func (mockDecryptor) IsEncryptedChunk(_ string) bool { return false }
func (mockDecryptor) Decrypt(_ string) ([]byte, error) {
	return nil, errors.New("mock decrypt")
}
func (mockDecryptor) Zero() {}

func TestHandlePinnedPostRelay_NoError_NoSession(t *testing.T) {
	s := newMinimalServer()
	prov := &provider.Provider{Name: "venice"}
	ms := &modelStats{}
	// No error, no session → success path, no cache update.
	s.handlePinnedPostRelay(context.Background(), prov, "model", nil, nil, ms, nil)
	t.Logf("errors after no-error/no-session: %d", ms.errors.Load())
	if ms.errors.Load() != 0 {
		t.Errorf("ms.errors = %d, want 0", ms.errors.Load())
	}
}

func TestHandlePinnedPostRelay_NoError_WithSession(t *testing.T) {
	s := newMinimalServer()
	prov := &provider.Provider{Name: "venice"}
	ms := &modelStats{}
	report := &attestation.VerificationReport{}
	// No error, session present → E2EE success path, cache updated.
	s.handlePinnedPostRelay(context.Background(), prov, "model", report, mockDecryptor{}, ms, nil)
	t.Logf("errors after no-error/with-session: %d", ms.errors.Load())
	if ms.errors.Load() != 0 {
		t.Errorf("ms.errors = %d, want 0 on success", ms.errors.Load())
	}
}

func TestHandlePinnedPostRelay_NonDecryptionError(t *testing.T) {
	s := newMinimalServer()
	prov := &provider.Provider{Name: "venice"}
	ms := &modelStats{}
	relayErr := errors.New("upstream timeout")
	// Non-decryption error → error counters incremented.
	s.handlePinnedPostRelay(context.Background(), prov, "model", nil, nil, ms, relayErr)
	t.Logf("ms.errors = %d", ms.errors.Load())
	if ms.errors.Load() != 1 {
		t.Errorf("ms.errors = %d, want 1", ms.errors.Load())
	}
}

func TestHandlePinnedPostRelay_E2EEDecryptionFailure(t *testing.T) {
	s := newMinimalServer()
	prov := &provider.Provider{Name: "venice"}
	ms := &modelStats{}
	relayErr := fmt.Errorf("relay: %w", e2ee.ErrDecryptionFailed)
	// E2EE decryption failure with session → cache invalidated, error counters incremented.
	s.handlePinnedPostRelay(context.Background(), prov, "model", nil, mockDecryptor{}, ms, relayErr)
	t.Logf("ms.errors = %d", ms.errors.Load())
	if ms.errors.Load() != 1 {
		t.Errorf("ms.errors = %d, want 1", ms.errors.Load())
	}
}

// ---------------------------------------------------------------------------
// extractMultipartField — missing branches
// ---------------------------------------------------------------------------

func TestExtractMultipartField_NotMultipart(t *testing.T) {
	_, err := extractMultipartField("application/json", []byte(`{}`), "model")
	if err == nil {
		t.Error("expected error for non-multipart content-type")
	}
	if !strings.Contains(err.Error(), "not multipart") {
		t.Errorf("error = %q, should mention 'not multipart'", err)
	}
}

func TestExtractMultipartField_MissingBoundary(t *testing.T) {
	// multipart/form-data without boundary parameter.
	_, err := extractMultipartField("multipart/form-data", []byte{}, "model")
	if err == nil {
		t.Error("expected error for missing boundary")
	}
	if !strings.Contains(err.Error(), "missing boundary") {
		t.Errorf("error = %q, should mention 'missing boundary'", err)
	}
}

func TestExtractMultipartField_FieldNotFound(t *testing.T) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, _ := w.CreateFormField("other_field")
	fmt.Fprint(fw, "value")
	w.Close()
	_, err := extractMultipartField(w.FormDataContentType(), buf.Bytes(), "missing_field")
	if err == nil {
		t.Error("expected error when field not found")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, should mention 'not found'", err)
	}
}

func TestExtractMultipartField_Success(t *testing.T) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, _ := w.CreateFormField("model")
	fmt.Fprint(fw, "deepseek-v3")
	w.Close()
	val, err := extractMultipartField(w.FormDataContentType(), buf.Bytes(), "model")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "deepseek-v3" {
		t.Errorf("val = %q, want %q", val, "deepseek-v3")
	}
}

// ---------------------------------------------------------------------------
// verifyTDX — empty IntelQuote early return
// ---------------------------------------------------------------------------

func TestVerifyTDX_EmptyIntelQuote(t *testing.T) {
	s := newMinimalServer()
	raw := &attestation.RawAttestation{} // IntelQuote == ""
	result, dur := s.verifyTDX(context.Background(), raw, attestation.Nonce{}, &provider.Provider{})
	t.Logf("verifyTDX(empty IntelQuote): result=%v dur=%v", result, dur)
	if result != nil {
		t.Error("expected nil result for empty IntelQuote")
	}
	if dur != 0 {
		t.Errorf("expected 0 duration for empty IntelQuote, got %v", dur)
	}
}

func TestVerifyTDX_WithFakeQuote(t *testing.T) {
	s := newMinimalServer()
	// Use offline TDX verifier — parses the quote without network calls.
	s.verifyQuote = attestation.NewTDXVerifier(true, nil)
	// Non-empty but invalid hex quote: verifyQuote parses and returns ParseErr.
	raw := &attestation.RawAttestation{IntelQuote: "deadbeef"}
	// nil ReportDataVerifier: skip the binding check.
	prov := &provider.Provider{Name: "test", ReportDataVerifier: nil}
	result, dur := s.verifyTDX(context.Background(), raw, attestation.Nonce{}, prov)
	if result == nil {
		t.Fatal("expected non-nil result for non-empty IntelQuote")
	}
	t.Logf("verifyTDX(fake quote): result.ParseErr=%v dur=%v", result.ParseErr, dur)
	// ParseErr is expected since the quote is invalid.
	if result.ParseErr == nil {
		t.Error("expected ParseErr for fake quote")
	}
	if dur == 0 {
		t.Error("expected non-zero duration for non-empty IntelQuote")
	}
}

// ---------------------------------------------------------------------------
// verifyNVIDIA — NvidiaPayload and GPUEvidence paths
// ---------------------------------------------------------------------------

func TestVerifyNVIDIA_WithPayload(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{NvidiaPayload: "not-a-real-nvidia-payload"}
	result, dur := verifyNVIDIA(ctx, raw, attestation.Nonce{}, "test-provider")
	t.Logf("verifyNVIDIA(payload): result=%v dur=%v", result, dur)
	if result == nil {
		t.Error("expected non-nil result when NvidiaPayload is set")
	}
	_ = dur
}

func TestVerifyNVIDIA_GPUEvidence_BadNonce(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{
		GPUEvidence: []attestation.GPUEvidence{{Certificate: "test", Evidence: "test", Arch: "HOPPER"}},
		Nonce:       "not-valid-hex-nonce",
	}
	result, _ := verifyNVIDIA(ctx, raw, attestation.Nonce{}, "test-provider")
	if result == nil {
		t.Fatal("expected non-nil result for GPUEvidence with bad nonce")
	}
	t.Logf("verifyNVIDIA(GPUEvidence bad nonce): result=%v", result)
	if result.SignatureErr == nil {
		t.Error("expected SignatureErr for bad nonce")
	}
}

// ---------------------------------------------------------------------------
// verifyNVIDIAOnline — offline flag, empty, JSON payload, GPUEvidence paths
// ---------------------------------------------------------------------------

func TestVerifyNVIDIAOnline_Offline(t *testing.T) {
	s := newMinimalServer()
	s.cfg.Offline = true
	raw := &attestation.RawAttestation{NvidiaPayload: `{"test": true}`}
	result, dur := s.verifyNVIDIAOnline(context.Background(), raw, "test-provider")
	t.Logf("verifyNVIDIAOnline(offline): result=%v dur=%v", result, dur)
	if result != nil {
		t.Error("expected nil result in offline mode")
	}
	if dur != 0 {
		t.Errorf("expected 0 duration in offline mode, got %v", dur)
	}
}

func TestVerifyNVIDIAOnline_Empty(t *testing.T) {
	s := newMinimalServer()
	s.nvidiaVerifier = attestation.NewNVIDIAVerifier("http://nras.example.com", "http://jwks.example.com")
	s.attestClient = http.DefaultClient
	raw := &attestation.RawAttestation{} // no payload, no GPUEvidence
	result, dur := s.verifyNVIDIAOnline(context.Background(), raw, "test-provider")
	t.Logf("verifyNVIDIAOnline(empty): result=%v dur=%v", result, dur)
	if result != nil {
		t.Error("expected nil result for empty raw")
	}
	if dur != 0 {
		t.Errorf("expected 0 duration for empty raw, got %v", dur)
	}
}

func TestVerifyNVIDIAOnline_JSONPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer srv.Close()

	s := newMinimalServer()
	s.nvidiaVerifier = attestation.NewNVIDIAVerifier(srv.URL, srv.URL)
	s.attestClient = srv.Client()
	raw := &attestation.RawAttestation{NvidiaPayload: `{"test": true}`}
	result, _ := s.verifyNVIDIAOnline(context.Background(), raw, "test-provider")
	t.Logf("verifyNVIDIAOnline(JSON payload): result=%v", result)
	if result == nil {
		t.Error("expected non-nil result when JSON payload is set")
	}
}

func TestVerifyNVIDIAOnline_GPUEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer srv.Close()

	s := newMinimalServer()
	s.nvidiaVerifier = attestation.NewNVIDIAVerifier(srv.URL, srv.URL)
	s.attestClient = srv.Client()
	raw := &attestation.RawAttestation{
		GPUEvidence: []attestation.GPUEvidence{{Certificate: "cert", Evidence: "ev", Arch: "HOPPER"}},
		Nonce:       strings.Repeat("aa", 32),
	}
	result, _ := s.verifyNVIDIAOnline(context.Background(), raw, "test-provider")
	t.Logf("verifyNVIDIAOnline(GPUEvidence): result=%v", result)
	if result == nil {
		t.Error("expected non-nil result when GPUEvidence is set")
	}
}

// ---------------------------------------------------------------------------
// verifySupplyChain — skip paths
// ---------------------------------------------------------------------------

func TestVerifySupplyChain_EmptyAppCompose(t *testing.T) {
	s := newMinimalServer()
	raw := &attestation.RawAttestation{} // AppCompose == ""
	sc, dur := s.verifySupplyChain(context.Background(), raw, nil)
	t.Logf("verifySupplyChain(empty AppCompose): compose=%v dur=%v", sc.Compose, dur)
	if sc.Compose != nil {
		t.Error("expected empty supplyChainResult for empty AppCompose")
	}
	if dur != 0 {
		t.Errorf("expected 0 duration for skipped supply chain, got %v", dur)
	}
}

func TestVerifySupplyChain_TDXParseErr(t *testing.T) {
	s := newMinimalServer()
	raw := &attestation.RawAttestation{AppCompose: "version: '3'\nservices:\n  app:\n    image: ubuntu:latest\n"}
	tdxResult := &attestation.TDXVerifyResult{ParseErr: errors.New("parse failed")}
	sc, _ := s.verifySupplyChain(context.Background(), raw, tdxResult)
	t.Logf("verifySupplyChain(TDX ParseErr): compose=%v", sc.Compose)
	if sc.Compose != nil {
		t.Error("expected empty result when TDX ParseErr is set")
	}
}

func TestVerifySupplyChain_WithAppCompose(t *testing.T) {
	s := newMinimalServer()
	raw := &attestation.RawAttestation{AppCompose: `{"docker_compose_file":"version: '3'\n"}`}
	// TDXVerifyResult with no ParseErr but empty MRConfigID — VerifyComposeBinding returns error.
	tdxResult := &attestation.TDXVerifyResult{}
	sc, dur := s.verifySupplyChain(context.Background(), raw, tdxResult)
	t.Logf("verifySupplyChain(AppCompose): compose=%v dur=%v", sc.Compose, dur)
	if sc.Compose == nil {
		t.Error("expected non-nil Compose result when AppCompose is set")
	}
	if !sc.Compose.Checked {
		t.Error("Compose.Checked should be true")
	}
	// VerifyComposeBinding fails (empty MRConfigID), so Err should be non-nil.
	if sc.Compose.Err == nil {
		t.Error("expected Compose.Err for empty MRConfigID")
	} else {
		t.Logf("Compose.Err: %v", sc.Compose.Err)
	}
}

// ---------------------------------------------------------------------------
// fromConfig — all provider cases and error cases
// ---------------------------------------------------------------------------

func TestFromConfig_UnknownProvider(t *testing.T) {
	cp := &config.Provider{Name: "unknown-xyz-provider"}
	_, err := fromConfig(cp, attestation.NewSPKICache(), false, nil,
		attestation.MeasurementPolicy{}, attestation.MeasurementPolicy{},
		nil, nil, nil)
	t.Logf("fromConfig(unknown): err=%v", err)
	if err == nil {
		t.Error("expected error for unknown provider")
	}
	if !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("error %q should mention 'unknown provider'", err)
	}
}

func TestFromConfig_Nanogpt(t *testing.T) {
	cp := &config.Provider{Name: "nanogpt", BaseURL: "https://nano-gpt.com", APIKey: "test-key"}
	p, err := fromConfig(cp, attestation.NewSPKICache(), false, nil,
		attestation.MeasurementPolicy{}, attestation.MeasurementPolicy{},
		nil, nil, nil)
	t.Logf("fromConfig(nanogpt): err=%v ChatPath=%s", err, p.ChatPath)
	if err != nil {
		t.Fatalf("unexpected error for nanogpt: %v", err)
	}
	if p.ChatPath != "/v1/chat/completions" {
		t.Errorf("ChatPath = %q, want /v1/chat/completions", p.ChatPath)
	}
}

func TestFromConfig_Phalacloud(t *testing.T) {
	cp := &config.Provider{Name: "phalacloud", BaseURL: "https://api.redpill.ai", APIKey: "test-key"}
	p, err := fromConfig(cp, attestation.NewSPKICache(), false, nil,
		attestation.MeasurementPolicy{}, attestation.MeasurementPolicy{},
		nil, nil, nil)
	t.Logf("fromConfig(phalacloud): err=%v ChatPath=%s", err, p.ChatPath)
	if err != nil {
		t.Fatalf("unexpected error for phalacloud: %v", err)
	}
	if p.ChatPath != "/v1/chat/completions" {
		t.Errorf("ChatPath = %q, want /v1/chat/completions", p.ChatPath)
	}
}

func TestFromConfig_Phalacloud_PathSuffix(t *testing.T) {
	for _, badURL := range []string{
		"https://api.redpill.ai/v1",
		"https://api.redpill.ai/v1/",
	} {
		cp := &config.Provider{Name: "phalacloud", BaseURL: badURL, APIKey: "test-key"}
		_, err := fromConfig(cp, attestation.NewSPKICache(), false, nil,
			attestation.MeasurementPolicy{}, attestation.MeasurementPolicy{},
			nil, nil, nil)
		t.Logf("fromConfig(phalacloud, base_url=%q): err=%v", badURL, err)
		if err == nil {
			t.Errorf("expected error when phalacloud base_url includes /v1 path suffix: %q", badURL)
		}
	}
}

func TestFromConfig_Venice(t *testing.T) {
	cp := &config.Provider{Name: "venice", BaseURL: "https://api.venice.ai", APIKey: "test-key"}
	p, err := fromConfig(cp, attestation.NewSPKICache(), false, nil,
		attestation.MeasurementPolicy{}, attestation.MeasurementPolicy{},
		nil, nil, nil)
	t.Logf("fromConfig(venice): err=%v ChatPath=%s", err, p.ChatPath)
	if err != nil {
		t.Fatalf("unexpected error for venice: %v", err)
	}
	if p.ChatPath != "/api/v1/chat/completions" {
		t.Errorf("ChatPath = %q, want /api/v1/chat/completions", p.ChatPath)
	}
}

func TestFromConfig_Nearcloud(t *testing.T) {
	cp := &config.Provider{Name: "nearcloud", APIKey: "test-key"}
	p, err := fromConfig(cp, attestation.NewSPKICache(), false, nil,
		attestation.MeasurementPolicy{}, attestation.MeasurementPolicy{},
		nil, attestation.NewNVIDIAVerifier("http://nras.example.com", "http://jwks.example.com"), nil)
	t.Logf("fromConfig(nearcloud): err=%v ChatPath=%s", err, p.ChatPath)
	if err != nil {
		t.Fatalf("unexpected error for nearcloud: %v", err)
	}
	if p.ChatPath != "/v1/chat/completions" {
		t.Errorf("ChatPath = %q, want /v1/chat/completions", p.ChatPath)
	}
}

func TestFromConfig_Chutes(t *testing.T) {
	cp := &config.Provider{Name: "chutes", APIKey: "test-key"}
	p, err := fromConfig(cp, attestation.NewSPKICache(), false, nil,
		attestation.MeasurementPolicy{}, attestation.MeasurementPolicy{},
		nil, nil, nil)
	t.Logf("fromConfig(chutes): err=%v ChatPath=%s", err, p.ChatPath)
	if err != nil {
		t.Fatalf("unexpected error for chutes: %v", err)
	}
	if p.ChatPath != "/v1/chat/completions" {
		t.Errorf("ChatPath = %q, want /v1/chat/completions", p.ChatPath)
	}
}

// ---------------------------------------------------------------------------
// buildUpstreamBody — easy error paths
// ---------------------------------------------------------------------------

func TestBuildUpstreamBody_E2EERequiredButNotActive(t *testing.T) {
	s := newMinimalServer()
	prov := &provider.Provider{Name: "test-e2ee", E2EE: true}
	_, err := s.buildUpstreamBody(context.Background(), []byte(`{}`), "model", false /* e2eeActive */, prov, nil, "/chat")
	t.Logf("buildUpstreamBody(E2EE required, not active): err=%v", err)
	if err == nil {
		t.Error("expected error when E2EE required but not active")
	}
	if !strings.Contains(err.Error(), "refusing plaintext") {
		t.Errorf("error %q should mention 'refusing plaintext'", err)
	}
}

func TestBuildUpstreamBody_FreshRaw_MissingSigningKey(t *testing.T) {
	s := newMinimalServer()
	prov := &provider.Provider{Name: "test", E2EE: false}
	freshRaw := &attestation.RawAttestation{SigningKey: ""} // no signing key
	_, err := s.buildUpstreamBody(context.Background(), []byte(`{}`), "model", true /* e2eeActive */, prov, freshRaw, "/chat")
	t.Logf("buildUpstreamBody(freshRaw, missing signing key): err=%v", err)
	if err == nil {
		t.Error("expected error for missing signing key")
	}
	if !strings.Contains(err.Error(), "missing signing_key") {
		t.Errorf("error %q should mention 'missing signing_key'", err)
	}
}

// ---------------------------------------------------------------------------
// relayResponse — Chutes session paths
// ---------------------------------------------------------------------------

func TestRelayResponse_ChutesStream(t *testing.T) {
	ctx := context.Background()
	rec := httptest.NewRecorder()
	session, err := e2ee.NewChutesSession()
	if err != nil {
		t.Fatalf("NewChutesSession: %v", err)
	}
	meta := &e2ee.ChutesE2EE{Session: session}
	// SSE body ending with [DONE] — RelayStreamChutes parses it and returns cleanly.
	body := strings.NewReader("data: [DONE]\n\n")
	ss, relayErr := relayResponse(ctx, rec, body, nil, meta, true /* stream */)
	t.Logf("relayResponse(chutes stream): ss=%v err=%v status=%d", ss, relayErr, rec.Code)
	// [DONE]-only stream succeeds with zero stats.
	if relayErr != nil {
		t.Errorf("unexpected error: %v", relayErr)
	}
}

func TestRelayResponse_ChutesNonStream(t *testing.T) {
	ctx := context.Background()
	rec := httptest.NewRecorder()
	session, err := e2ee.NewChutesSession()
	if err != nil {
		t.Fatalf("NewChutesSession: %v", err)
	}
	meta := &e2ee.ChutesE2EE{Session: session}
	// Non-encrypted body causes DecryptResponseBlobChutes to fail.
	body := strings.NewReader(`{"choices":[]}`)
	ss, relayErr := relayResponse(ctx, rec, body, nil, meta, false /* non-stream */)
	t.Logf("relayResponse(chutes non-stream): ss=%v err=%v", ss, relayErr)
	// Decryption failure is expected with an uninitialized session.
	if relayErr == nil {
		t.Error("expected decryption error for non-encrypted body")
	}
}

// ---------------------------------------------------------------------------
// mock types for unit testing
// ---------------------------------------------------------------------------

type mockReportDataVerifier struct{ err error }

func (m *mockReportDataVerifier) VerifyReportData(_ [64]byte, _ *attestation.RawAttestation, _ attestation.Nonce) (string, error) {
	return "mock-detail", m.err
}

type mockRequestEncryptor struct{ err error }

func (m *mockRequestEncryptor) EncryptRequest(_ []byte, _ *attestation.RawAttestation, _ string) ([]byte, e2ee.Decryptor, *e2ee.ChutesE2EE, error) {
	return []byte("encrypted"), nil, nil, m.err
}

type mockAttester struct{ err error }

func (m *mockAttester) FetchAttestation(_ context.Context, _ string, _ attestation.Nonce) (*attestation.RawAttestation, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &attestation.RawAttestation{SigningKey: "attested-key"}, nil
}

type mockE2EEMaterialFetcher struct {
	material    *provider.E2EEMaterial
	err         error
	invalidated []string
}

func (m *mockE2EEMaterialFetcher) FetchE2EEMaterial(_ context.Context, _ string) (*provider.E2EEMaterial, error) {
	return m.material, m.err
}
func (m *mockE2EEMaterialFetcher) MarkFailed(_, _ string) {}
func (m *mockE2EEMaterialFetcher) Invalidate(chuteID string) {
	m.invalidated = append(m.invalidated, chuteID)
}

// ---------------------------------------------------------------------------
// verifyTDX — ReportDataVerifier paths
// ---------------------------------------------------------------------------

// TestVerifyTDX_WithReportDataVerifier_ErrNoVerifier verifies that when
// verifyQuote returns ParseErr==nil and the ReportDataVerifier returns
// multi.ErrNoVerifier, the debug-log branch is taken and ReportDataBindingErr
// remains nil.
func TestVerifyTDX_WithReportDataVerifier_ErrNoVerifier(t *testing.T) {
	s := newMinimalServer()
	s.verifyQuote = func(_ context.Context, _ string) *attestation.TDXVerifyResult {
		return &attestation.TDXVerifyResult{} // ParseErr == nil
	}
	prov := &provider.Provider{
		Name:               "test",
		ReportDataVerifier: &mockReportDataVerifier{err: fmt.Errorf("%w %q", multi.ErrNoVerifier, "test-format")},
	}
	raw := &attestation.RawAttestation{IntelQuote: "fakequote"}
	result, dur := s.verifyTDX(context.Background(), raw, attestation.Nonce{}, prov)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	t.Logf("verifyTDX(ErrNoVerifier): result.ReportDataBindingErr=%v dur=%v", result.ReportDataBindingErr, dur)
	// ErrNoVerifier → debug log; ReportDataBindingErr must stay nil.
	if result.ReportDataBindingErr != nil {
		t.Errorf("ReportDataBindingErr should be nil for ErrNoVerifier, got: %v", result.ReportDataBindingErr)
	}
}

// TestVerifyTDX_WithReportDataVerifier_OtherError verifies that a non-ErrNoVerifier
// error from ReportDataVerifier is stored in result.ReportDataBindingErr.
func TestVerifyTDX_WithReportDataVerifier_OtherError(t *testing.T) {
	s := newMinimalServer()
	s.verifyQuote = func(_ context.Context, _ string) *attestation.TDXVerifyResult {
		return &attestation.TDXVerifyResult{} // ParseErr == nil
	}
	bindingErr := errors.New("reportdata binding mismatch")
	prov := &provider.Provider{
		Name:               "test",
		ReportDataVerifier: &mockReportDataVerifier{err: bindingErr},
	}
	raw := &attestation.RawAttestation{IntelQuote: "fakequote"}
	result, dur := s.verifyTDX(context.Background(), raw, attestation.Nonce{}, prov)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	t.Logf("verifyTDX(binding error): result.ReportDataBindingErr=%v dur=%v", result.ReportDataBindingErr, dur)
	if !errors.Is(result.ReportDataBindingErr, bindingErr) {
		t.Errorf("ReportDataBindingErr = %v, want %v", result.ReportDataBindingErr, bindingErr)
	}
}

// ---------------------------------------------------------------------------
// verifySupplyChain — success path (Compose.Err == nil)
// ---------------------------------------------------------------------------

// TestVerifySupplyChain_SuccessPath verifies that a valid AppCompose with a
// correctly computed MRConfigID passes VerifyComposeBinding, covering the
// sc.Compose.Err == nil branch and the ExtractComposeDigests call.
func TestVerifySupplyChain_SuccessPath(t *testing.T) {
	appCompose := `{"docker_compose_file":"services:\n  app:\n    image: myapp:latest\n"}`

	// MRConfigID = 0x01 || sha256(appCompose), zero-padded to 48 bytes.
	hash := sha256.Sum256([]byte(appCompose))
	mrConfigID := make([]byte, 48)
	mrConfigID[0] = 0x01
	copy(mrConfigID[1:], hash[:])

	s := newMinimalServer()
	raw := &attestation.RawAttestation{AppCompose: appCompose}
	tdxResult := &attestation.TDXVerifyResult{MRConfigID: mrConfigID}

	sc, dur := s.verifySupplyChain(context.Background(), raw, tdxResult)
	t.Logf("verifySupplyChain(success): compose=%+v dur=%v", sc.Compose, dur)
	if sc.Compose == nil {
		t.Fatal("expected non-nil Compose result")
	}
	if !sc.Compose.Checked {
		t.Error("Compose.Checked should be true")
	}
	if sc.Compose.Err != nil {
		t.Errorf("Compose.Err should be nil for valid binding, got: %v", sc.Compose.Err)
	}
	if dur == 0 {
		t.Error("expected non-zero duration for supply chain verification")
	}
}

// ---------------------------------------------------------------------------
// buildUpstreamBody — Encryptor paths
// ---------------------------------------------------------------------------

// TestBuildUpstreamBody_FreshRaw_WithKey_EncryptorError verifies that when
// freshRaw has a non-empty SigningKey, buildUpstreamBody delegates to
// prov.Encryptor and returns its error.
func TestBuildUpstreamBody_FreshRaw_WithKey_EncryptorError(t *testing.T) {
	s := newMinimalServer()
	mockEnc := &mockRequestEncryptor{err: errors.New("mock encrypt error")}
	prov := &provider.Provider{Name: "test", E2EE: false, Encryptor: mockEnc}
	freshRaw := &attestation.RawAttestation{SigningKey: "some-signing-key"}
	_, err := s.buildUpstreamBody(context.Background(), []byte(`{}`), "model", true, prov, freshRaw, "/chat")
	t.Logf("buildUpstreamBody(fresh key, encryptor error): err=%v", err)
	if err == nil {
		t.Error("expected error from mock encryptor")
	}
	if !strings.Contains(err.Error(), "mock encrypt error") {
		t.Errorf("error %q should mention 'mock encrypt error'", err.Error())
	}
}

// TestBuildUpstreamBody_FreshRaw_WithKey_Success verifies that when freshRaw
// has a non-empty SigningKey and Encryptor succeeds, buildUpstreamBody returns
// a non-nil upstreamBody.
func TestBuildUpstreamBody_FreshRaw_WithKey_Success(t *testing.T) {
	s := newMinimalServer()
	mockEnc := &mockRequestEncryptor{} // err == nil → success
	prov := &provider.Provider{Name: "test", E2EE: false, Encryptor: mockEnc}
	freshRaw := &attestation.RawAttestation{SigningKey: "some-signing-key"}
	body, err := s.buildUpstreamBody(context.Background(), []byte(`{}`), "model", true, prov, freshRaw, "/chat")
	t.Logf("buildUpstreamBody(fresh key, success): body=%v err=%v", body, err)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if body == nil {
		t.Error("expected non-nil upstreamBody on success")
	}
}

// TestBuildUpstreamBody_CachedSigningKey verifies that when a signing key is
// in the cache and freshRaw is nil, buildUpstreamBody uses the cached key and
// calls Encryptor (covering the signingKeyCache hit path).
func TestBuildUpstreamBody_CachedSigningKey(t *testing.T) {
	s := newMinimalServer()
	s.signingKeyCache.Put("test", "model", "cached-key-value")
	mockEnc := &mockRequestEncryptor{err: errors.New("encryptor reached with cached key")}
	prov := &provider.Provider{
		Name:                "test",
		E2EE:                false,
		Encryptor:           mockEnc,
		SkipSigningKeyCache: false,
		E2EEMaterialFetcher: nil,
	}
	_, err := s.buildUpstreamBody(context.Background(), []byte(`{}`), "model", true, prov, nil, "/chat")
	t.Logf("buildUpstreamBody(cached key): err=%v", err)
	// Encryptor was reached — it returned our sentinel error.
	if err == nil {
		t.Error("expected error from mock encryptor (cached key path)")
	}
	if !strings.Contains(err.Error(), "encryptor reached with cached key") {
		t.Errorf("error %q should mention 'encryptor reached with cached key'", err.Error())
	}
}

// TestBuildUpstreamBody_E2EEMaterialFetcher_NoCachedKey verifies the debug path
// when a nonce-pool fetcher is set but the signing key cache is empty.
// Falls through to fresh attestation (which fails because Attester returns error).
func TestBuildUpstreamBody_E2EEMaterialFetcher_NoCachedKey(t *testing.T) {
	s := newMinimalServer()
	// No key in signingKeyCache — forces "no cached signing key; skipping nonce pool".
	fetcher := &mockE2EEMaterialFetcher{}
	mockEnc := &mockRequestEncryptor{}
	mockAtt := &mockAttester{err: errors.New("mock attester error")}
	prov := &provider.Provider{
		Name:                "test",
		E2EE:                false,
		Encryptor:           mockEnc,
		Attester:            mockAtt,
		E2EEMaterialFetcher: fetcher,
	}
	_, err := s.buildUpstreamBody(context.Background(), []byte(`{}`), "model", true, prov, nil, "/chat")
	t.Logf("buildUpstreamBody(no cached key): err=%v", err)
	// Falls through to fresh attest which returns our mock error.
	if err == nil {
		t.Error("expected error from mock attester")
	}
	if !strings.Contains(err.Error(), "mock attester error") {
		t.Errorf("error %q should mention 'mock attester error'", err.Error())
	}
}

// TestBuildUpstreamBody_E2EEMaterialFetcher_FetchError verifies the log path
// when FetchE2EEMaterial returns an error — falls through to fresh attestation.
func TestBuildUpstreamBody_E2EEMaterialFetcher_FetchError(t *testing.T) {
	s := newMinimalServer()
	s.signingKeyCache.Put("test", "model", "some-cached-key")
	fetcher := &mockE2EEMaterialFetcher{err: errors.New("fetch material error")}
	mockAtt := &mockAttester{err: errors.New("attester fallback error")}
	prov := &provider.Provider{
		Name:                "test",
		Encryptor:           &mockRequestEncryptor{},
		Attester:            mockAtt,
		E2EEMaterialFetcher: fetcher,
	}
	_, err := s.buildUpstreamBody(context.Background(), []byte(`{}`), "model", true, prov, nil, "/chat")
	t.Logf("buildUpstreamBody(fetch error): err=%v", err)
	// Falls through to fresh attest.
	if err == nil {
		t.Error("expected error from mock attester fallback")
	}
}

// TestBuildUpstreamBody_E2EEMaterialFetcher_KeyMismatch verifies that when the
// nonce pool returns a key different from the cached key, the pool is invalidated
// and fresh attestation is attempted.
func TestBuildUpstreamBody_E2EEMaterialFetcher_KeyMismatch(t *testing.T) {
	s := newMinimalServer()
	s.signingKeyCache.Put("test", "model", "cached-key-ABC")
	fetcher := &mockE2EEMaterialFetcher{
		material: &provider.E2EEMaterial{
			E2EPubKey:  "different-key-XYZ",
			InstanceID: "inst-1",
			ChuteID:    "chute-1",
		},
	}
	mockAtt := &mockAttester{err: errors.New("attester after invalidation")}
	prov := &provider.Provider{
		Name:                "test",
		Encryptor:           &mockRequestEncryptor{},
		Attester:            mockAtt,
		E2EEMaterialFetcher: fetcher,
	}
	_, err := s.buildUpstreamBody(context.Background(), []byte(`{}`), "model", true, prov, nil, "/chat")
	t.Logf("buildUpstreamBody(key mismatch): err=%v invalidated=%v", err, fetcher.invalidated)
	// Pool invalidated, falls through to fresh attest.
	if len(fetcher.invalidated) == 0 {
		t.Error("expected pool to be invalidated on key mismatch")
	}
	if fetcher.invalidated[0] != "chute-1" {
		t.Errorf("invalidated chuteID = %q, want %q", fetcher.invalidated[0], "chute-1")
	}
}

// TestBuildUpstreamBody_E2EEMaterialFetcher_KeyMatch verifies that when the
// nonce pool returns a key matching the cached key, the nonce pool data is used
// directly (no fresh attestation) and Encryptor is called.
func TestBuildUpstreamBody_E2EEMaterialFetcher_KeyMatch(t *testing.T) {
	s := newMinimalServer()
	matchKey := "matching-pub-key"
	s.signingKeyCache.Put("test", "model", matchKey)
	fetcher := &mockE2EEMaterialFetcher{
		material: &provider.E2EEMaterial{
			E2EPubKey:  matchKey,
			InstanceID: "inst-2",
			E2ENonce:   "nonce-xyz",
			ChuteID:    "chute-2",
		},
	}
	mockEnc := &mockRequestEncryptor{err: errors.New("encryptor called with nonce pool key")}
	prov := &provider.Provider{
		Name:                "test",
		Encryptor:           mockEnc,
		E2EEMaterialFetcher: fetcher,
	}
	_, err := s.buildUpstreamBody(context.Background(), []byte(`{}`), "model", true, prov, nil, "/chat")
	t.Logf("buildUpstreamBody(key match): err=%v", err)
	// Encryptor was reached via nonce pool path.
	if err == nil {
		t.Error("expected sentinel error from mock encryptor")
	}
	if !strings.Contains(err.Error(), "encryptor called with nonce pool key") {
		t.Errorf("error %q should come from mock encryptor", err.Error())
	}
}

// TestBuildUpstreamBody_FreshAttestation_AttesterError verifies the fresh-attestation
// path when no signing key is cached and no E2EEMaterialFetcher is set.
func TestBuildUpstreamBody_FreshAttestation_AttesterError(t *testing.T) {
	s := newMinimalServer()
	// Cache empty, no fetcher → raw == nil → fresh attest required.
	mockAtt := &mockAttester{err: errors.New("attester network error")}
	prov := &provider.Provider{
		Name:                "test",
		Attester:            mockAtt,
		SkipSigningKeyCache: false,
		E2EEMaterialFetcher: nil,
	}
	_, err := s.buildUpstreamBody(context.Background(), []byte(`{}`), "model", true, prov, nil, "/chat")
	t.Logf("buildUpstreamBody(fresh attest error): err=%v", err)
	if err == nil {
		t.Error("expected error from mock attester")
	}
	if !strings.Contains(err.Error(), "attester network error") {
		t.Errorf("error %q should mention attester error", err.Error())
	}
}

// ---------------------------------------------------------------------------
// handleEvents tests
// ---------------------------------------------------------------------------

// noFlushWriter is an http.ResponseWriter that does NOT implement http.Flusher.
// Used to exercise the "streaming not supported" path in handleEvents.
type noFlushWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newNoFlushWriter() *noFlushWriter {
	return &noFlushWriter{header: make(http.Header)}
}

func (w *noFlushWriter) Header() http.Header         { return w.header }
func (w *noFlushWriter) WriteHeader(code int)        { w.status = code }
func (w *noFlushWriter) Write(b []byte) (int, error) { return w.body.Write(b) }

// TestHandleEvents_TooManyConns verifies that handleEvents returns 503 when
// the SSE connection limit is already at maxSSEConns.
func TestHandleEvents_TooManyConns(t *testing.T) {
	s := newMinimalServer()
	s.sseConns.Store(maxSSEConns)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled so the handler exits quickly if it gets past the guard

	req := httptest.NewRequest(http.MethodGet, "/events", http.NoBody).WithContext(ctx)
	rec := httptest.NewRecorder()

	s.handleEvents(rec, req)

	t.Logf("handleEvents(too many conns): status=%d body=%q", rec.Code, rec.Body.String())
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	// Counter must be restored to maxSSEConns (the guard decrements it back).
	if got := s.sseConns.Load(); got != maxSSEConns {
		t.Errorf("sseConns after rejection = %d, want %d", got, maxSSEConns)
	}
}

// TestHandleEvents_FlusherNotSupported verifies that handleEvents returns 500
// when the ResponseWriter does not implement http.Flusher.
func TestHandleEvents_FlusherNotSupported(t *testing.T) {
	s := newMinimalServer()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := httptest.NewRequest(http.MethodGet, "/events", http.NoBody).WithContext(ctx)
	w := newNoFlushWriter()

	s.handleEvents(w, req)

	t.Logf("handleEvents(no flusher): status=%d body=%q", w.status, w.body.String())
	if w.status != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.status, http.StatusInternalServerError)
	}
	// sseConns must be back to 0 after the early return.
	if got := s.sseConns.Load(); got != 0 {
		t.Errorf("sseConns after no-flusher return = %d, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// rewriteModelInBody tests
// ---------------------------------------------------------------------------

func TestRewriteModelInBody_Chat(t *testing.T) {
	body := []byte(`{"model":"venice:qwen3-5b","messages":[{"role":"user","content":"hello"}],"stream":false}`)

	got, err := rewriteModelInBody("application/json", body, "application/json", "qwen3-5b")
	if err != nil {
		t.Fatalf("rewriteModelInBody: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if m["model"] != "qwen3-5b" {
		t.Errorf("model = %q, want %q", m["model"], "qwen3-5b")
	}
	t.Logf("rewritten body: %s", got)
}

func TestRewriteModelInBody_PreservesOtherFields(t *testing.T) {
	body := []byte(`{"model":"venice:qwen3-5b","messages":[{"role":"user","content":"hi"}],"stream":true,"temperature":0.7}`)

	got, err := rewriteModelInBody("application/json", body, "application/json", "qwen3-5b")
	if err != nil {
		t.Fatalf("rewriteModelInBody: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if m["model"] != "qwen3-5b" {
		t.Errorf("model = %q, want qwen3-5b", m["model"])
	}
	if m["stream"] != true {
		t.Errorf("stream = %v, want true", m["stream"])
	}
	if m["temperature"] != 0.7 {
		t.Errorf("temperature = %v, want 0.7", m["temperature"])
	}
	msgs, ok := m["messages"].([]any)
	if !ok || len(msgs) != 1 {
		t.Errorf("messages field not preserved: %v", m["messages"])
	}
	t.Logf("rewritten body: %s", got)
}

func TestRewriteModelInBody_Audio(t *testing.T) {
	const boundary = "testboundary"
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.SetBoundary(boundary); err != nil {
		t.Fatalf("SetBoundary: %v", err)
	}
	if err := mw.WriteField("model", "neardirect:whisper-large-v3"); err != nil {
		t.Fatalf("WriteField model: %v", err)
	}
	if err := mw.WriteField("language", "en"); err != nil {
		t.Fatalf("WriteField language: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	body := buf.Bytes()
	contentType := "multipart/form-data; boundary=" + boundary
	got, err := rewriteModelInBody(contentType, body, "", "whisper-large-v3")
	if err != nil {
		t.Fatalf("rewriteModelInBody: %v", err)
	}
	t.Logf("rewritten body length: %d", len(got))

	// Extract model field from rebuilt body.
	model, err := extractMultipartField(contentType, got, "model")
	if err != nil {
		t.Fatalf("extractMultipartField model: %v", err)
	}
	if model != "whisper-large-v3" {
		t.Errorf("model = %q, want %q", model, "whisper-large-v3")
	}

	// Verify other field is preserved.
	lang, err := extractMultipartField(contentType, got, "language")
	if err != nil {
		t.Fatalf("extractMultipartField language: %v", err)
	}
	if lang != "en" {
		t.Errorf("language = %q, want %q", lang, "en")
	}
}

func TestRewriteModelInBody_Audio_WithBinaryFile(t *testing.T) {
	const boundary = "testboundary"
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.SetBoundary(boundary); err != nil {
		t.Fatalf("SetBoundary: %v", err)
	}
	if err := mw.WriteField("model", "neardirect:whisper-large-v3"); err != nil {
		t.Fatalf("WriteField model: %v", err)
	}
	fw, err := mw.CreateFormFile("file", "test.wav")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	fileContent := []byte{0x52, 0x49, 0x46, 0x46, 0x00, 0xff, 0x00, 0xfe, 0x57, 0x41, 0x56, 0x45} // fake WAV header
	if _, err := fw.Write(fileContent); err != nil {
		t.Fatalf("Write file: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	body := buf.Bytes()
	contentType := "multipart/form-data; boundary=" + boundary
	got, err := rewriteModelInBody(contentType, body, "", "whisper-large-v3")
	if err != nil {
		t.Fatalf("rewriteModelInBody: %v", err)
	}
	t.Logf("rewritten body length: %d", len(got))

	// Verify model was rewritten.
	model, err := extractMultipartField(contentType, got, "model")
	if err != nil {
		t.Fatalf("extractMultipartField model: %v", err)
	}
	if model != "whisper-large-v3" {
		t.Errorf("model = %q, want %q", model, "whisper-large-v3")
	}

	// Verify binary file part survived intact.
	mr := multipart.NewReader(bytes.NewReader(got), boundary)
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		if p.FileName() != "test.wav" {
			_ = p.Close()
			continue
		}
		data, readErr := io.ReadAll(p)
		_ = p.Close()
		if readErr != nil {
			t.Fatalf("ReadAll file part: %v", readErr)
		}
		if !bytes.Equal(data, fileContent) {
			t.Errorf("file content corrupted: got %x, want %x", data, fileContent)
		}
		t.Logf("binary file part verified: %d bytes intact", len(data))
		return
	}
	t.Error("file part not found in rewritten body")
}
