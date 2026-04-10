package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
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
		cache:           attestation.NewCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(time.Minute),
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
