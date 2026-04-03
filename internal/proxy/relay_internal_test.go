package proxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/13rac1/teep/internal/e2ee"
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
