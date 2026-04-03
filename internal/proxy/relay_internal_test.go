package proxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
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
	ri := &responseInterceptor{ResponseWriter: rec}

	// Flush should not panic and should work through to the underlying writer.
	ri.Flush()
}

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
