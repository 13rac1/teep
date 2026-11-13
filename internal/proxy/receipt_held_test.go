package proxy

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/13rac1/teep/internal/e2ee"
)

// A held non-stream response is bounded: a body over the bound fails, and
// release writes nothing even when the writer of the body ignored the error.
func TestHeldResponseBound(t *testing.T) {
	w := httptest.NewRecorder()
	h := &heldResponse{header: w.Header()}
	if _, err := h.Write(bytes.Repeat([]byte("a"), e2ee.MaxNonStreamResponseBytes)); err != nil {
		t.Fatalf("a body at the bound failed: %v", err)
	}
	if _, err := h.Write([]byte("b")); !errors.Is(err, errHeldResponseTooLarge) {
		t.Fatalf("Write over the bound = %v", err)
	}
	if err := h.release(w); !errors.Is(err, errHeldResponseTooLarge) || w.Body.Len() != 0 {
		t.Fatalf("release = %v, wrote %d bytes", err, w.Body.Len())
	}

	ok := httptest.NewRecorder()
	h = &heldResponse{header: ok.Header()}
	h.WriteHeader(http.StatusOK)
	if _, err := h.Write([]byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := h.release(ok); err != nil || ok.Body.String() != "{}" {
		t.Fatalf("release = %v, body %q", err, ok.Body.String())
	}
}
