package aci

import (
	"crypto/sha256"
	"io"
	"strings"
	"testing"
)

// Finish hashes the whole body, also the bytes after the point where the
// reader stopped, and fails when more than MaxResponseTail bytes follow.
func TestResponseHash(t *testing.T) {
	body := "data: {}\n\ndata: [DONE]\n\n: trailing comment\n"
	h := NewResponseHash(strings.NewReader(body))
	if _, err := io.ReadFull(h, make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	sum, err := h.Finish()
	if err != nil || sum != sha256.Sum256([]byte(body)) {
		t.Fatalf("Finish = %x, %v; want the hash of the whole body", sum, err)
	}

	long := NewResponseHash(strings.NewReader(strings.Repeat("x", MaxResponseTail+1)))
	if _, err := long.Finish(); err == nil {
		t.Fatal("Finish accepted a tail longer than MaxResponseTail")
	}
}
