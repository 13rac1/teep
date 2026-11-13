package aci

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
)

// MaxResponseTail bounds the response bytes that ResponseHash.Finish reads
// after the reader of the response stops.
const MaxResponseTail = 1 << 20

// ResponseHash reads a response body and hashes its wire bytes, which
// response.returned of the receipt states (§7.4). The gateway hashes the
// bytes that it sends, before any decryption.
type ResponseHash struct {
	sum  hash.Hash
	wire io.Reader
}

// NewResponseHash returns a reader of body that hashes what it reads.
func NewResponseHash(body io.Reader) *ResponseHash {
	h := &ResponseHash{sum: sha256.New()}
	h.wire = io.TeeReader(body, h.sum)
	return h
}

func (h *ResponseHash) Read(p []byte) (int, error) { return h.wire.Read(p) }

// Finish reads the bytes that the reader left, up to MaxResponseTail, and
// returns the sha256 of the whole body.
func (h *ResponseHash) Finish() ([32]byte, error) {
	n, err := io.Copy(io.Discard, io.LimitReader(h.wire, MaxResponseTail+1))
	if err != nil {
		return [32]byte{}, fmt.Errorf("read the end of the response: %w", err)
	}
	if n > MaxResponseTail {
		return [32]byte{}, fmt.Errorf("response continues for more than %d bytes after the reader stopped", MaxResponseTail)
	}
	var out [32]byte
	copy(out[:], h.sum.Sum(nil))
	return out, nil
}
