package e2ee

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"

	"golang.org/x/crypto/hkdf"
)

// maxChunkSize is the maximum allowed EHBP chunk payload (16 MiB).
// Chunk length prefixes larger than this are rejected before allocation.
const maxChunkSize = 16 * 1024 * 1024

// ehbpChunkSize is the plaintext chunk size for streaming request encryption
// (8 KiB), matching the Tinfoil reference implementation.
const ehbpChunkSize = 8192

// maxChunkIdx is the maximum chunk index (2^31 - 1). The overflow check
// fires at this value to prevent nonce reuse from counter wrap.
const maxChunkIdx = math.MaxInt32

// EHBPSession holds per-request EHBP state for encrypt+decrypt.
type EHBPSession struct {
	encapKey  []byte       // 32-byte encapsulated key
	senderCtx *hpke.Sender // HPKE sender context for Seal + Export
}

// NewEHBPSession creates a new EHBP session by performing HPKE SetupBaseS
// with the server's X25519 public key (32 bytes raw).
func NewEHBPSession(serverPubKey []byte) (*EHBPSession, error) {
	ecdhPub, err := ecdh.X25519().NewPublicKey(serverPubKey)
	if err != nil {
		return nil, fmt.Errorf("ehbp: parse X25519 public key: %w", err)
	}
	hpkePub, err := hpke.NewDHKEMPublicKey(ecdhPub)
	if err != nil {
		return nil, fmt.Errorf("ehbp: create HPKE public key: %w", err)
	}
	enc, sender, err := hpke.NewSender(hpkePub, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte("ehbp request"))
	if err != nil {
		return nil, fmt.Errorf("ehbp: HPKE SetupBaseS: %w", err)
	}
	return &EHBPSession{
		encapKey:  enc,
		senderCtx: sender,
	}, nil
}

// EncryptRequest returns a streaming reader that encrypts the request body
// into EHBP chunk framing. Each chunk: [4-byte big-endian length][AEAD ciphertext].
// The HPKE context's Seal auto-increments the nonce per chunk.
// Plaintext is read in ehbpChunkSize (8 KiB) chunks to avoid buffering the
// entire body in memory.
func (s *EHBPSession) EncryptRequest(body io.Reader) io.Reader {
	return &ehbpRequestReader{
		body:   body,
		sender: s.senderCtx,
	}
}

// ehbpRequestReader encrypts plaintext from body into EHBP chunked frames.
type ehbpRequestReader struct {
	body    io.Reader
	sender  *hpke.Sender
	pending []byte // buffered framed ciphertext not yet returned
	done    bool
}

func (r *ehbpRequestReader) Read(p []byte) (int, error) {
	// Drain any buffered data from a previous chunk.
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}
	if r.done {
		return 0, io.EOF
	}

	// Read up to ehbpChunkSize plaintext bytes.
	plaintext := make([]byte, ehbpChunkSize)
	n, err := r.body.Read(plaintext)
	if n == 0 && err != nil {
		r.done = true
		if errors.Is(err, io.EOF) {
			return 0, io.EOF
		}
		return 0, fmt.Errorf("ehbp: read request body: %w", err)
	}

	ciphertext, sealErr := r.sender.Seal(nil, plaintext[:n])
	if sealErr != nil {
		r.done = true
		return 0, fmt.Errorf("ehbp: seal request chunk: %w", sealErr)
	}

	// Frame: [4-byte big-endian length][ciphertext]
	frame := make([]byte, 4+len(ciphertext))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(ciphertext))) //nolint:gosec // bounded by ehbpChunkSize (8 KiB) + AEAD overhead
	copy(frame[4:], ciphertext)

	copied := copy(p, frame)
	if copied < len(frame) {
		r.pending = frame[copied:]
	}

	// If the underlying read hit EOF, we're done after this chunk.
	if errors.Is(err, io.EOF) {
		r.done = true
	}

	return copied, nil
}

// EncapKeyHex returns the lowercase hex-encoded encapsulated key for the
// Ehbp-Encapsulated-Key request header (32 bytes → 64 hex chars).
func (s *EHBPSession) EncapKeyHex() string {
	return hex.EncodeToString(s.encapKey)
}

// DecryptResponse decrypts an EHBP-encrypted response body using the
// response nonce from the Ehbp-Response-Nonce header.
// responseNonceHex is the hex-encoded 32-byte nonce (64 hex chars).
func (s *EHBPSession) DecryptResponse(body io.Reader, responseNonceHex string) (io.ReadCloser, error) {
	responseNonce, err := hex.DecodeString(responseNonceHex)
	if err != nil {
		return nil, fmt.Errorf("ehbp: decode response nonce hex: %w", err)
	}
	if len(responseNonce) != 32 {
		return nil, fmt.Errorf("ehbp: response nonce wrong size: %d bytes, want 32", len(responseNonce))
	}

	// Export secret from HPKE sender context.
	secret, err := s.senderCtx.Export("ehbp response", 32)
	if err != nil {
		return nil, fmt.Errorf("ehbp: HPKE export: %w", err)
	}
	defer clear(secret)

	// Construct salt: encapKey || responseNonce
	salt := make([]byte, 0, len(s.encapKey)+len(responseNonce))
	salt = append(salt, s.encapKey...)
	salt = append(salt, responseNonce...)

	// HKDF-Extract + Expand for key and nonce.
	prk := hkdf.Extract(sha256.New, secret, salt)
	defer clear(prk)

	aeadKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("key")), aeadKey); err != nil {
		return nil, fmt.Errorf("ehbp: hkdf expand key: %w", err)
	}
	defer clear(aeadKey)
	aeadNonce := make([]byte, 12)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("nonce")), aeadNonce); err != nil {
		return nil, fmt.Errorf("ehbp: hkdf expand nonce: %w", err)
	}

	// Create AES-256-GCM AEAD.
	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, fmt.Errorf("ehbp: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ehbp: cipher.NewGCM: %w", err)
	}

	return &ehbpResponseReader{
		body:      body,
		gcm:       gcm,
		baseNonce: aeadNonce,
		chunkIdx:  0,
	}, nil
}

// Zero clears key material. Note: the HPKE sender context's internal shared
// secret cannot be zeroed because crypto/hpke does not expose a method to
// overwrite internal state. The secret persists until GC reclaims the memory.
// This matches the limitation documented in ChutesSession.Zero().
func (s *EHBPSession) Zero() {
	clear(s.encapKey)
	s.encapKey = nil
	s.senderCtx = nil
}

// ehbpResponseReader decrypts EHBP chunked response frames on the fly.
// Each Read returns one decrypted chunk.
type ehbpResponseReader struct {
	body      io.Reader
	gcm       cipher.AEAD
	baseNonce []byte // 12-byte base nonce
	chunkIdx  uint64
	pending   []byte // buffered plaintext from current chunk
	done      bool
}

func (r *ehbpResponseReader) Read(p []byte) (int, error) {
	// Drain any buffered plaintext from a previous chunk.
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}
	if r.done {
		return 0, io.EOF
	}

	// Check chunk index limit before consuming any wire bytes.
	if r.chunkIdx >= maxChunkIdx {
		r.done = true
		return 0, errors.New("ehbp: chunk index overflow (>=2^31-1)")
	}

	// Read next chunk length prefix.
	var lenBuf [4]byte
	_, err := io.ReadFull(r.body, lenBuf[:])
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			r.done = true
			return 0, io.EOF
		}
		return 0, fmt.Errorf("ehbp: read chunk length: %w", err)
	}

	chunkLen := binary.BigEndian.Uint32(lenBuf[:])
	if chunkLen > maxChunkSize {
		r.done = true
		return 0, fmt.Errorf("ehbp: chunk size %d exceeds maximum %d", chunkLen, maxChunkSize)
	}

	// Read ciphertext.
	ciphertext := make([]byte, chunkLen)
	if _, err := io.ReadFull(r.body, ciphertext); err != nil {
		r.done = true
		return 0, fmt.Errorf("ehbp: read chunk ciphertext: %w", err)
	}

	// Compute nonce: baseNonce XOR chunkIdx (big-endian uint64 in bytes [4:12]).
	nonce := make([]byte, 12)
	copy(nonce, r.baseNonce)
	var counterBuf [8]byte
	binary.BigEndian.PutUint64(counterBuf[:], r.chunkIdx)
	for i := range 8 {
		nonce[4+i] ^= counterBuf[i]
	}
	r.chunkIdx++

	plaintext, err := r.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		r.done = true
		return 0, fmt.Errorf("ehbp: AEAD authentication failed at chunk %d: %w", r.chunkIdx-1, err)
	}

	n := copy(p, plaintext)
	if n < len(plaintext) {
		r.pending = plaintext[n:]
	}
	return n, nil
}

func (r *ehbpResponseReader) Close() error {
	r.done = true
	r.pending = nil
	clear(r.baseNonce)
	r.baseNonce = nil
	r.gcm = nil // cipher.AEAD does not expose key zeroing; nil for GC
	return nil
}
