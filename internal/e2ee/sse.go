package e2ee

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"sync"
)

const (
	// sseScannerBufSize is the bufio.Scanner buffer for SSE parsing.
	// Encrypted chunks can be large; 1 MiB is sufficient.
	sseScannerBufSize = 1 << 20 // 1 MiB
)

// sseScannerBufPool reuses 1 MiB scanner buffers across SSE requests.
var sseScannerBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, sseScannerBufSize)
		return &buf
	},
}

// newSSEScanner creates a bufio.Scanner backed by a pooled 1 MiB buffer.
// The caller must call the returned cleanup function (defer it) to return
// the buffer to the pool.
func newSSEScanner(body io.Reader) (scanner *bufio.Scanner, cleanup func()) {
	scanner = bufio.NewScanner(body)
	bufp, ok := sseScannerBufPool.Get().(*[]byte)
	if !ok {
		panic("sseScannerBufPool: unexpected type")
	}
	scanner.Buffer((*bufp)[:cap(*bufp)], sseScannerBufSize)
	return scanner, func() { sseScannerBufPool.Put(bufp) }
}

// WriteSSEError writes an SSE error event and flushes. Used when streaming
// has already started and we can't use http.Error.
func WriteSSEError(w http.ResponseWriter, flusher http.Flusher, msg string) {
	fmt.Fprintf(w, "event: error\ndata: {\"error\":{\"message\":%q,\"type\":\"decryption_error\"}}\n\n", msg)
	flusher.Flush()
}

// SafePrefix returns up to n characters of s for safe use in log messages.
func SafePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
