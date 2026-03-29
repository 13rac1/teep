package e2ee

import (
	"fmt"
	"net/http"
	"sync"
)

const (
	// SSEScannerBufSize is the bufio.Scanner buffer for SSE parsing.
	// Encrypted chunks can be large; 1 MiB is sufficient.
	SSEScannerBufSize = 1 << 20 // 1 MiB
)

// SSEScannerBufPool reuses 1 MiB scanner buffers across SSE requests.
var SSEScannerBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, SSEScannerBufSize)
		return &buf
	},
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
