package e2ee

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// SSEData returns an SSE data field, removing its one optional leading space.
// A field without a colon has an empty value under the SSE framing rules.
func SSEData(line string) (string, bool) {
	field, value, _ := strings.Cut(line, ":")
	return strings.TrimPrefix(value, " "), field == "data"
}

// splitSSELine accepts LF, CRLF, and CR without exposing embedded line breaks
// to a downstream SSE parser.
func splitSSELine(data []byte, atEOF bool) (advance int, token []byte) {
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		end := i + 1
		if data[i] == '\r' {
			if end == len(data) && !atEOF {
				return 0, nil
			}
			if end < len(data) && data[end] == '\n' {
				end++
			}
		}
		return end, data[:i]
	}
	if atEOF && len(data) > 0 {
		return len(data), data
	}
	return 0, nil
}

// CheckSSEEvent rejects an explicit provider error event without exposing its data.
func CheckSSEEvent(line string) error {
	if event, ok := strings.CutPrefix(line, "event:"); ok && strings.TrimSpace(event) == "error" {
		return errors.New("upstream SSE error event")
	}
	return nil
}

// CheckSSEEndMarker requires the NEAR chat completion marker. Other protocols
// retain their own completion rules, including EHBP frame authentication.
func CheckSSEEndMarker(session Decryptor, endpoint EndpointType, seen bool) error {
	if _, near := session.(*NearCloudSession); near && endpoint == EndpointChat && !seen {
		return errors.New("NEAR SSE stream ended without [DONE]")
	}
	return nil
}

// FinishSSE reads to EOF after the application end marker. Only bounded empty
// lines and SSE comments may follow it. Reading through the scanner preserves
// buffered bytes and propagates errors from an underlying authenticated reader.
func FinishSSE(scanner *bufio.Scanner) error {
	const maxTrailingBytes = 64 << 10
	remaining := maxTrailingBytes
	for scanner.Scan() {
		line := scanner.Text()
		remaining -= len(line) + 1
		if remaining < 0 {
			return errors.New("SSE data after end marker exceeds limit")
		}
		if line != "" && !strings.HasPrefix(line, ":") {
			return errors.New("unexpected SSE data after end marker")
		}
	}
	return scanner.Err()
}

// NewSSEScanner creates a bufio.Scanner backed by a pooled 1 MiB buffer.
// The caller must call the returned cleanup function (defer it) to return
// the buffer to the pool.
func NewSSEScanner(body io.Reader) (scanner *bufio.Scanner, cleanup func()) {
	scanner = bufio.NewScanner(body)
	first := true
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		advance, line := splitSSELine(data, atEOF)
		if first && line != nil {
			line = bytes.TrimPrefix(line, []byte("\uFEFF"))
			first = false
		}
		return advance, line, nil
	})
	bufp, ok := sseScannerBufPool.Get().(*[]byte)
	if !ok {
		panic("sseScannerBufPool: unexpected type")
	}
	scanner.Buffer((*bufp)[:cap(*bufp)], sseScannerBufSize)
	return scanner, func() {
		clear(*bufp)
		sseScannerBufPool.Put(bufp)
	}
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
