package proxy

import (
	"io"
	"log/slog"
	"time"

	"github.com/13rac1/teep/internal/e2ee"
)

// responseReadProgress belongs to one relay goroutine. It records progress at
// the relay input, after any outer response decryption, without retaining data.
type responseReadProgress struct {
	io.Reader
	bytes    int64
	lastRead time.Time
	failed   bool
}

func (r *responseReadProgress) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.bytes += int64(n)
	if n > 0 {
		r.lastRead = time.Now()
	}
	if err != nil && err != io.EOF {
		r.failed = true
	}
	return n, err
}

func streamFailureDiagnostics(started time.Time, stats e2ee.StreamStats, reader *responseReadProgress, writer *responseLifetime) []slog.Attr {
	attrs := append(responseFailureDiagnostics(reader, writer),
		slog.Duration("stream_elapsed", time.Since(started)),
		slog.Int("stream_chunks_processed", stats.Chunks),
		slog.Bool("stream_end_marker_seen", stats.EndMarkerSeen),
	)
	if !stats.LastChunkAt.IsZero() {
		attrs = append(attrs, slog.Duration("stream_last_chunk_ago", time.Since(stats.LastChunkAt)))
	}
	return attrs
}

func responseFailureDiagnostics(reader *responseReadProgress, writer *responseLifetime) []slog.Attr {
	attrs := []slog.Attr{
		slog.Int64("response_body_bytes_read", reader.bytes),
		slog.Bool("response_body_read_failed", reader.failed),
	}
	if !reader.lastRead.IsZero() {
		attrs = append(attrs, slog.Duration("response_last_read_ago", time.Since(reader.lastRead)))
	}
	// Preserve a read failure even if writing the error response also fails.
	// The operation field identifies the downstream failure when both occur.
	operation := writer.failedOperation
	if operation == "" && reader.failed {
		operation = "response_body_read"
	}
	if operation != "" {
		attrs = append(attrs, slog.String("response_io_failure", operation))
	}
	return attrs
}
