package proxy

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/e2ee"
)

type canceledStreamReader struct{}

func (canceledStreamReader) Read([]byte) (int, error) { return 0, context.Canceled }

func TestStreamReadFailureDiagnostics(t *testing.T) {
	started := time.Now()
	reader := &responseReadProgress{Reader: io.MultiReader(strings.NewReader(": heartbeat\n\n"), canceledStreamReader{})}
	_, err := io.Copy(io.Discard, reader)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	attrs := streamFailureDiagnostics(started, e2ee.StreamStats{}, reader, &responseLifetime{failedOperation: "downstream_write"})
	values := diagnosticFields(t, attrs)
	if values["response_io_failure"] != "downstream_write" || values["response_body_read_failed"] != true || values["stream_chunks_processed"] != int64(0) || values["response_body_bytes_read"] != int64(13) {
		t.Fatalf("incorrect read diagnostics: %v", values)
	}
	if _, ok := values["stream_last_chunk_ago"]; ok {
		t.Fatal("heartbeat counted as a data chunk")
	}
	if _, ok := values["response_last_read_ago"]; !ok {
		t.Fatal("missing heartbeat read progress")
	}
}

type partialDiagnosticWriter struct{ *inferenceRecorder }

func (partialDiagnosticWriter) Write([]byte) (int, error) { return 2, io.ErrClosedPipe }

func TestDownstreamProgressCountsPartialWrites(t *testing.T) {
	interceptor, writer := newResponseInterceptor(partialDiagnosticWriter{newInferenceRecorder()})
	if interceptor.headerSent || interceptor.bytesWritten != 0 {
		t.Fatal("new response already reports downstream progress")
	}
	n, err := writer.Write([]byte("test"))
	if n != 2 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("partial write result changed: n=%d err=%v", n, err)
	}
	if !interceptor.headerSent || interceptor.bytesWritten != 2 {
		t.Fatalf("incorrect partial progress: headers=%v bytes=%d", interceptor.headerSent, interceptor.bytesWritten)
	}
}
