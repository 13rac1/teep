package reqid_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"log/slog"
	"testing"

	"github.com/13rac1/teep/internal/reqid"
)

func TestNew(t *testing.T) {
	id := reqid.New()
	t.Logf("generated ID: %s", id)
	if len(id) != 8 {
		t.Fatalf("expected 8-char hex, got %d chars: %q", len(id), id)
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Fatalf("not valid hex: %v", err)
	}
}

func TestFromContext_Empty(t *testing.T) {
	id := reqid.FromContext(context.Background())
	t.Logf("empty context ID: %q", id)
	if id != "" {
		t.Fatalf("expected empty string, got %q", id)
	}
}

func TestRoundTrip(t *testing.T) {
	ctx := reqid.WithID(context.Background(), "deadbeef")
	got := reqid.FromContext(ctx)
	t.Logf("round-trip ID: %s", got)
	if got != "deadbeef" {
		t.Fatalf("expected deadbeef, got %q", got)
	}
}

func TestHandler_AddsReqAttr(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(reqid.NewHandler(base))

	ctx := reqid.WithID(context.Background(), "abc12345")
	logger.InfoContext(ctx, "test message", "key", "val")

	out := buf.String()
	t.Logf("log output: %s", out)
	if !bytes.Contains(buf.Bytes(), []byte("req=abc12345")) {
		t.Fatalf("expected req=abc12345 in log output: %s", out)
	}
	if !bytes.Contains(buf.Bytes(), []byte("key=val")) {
		t.Fatalf("expected key=val in log output: %s", out)
	}
}

func TestHandler_NoContext(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(reqid.NewHandler(base))

	logger.Info("no context")

	out := buf.String()
	t.Logf("log output: %s", out)
	if bytes.Contains(buf.Bytes(), []byte("req=")) {
		t.Fatalf("expected no req= in log output: %s", out)
	}
}
