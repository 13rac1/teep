// Package reqid provides request correlation IDs for structured logging.
//
// Generate an ID with [New], store it in context with [WithID], and wrap
// your slog handler with [NewHandler] so that every slog.*Context call
// automatically includes a "req" attribute.
package reqid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
)

type ctxKey struct{}

// New generates an 8-character hex request ID (4 random bytes).
func New() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b[:])
}

// WithID stores a request ID in the context.
func WithID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext retrieves the request ID from ctx, or "" if absent.
func FromContext(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

// handler wraps a slog.Handler to prepend "req" from context.
type handler struct {
	next slog.Handler
}

// NewHandler wraps next so that every record with a request ID in its
// context gets a "req" attribute prepended.
func NewHandler(next slog.Handler) slog.Handler {
	return &handler{next: next}
}

func (h *handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error { //nolint:gocritic // slog.Handler interface requires value receiver
	if id := FromContext(ctx); id != "" {
		r.AddAttrs(slog.String("req", id))
	}
	return h.next.Handle(ctx, r)
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &handler{next: h.next.WithAttrs(attrs)}
}

func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{next: h.next.WithGroup(name)}
}
