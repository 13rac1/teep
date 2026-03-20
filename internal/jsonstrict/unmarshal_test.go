package jsonstrict_test

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/jsonstrict"
)

// testStruct is the target for most tests.
type testStruct struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

// embeddedParent embeds embeddedInner to test embedded struct handling.
type embeddedInner struct {
	InnerField string `json:"inner_field"`
}

type embeddedParent struct {
	embeddedInner
	Outer string `json:"outer"`
}

// dashStruct has a field tagged json:"-" that should be excluded.
type dashStruct struct {
	Visible string `json:"visible"`
	Hidden  string `json:"-"`
}

// omitemptyStruct has a field with the omitempty option.
type omitemptyStruct struct {
	Field string `json:"field,omitempty"`
}

// untaggedStruct has a field with no json tag (falls back to Go name).
type untaggedStruct struct {
	GoName string
}

// recordingHandler captures slog records for test assertions.
type recordingHandler struct {
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler            { return h }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error { //nolint:gocritic // hugeParam: slog.Handler interface requires value receiver
	h.records = append(h.records, r)
	return nil
}

// withRecorder swaps the default slog logger with a recording handler for the
// duration of the test and returns the handler for inspection.
func withRecorder(t *testing.T) *recordingHandler {
	t.Helper()
	h := &recordingHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return h
}

// warns returns records at Warn level.
func warns(h *recordingHandler) []slog.Record {
	var out []slog.Record
	for i := range h.records {
		if h.records[i].Level == slog.LevelWarn {
			out = append(out, h.records[i])
		}
	}
	return out
}

// recordFields extracts the "fields" attribute from a record as a string slice.
func recordFields(r *slog.Record) []string {
	var fields []string
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "fields" {
			// slog stores []string as a Group of indexed attrs.
			// Use the string representation and parse it.
			s := a.Value.String()
			s = strings.Trim(s, "[]")
			if s != "" {
				fields = strings.Split(s, " ")
			}
		}
		return true
	})
	return fields
}

func TestUnmarshalWarn_NoUnknownFields(t *testing.T) {
	h := withRecorder(t)
	var v testStruct
	err := jsonstrict.UnmarshalWarn([]byte(`{"name":"alice","value":42}`), &v, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Name != "alice" || v.Value != 42 {
		t.Errorf("decode wrong: got %+v", v)
	}
	if len(warns(h)) != 0 {
		t.Errorf("expected no warnings, got %d", len(warns(h)))
	}
}

func TestUnmarshalWarn_UnknownFields(t *testing.T) {
	h := withRecorder(t)
	var v testStruct
	err := jsonstrict.UnmarshalWarn([]byte(`{"name":"bob","value":1,"extra":"x"}`), &v, "test ctx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Name != "bob" {
		t.Errorf("decode wrong: got %+v", v)
	}
	w := warns(h)
	if len(w) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(w))
	}
	fields := recordFields(&w[0])
	if !slices.Contains(fields, "extra") {
		t.Errorf("warning should mention 'extra', got fields=%v", fields)
	}
}

func TestUnmarshalWarn_MultipleUnknownFields(t *testing.T) {
	h := withRecorder(t)
	var v testStruct
	data := `{"name":"c","value":0,"a":"1","b":"2","c":"3"}`
	err := jsonstrict.UnmarshalWarn([]byte(data), &v, "multi")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	w := warns(h)
	if len(w) != 1 {
		t.Fatalf("expected 1 warning (not one per field), got %d", len(w))
	}
	fields := recordFields(&w[0])
	if len(fields) != 3 {
		t.Errorf("expected 3 unknown fields, got %d: %v", len(fields), fields)
	}
}

func TestUnmarshalWarn_InvalidJSON(t *testing.T) {
	h := withRecorder(t)
	var v testStruct
	err := jsonstrict.UnmarshalWarn([]byte(`not json`), &v, "bad")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if len(warns(h)) != 0 {
		t.Error("should not warn on invalid JSON")
	}
}

func TestUnmarshalWarn_ContextInWarning(t *testing.T) {
	h := withRecorder(t)
	var v testStruct
	_ = jsonstrict.UnmarshalWarn([]byte(`{"name":"x","unknown":1}`), &v, "venice attestation response")
	w := warns(h)
	if len(w) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(w))
	}
	var ctx string
	w[0].Attrs(func(a slog.Attr) bool {
		if a.Key == "context" {
			ctx = a.Value.String()
		}
		return true
	})
	if ctx != "venice attestation response" {
		t.Errorf("context attr: got %q, want %q", ctx, "venice attestation response")
	}
}

func TestUnmarshalWarn_EmbeddedStruct(t *testing.T) {
	h := withRecorder(t)
	var v embeddedParent
	data := `{"inner_field":"i","outer":"o"}`
	err := jsonstrict.UnmarshalWarn([]byte(data), &v, "embed")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warns(h)) != 0 {
		t.Errorf("embedded fields should be known, got %d warnings", len(warns(h)))
	}
	if v.InnerField != "i" || v.Outer != "o" {
		t.Errorf("decode wrong: got %+v", v)
	}
}

func TestUnmarshalWarn_DashExcluded(t *testing.T) {
	h := withRecorder(t)
	var v dashStruct
	// "Hidden" is the Go field name, which would be the fallback if not tagged "-".
	// Since it IS tagged "-", "Hidden" in JSON should be unknown.
	data := `{"visible":"v","Hidden":"h"}`
	err := jsonstrict.UnmarshalWarn([]byte(data), &v, "dash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	w := warns(h)
	if len(w) != 1 {
		t.Fatalf("expected 1 warning for json:\"-\" field, got %d", len(w))
	}
}

func TestUnmarshalWarn_OmitemptyStripped(t *testing.T) {
	h := withRecorder(t)
	var v omitemptyStruct
	data := `{"field":"val"}`
	err := jsonstrict.UnmarshalWarn([]byte(data), &v, "omit")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warns(h)) != 0 {
		t.Errorf("field with omitempty should be known, got %d warnings", len(warns(h)))
	}
}

func TestUnmarshalWarn_UntaggedField(t *testing.T) {
	h := withRecorder(t)
	var v untaggedStruct
	data := `{"GoName":"val"}`
	err := jsonstrict.UnmarshalWarn([]byte(data), &v, "untag")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warns(h)) != 0 {
		t.Errorf("untagged field should use Go name, got %d warnings", len(warns(h)))
	}
	if v.GoName != "val" {
		t.Errorf("decode wrong: got %+v", v)
	}
}
