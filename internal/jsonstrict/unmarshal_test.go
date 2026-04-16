package jsonstrict_test

import (
	"slices"
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

// PtrEmbeddedInner is the target for pointer-embedded struct tests.
// Exported because encoding/json requires embedded pointer targets to be
// exported when used from external test packages.
type PtrEmbeddedInner struct {
	Deep string `json:"deep"`
}

type ptrEmbeddedParent struct {
	*PtrEmbeddedInner
	Top string `json:"top"`
}

func TestUnmarshal_NoUnknownFields(t *testing.T) {
	var v testStruct
	unknown, err := jsonstrict.Unmarshal([]byte(`{"name":"alice","value":42}`), &v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Name != "alice" || v.Value != 42 {
		t.Errorf("decode wrong: got %+v", v)
	}
	if len(unknown) != 0 {
		t.Errorf("expected no unknown fields, got %v", unknown)
	}
}

func TestUnmarshal_UnknownFields(t *testing.T) {
	var v testStruct
	unknown, err := jsonstrict.Unmarshal([]byte(`{"name":"bob","value":1,"extra":"x"}`), &v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Name != "bob" {
		t.Errorf("decode wrong: got %+v", v)
	}
	if !slices.Contains(unknown, "extra") {
		t.Errorf("unknown fields should contain 'extra', got %v", unknown)
	}
}

func TestUnmarshal_MultipleUnknownFields(t *testing.T) {
	var v testStruct
	data := `{"name":"c","value":0,"a":"1","b":"2","c":"3"}`
	unknown, err := jsonstrict.Unmarshal([]byte(data), &v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(unknown) != 3 {
		t.Errorf("expected 3 unknown fields, got %d: %v", len(unknown), unknown)
	}
	// Must be sorted.
	if !slices.IsSorted(unknown) {
		t.Errorf("unknown fields should be sorted, got %v", unknown)
	}
}

func TestUnmarshal_InvalidJSON(t *testing.T) {
	var v testStruct
	unknown, err := jsonstrict.Unmarshal([]byte(`not json`), &v)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if len(unknown) != 0 {
		t.Errorf("should not report unknown fields on invalid JSON, got %v", unknown)
	}
}

func TestUnmarshal_EmbeddedStruct(t *testing.T) {
	var v embeddedParent
	data := `{"inner_field":"i","outer":"o"}`
	unknown, err := jsonstrict.Unmarshal([]byte(data), &v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(unknown) != 0 {
		t.Errorf("embedded fields should be known, got %v", unknown)
	}
	if v.InnerField != "i" || v.Outer != "o" {
		t.Errorf("decode wrong: got %+v", v)
	}
}

func TestUnmarshal_DashExcluded(t *testing.T) {
	var v dashStruct
	// "Hidden" is the Go field name, which would be the fallback if not tagged "-".
	// Since it IS tagged "-", "Hidden" in JSON should be unknown.
	data := `{"visible":"v","Hidden":"h"}`
	unknown, err := jsonstrict.Unmarshal([]byte(data), &v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Contains(unknown, "Hidden") {
		t.Errorf("json:\"-\" field should be unknown, got %v", unknown)
	}
}

func TestUnmarshal_OmitemptyStripped(t *testing.T) {
	var v omitemptyStruct
	data := `{"field":"val"}`
	unknown, err := jsonstrict.Unmarshal([]byte(data), &v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(unknown) != 0 {
		t.Errorf("field with omitempty should be known, got %v", unknown)
	}
}

func TestUnmarshal_UntaggedField(t *testing.T) {
	var v untaggedStruct
	data := `{"GoName":"val"}`
	unknown, err := jsonstrict.Unmarshal([]byte(data), &v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(unknown) != 0 {
		t.Errorf("untagged field should use Go name, got %v", unknown)
	}
	if v.GoName != "val" {
		t.Errorf("decode wrong: got %+v", v)
	}
}

func TestUnmarshal_PtrEmbeddedStruct(t *testing.T) {
	var v ptrEmbeddedParent
	data := `{"deep":"d","top":"t"}`
	unknown, err := jsonstrict.Unmarshal([]byte(data), &v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(unknown) != 0 {
		t.Errorf("ptr-embedded fields should be known, got %v", unknown)
	}
	if v.Deep != "d" || v.Top != "t" {
		t.Errorf("decode wrong: got %+v", v)
	}
}

func TestUnmarshal_RepeatedCallsReturnFields(t *testing.T) {
	var v testStruct
	data := []byte(`{"name":"x","extra":"y"}`)

	// Each call must independently report unknown fields (no dedup).
	for i := range 3 {
		unknown, _ := jsonstrict.Unmarshal(data, &v)
		if !slices.Contains(unknown, "extra") {
			t.Errorf("call %d: expected 'extra' in unknown fields, got %v", i, unknown)
		}
	}
}
