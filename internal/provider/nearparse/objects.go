// Package nearparse decodes the nested evidence structures shared by NEAR
// model and gateway attestations. Callers own schema diagnostic policy.
package nearparse

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/13rac1/teep/internal/jsonstrict"
)

// MaxEvidenceBytes bounds a complete NEAR attestation document.
const MaxEvidenceBytes = 1 << 20

// MaxEvents bounds each supported event-log array.
const MaxEvents = 10000

// Object decodes one object boundary and returns unknown field paths. Missing
// required fields and null supported fields are structural errors.
func Object(data []byte, target any, path string) ([]string, error) {
	if len(data) > MaxEvidenceBytes {
		return nil, fmt.Errorf("%s: object exceeds size limit %d bytes", path, MaxEvidenceBytes)
	}
	return jsonstrict.UnmarshalObject(data, target, path)
}

// EncodedObject accepts one object or its one defined JSON string encoding.
func EncodedObject(data []byte) ([]byte, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || len(data) > MaxEvidenceBytes {
		return nil, errors.New("missing or oversized TCB object")
	}
	if data[0] == '"' {
		var wrapped struct {
			Value string `json:"value"`
		}
		if _, _, err := jsonstrict.Unmarshal(append(append([]byte(`{"value":`), data...), '}'), &wrapped); err != nil {
			return nil, err
		}
		data = bytes.TrimSpace([]byte(wrapped.Value))
	}
	if len(data) == 0 || data[0] != '{' {
		return nil, errors.New("TCB value must contain a JSON object")
	}
	return data, nil
}

// Prefix qualifies diagnostics without logging or deduplication.
func Prefix(parent string, fields []string) []string {
	out := make([]string, len(fields))
	for i, field := range fields {
		out[i] = parent + "." + field
	}
	return out
}
