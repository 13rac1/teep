package jsonstrict

import (
	"encoding/json"
	"errors"

	strict "github.com/13rac1/jsonstrict"
)

// ValidateUniqueFields rejects a document that is not one JSON value, that
// has duplicate object members at any depth (also names that use different
// JSON escapes for the same string), or that has a string with invalid UTF-8.
// It decodes no fields; Unmarshal makes the same checks while it decodes, so a
// caller needs this only for a document that it does not decode with
// Unmarshal. Callers must bound input size. The errors name no member.
func ValidateUniqueFields(data []byte) error {
	// The library decodes into a struct, so the document becomes the value of
	// one member. json.Valid first makes sure that the document is one
	// complete JSON value, so the wrapping cannot join it with other text.
	if !json.Valid(data) {
		return errors.New("invalid JSON document")
	}
	wrapped := make([]byte, 0, len(data)+6)
	wrapped = append(wrapped, `{"v":`...)
	wrapped = append(wrapped, data...)
	wrapped = append(wrapped, '}')
	var doc struct {
		V json.RawMessage `json:"v"`
	}
	result, err := strict.Unmarshal(wrapped, &doc)
	if err != nil {
		return errors.New("invalid JSON document")
	}
	return structuralError(&result)
}
