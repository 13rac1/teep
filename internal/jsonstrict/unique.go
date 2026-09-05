package jsonstrict

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

type objectFields struct {
	names    map[string]struct{}
	wantName bool
}

// ValidateUniqueFields rejects duplicate object members at every depth, including
// names that use different JSON escapes for the same string. Callers must bound
// input size. The iterative traversal uses no recursion and logs no input data.
// This is an opt-in check for protocols that require unambiguous JSON objects.
func ValidateUniqueFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var stack []objectFields
	started := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) && started && len(stack) == 0 {
			return nil
		}
		if err != nil {
			return errors.New("invalid JSON document")
		}
		if started && len(stack) == 0 {
			return errors.New("multiple JSON values")
		}
		started = true
		if token == json.Delim('}') || token == json.Delim(']') {
			stack = stack[:len(stack)-1] // Decoder validates matching delimiters.
			continue
		}
		if len(stack) != 0 {
			object := &stack[len(stack)-1]
			if object.names != nil {
				if object.wantName {
					name, ok := token.(string)
					if !ok {
						return errors.New("invalid JSON member name")
					}
					if _, exists := object.names[name]; exists {
						return errors.New("duplicate JSON member")
					}
					object.names[name] = struct{}{}
					object.wantName = false
					continue
				}
				object.wantName = true
			}
		}
		switch token {
		case json.Delim('{'):
			stack = append(stack, objectFields{names: make(map[string]struct{}), wantName: true})
		case json.Delim('['):
			stack = append(stack, objectFields{})
		}
	}
}
