package jsonstrict

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// UnmarshalObject decodes exact supported field names and returns unknown paths.
// Callers must bound data. Required fields cannot be absent, and supported fields
// cannot be null unless listed in nullable. Duplicate members at any depth fail,
// including within unknown additions. Nested decoders remain independently safe.
// Re-encoding is needed only when removing unknown members before typed decoding.
func UnmarshalObject(data []byte, target any, path string, nullable ...string) ([]string, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return nil, fmt.Errorf("%s: expected JSON object", path)
	}
	if err := ValidateUniqueFields(data); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	known := make(map[string]bool)
	for _, field := range reflect.VisibleFields(reflect.TypeOf(target).Elem()) {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name != "" && name != "-" {
			known[name] = true
		}
	}
	var unknown []string
	for name, value := range fields {
		if !known[name] {
			unknown = append(unknown, path+"."+name)
			delete(fields, name)
			continue
		}
		if string(bytes.TrimSpace(value)) == "null" && !slices.Contains(nullable, name) {
			return unknown, fmt.Errorf("%s.%s: null is not permitted", path, name)
		}
	}
	slices.Sort(unknown)
	// Remove unknown members before typed decoding. encoding/json otherwise
	// permits a differently cased unknown name to overwrite a supported field.
	supported := data
	if len(unknown) != 0 {
		var err error
		supported, err = json.Marshal(fields)
		if err != nil {
			return unknown, fmt.Errorf("%s: encode supported fields: %w", path, err)
		}
	}
	_, missing, err := Unmarshal(supported, target)
	if err != nil {
		return unknown, fmt.Errorf("%s: %w", path, err)
	}
	if len(missing) != 0 {
		return unknown, fmt.Errorf("%s: missing required fields: %s", path, strings.Join(missing, ", "))
	}
	return unknown, nil
}
