// Package jsonstrict provides JSON unmarshaling that detects unknown fields.
//
// Standard encoding/json silently ignores unknown JSON keys. For security-critical
// payloads like TEE attestation responses, silent drops mean API format changes
// go unnoticed. Unmarshal returns the names of unknown fields alongside the
// decoded value, letting callers decide how to handle format drift.
package jsonstrict

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
)

// Unmarshal unmarshals data into v and returns the names of any JSON keys
// not represented by a json struct tag on v's type. Unknown fields never cause
// an error — only the normal json.Unmarshal error (if any) is returned.
//
// v must be a non-nil pointer to a struct. Any other type panics.
func Unmarshal(data []byte, v any) (unknownFields []string, err error) {
	var raw map[string]json.RawMessage
	if jsonErr := json.Unmarshal(data, &raw); jsonErr == nil {
		known := knownJSONKeys(reflect.TypeOf(v).Elem())
		for key := range raw {
			if _, ok := known[key]; !ok {
				unknownFields = append(unknownFields, key)
			}
		}
		if len(unknownFields) > 0 {
			sort.Strings(unknownFields)
		}
	}

	return unknownFields, json.Unmarshal(data, v)
}

// knownJSONKeys returns the set of JSON field names declared by t's struct tags.
// It recurses into anonymous (embedded) struct fields. Fields tagged json:"-"
// are excluded. Tag options (e.g. ",omitempty") are stripped. Untagged fields
// fall back to the Go field name, matching encoding/json behavior.
func knownJSONKeys(t reflect.Type) map[string]struct{} {
	keys := make(map[string]struct{})
	for i := range t.NumField() {
		field := t.Field(i)

		if field.Anonymous {
			ft := field.Type
			if ft.Kind() == reflect.Ptr {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				for k := range knownJSONKeys(ft) {
					keys[k] = struct{}{}
				}
				continue
			}
		}

		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" {
			name = field.Name
		}
		keys[name] = struct{}{}
	}
	return keys
}
