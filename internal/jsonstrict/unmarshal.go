// Package jsonstrict provides JSON unmarshaling that warns on unknown fields.
//
// Standard encoding/json silently ignores unknown JSON keys. For security-critical
// payloads like TEE attestation responses, silent drops mean API format changes
// go unnoticed. UnmarshalWarn logs unknown fields at Warn level without failing
// the decode, so operators see format drift in logs while existing verification
// continues to work.
package jsonstrict

import (
	"encoding/json"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"sync"
)

// warned tracks (context, sorted-fields) pairs that have already been logged,
// so each unique combination produces at most one warning per process lifetime.
var warned sync.Map

// UnmarshalWarn unmarshals data into v and logs a slog.Warn for every JSON key
// not represented by a json struct tag on v's type. Unknown fields never cause
// an error — only the normal json.Unmarshal error (if any) is returned.
//
// context is a caller-supplied label included in the warning to identify which
// response body contained the unexpected fields (e.g. "venice attestation response").
//
// v must be a non-nil pointer to a struct. Any other type panics.
func UnmarshalWarn(data []byte, v any, context string) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err == nil {
		known := knownJSONKeys(reflect.TypeOf(v).Elem())
		var unknown []string
		for key := range raw {
			if _, ok := known[key]; !ok {
				unknown = append(unknown, key)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			key := context + "\x00" + strings.Join(unknown, "\x00")
			if _, loaded := warned.LoadOrStore(key, struct{}{}); !loaded {
				slog.Warn("unknown JSON fields in response",
					"context", context,
					"fields", unknown,
				)
			}
		}
	}

	return json.Unmarshal(data, v)
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
