// Package jsonstrict wraps github.com/13rac1/jsonstrict to provide strict JSON
// unmarshaling that detects unknown and missing fields.
//
// Standard encoding/json silently ignores unknown JSON keys and does not report
// absent ones. This package returns both alongside the decoded value, letting
// callers decide how to handle format drift.
//
// UnmarshalWarn is the primary entry point for most call sites: it unmarshals,
// logs warnings for unknown/missing fields, and returns the field names for
// factor evaluation.
package jsonstrict

import (
	"log/slog"
	"maps"
	"slices"

	strict "github.com/13rac1/jsonstrict"
)

// unmarshal unmarshals data into v and returns the names of any unknown JSON
// keys and any missing struct fields as sorted slices.
//
// v must be a non-nil pointer to a struct.
func unmarshal(data []byte, v any) (unknown, missing []string, err error) {
	result, err := strict.Unmarshal(data, v)
	if err != nil {
		return nil, nil, err
	}
	if len(result.Unknown) > 0 {
		unknown = slices.Sorted(maps.Keys(result.Unknown))
	}
	if len(result.Missing) > 0 {
		missing = result.Missing
		slices.Sort(missing)
	}
	return unknown, missing, nil
}

// UnmarshalWarn unmarshals data into v and logs warnings for any unknown or
// missing fields. label identifies the call site in log output.
func UnmarshalWarn(data []byte, v any, label string) (unknown, missing []string, err error) {
	unknown, missing, err = unmarshal(data, v)
	if len(unknown) > 0 {
		slog.Warn("unexpected JSON fields", "fields", unknown, "label", label)
	}
	if len(missing) > 0 {
		slog.Warn("missing JSON fields", "fields", missing, "label", label)
	}
	return unknown, missing, err
}
