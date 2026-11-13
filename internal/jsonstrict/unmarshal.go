// Package jsonstrict wraps github.com/13rac1/jsonstrict to provide strict JSON
// unmarshaling that detects unknown and missing fields at every depth, and
// rejects duplicate members, members that match a defined field only by
// letter case, and invalid UTF-8.
//
// Standard encoding/json silently ignores unknown JSON keys, does not report
// absent ones, keeps the last of duplicated keys, matches keys to fields
// without regard to case, and replaces invalid UTF-8. This package returns
// unknown and missing field paths alongside the decoded value, letting
// callers decide how to handle format drift. It fails the decode for
// duplicate members, case-folded aliases of defined fields and invalid UTF-8,
// which make the decoded value ambiguous.
//
// These checks apply only to documents decoded through this package. A
// value with its own UnmarshalJSON that calls encoding/json, and a document
// decoded with encoding/json directly, get none of them.
//
// Field paths are dotted: a top-level field is its name ("nonce"), a nested
// field joins the names ("attestation.report_data"), and a list element adds
// its index ("items[0].name").
//
// UnmarshalWarn is the primary entry point for most call sites: it unmarshals,
// logs warnings for unknown/missing fields, and returns the field paths for
// factor evaluation.
package jsonstrict

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"

	strict "github.com/13rac1/jsonstrict"
)

// unmarshal unmarshals data into v and returns the paths of any unknown JSON
// keys and any missing struct fields as sorted slices. Duplicate members,
// members that match a defined field only by letter case (the library's
// *CaseFoldError, wrapped), and invalid UTF-8 fail the decode.
//
// v must be a non-nil pointer to a struct.
func unmarshal(data []byte, v any) (unknown, missing []string, err error) {
	result, err := strict.Unmarshal(data, v)
	if _, ok := errors.AsType[*strict.CaseFoldError](err); ok {
		// The error names only defined fields, never a member of the input.
		return nil, nil, fmt.Errorf("ambiguous JSON document: %w", err)
	}
	if err != nil {
		return nil, nil, err
	}
	if err := structuralError(&result); err != nil {
		return nil, nil, err
	}
	if len(result.Unknown) > 0 {
		unknown = dottedPaths(slices.Collect(maps.Keys(result.Unknown)))
	}
	if len(result.Missing) > 0 {
		missing = dottedPaths(result.Missing)
	}
	return unknown, missing, nil
}

// structuralError returns an error for duplicate members or invalid UTF-8.
// The error names no member: member names are untrusted input.
func structuralError(result *strict.Result) error {
	if len(result.Duplicates) > 0 {
		return errors.New("duplicate JSON member")
	}
	if len(result.InvalidUTF8) > 0 {
		return errors.New("invalid UTF-8 in JSON string")
	}
	return nil
}

// dottedPaths converts the bracket paths of the library (["a"]["b"][0]) to
// dotted paths (a.b[0]) and sorts them. A path that does not parse is kept as
// the library wrote it.
func dottedPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, dottedPath(p))
	}
	slices.Sort(out)
	return out
}

func dottedPath(path string) string {
	var b strings.Builder
	rest := path
	for rest != "" {
		if rest[0] != '[' {
			return path
		}
		rest = rest[1:]
		if strings.HasPrefix(rest, `"`) {
			quoted, err := strconv.QuotedPrefix(rest)
			if err != nil {
				return path
			}
			key, err := strconv.Unquote(quoted)
			if err != nil {
				return path
			}
			rest = rest[len(quoted):]
			if b.Len() > 0 {
				b.WriteByte('.')
			}
			b.WriteString(key)
		} else {
			end := strings.IndexByte(rest, ']')
			if end <= 0 {
				return path
			}
			if _, err := strconv.Atoi(rest[:end]); err != nil {
				return path
			}
			b.WriteString("[" + rest[:end] + "]")
			rest = rest[end:]
		}
		if !strings.HasPrefix(rest, "]") {
			return path
		}
		rest = rest[1:]
	}
	return b.String()
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

// Unmarshal returns field diagnostics without logging untrusted field names.
// Low-level protocol parsers return these diagnostics to their callers.
func Unmarshal(data []byte, v any) (unknown, missing []string, err error) {
	return unmarshal(data, v)
}
