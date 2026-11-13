// Package aliastest builds JSON documents with a member that differs from a
// defined member only in letter case, for the tests that check each parser
// refuses them (github.com/13rac1/jsonstrict CaseFoldError).
package aliastest

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	strict "github.com/13rac1/jsonstrict"
)

// Append writes `,"name":value` before the final closing brace of the JSON
// object body, after every other member. encoding/json keeps the last
// member that matches a field, so an alias written last would set the
// defined field.
func Append(t *testing.T, body []byte, name, value string) []byte {
	t.Helper()
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[len(body)-1] != '}' {
		t.Fatal("aliastest: not a JSON object")
	}
	out := append([]byte{}, body[:len(body)-1]...)
	return append(out, []byte(`,"`+name+`":`+value+`}`)...)
}

// Read returns the contents of path.
func Read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Refused requires err to wrap the library's refusal of a case-folded alias.
func Refused(t *testing.T, err error) {
	t.Helper()
	if _, ok := errors.AsType[*strict.CaseFoldError](err); !ok {
		t.Fatalf("err = %v, want the case-folded alias refused", err)
	}
}
