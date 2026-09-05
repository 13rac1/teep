package jsonstrict_test

import (
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/jsonstrict"
)

func TestValidateUniqueFields(t *testing.T) {
	for _, input := range []string{
		`{}`, `[]`, `null`, `42`, `"text"`, `{"a":1,"b":2}`,
		`{"a":{"name":1},"b":{"name":2}}`, `[{"name":1},{"name":2}]`,
		`{"a":[{"b":null},true,1e9999,"a"],"b":{}}`,
		strings.Repeat("[", 1000) + "0" + strings.Repeat("]", 1000),
	} {
		if err := jsonstrict.ValidateUniqueFields([]byte(input)); err != nil {
			t.Errorf("valid document rejected: %v", err)
		}
	}
	for _, input := range []string{
		`{"a":1,"a":2}`, `{"a":1,"\u0061":2}`,
		`{"a":{"b":1,"b":1}}`, `[{"a":1,"a":2}]`,
		``, `{`, `[`, `{"a":}`, `{"a":1,}`, `]`, `{} {}`, `1 2`, `true false`,
	} {
		if err := jsonstrict.ValidateUniqueFields([]byte(input)); err == nil {
			t.Errorf("ambiguous or invalid document accepted: %s", input)
		}
	}
}
