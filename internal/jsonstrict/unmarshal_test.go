package jsonstrict

import (
	"slices"
	"testing"
)

type inner struct {
	Name string `json:"name"`
	Opt  string `json:"opt,omitempty"`
}

type outer struct {
	ID    string  `json:"id"`
	Inner inner   `json:"inner"`
	Items []inner `json:"items"`
}

// Unknown and missing fields are reported at every depth as dotted paths;
// top-level fields keep their bare names.
func TestUnmarshalNestedPaths(t *testing.T) {
	var v outer
	unknown, missing, err := Unmarshal([]byte(`{"extra":1,"inner":{"x":2},"items":[{"name":"a"},{"y":3}]}`), &v)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"extra", "inner.x", "items[1].y"}; !slices.Equal(unknown, want) {
		t.Errorf("unknown = %v, want %v", unknown, want)
	}
	if want := []string{"id", "inner.name", "items[1].name"}; !slices.Equal(missing, want) {
		t.Errorf("missing = %v, want %v", missing, want)
	}
}

// Duplicate members, also differently escaped ones and nested ones, and
// invalid UTF-8 fail the decode.
func TestUnmarshalStructuralErrors(t *testing.T) {
	for _, input := range []string{
		`{"id":"a","id":"b","inner":{"name":"n"},"items":[]}`,
		`{"id":"a","id":"b","inner":{"name":"n"},"items":[]}`,
		`{"id":"a","inner":{"name":"n","name":"m"},"items":[]}`,
		`{"id":"a","extra":{"k":1,"k":2},"inner":{"name":"n"},"items":[]}`,
		"{\"id\":\"\xff\",\"inner\":{\"name\":\"n\"},\"items\":[]}",
	} {
		var v outer
		if _, _, err := Unmarshal([]byte(input), &v); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}

func TestDottedPath(t *testing.T) {
	for in, want := range map[string]string{
		`["a"]`:                "a",
		`["a"]["b"]`:           "a.b",
		`["items"][0]["name"]`: "items[0].name",
		`["a.b"]`:              "a.b",
		`["q\"t"]`:             `q"t`,
		`not-a-path`:           "not-a-path",
		`["unterminated`:       `["unterminated`,
		`[x]`:                  "[x]",
	} {
		if got := dottedPath(in); got != want {
			t.Errorf("dottedPath(%q) = %q, want %q", in, got, want)
		}
	}
}
