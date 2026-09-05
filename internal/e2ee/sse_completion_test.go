package e2ee

import (
	"errors"
	"io"
	"strings"
	"testing"
)

type completionReadFailure struct{}

func (completionReadFailure) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestReassembleSSECompletion(t *testing.T) {
	prefix := "data: {\"choices\":[]}\n\ndata: [DONE]\n\n"
	for _, tc := range []struct {
		name, suffix         string
		readFailure, wantErr bool
	}{
		{name: "complete"},
		{name: "comments", suffix: ": done\n\n"},
		{name: "extra_data", suffix: "data: {}\n\n", wantErr: true},
		{name: "bounded_comments", suffix: strings.Repeat(":\n", 64<<10), wantErr: true},
		{name: "read_failure", readFailure: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body io.Reader = strings.NewReader(prefix + tc.suffix)
			if tc.readFailure {
				body = io.MultiReader(body, completionReadFailure{})
			}
			_, _, err := ReassembleNonStream(body, nil, EndpointChat)
			if (err != nil) != tc.wantErr {
				t.Fatalf("completion error: %v", err)
			}
			if tc.readFailure && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("lost read error: %v", err)
			}
		})
	}
}
