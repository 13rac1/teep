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

func TestFinishSSETrailingByteLimit(t *testing.T) {
	t.Parallel()
	const limit = 64 << 10
	for _, tc := range []struct {
		name, suffix string
		wantErr      bool
	}{
		{"empty", "", false},
		{"crlf_blank_exact_limit", strings.Repeat("\r\n", limit/2), false},
		{"crlf_blank_over_limit", strings.Repeat("\r\n", limit/2+1), true},
		{"crlf_comment_exact_limit", ":" + strings.Repeat(" ", limit-3) + "\r\n", false},
		{"crlf_comment_over_limit", ":" + strings.Repeat(" ", limit-2) + "\r\n", true},
		{"lf_blank_budget", strings.Repeat("\n", limit/2), false},
		{"lf_blank_over_budget", strings.Repeat("\n", limit/2+1), true},
		{"cr_blank_budget", strings.Repeat("\r", limit/2), false},
		{"cr_blank_over_budget", strings.Repeat("\r", limit/2+1), true},
		{"unterminated_comment_budget", ":" + strings.Repeat(" ", limit-3), false},
		{"unterminated_comment_over_budget", ":" + strings.Repeat(" ", limit-2), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			scanner, cleanup := NewSSEScanner(strings.NewReader("data: [DONE]\n" + tc.suffix))
			defer cleanup()
			if !scanner.Scan() {
				t.Fatal("missing end marker")
			}
			if err := FinishSSE(scanner); (err != nil) != tc.wantErr {
				t.Fatalf("trailing limit error=%v, want error=%v", err, tc.wantErr)
			}
		})
	}
}
