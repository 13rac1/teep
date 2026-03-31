package provider_test

import (
	"testing"

	"github.com/13rac1/teep/internal/provider"
)

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		n     int
		want  string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 5, "hello..."},
		{"", 5, ""},
		{"ab", 0, "..."},
		{"abc", 1, "a..."},
	}
	for _, tt := range tests {
		got := provider.Truncate(tt.input, tt.n)
		t.Logf("Truncate(%q, %d) = %q", tt.input, tt.n, got)
		if got != tt.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tt.input, tt.n, got, tt.want)
		}
	}
}
