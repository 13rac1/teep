package provider_test

import (
	"testing"

	"github.com/13rac1/teep/internal/provider"
)

func TestUnwrapDoubleEncoded(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "json_string_containing_json",
			input: `"{\"key\":\"val\"}"`,
			want:  `{"key":"val"}`,
		},
		{
			name:  "raw_json_object",
			input: `{"key":"val"}`,
			want:  `{"key":"val"}`,
		},
		{
			name:  "invalid_json",
			input: `not json at all`,
			want:  `not json at all`,
		},
		{
			name:  "empty_json_string",
			input: `""`,
			want:  ``,
		},
		{
			name:  "plain_string_value",
			input: `"hello"`,
			want:  `hello`,
		},
		{
			name:  "json_array",
			input: `[1,2,3]`,
			want:  `[1,2,3]`,
		},
		{
			name:  "empty_input",
			input: ``,
			want:  ``,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := provider.UnwrapDoubleEncoded([]byte(tt.input))
			if string(got) != tt.want {
				t.Errorf("UnwrapDoubleEncoded(%q) = %q, want %q", tt.input, got, tt.want)
			}
			t.Logf("UnwrapDoubleEncoded(%q) = %q", tt.input, got)
		})
	}
}

func TestNormalizeUncompressedKey(t *testing.T) {
	hex128 := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	tests := []struct {
		name string
		key  string
		want string
	}{
		{
			name: "128_hex_chars_gets_04_prefix",
			key:  hex128,
			want: "04" + hex128,
		},
		{
			name: "130_chars_already_prefixed",
			key:  "04" + hex128,
			want: "04" + hex128,
		},
		{
			name: "short_key_64_chars",
			key:  hex128[:64],
			want: hex128[:64],
		},
		{
			name: "empty",
			key:  "",
			want: "",
		},
		{
			name: "127_chars",
			key:  hex128[:127],
			want: hex128[:127],
		},
		{
			name: "129_chars",
			key:  hex128 + "a",
			want: hex128 + "a",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := provider.NormalizeUncompressedKey(tt.key)
			if got != tt.want {
				t.Errorf("NormalizeUncompressedKey(len=%d) = len=%d, want len=%d", len(tt.key), len(got), len(tt.want))
			}
			t.Logf("NormalizeUncompressedKey(len=%d) = len=%d", len(tt.key), len(got))
		})
	}
}
