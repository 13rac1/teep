package provider_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/13rac1/teep/internal/provider"
)

func TestUpstreamErrorMessage(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"JSON error message",
			`{"error":{"message":"This API key's organization is not allowed to use this endpoint.","type":"forbidden","param":null,"code":null}}`,
			"This API key's organization is not allowed to use this endpoint."},
		{"text body", "upstream connect error", "upstream connect error"},
		{"JSON without a message", `{"detail":"Not Found"}`, `{"detail":"Not Found"}`},
		{"control characters", "\x1b[31mforbidden\x1b[0m\x00 now\r\nretry", "[31mforbidden[0m now  retry"},
		{"control characters in the JSON message", `{"error":{"message":"bad\u001b]0;title\u0007 key"}}`, "bad]0;title key"},
		{"invalid UTF-8", "ok\xff\xfeend", "okend"},
		{"empty body", "", ""},
		{"only control characters", "\x00\x01\x1b", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := provider.UpstreamErrorMessage([]byte(tc.body)); got != tc.want {
				t.Errorf("message = %q, want %q", got, tc.want)
			}
		})
	}
}

// A long body, as JSON message or as text, yields at most 200 runes, also
// when the provider quotes request text in its error.
func TestUpstreamErrorMessageBounded(t *testing.T) {
	quoted := strings.Repeat("the user prompt that the provider quotes back ", 100)
	for _, body := range []string{
		`{"error":{"message":"invalid value: ` + quoted + `"}}`,
		"invalid value: " + quoted,
		strings.Repeat("é", 1000),
	} {
		got := provider.UpstreamErrorMessage([]byte(body))
		if n := utf8.RuneCountInString(got); n == 0 || n > 200 {
			t.Errorf("message has %d runes, want 1 to 200", n)
		}
		if !utf8.ValidString(got) {
			t.Errorf("message is not valid UTF-8: %q", got)
		}
	}
}
