package provider

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/13rac1/teep/internal/jsonstrict"
)

// maxUpstreamMessage bounds the upstream error text, in runes, that
// UpstreamErrorMessage returns.
const maxUpstreamMessage = 200

// UpstreamErrorMessage returns the error message of an upstream error body
// for a diagnostic: the error.message member of a JSON body, else the start
// of the body as text. It drops control and other non-printable runes and
// returns at most maxUpstreamMessage runes, so the body cannot change the
// terminal or the report layout. The body is untrusted provider text and can
// quote the request; callers use it only where the request is teep's own.
func UpstreamErrorMessage(body []byte) string {
	var parsed struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	var text string
	if _, _, err := jsonstrict.Unmarshal(body, &parsed); err == nil && parsed.Error.Message != "" {
		text = parsed.Error.Message
	} else {
		// Bound the input before the rune scan: 4 bytes per rune at most.
		if len(body) > 4*maxUpstreamMessage {
			body = body[:4*maxUpstreamMessage]
		}
		text = string(body)
	}
	var b strings.Builder
	n := 0
	for _, r := range text {
		if n == maxUpstreamMessage {
			break
		}
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			if r == '\n' || r == '\t' || r == '\r' {
				r = ' '
			} else {
				continue
			}
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}
