package aci

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The gateway hashes request.received over its own serialization of the
// restored request (E2EE v2 §8): it parses the wire body into a serde_json
// Value with the member order kept, puts the plaintext in place of each
// ciphertext, and writes the value with serde_json::to_vec. RestoredRequestHash
// reproduces that form for the values on which Go and serde_json write the
// same bytes, and states for every other value that it cannot.

var (
	integerText  = regexp.MustCompile(`^-?(0|[1-9]\d*)$`)
	fractionText = regexp.MustCompile(`^-?(0|[1-9]\d*)\.\d+$`)
)

// RestoredRequestHash returns the sha256 of the compact form of the restored
// request body: the members in the order of body, no whitespace, strings
// without HTML escapes. It returns nil when the gateway can write another
// form of body (SEE: reproducibleNumber, reproducibleString); the request
// hash is then not checked. It returns an error only for a body that is not
// JSON.
func RestoredRequestHash(body []byte) (*[32]byte, error) {
	form, ok, err := restoredForm(body)
	if err != nil || !ok {
		return nil, err
	}
	sum := sha256.Sum256(form)
	return &sum, nil
}

type restoredFrame struct {
	object bool
	n      int // tokens written in this container
}

func restoredForm(body []byte) (form []byte, reproducible bool, err error) {
	if !json.Valid(body) {
		return nil, false, errors.New("body is not one JSON value")
	}
	if !utf8.Valid(body) {
		return nil, false, nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var out bytes.Buffer
	var stack []restoredFrame
	reproducible = true
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, false, err
		}
		if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
			stack = stack[:len(stack)-1]
			out.WriteRune(rune(d))
			continue
		}
		if len(stack) > 0 {
			top := &stack[len(stack)-1]
			switch {
			case top.object && top.n%2 == 1:
				out.WriteByte(':')
			case top.n > 0:
				out.WriteByte(',')
			}
			top.n++
		}
		ok, err := writeRestoredToken(&out, tok)
		if err != nil {
			return nil, false, err
		}
		reproducible = reproducible && ok
		if d, isDelim := tok.(json.Delim); isDelim {
			stack = append(stack, restoredFrame{object: d == '{'})
		}
	}
	return out.Bytes(), reproducible, nil
}

func writeRestoredToken(out *bytes.Buffer, tok json.Token) (bool, error) {
	switch v := tok.(type) {
	case json.Delim:
		out.WriteRune(rune(v))
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(v))
	case json.Number:
		out.WriteString(v.String())
		return reproducibleNumber(v.String()), nil
	case string:
		enc := json.NewEncoder(out)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return false, err
		}
		out.Truncate(out.Len() - 1) // Encode ends with a newline.
		return reproducibleString(v), nil
	default:
		return false, errors.New("unexpected JSON token")
	}
	return true, nil
}

// reproducibleNumber reports whether serde_json writes the number as its
// text: an integer within i64 or u64 other than -0, or a decimal fraction
// of at most 15 significant digits, magnitude 1e-4 to 1e15, that is already
// the shortest form of its float64 (ryu writes 1.5 as "1.5" and 1.0 as
// "1.0", but 1.50 as "1.5" and 1e20 as "1e20").
func reproducibleNumber(s string) bool {
	if integerText.MatchString(s) {
		if s == "-0" {
			return false
		}
		if _, err := strconv.ParseInt(s, 10, 64); err == nil {
			return true
		}
		_, err := strconv.ParseUint(s, 10, 64)
		return err == nil
	}
	if !fractionText.MatchString(s) || len(strings.Trim(strings.NewReplacer("-", "", ".", "").Replace(s), "0")) > 15 {
		return false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return false
	}
	if a := math.Abs(f); a != 0 && (a < 1e-4 || a >= 1e15) {
		return false
	}
	short := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(short, ".") {
		short += ".0"
	}
	return short == s
}

// reproducibleString reports whether Go and serde_json escape s in the same
// way. Both write UTF-8 as is and escape '"', '\\' and the control
// characters in the same form; Go also escapes U+2028 and U+2029.
func reproducibleString(s string) bool {
	return !strings.ContainsAny(s, "  ")
}
