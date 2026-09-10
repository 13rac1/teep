// Package nearroute defines NEAR route input validation independently of client construction.
package nearroute

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/13rac1/teep/internal/tlsct"
)

// ErrorKind classifies route failures for callers.
type ErrorKind uint8

// Route error classifications.
const (
	Input ErrorKind = iota + 1
	UnknownModel
	Metadata
	Capacity
	Delay
	Expired
	Configuration
)

// Error preserves a non-secret classification and underlying cause.
type Error struct {
	Kind   ErrorKind
	Detail string
	Cause  error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return e.Detail + ": " + e.Cause.Error()
	}
	return e.Detail
}
func (e *Error) Unwrap() error { return e.Cause }

// ValidateModel bounds identifiers before lookup or state allocation.
func ValidateModel(model string) error {
	if model == "" {
		return &Error{Kind: Input, Detail: "model identifier must not be empty"}
	}
	if len(model) > 256 {
		return &Error{Kind: Input, Detail: "model identifier exceeds 256 bytes"}
	}
	if strings.ContainsFunc(model, func(c rune) bool { return c < 32 || c == 127 }) {
		return &Error{Kind: Input, Detail: "model identifier contains a control character"}
	}
	return nil
}

// Origin describes the normalized configured route.
type Origin struct {
	Authority string
	Canonical string
	Index     uint64
	Indexed   bool
	Static    bool
}

// ParseOrigin applies non-default-port precedence before interpreting NEAR index syntax.
func ParseOrigin(origin string) (Origin, error) {
	authority, err := tlsct.HTTPSOriginAuthority(origin)
	if err != nil {
		return Origin{}, err
	}
	out := Origin{Authority: authority}
	if _, _, err := net.SplitHostPort(authority); err == nil || strings.HasPrefix(authority, "[") {
		out.Static = true
		return out, nil
	}
	if authority == "api.near.ai" || authority == "completions.near.ai" {
		return out, nil
	}
	const suffix = ".completions.near.ai"
	label, recognized := strings.CutSuffix(authority, suffix)
	if !recognized || strings.Contains(label, ".") {
		out.Static = true
		return out, nil
	}
	out.Canonical = authority
	pos := strings.LastIndex(label, "-i")
	if pos < 0 {
		return out, nil
	}
	indexText := label[pos+2:]
	// Ordinary names such as "model-instruct" are canonical labels.
	if indexText != "" && (indexText[0] < '0' || indexText[0] > '9') && indexText[0] != '+' && indexText[0] != '-' {
		return out, nil
	}
	index, err := strconv.ParseUint(indexText, 10, 64)
	if err != nil || strconv.FormatUint(index, 10) != indexText || pos == 0 {
		return Origin{}, errors.New("invalid canonical NEAR index suffix")
	}
	out.Indexed = true
	out.Index = index
	out.Canonical = label[:pos] + suffix
	return out, nil
}

// IndexedAuthority formats an exact uint64 index and validates DNS limits.
func IndexedAuthority(canonical string, index uint64) (string, error) {
	const suffix = ".completions.near.ai"
	label, ok := strings.CutSuffix(canonical, suffix)
	if !ok || label == "" || strings.ContainsAny(label, ".:") {
		return "", errors.New("automatic NEAR routing requires a canonical model label")
	}
	authority := label + "-i" + strconv.FormatUint(index, 10) + suffix
	checked, err := tlsct.HTTPSOriginAuthority("https://" + authority)
	if err != nil || checked != authority {
		return "", errors.New("indexed NEAR authority is invalid")
	}
	return authority, nil
}
