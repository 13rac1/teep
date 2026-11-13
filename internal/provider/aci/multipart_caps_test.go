package aci_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/provider/aci"
)

func withMultipartEndpoints(t *testing.T, value any) []byte {
	t.Helper()
	return mutateCanonical(t, func(top map[string]any) {
		top["service_capabilities"].(map[string]any)["supported_multipart_constraint_endpoints"] = value
	})
}

// The canonical report of the current gateway carries
// service_capabilities.supported_multipart_constraint_endpoints (ACI/1 §4.1).
// It is a defined member: the report parses with it, and without it.
func TestParseCanonicalMultipartConstraintEndpoints(t *testing.T) {
	for name, body := range map[string][]byte{
		"listed": withMultipartEndpoints(t, []string{"/v1/audio/transcriptions"}),
		"empty":  withMultipartEndpoints(t, []string{}),
		"absent": canonicalBody(t),
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := aci.ParseCanonical(context.Background(), body, "phalacloud")
			if err != nil {
				t.Fatalf("ParseCanonical: %v", err)
			}
			if len(raw.UnknownFields) != 0 {
				t.Errorf("unknown fields %v", raw.UnknownFields)
			}
		})
	}
}

// A list that is not a short list of distinct clean URL paths fails the report.
func TestParseCanonicalRefusesMalformedMultipartConstraintEndpoints(t *testing.T) {
	tooMany := make([]string, 17)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("/v1/p%d", i)
	}
	for name, tc := range map[string]struct {
		value any
		want  string
	}{
		"not a list":    {"/v1/audio/transcriptions", "unmarshal"},
		"not strings":   {[]int{1}, "unmarshal"},
		"too many":      {tooMany, "more than 16"},
		"relative path": {[]string{"v1/audio/transcriptions"}, "not a clean URL path"},
		"query":         {[]string{"/v1/audio/transcriptions?x=1"}, "not a clean URL path"},
		"dot segment":   {[]string{"/v1/../audio"}, "not a clean URL path"},
		"space":         {[]string{"/v1/audio transcriptions"}, "not a clean URL path"},
		"too long":      {[]string{"/" + strings.Repeat("a", 256)}, "not a clean URL path"},
		"duplicate":     {[]string{"/v1/audio/transcriptions", "/v1/audio/transcriptions"}, "twice"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := aci.ParseCanonical(context.Background(), withMultipartEndpoints(t, tc.value), "phalacloud")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseCanonical error = %v, want %q", err, tc.want)
			}
		})
	}
}
