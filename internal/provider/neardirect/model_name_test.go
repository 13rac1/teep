package neardirect_test

import (
	"testing"

	"github.com/13rac1/teep/internal/provider/neardirect"
)

// The attested model name is the provider's assertion. An exact name, a
// name that contains or is contained in the requested name, and another
// name are all accepted; the raw attestation states which one it is.
func TestDirectModelNameMatch(t *testing.T) {
	for _, tc := range []struct {
		requested, attested, want string
	}{
		{"z-ai/glm-5.3-flash", "z-ai/glm-5.3-flash", ""},
		{"z-ai/glm-5.3-flash-long", "z-ai/glm-5.3-flash", "contains"},
		{"z-ai/glm-5.3-flash", "z-ai/glm-5.3-flash-long", "contains"},
		{"deepseek-ai/DeepSeek-V4.1-Flash-1017", "z-ai/glm-5.3-flash", "differs"},
	} {
		raw, err := neardirect.ParseAttestationResponse(t.Context(), []byte(directTestResponse(t, tc.attested, nil)), tc.requested)
		if err != nil {
			t.Fatalf("%s for %s: %v", tc.attested, tc.requested, err)
		}
		if raw.ModelNameMatch != tc.want || raw.Model != tc.attested {
			t.Errorf("%s for %s: match %q, model %q; want %q", tc.attested, tc.requested, raw.ModelNameMatch, raw.Model, tc.want)
		}
	}
	if _, err := neardirect.ParseAttestationResponse(t.Context(), []byte(directTestResponse(t, "", nil)), "model"); err == nil {
		t.Error("accepted an empty attested model name")
	}
}
