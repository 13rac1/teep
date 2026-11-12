package nearcloud_test

import (
	"encoding/json"
	"maps"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/provider/nearcloud"
)

// modelEntries returns a model_attestations array with one entry per name.
func modelEntries(t *testing.T, names ...string) json.RawMessage {
	t.Helper()
	entry := cloudFixture(t)["model_attestations"].([]any)[0].(map[string]any)
	out := make([]any, 0, len(names))
	for _, name := range names {
		e := maps.Clone(entry)
		e["model_name"] = name
		out = append(out, e)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The gateway's model array: the exact entry is selected; else the one
// entry whose name contains, or is contained in, the requested name; else
// the only entry. Any other array has no entry that teep can attribute to
// the request.
func TestCloudModelNameSelection(t *testing.T) {
	for _, tc := range []struct {
		name, requested string
		entries         []string
		wantModel       string
		wantMatch       string
	}{
		{"exact among others", "m", []string{"m-long", "m"}, "m", ""},
		{"one containing entry", "z-ai/glm-5.3-flash-long", []string{"z-ai/glm-5.3-flash", "other"}, "z-ai/glm-5.3-flash", "contains"},
		{"contained entry", "z-ai/glm-5.3-flash", []string{"z-ai/glm-5.3-flash-long"}, "z-ai/glm-5.3-flash-long", "contains"},
		{"only entry of another name", "model-b", []string{"model-a"}, "model-a", "differs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, raw, err := nearcloud.ParseGatewayResponse(t.Context(), cloudModelsResponse(t, modelEntries(t, tc.entries...)), tc.requested)
			if err != nil {
				t.Fatal(err)
			}
			if raw.Model != tc.wantModel || raw.ModelNameMatch != tc.wantMatch {
				t.Errorf("selected %q with match %q; want %q, %q", raw.Model, raw.ModelNameMatch, tc.wantModel, tc.wantMatch)
			}
		})
	}
	for _, tc := range []struct {
		name, requested string
		entries         []string
	}{
		{"two containing entries", "glm", []string{"glm-a", "glm-b"}},
		{"no entry of the name among several", "model-b", []string{"model-a", "model-c"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := nearcloud.ParseGatewayResponse(t.Context(), cloudModelsResponse(t, modelEntries(t, tc.entries...)), tc.requested)
			if err == nil || !strings.Contains(err.Error(), "requested model") {
				t.Fatalf("err = %v, want no attributable entry", err)
			}
		})
	}
}
