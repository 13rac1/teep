package nearcloud_test

import (
	"encoding/json"
	"maps"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/provider/nearcloud"
)

// instanceEntry is one model_attestations entry of the instance id; the
// fields that the instances of one model share have the values of the
// gateway response of 2026-11-13.
type instanceEntry struct {
	model, instanceID, signingKey, ohttpKeyConfig string
}

const (
	glmKey   = "5a0210f2442c79355784f9de021985429561da5bacc3a4424b01ac52b7e0caff"
	glmOHTTP = "010020da8c5a2429c23ca13bc29fbbcf6f665bfc43fb7190b4141aeac79ebcae746d14"
	dsKey    = "236f5a6b91dd47dc"
	dsAblKey = "88fbc43bdd80a7cc"
)

func instanceEntries(t *testing.T, entries ...instanceEntry) json.RawMessage {
	t.Helper()
	base := cloudFixture(t)["model_attestations"].([]any)[0].(map[string]any)
	out := make([]any, 0, len(entries))
	for _, e := range entries {
		entry := maps.Clone(base)
		info := maps.Clone(base["info"].(map[string]any))
		info["instance_id"] = e.instanceID
		entry["info"] = info
		entry["model_name"] = e.model
		entry["signing_algo"] = "ed25519"
		entry["signing_public_key"] = e.signingKey
		entry["signing_address"] = e.signingKey
		if e.ohttpKeyConfig != "" {
			entry["ohttp_key_config"] = e.ohttpKeyConfig
		}
		out = append(out, entry)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The gateway response of 2026-11-13 lists several instances of one model:
// three of z-ai/glm-5.3-flash, two of each DeepSeek model, with the
// abliterated model on the same instances under another key. Teep returns
// every instance of the requested model for verification.
func TestCloudModelInstances(t *testing.T) {
	const glm, ds, abl = "z-ai/glm-5.3-flash", "deepseek-ai/DeepSeek-V4.1-Flash-1017", "deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated"
	glmEntries := []instanceEntry{
		{glm, "19aea1693533dc2d529db03e3f725f20bde8d66d", glmKey, glmOHTTP},
		{glm, "a8a25faab3ef437d2da809382e05e59e3c55a0f5", glmKey, glmOHTTP},
		{glm, "cc796618bcd5a6b22907d8de7ac414a968d6a1aa", glmKey, glmOHTTP},
	}
	dsEntries := []instanceEntry{
		{ds, "7bb9af0ac5b0e22dde3903218f58e56f743164a1", dsKey, "0100200a"},
		{ds, "fccd496ae28c19105777793efa98fbbd726219cc", dsKey, "0100200a"},
		{abl, "7bb9af0ac5b0e22dde3903218f58e56f743164a1", dsAblKey, "0100200e"},
		{abl, "fccd496ae28c19105777793efa98fbbd726219cc", dsAblKey, "0100200e"},
	}
	for _, tc := range []struct {
		name, requested string
		entries         []instanceEntry
		wantKey         string
	}{
		{"three instances", glm, glmEntries, glmKey},
		{"two instances among another model", ds, dsEntries, dsKey},
		{"two instances of the longer name", abl, dsEntries, dsAblKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, raw, err := nearcloud.ParseGatewayResponse(t.Context(), cloudModelsResponse(t, instanceEntries(t, tc.entries...)), tc.requested)
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			for _, e := range tc.entries {
				if e.model == tc.requested {
					want = append(want, e.instanceID)
				}
			}
			got := []string{raw.ModelInstanceID}
			for _, replica := range raw.Replicas {
				if replica.Model != tc.requested || replica.SigningKey != tc.wantKey {
					t.Errorf("replica %s: model %q key %q", replica.ModelInstanceID, replica.Model, replica.SigningKey)
				}
				got = append(got, replica.ModelInstanceID)
			}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("instances = %v, want %v", got, want)
			}
		})
	}
}

// Several entries of one name are refused unless each is a distinct
// instance with the same signing key and OHTTP key configuration, and the
// number of entries is bounded.
func TestCloudModelInstancesRefused(t *testing.T) {
	const m = "z-ai/glm-5.3-flash"
	a, b := "19aea1693533dc2d529db03e3f725f20bde8d66d", "a8a25faab3ef437d2da809382e05e59e3c55a0f5"
	many := make([]instanceEntry, 9)
	for i := range many {
		many[i] = instanceEntry{m, strings.Repeat(string(rune('a'+i)), 40), glmKey, glmOHTTP}
	}
	for _, tc := range []struct {
		name    string
		entries []instanceEntry
		want    string
	}{
		{"same instance id", []instanceEntry{{m, a, glmKey, glmOHTTP}, {m, a, glmKey, glmOHTTP}}, "distinct instance ids"},
		{"no instance id", []instanceEntry{{m, "", glmKey, glmOHTTP}, {m, b, glmKey, glmOHTTP}}, "distinct instance ids"},
		{"different signing key", []instanceEntry{{m, a, glmKey, glmOHTTP}, {m, b, dsKey, glmOHTTP}}, "different signing keys"},
		{"different OHTTP key", []instanceEntry{{m, a, glmKey, glmOHTTP}, {m, b, glmKey, "0100200e"}}, "different OHTTP key"},
		{"OHTTP key on one instance", []instanceEntry{{m, a, glmKey, glmOHTTP}, {m, b, glmKey, ""}}, "different OHTTP key"},
		{"more than eight instances", many, "more than 8"},
		{"refused entries of another model", []instanceEntry{{m, a, glmKey, glmOHTTP}, {"other", a, glmKey, ""}, {"other", a, glmKey, ""}}, "distinct instance ids"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := nearcloud.ParseGatewayResponse(t.Context(), cloudModelsResponse(t, instanceEntries(t, tc.entries...)), m)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
