package aci

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// canonicalWith returns the canonical report fixture after change.
func canonicalWith(t *testing.T, change func(top map[string]any)) []byte {
	t.Helper()
	body, err := os.ReadFile("testdata/canonical_report.json")
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatal(err)
	}
	change(top)
	out, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func keysetOf(top map[string]any) map[string]any {
	return top["attestation"].(map[string]any)["workload_keyset"].(map[string]any)
}

// A member that the canonical report does not define is reported in
// UnknownFields with its path and does not stop the parse.
func TestParseCanonicalReportsUndefinedMembers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(top map[string]any)
		path   string
	}{
		{"top level", func(top map[string]any) { top["future_member"] = "00" }, "future_member"},
		{"nested", func(top map[string]any) { top["attestation"].(map[string]any)["extra"] = 1 }, "attestation.extra"},
		{"keyset entry", func(top map[string]any) {
			keysetOf(top)["e2ee_public_keys"].([]any)[0].(map[string]any)["note"] = "x"
		}, "note"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := ParseCanonical(context.Background(), canonicalWith(t, tc.change), "phalacloud")
			if err != nil {
				t.Fatalf("ParseCanonical: %v", err)
			}
			if !slices.ContainsFunc(raw.UnknownFields, func(p string) bool { return strings.HasSuffix(p, tc.path) }) {
				t.Errorf("UnknownFields = %v, want a path ending in %s", raw.UnknownFields, tc.path)
			}
		})
	}
}

// A member of the attestation response variants is not unknown: it marks
// another document, which ParseCanonical refuses.
func TestParseCanonicalRefusesVariantMembers(t *testing.T) {
	for _, name := range []string{"all_attestations", "nonce", "intel_quote", "signing_public_key"} {
		t.Run(name, func(t *testing.T) {
			body := canonicalWith(t, func(top map[string]any) { top[name] = "x" })
			_, err := ParseCanonical(context.Background(), body, "phalacloud")
			if err == nil || !strings.Contains(err.Error(), "it is not the report of") {
				t.Fatalf("ParseCanonical error = %v, want the variant member refused", err)
			}
		})
	}
	for _, name := range []string{"api_version", "attestation", "workload_keyset_digest", "service_capabilities"} {
		if otherVariantMembers[name] {
			t.Errorf("%s is a member of the canonical report", name)
		}
	}
}

// The keyset digest covers the keyset as served: a member that teep does
// not define is in the digest, as in the digest that the service computed.
func TestKeysetDigestCoversServedMembers(t *testing.T) {
	body := canonicalWith(t, func(top map[string]any) { keysetOf(top)["future_member"] = "v" })
	raw, err := ParseCanonical(context.Background(), body, "phalacloud")
	if err != nil {
		t.Fatal(err)
	}
	ks := raw.ACIWorkloadKeyset.(*aciWorkloadKeyset)
	value, err := ks.digestValue()
	if err != nil {
		t.Fatalf("digestValue: %v", err)
	}
	got, err := jcsSHA256Hex(value)
	if err != nil {
		t.Fatal(err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatal(err)
	}
	var att map[string]json.RawMessage
	if err := json.Unmarshal(top["attestation"], &att); err != nil {
		t.Fatal(err)
	}
	served, err := sessionValue(att["workload_keyset"])
	if err != nil {
		t.Fatal(err)
	}
	want, err := jcsSHA256Hex(served)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("digest %s, want the digest of the served keyset %s", got, want)
	}
	typed, err := ks.toCanonicalValue()
	if err != nil {
		t.Fatal(err)
	}
	typedDigest, err := jcsSHA256Hex(typed)
	if err != nil {
		t.Fatal(err)
	}
	if typedDigest == got {
		t.Error("the digest leaves out the member that teep does not define")
	}
}

// servedHolds requires every decoded member in the served object with the
// same value, and allows served members that teep does not define.
func TestServedHolds(t *testing.T) {
	typed := map[string]any{"a": "x", "n": uint64(5), "l": []any{map[string]any{"k": "v"}}}
	for _, tc := range []struct {
		name   string
		served map[string]any
		ok     bool
	}{
		{"equal", map[string]any{"a": "x", "n": int64(5), "l": []any{map[string]any{"k": "v"}}}, true},
		{"extra members", map[string]any{"a": "x", "n": int64(5), "l": []any{map[string]any{"k": "v", "z": true}}, "e": 1}, true},
		{"other value", map[string]any{"a": "y", "n": int64(5), "l": []any{map[string]any{"k": "v"}}}, false},
		{"other number", map[string]any{"a": "x", "n": int64(6), "l": []any{map[string]any{"k": "v"}}}, false},
		{"missing member", map[string]any{"a": "x", "l": []any{map[string]any{"k": "v"}}}, false},
		{"longer list", map[string]any{"a": "x", "n": int64(5), "l": []any{map[string]any{"k": "v"}, map[string]any{"k": "w"}}}, false},
		{"not an object", map[string]any{"a": "x", "n": int64(5), "l": []any{"v"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := servedHolds(typed, tc.served, "keyset")
			if (err == nil) != tc.ok {
				t.Fatalf("servedHolds error = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}
