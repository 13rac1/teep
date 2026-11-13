package aci

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// Members that a receipt or one of its events does not define are returned
// in Receipt.Unknown and stay in the signed form. A member of the other form
// of upstream.verified still fails (TestParseReceiptRefusesMalformed).
func TestParseReceiptReportsUndefinedMembers(t *testing.T) {
	body, err := os.ReadFile("testdata/receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatal(err)
	}
	d["note"] = "x"
	d["event_log"].([]any)[0].(map[string]any)["future"] = "y"
	upstreamEvent(d)["latency_ms"] = 3
	changed, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseReceipt(changed)
	if err != nil {
		t.Fatalf("ParseReceipt: %v", err)
	}
	for _, want := range []string{"note", "event_log[0].future", ".latency_ms"} {
		if !slices.ContainsFunc(r.Unknown, func(p string) bool { return p == want || strings.HasSuffix(p, want) }) {
			t.Errorf("Unknown = %v, want %s", r.Unknown, want)
		}
	}
	var signed map[string]any
	if err := json.Unmarshal(r.signed, &signed); err != nil {
		t.Fatal(err)
	}
	if signed["note"] != "x" {
		t.Error("the signed form leaves out a member that teep does not define")
	}
}
