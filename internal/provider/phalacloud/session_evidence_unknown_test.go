package phalacloud

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
)

// A member that the Phala model CVM evidence does not define is returned
// for the audit to report and does not stop the parse.
func TestPhalaDirectEvidenceReportsUndefinedMembers(t *testing.T) {
	s := loadSession(t, "session_phala_direct.json", phalaDirectSessionID)
	var top map[string]any
	if err := json.Unmarshal(s.Evidence.Data, &top); err != nil {
		t.Fatal(err)
	}
	top["info"].(map[string]any)["tcb_info"].(map[string]any)["note"] = "x"
	data, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	s.Evidence.Data = data
	ev, err := sessionEvidenceOf(context.Background(), s)
	if err != nil {
		t.Fatalf("sessionEvidenceOf: %v", err)
	}
	if !slices.ContainsFunc(ev.unknown, func(p string) bool { return p == "info.tcb_info.note" }) {
		t.Errorf("unknown = %v, want info.tcb_info.note", ev.unknown)
	}
}
