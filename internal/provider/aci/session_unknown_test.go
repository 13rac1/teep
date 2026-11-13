package aci

import (
	"encoding/json"
	"slices"
	"testing"
)

// A member that a session record does not define is returned in
// Session.Unknown and does not stop the parse. The session id stays the
// digest of the whole record, the member included.
func TestParseSessionReportsUndefinedMembers(t *testing.T) {
	value := smallSession(t)
	value["note"] = "x"
	value["channel_binding"].([]any)[0].(map[string]any)["future"] = "y"
	value["claims"].(map[string]any)["fast"] = map[string]any{"status": "unknown"}
	body, id := withID(t, value)
	s, err := ParseSession(body, id)
	if err != nil {
		t.Fatalf("ParseSession: %v", err)
	}
	for _, want := range []string{"note", "channel_binding[0].future", "claims.fast"} {
		if !slices.Contains(s.Unknown, want) {
			t.Errorf("Unknown = %v, want %s", s.Unknown, want)
		}
	}
	if s.ID != id {
		t.Errorf("id %s, want %s", s.ID, id)
	}
}

// Undefined members of the session list are returned: those outside the
// entries as the second result, those of an entry in its Session.Unknown.
func TestParseSessionListReportsUndefinedMembers(t *testing.T) {
	var list map[string]any
	if err := json.Unmarshal(readTestdata(t, "session_list.json"), &list); err != nil {
		t.Fatal(err)
	}
	list["next"] = "x"
	list["sessions"].([]any)[0].(map[string]any)["note"] = "y"
	body, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	sessions, listUnknown, err := ParseSessionList(body)
	if err != nil {
		t.Fatalf("ParseSessionList: %v", err)
	}
	if !slices.Equal(listUnknown, []string{"next"}) {
		t.Errorf("list unknown = %v, want [next]", listUnknown)
	}
	if !slices.Contains(sessions[0].Unknown, "note") {
		t.Errorf("entry unknown = %v, want note", sessions[0].Unknown)
	}
}
