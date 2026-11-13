package aci

import (
	"encoding/json"
	"strings"
	"testing"
)

// PinSessions sets provider.aci_session_ids and keeps every other member,
// also the other members of provider.
func TestPinSessions(t *testing.T) {
	ids := []string{strings.Repeat("ab", 32), strings.Repeat("cd", 32)}
	out, err := PinSessions([]byte(`{"model":"m","stream":true,"max_tokens":64,"provider":{"order":["a"]},"messages":[{"role":"user","content":"hi"}]}`), ids)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Model     string `json:"model"`
		Stream    bool   `json:"stream"`
		MaxTokens int    `json:"max_tokens"`
		Provider  struct {
			Order         []string `json:"order"`
			ACISessionIDs []string `json:"aci_session_ids"`
		} `json:"provider"`
		Messages []map[string]string `json:"messages"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got.Model != "m" || !got.Stream || got.MaxTokens != 64 || len(got.Messages) != 1 || got.Messages[0]["content"] != "hi" {
		t.Errorf("request members changed: %s", out)
	}
	if len(got.Provider.Order) != 1 || strings.Join(got.Provider.ACISessionIDs, ",") != strings.Join(ids, ",") {
		t.Errorf("provider = %+v", got.Provider)
	}
}

// A request without pinned sessions, a client's own ACI constraint, and a
// malformed body fail.
func TestPinSessionsRefuses(t *testing.T) {
	id := []string{strings.Repeat("ab", 32)}
	for _, tc := range []struct {
		name string
		body string
		ids  []string
	}{
		{"no session", `{"model":"m"}`, nil},
		{"uppercase id", `{"model":"m"}`, []string{strings.Repeat("AB", 32)}},
		{"client pins sessions", `{"model":"m","provider":{"aci_session_ids":["x"]}}`, id},
		{"client relaxes verification", `{"model":"m","provider":{"aci_verified":false}}`, id},
		{"provider not an object", `{"model":"m","provider":"x"}`, id},
		{"provider null", `{"model":"m","provider":null}`, id},
		{"not an object", `["m"]`, id},
		{"duplicate member", `{"model":"m","model":"n"}`, id},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PinSessions([]byte(tc.body), tc.ids); err == nil {
				t.Fatal("request accepted")
			}
		})
	}
}
