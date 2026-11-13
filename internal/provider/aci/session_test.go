package aci

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Session ids of the live captures of 2026-10-31 from tee.redpill.ai for
// qwen/qwen3.8-27b. The Chutes session shares its evidence bundle with two
// other sessions of the list.
const (
	phalaDirectSessionID = "4d849e211f7078bd8d27a748a7ac0ddfe164d2ef5c0e29e6e30292a371276320"
	chutesSessionID      = "299f127652dcdb0edddda771afc55c80b31de39de1c38e26b7b57fd777ef68a1"
	chutesBundleDigest   = "sha256:db6045f43a9df068aec310a34df802f0fa06342f4bd0beb888c42a1c4c15cc89"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestParseSessionFixtures(t *testing.T) {
	direct, err := ParseSession(readTestdata(t, "session_phala_direct.json"), phalaDirectSessionID)
	if err != nil {
		t.Fatalf("phala-direct session: %v", err)
	}
	if direct.VerifierID != "private-ai-verifier/phala-direct/v1" || direct.Endpoint != "https://qwen3-8-27b.use1-9b.phala.com" || direct.Identity == nil {
		t.Errorf("phala-direct session: verifier %q endpoint %q identity %v", direct.VerifierID, direct.Endpoint, direct.Identity != nil)
	}
	if b := direct.ChannelBindings; len(b) != 1 || b[0].Type != BindingTLSSPKI || b[0].SPKISHA256 != "1eff9bb68300cb00c2776a9ae583e5a058dfa96972cb4390b6e8c704b0a44040" {
		t.Errorf("phala-direct channel binding = %+v", b)
	}
	if direct.Evidence.MediaType != "application/json" || direct.Claims["tee_attested"].Source != "hardware_proven" {
		t.Errorf("phala-direct evidence %s, tee_attested %+v", direct.Evidence.MediaType, direct.Claims["tee_attested"])
	}

	chutes, err := ParseSession(readTestdata(t, "session_chutes.json"), chutesSessionID)
	if err != nil {
		t.Fatalf("Chutes session: %v", err)
	}
	if chutes.Identity != nil || chutes.EvidenceDigest != chutesBundleDigest {
		t.Errorf("Chutes session: identity %v digest %s", chutes.Identity, chutes.EvidenceDigest)
	}
	if b := chutes.ChannelBindings; len(b) != 1 || b[0].Type != BindingE2EEPublicKey || b[0].KeyID != "fa2cbed2-284e-4ace-9de0-b003a928c000" || b[0].Algorithm != "chutes-ml-kem-768" {
		t.Errorf("Chutes channel binding = %+v", b)
	}
	parts, err := chutes.Evidence.Parts()
	if err != nil {
		t.Fatalf("Chutes evidence parts: %v", err)
	}
	ids := make([]string, 0, len(parts))
	for _, p := range parts {
		ids = append(ids, p.ContentID)
	}
	want := "<chutes.measurements> <chutes.attestation_evidence> <chutes.e2ee_instances.0> <chutes.e2ee_instances.1> <chutes.e2ee_instances.2>"
	if strings.Join(ids, " ") != want {
		t.Errorf("parts %q, want %q", ids, want)
	}
}

// The cited id must be the hash of the record: another id, or the id in
// another form, fails.
func TestParseSessionChecksID(t *testing.T) {
	body := readTestdata(t, "session_phala_direct.json")
	for _, id := range []string{chutesSessionID, strings.ToUpper(phalaDirectSessionID), phalaDirectSessionID[:63], ""} {
		if _, err := ParseSession(body, id); err == nil {
			t.Errorf("id %q accepted", id)
		}
	}
}

func TestParseSessionList(t *testing.T) {
	sessions, err := ParseSessionList(readTestdata(t, "session_list.json"))
	if err != nil {
		t.Fatal(err)
	}
	direct, chutes, sameBundle := 0, 0, 0
	for _, s := range sessions {
		if s.Evidence != nil {
			t.Errorf("list entry %s has evidence data", s.ID)
		}
		switch s.VerifierID {
		case "private-ai-verifier/phala-direct/v1":
			direct++
		case "private-ai-verifier/chutes/v1":
			chutes++
		}
		if s.EvidenceDigest == chutesBundleDigest {
			sameBundle++
		}
	}
	if len(sessions) != 15 || direct != 1 || chutes != 14 || sameBundle != 3 {
		t.Errorf("sessions=%d phala-direct=%d chutes=%d bundle=%d, want 15, 1, 14, 3", len(sessions), direct, chutes, sameBundle)
	}
}

// One full record confirms every list entry of its evidence bundle: the
// rebuilt records hash to their ids. An entry of another bundle fails.
func TestRebuildSession(t *testing.T) {
	sessions, err := ParseSessionList(readTestdata(t, "session_list.json"))
	if err != nil {
		t.Fatal(err)
	}
	full, err := ParseSession(readTestdata(t, "session_chutes.json"), chutesSessionID)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt := 0
	for _, entry := range sessions {
		got, err := RebuildSession(entry, full)
		if entry.EvidenceDigest != chutesBundleDigest {
			if err == nil {
				t.Errorf("entry %s of another bundle was rebuilt", entry.ID)
			}
			continue
		}
		if err != nil {
			t.Errorf("rebuild %s: %v", entry.ID, err)
			continue
		}
		if got.ID != entry.ID || got.Evidence == nil || got.ChannelBindings[0].KeyID == "" {
			t.Errorf("rebuilt %s: id %s", entry.ID, got.ID)
		}
		rebuilt++
	}
	if rebuilt != 3 {
		t.Errorf("rebuilt %d sessions, want 3", rebuilt)
	}
	if _, err := RebuildSession(full, full); err == nil {
		t.Error("a full record was rebuilt as a list entry")
	}
}

// smallSession returns the phala-direct record with a small JSON evidence,
// as a canonical value that a test changes before it computes the id.
func smallSession(t *testing.T) map[string]any {
	t.Helper()
	value, err := sessionValue(readTestdata(t, "session_phala_direct.json"))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"evidence":"small"}`)
	sum := sha256.Sum256(data)
	value["evidence"] = map[string]any{
		"digest": "sha256:" + hex.EncodeToString(sum[:]),
		"data":   "data:application/json;base64," + base64.StdEncoding.EncodeToString(data),
	}
	return value
}

// withID returns the record bytes and their session id.
func withID(t *testing.T, value map[string]any) (body []byte, id string) {
	t.Helper()
	body, err := canonicalize(value)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return body, hex.EncodeToString(sum[:])
}

func claims(v map[string]any) map[string]any { return v["claims"].(map[string]any) }

func TestParseSessionRejectsMalformedRecords(t *testing.T) {
	if _, err := ParseSession(withID(t, smallSession(t))); err != nil {
		t.Fatalf("small session: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"undefined member", func(v map[string]any) { v["note"] = "x" }},
		{"no endpoint", func(v map[string]any) { delete(v, "endpoint") }},
		{"empty endpoint", func(v map[string]any) { v["endpoint"] = "" }},
		{"other api_version", func(v map[string]any) { v["api_version"] = "aci/2" }},
		{"empty period", func(v map[string]any) { v["expires_at"] = v["established_at"] }},
		{"null identity", func(v map[string]any) { v["identity"] = nil }},
		{"no channel binding", func(v map[string]any) { v["channel_binding"] = []any{} }},
		{"other binding type", func(v map[string]any) {
			v["channel_binding"] = []any{map[string]any{"type": "dns_name", "origin": "https://a.example"}}
		}},
		{"binding with undefined member", func(v map[string]any) {
			b := v["channel_binding"].([]any)[0].(map[string]any)
			b["note"] = "x"
		}},
		{"TLS binding with an E2EE member", func(v map[string]any) {
			b := v["channel_binding"].([]any)[0].(map[string]any)
			b["provider"] = "chutes"
		}},
		{"E2EE binding with a TLS member", func(v map[string]any) {
			v["channel_binding"] = []any{map[string]any{"type": BindingE2EEPublicKey, "provider": "chutes", "algorithm": "chutes-ml-kem-768",
				"public_key_sha256": strings.Repeat("ab", 32), "origin": "https://a.example"}}
		}},
		{"E2EE binding without its algorithm", func(v map[string]any) {
			v["channel_binding"] = []any{map[string]any{"type": BindingE2EEPublicKey, "provider": "chutes", "public_key_sha256": strings.Repeat("ab", 32)}}
		}},
		{"uppercase spki", func(v map[string]any) {
			b := v["channel_binding"].([]any)[0].(map[string]any)
			b["spki_sha256"] = strings.ToUpper(b["spki_sha256"].(string))
		}},
		{"undefined claim", func(v map[string]any) { claims(v)["fast"] = map[string]any{"status": "unknown"} }},
		{"missing claim", func(v map[string]any) { delete(claims(v), "gpu_attested") }},
		{"no extra", func(v map[string]any) { delete(claims(v), "extra") }},
		{"unknown claim with source", func(v map[string]any) {
			claims(v)["model_weights_provenance"] = map[string]any{"status": "unknown", "source": "hardware_proven", "reason": "x"}
		}},
		{"asserted claim without source", func(v map[string]any) {
			claims(v)["tee_attested"] = map[string]any{"status": "asserted", "reason": "x"}
		}},
		{"other claim status", func(v map[string]any) { claims(v)["tee_attested"] = map[string]any{"status": "probably"} }},
		{"other claim source", func(v map[string]any) {
			claims(v)["tee_attested"] = map[string]any{"status": "asserted", "source": "rumor", "reason": "x"}
		}},
		{"evidence of another digest", func(v map[string]any) {
			v["evidence"].(map[string]any)["digest"] = chutesBundleDigest
		}},
		{"evidence not base64", func(v map[string]any) {
			v["evidence"].(map[string]any)["data"] = "data:application/json,{}"
		}},
		{"evidence without data", func(v map[string]any) { delete(v["evidence"].(map[string]any), "data") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := smallSession(t)
			tc.change(value)
			_, err := ParseSession(withID(t, value))
			t.Log(err)
			if err == nil {
				t.Fatal("malformed session accepted")
			}
		})
	}
}

// key_id is the optional member of an E2EE binding.
func TestParseSessionE2EEBindingWithoutKeyID(t *testing.T) {
	value := smallSession(t)
	value["channel_binding"] = []any{map[string]any{"type": BindingE2EEPublicKey, "provider": "chutes", "algorithm": "chutes-ml-kem-768",
		"public_key_sha256": strings.Repeat("ab", 32)}}
	s, err := ParseSession(withID(t, value))
	if err != nil {
		t.Fatal(err)
	}
	if b := s.ChannelBindings[0]; b.KeyID != "" || b.Provider != "chutes" {
		t.Errorf("binding = %+v", b)
	}
}

// A duplicate member and a fractional number fail before the id check: the
// canonical form of either is not defined.
func TestParseSessionRejectsUndefinedCanonicalForm(t *testing.T) {
	body, id := withID(t, smallSession(t))
	for name, changed := range map[string]string{
		"duplicate member": strings.Replace(string(body), `{"api_version":"aci/1",`, `{"api_version":"aci/1","api_version":"aci/1",`, 1),
		"fraction":         strings.Replace(string(body), `"established_at":1793473465`, `"established_at":1793473465.5`, 1),
	} {
		if changed == string(body) {
			t.Fatalf("%s: test did not change the record", name)
		}
		if _, err := ParseSession([]byte(changed), id); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestEvidencePartsRejectsMalformedBundles(t *testing.T) {
	part := func(id, digest, body string) string {
		return "--b\r\nContent-Type: application/json\r\nContent-ID: " + id + "\r\nDigest: " + digest + "\r\n\r\n" + body + "\r\n"
	}
	digestOf := func(body string) string {
		sum := sha256.Sum256([]byte(body))
		return "sha-256=" + base64.StdEncoding.EncodeToString(sum[:])
	}
	good := part("<a>", digestOf("{}"), "{}")
	for name, bundle := range map[string]string{
		"digest mismatch":   part("<a>", digestOf("[]"), "{}") + "--b--\r\n",
		"other algorithm":   part("<a>", "md5=mZFLkyvTelC5g8XnyQrpOw==", "{}") + "--b--\r\n",
		"duplicate part id": good + good + "--b--\r\n",
		"no parts":          "--b--\r\n",
		"no Content-ID":     "--b\r\nContent-Type: application/json\r\nDigest: " + digestOf("{}") + "\r\n\r\n{}\r\n--b--\r\n",
	} {
		e := &SessionEvidence{MediaType: "multipart/mixed", Params: map[string]string{"boundary": "b"}, Data: []byte(bundle)}
		if _, err := e.Parts(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	ok := &SessionEvidence{MediaType: "multipart/mixed", Params: map[string]string{"boundary": "b"}, Data: []byte(good + "--b--\r\n")}
	if parts, err := ok.Parts(); err != nil || len(parts) != 1 || string(parts[0].Body) != "{}" {
		t.Fatalf("good bundle: %v %v", parts, err)
	}
	if _, err := (&SessionEvidence{MediaType: "application/json"}).Parts(); err == nil {
		t.Error("JSON evidence returned parts")
	}
}

// A session id is bare lowercase hex in the list as in the record.
func TestParseSessionListRejectsMalformedEntries(t *testing.T) {
	var list map[string]any
	if err := json.Unmarshal(readTestdata(t, "session_list.json"), &list); err != nil {
		t.Fatal(err)
	}
	encode := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	sessions := list["sessions"].([]any)
	first := sessions[0].(map[string]any)
	for name, change := range map[string]func(){
		"uppercase id":       func() { first["session_id"] = strings.ToUpper(first["session_id"].(string)) },
		"evidence with data": func() { first["evidence"].(map[string]any)["data"] = "data:application/json;base64,e30=" },
		"listed twice":       func() { list["sessions"] = append(sessions, sessions[0]) },
		"other api_version":  func() { list["api_version"] = "aci/2" },
		"undefined member":   func() { list["next"] = "x" },
		"entry without id":   func() { delete(first, "session_id") },
		"entry member":       func() { first["note"] = "x" },
	} {
		saved := encode(list)
		change()
		if _, err := ParseSessionList(encode(list)); err == nil {
			t.Errorf("%s accepted", name)
		}
		if err := json.Unmarshal(saved, &list); err != nil {
			t.Fatal(err)
		}
		sessions = list["sessions"].([]any)
		first = sessions[0].(map[string]any)
	}
}
