package phalacloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
)

// chutesParts returns the evidence and instance parts of the Chutes
// session's bundle, and the nonce of its evidence request.
func chutesParts(t *testing.T) (evidence []byte, instances [][]byte, nonce attestation.Nonce) {
	t.Helper()
	s := loadSession(t, "session_chutes.json", chutesSessionID)
	parts, err := s.Evidence.Parts()
	if err != nil {
		t.Fatal(err)
	}
	for i := range parts {
		switch {
		case parts[i].ContentID == chutesEvidencePart:
			evidence = parts[i].Body
			if nonce, err = chutesEvidenceNonce(parts[i].ContentLocation); err != nil {
				t.Fatal(err)
			}
		case strings.HasPrefix(parts[i].ContentID, chutesInstancesPart):
			instances = append(instances, parts[i].Body)
		}
	}
	return evidence, instances, nonce
}

// chutesBoundInstance is the instance that the Chutes session binds.
const chutesBoundInstance = "5616c527-26bc-4bd4-9660-16ccae26994c"

// The session path requires exactly the members of the Chutes evidence,
// with the newer members typed: tee_type tdx, an attested_body whose quote
// and nonce are those of the entry and of the request, a signature, and
// excluded_instance_ids. Any other member fails.
func TestParseChutesInstanceIsStrict(t *testing.T) {
	evidence, instances, nonce := chutesParts(t)
	if _, err := parseChutesInstance(context.Background(), instances, evidence, chutesBoundInstance, nonce); err != nil {
		t.Fatalf("the gateway's bundle: %v", err)
	}
	bound := func(d map[string]any) map[string]any {
		for _, e := range d["evidence"].([]any) {
			if m := e.(map[string]any); m["instance_id"] == chutesBoundInstance {
				return m
			}
		}
		t.Fatal("no entry of the bound instance")
		return nil
	}
	attested := func(d map[string]any, change func(map[string]any)) {
		m := bound(d)
		data, err := base64.StdEncoding.DecodeString(m["attested_body"].(string))
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if err := json.Unmarshal(data, &body); err != nil {
			t.Fatal(err)
		}
		change(body)
		out, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		m["attested_body"] = base64.StdEncoding.EncodeToString(out)
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
		want   string
	}{
		{"no excluded_instance_ids", func(d map[string]any) { delete(d, "excluded_instance_ids") }, "excluded_instance_ids"},
		{"other tee_type", func(d map[string]any) { bound(d)["tee_type"] = "sev-snp" }, "tee_type"},
		{"no signature", func(d map[string]any) { delete(bound(d), "signature") }, "signature"},
		{"attested_body of another quote", func(d map[string]any) {
			attested(d, func(b map[string]any) { b["evidence"].(map[string]any)["tdx_quote"] = "AAAA" })
		}, "quote is not the quote of the entry"},
		{"attested_body of another nonce", func(d map[string]any) {
			attested(d, func(b map[string]any) { b["nonce"] = strings.Repeat("00", 32) })
		}, "nonce is not the nonce"},
		{"attested_body with both quote members", func(d map[string]any) {
			attested(d, func(b map[string]any) {
				ev := b["evidence"].(map[string]any)
				ev["quote"] = ev["tdx_quote"]
			})
		}, "exactly one of"},
		{"attested_body with an undefined member", func(d map[string]any) {
			attested(d, func(b map[string]any) { b["note"] = "x" })
		}, "undefined members"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var d map[string]any
			if err := json.Unmarshal(evidence, &d); err != nil {
				t.Fatal(err)
			}
			tc.change(d)
			changed, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			_, err = parseChutesInstance(context.Background(), instances, changed, chutesBoundInstance, nonce)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
