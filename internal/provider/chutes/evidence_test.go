package chutes_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/chutes"
	"github.com/13rac1/teep/internal/provider/chutes/chutestest"
)

func TestParseEvidence(t *testing.T) {
	nonce := attestation.NewNonce()
	body := chutestest.Marshal(t, chutestest.Evidence(t, nonce, "inst-a", "inst-b"))
	raw, err := chutes.ParseEvidence(context.Background(), body, nonce, 256)
	if err != nil {
		t.Fatalf("ParseEvidence: %v", err)
	}
	if raw.InstanceID != "inst-a" {
		t.Errorf("InstanceID = %q, want the first entry inst-a", raw.InstanceID)
	}
	if raw.SigningKey != "" || raw.SigningAlgo != "" {
		t.Errorf("SigningKey = %q, SigningAlgo = %q, want none: the response names no key", raw.SigningKey, raw.SigningAlgo)
	}
	if raw.CandidatesAvail != 2 || raw.CandidatesEval != 1 {
		t.Errorf("candidates = %d/%d evaluated, want 1/2", raw.CandidatesEval, raw.CandidatesAvail)
	}
	if want := hex.EncodeToString([]byte("quote of inst-a")); raw.IntelQuote != want {
		t.Errorf("IntelQuote = %q, want %q", raw.IntelQuote, want)
	}
	// The evidence response echoes no nonce in a place that a quote binds.
	if raw.Nonce != "" || raw.BackendFormat != attestation.FormatChutes {
		t.Errorf("Nonce = %q, BackendFormat = %q; want no nonce, chutes", raw.Nonce, raw.BackendFormat)
	}
	if len(raw.UnknownFields) != 0 || len(raw.MissingFields) != 0 {
		t.Errorf("UnknownFields = %q, MissingFields = %q, want none", raw.UnknownFields, raw.MissingFields)
	}
}

// A member that teep does not know is returned for the response_schema
// factor, not refused. An absent member that teep does not require is
// returned too.
func TestParseEvidence_UnknownMembersReported(t *testing.T) {
	nonce := attestation.NewNonce()
	doc := chutestest.Evidence(t, nonce, "inst-a")
	doc["note"] = "x"
	chutestest.Entry(t, doc, 0)["region"] = "x"
	delete(chutestest.Entry(t, doc, 0), "certificate")
	raw, err := chutes.ParseEvidence(context.Background(), chutestest.Marshal(t, doc), nonce, 256)
	if err != nil {
		t.Fatalf("ParseEvidence: %v", err)
	}
	t.Logf("UnknownFields = %q, MissingFields = %q", raw.UnknownFields, raw.MissingFields)
	for _, want := range []string{"note", "region"} {
		if !strings.Contains(strings.Join(raw.UnknownFields, " "), want) {
			t.Errorf("UnknownFields = %q, want %q", raw.UnknownFields, want)
		}
	}
	if !strings.Contains(strings.Join(raw.MissingFields, " "), "certificate") {
		t.Errorf("MissingFields = %q, want certificate", raw.MissingFields)
	}
}

// A non-empty failed or excluded list is not refused.
func TestParseEvidence_FailedAndExcludedInstances(t *testing.T) {
	nonce := attestation.NewNonce()
	doc := chutestest.Evidence(t, nonce, "inst-a")
	doc["failed_instance_ids"] = []any{"inst-f"}
	doc["excluded_instance_ids"] = []any{"inst-x"}
	if _, err := chutes.ParseEvidence(context.Background(), chutestest.Marshal(t, doc), nonce, 256); err != nil {
		t.Fatalf("ParseEvidence: %v", err)
	}
}

func TestParseEvidence_Refused(t *testing.T) {
	nonce := attestation.NewNonce()
	tooMany := make([]string, 257)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("inst-%d", i)
	}
	for _, tc := range []struct {
		name   string
		doc    map[string]any
		change func(map[string]any)
		want   string
	}{
		{"no entries", chutestest.Evidence(t, nonce), nil, "no evidence entries"},
		{"too many entries", chutestest.Evidence(t, nonce, tooMany...), nil, "max 256"},
		{"duplicate instance id", chutestest.Evidence(t, nonce, "inst-a", "inst-a"), nil, "instance inst-a is in evidence and in evidence"},
		{"empty instance id", chutestest.Evidence(t, nonce, ""), nil, "empty instance id"},
		{"failed id with evidence", chutestest.Evidence(t, nonce, "inst-a"), func(d map[string]any) {
			d["failed_instance_ids"] = []any{"inst-a"}
		}, "instance inst-a is in evidence and in failed_instance_ids"},
		{"excluded id with evidence", chutestest.Evidence(t, nonce, "inst-a"), func(d map[string]any) {
			d["excluded_instance_ids"] = []any{"inst-a"}
		}, "instance inst-a is in evidence and in excluded_instance_ids"},
		{"id failed and excluded", chutestest.Evidence(t, nonce, "inst-a"), func(d map[string]any) {
			d["failed_instance_ids"] = []any{"inst-f"}
			d["excluded_instance_ids"] = []any{"inst-f"}
		}, "in failed_instance_ids and in excluded_instance_ids"},
		{"failed id twice", chutestest.Evidence(t, nonce, "inst-a"), func(d map[string]any) {
			d["failed_instance_ids"] = []any{"inst-f", "inst-f"}
		}, "in failed_instance_ids and in failed_instance_ids"},
		{"no failed_instance_ids", chutestest.Evidence(t, nonce, "inst-a"), func(d map[string]any) {
			delete(d, "failed_instance_ids")
		}, "no failed_instance_ids"},
		{"no excluded_instance_ids", chutestest.Evidence(t, nonce, "inst-a"), func(d map[string]any) {
			delete(d, "excluded_instance_ids")
		}, "no excluded_instance_ids"},
		{"failed_instance_ids of another type", chutestest.Evidence(t, nonce, "inst-a"), func(d map[string]any) {
			d["failed_instance_ids"] = "inst-f"
		}, "unmarshal"},
		{"second entry of another nonce", chutestest.Evidence(t, nonce, "inst-a", "inst-b"), func(d map[string]any) {
			e := chutestest.Entry(t, d, 1)
			other := chutestest.Entry(t, chutestest.Evidence(t, attestation.NewNonce(), "inst-b"), 0)
			e["attested_body"] = other["attested_body"]
		}, "instance inst-b: attested_body nonce is not the nonce"},
		{"second entry of another tee_type", chutestest.Evidence(t, nonce, "inst-a", "inst-b"), func(d map[string]any) {
			chutestest.Entry(t, d, 1)["tee_type"] = "sev-snp"
		}, "tee_type"},
		{"entry without signature", chutestest.Evidence(t, nonce, "inst-a"), func(d map[string]any) {
			delete(chutestest.Entry(t, d, 0), "signature")
		}, "no signature"},
		{"quote that is not base64", chutestest.Evidence(t, nonce, "inst-a"), func(d map[string]any) {
			e := chutestest.Entry(t, d, 0)
			e["quote"] = "!!"
			body, _ := base64.StdEncoding.DecodeString(e["attested_body"].(string))
			e["attested_body"] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(body), `"tdx_quote":"`+base64.StdEncoding.EncodeToString([]byte("quote of inst-a"))+`"`, `"tdx_quote":"!!"`, 1)))
		}, "base64-decode quote"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.change != nil {
				tc.change(tc.doc)
			}
			_, err := chutes.ParseEvidence(context.Background(), chutestest.Marshal(t, tc.doc), nonce, 256)
			t.Logf("err: %v", err)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// The caller bounds the number of entries; the bound applies before any
// entry is checked.
func TestParseEvidence_MaxEntries(t *testing.T) {
	nonce := attestation.NewNonce()
	doc := chutestest.Evidence(t, nonce, "inst-a", "inst-b")
	if _, err := chutes.ParseEvidence(context.Background(), chutestest.Marshal(t, doc), nonce, 2); err != nil {
		t.Fatalf("2 entries, max 2: %v", err)
	}
	delete(chutestest.Entry(t, doc, 1), "attested_body")
	_, err := chutes.ParseEvidence(context.Background(), chutestest.Marshal(t, doc), nonce, 1)
	if err == nil || !strings.Contains(err.Error(), "evidence has 2 entries, max 1") {
		t.Fatalf("2 entries, max 1: err = %v, want the entry bound", err)
	}
}
