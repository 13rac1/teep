package aci

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// gatewayVariantBody reads the gateway variant attestation body of a live
// Phala Cloud capture (2026-10-27): no echoed nonce or model, and an
// all_attestations list of one entry.
func gatewayVariantBody(t *testing.T) []byte {
	t.Helper()
	body, err := os.ReadFile("testdata/gateway_variant.json")
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// mutateBody decodes body, applies change to the top-level members, and
// encodes it again.
func mutateBody(t *testing.T, body []byte, change func(top map[string]json.RawMessage, entry map[string]json.RawMessage) []json.RawMessage) []byte {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatal(err)
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(top["all_attestations"], &entries); err != nil || len(entries) != 1 {
		t.Fatalf("fixture all_attestations: %v (%d entries)", err, len(entries))
	}
	list := change(top, entries[0])
	if list == nil {
		entry, err := json.Marshal(entries[0])
		if err != nil {
			t.Fatal(err)
		}
		list = []json.RawMessage{entry}
	}
	encoded, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	top["all_attestations"] = encoded
	out, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParseGatewayVariant(t *testing.T) {
	raw, err := Parse(context.Background(), gatewayVariantBody(t), "phalacloud")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(raw.UnknownFields) != 0 || len(raw.MissingFields) != 0 {
		t.Fatalf("unknown=%v missing=%v, want none for the gateway variant", raw.UnknownFields, raw.MissingFields)
	}
	if raw.Nonce != "" || raw.Model != "" || raw.GatewayNonceHex != "" {
		t.Fatalf("gateway variant echoed nonce=%q model=%q", raw.Nonce, raw.Model)
	}
	if raw.GatewayIntelQuote == "" || raw.ACIWorkloadKeysetDigest == "" {
		t.Fatal("gateway evidence missing")
	}
}

// Venice variant responses keep reporting their echo fields as missing when
// they are absent: only the gateway variant omits them.
func TestParseVeniceVariantStillReportsMissingEcho(t *testing.T) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(fixtureBody(t), &top); err != nil {
		t.Fatal(err)
	}
	delete(top, "nonce")
	body, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Parse(context.Background(), body, "venice")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !slices.Contains(raw.MissingFields, "nonce") {
		t.Fatalf("missing = %v, want nonce reported for the Venice variant", raw.MissingFields)
	}
}

// all_attestations must hold exactly one entry equal to the top-level
// fields; every other content fails the parse.
func TestParseAllAttestationsRule(t *testing.T) {
	body := gatewayVariantBody(t)
	for _, tc := range []struct {
		name   string
		change func(top, entry map[string]json.RawMessage) []json.RawMessage
		want   string
	}{
		{"no entries", func(_, _ map[string]json.RawMessage) []json.RawMessage { return []json.RawMessage{} }, "has 0 entries"},
		{"two entries", func(_, entry map[string]json.RawMessage) []json.RawMessage {
			one, _ := json.Marshal(entry)
			return []json.RawMessage{one, one}
		}, "has 2 entries"},
		{"differing value", func(_, entry map[string]json.RawMessage) []json.RawMessage {
			entry["signing_address"] = json.RawMessage(`"0x0000000000000000000000000000000000000000"`)
			return nil
		}, "all_attestations[0].signing_address differs"},
		{"extra field", func(_, entry map[string]json.RawMessage) []json.RawMessage {
			entry["extra"] = json.RawMessage(`1`)
			return nil
		}, "all_attestations[0].extra is not a top-level field"},
		{"missing field", func(_, entry map[string]json.RawMessage) []json.RawMessage {
			delete(entry, "intel_quote")
			return nil
		}, "all_attestations[0] has no intel_quote field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(context.Background(), mutateBody(t, body, tc.change), "phalacloud")
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.HasPrefix(err.Error(), "phalacloud aci/1: ") {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// An entry with the same values in another encoding (key order, spacing)
// is equal.
func TestParseAllAttestationsEncodingIndependent(t *testing.T) {
	body := mutateBody(t, gatewayVariantBody(t), func(_, entry map[string]json.RawMessage) []json.RawMessage {
		indented, err := json.MarshalIndent(entry["service_capabilities"], "", "    ")
		if err != nil {
			t.Fatal(err)
		}
		entry["service_capabilities"] = indented
		return nil
	})
	if _, err := Parse(context.Background(), body, "phalacloud"); err != nil {
		t.Fatalf("Parse with a re-encoded equal entry: %v", err)
	}
}

// A top-level field that neither variant defines fails the parse of a
// gateway variant response: the single all_attestations entry must carry
// every top-level field, so a field outside it is not part of the attested
// copy.
func TestParseGatewayVariantUndefinedField(t *testing.T) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(gatewayVariantBody(t), &top); err != nil {
		t.Fatal(err)
	}
	top["undefined_field"] = json.RawMessage(`true`)
	body, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(context.Background(), body, "phalacloud")
	if err == nil || !strings.Contains(err.Error(), "all_attestations[0] has no undefined_field field") {
		t.Fatalf("err = %v, want the undefined field to fail the parse", err)
	}
}
