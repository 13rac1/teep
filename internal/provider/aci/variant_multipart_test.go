package aci

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// The gateway variant defines every member it carries, and
// service_capabilities.supported_multipart_constraint_endpoints is one of
// them (ACI/1 §4.1). A malformed list fails the variant too. The member is
// set in the top-level object and in its all_attestations copy, which must
// be equal.
func TestParseGatewayVariantMultipartConstraintEndpoints(t *testing.T) {
	set := func(value string) []byte {
		return mutateBody(t, gatewayVariantBody(t), func(top map[string]json.RawMessage, entry map[string]json.RawMessage) []json.RawMessage {
			var caps map[string]json.RawMessage
			if err := json.Unmarshal(entry["service_capabilities"], &caps); err != nil {
				t.Fatal(err)
			}
			caps["supported_multipart_constraint_endpoints"] = json.RawMessage(value)
			encoded, err := json.Marshal(caps)
			if err != nil {
				t.Fatal(err)
			}
			entry["service_capabilities"] = encoded
			top["service_capabilities"] = encoded
			return nil
		})
	}
	if _, err := Parse(context.Background(), set(`["/v1/audio/transcriptions"]`), "phalacloud"); err != nil {
		t.Fatalf("Parse with the member: %v", err)
	}
	_, err := Parse(context.Background(), set(`["v1/audio"]`), "phalacloud")
	if err == nil || !strings.Contains(err.Error(), "not a clean URL path") {
		t.Fatalf("Parse with a malformed member: %v", err)
	}
}
