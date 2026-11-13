package aci

import (
	"context"
	"os"
	"testing"
)

// The gateway variant (Venice, NanoGPT) carries its keyset not_after, as the
// canonical report does, so that the attestation cache can end the report
// at it.
func TestParseSetsKeysetNotAfter(t *testing.T) {
	body, err := os.ReadFile("testdata/gateway_variant.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Parse(context.Background(), body, "venice")
	if err != nil {
		t.Fatal(err)
	}
	if raw.ACIKeysetNotAfter != 1795221116 {
		t.Fatalf("ACIKeysetNotAfter = %d, want 1795221116", raw.ACIKeysetNotAfter)
	}
}
