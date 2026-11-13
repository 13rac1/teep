package aci

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// In the gateway variant, a keyset not_after above the int64 range parses,
// and the keyset fails its expiry bound. A not_after that is not an integer
// parses too, and the keyset fails its digest. Both fail the key-custody
// factor, not the parse. (The canonical report stores not_after as int64
// for the expiry of the cached authorization and refuses a larger value.)
func TestKeysetNotAfterNumbers(t *testing.T) {
	body, err := os.ReadFile("testdata/gateway_variant.json")
	if err != nil {
		t.Fatal(err)
	}
	with := func(value string) []byte {
		out := bytes.ReplaceAll(body, []byte(`"not_after":1796530946`), []byte(`"not_after":`+value))
		if bytes.Equal(out, body) {
			t.Fatal("fixture changed shape")
		}
		return out
	}
	now := time.Unix(1796530946-3600, 0)

	raw, err := Parse(context.Background(), with("18446744073709551615"), "phalacloud")
	if err != nil {
		t.Fatalf("Parse with a u64 not_after: %v", err)
	}
	ks := raw.ACIWorkloadKeyset.(*aciWorkloadKeyset)
	if _, err := ks.digestValue(); err != nil {
		t.Fatalf("digestValue: %v", err)
	}
	if ok, detail := keysetNotExpired(ks.NotAfter.String(), now); ok || !strings.Contains(detail, "more than") {
		t.Errorf("keysetNotExpired = %v, %q; want the lifetime bound to fail", ok, detail)
	}

	raw, err = Parse(context.Background(), with("1796530946.5"), "phalacloud")
	if err != nil {
		t.Fatalf("Parse with a fractional not_after: %v", err)
	}
	ks = raw.ACIWorkloadKeyset.(*aciWorkloadKeyset)
	if _, err := ks.digestValue(); err == nil || !strings.Contains(err.Error(), "not an integer") {
		t.Errorf("digestValue error = %v, want the served keyset refused", err)
	}
}
