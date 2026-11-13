package aci

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/13rac1/teep/internal/jsonstrict/aliastest"
)

// A member whose name differs from a defined member only in letter case
// makes the document ambiguous and fails every ACI/1 parser with the
// jsonstrict refusal (CaseFoldError), also when it follows the defined
// member or stands alone. Unknown members are only reported; these are not
// unknown members.
func TestACIParsersRefuseFoldedAliases(t *testing.T) {
	ctx := context.Background()
	read := func(name string) []byte {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	gateway := read("gateway_variant.json")
	canonical := read("canonical_report.json")
	receipt := read("receipt.json")
	sessionBody, _ := withID(t, smallSession(t))

	cases := []struct {
		name  string
		parse func() error
	}{
		{"gateway variant signing key after the member", func() error {
			_, err := Parse(ctx, aliastest.Append(t, gateway, "Signing_Public_Key", `"04aa"`), "phalacloud")
			return err
		}},
		{"gateway variant nonce alone", func() error {
			_, err := Parse(ctx, aliastest.Append(t, gateway, "Nonce", `"00"`), "phalacloud")
			return err
		}},
		{"canonical report", func() error {
			_, err := ParseCanonical(ctx, aliastest.Append(t, canonical, "API_Version", `"aci/1"`), "phalacloud")
			return err
		}},
		{"session record", func() error {
			// The session id is the digest of the canonical form, which
			// sorts members, so it does not depend on where the alias is.
			body := aliastest.Append(t, sessionBody, "Verifier_ID", `"chutes"`)
			value, err := sessionValue(body)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := canonicalize(value)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(canonical)
			_, err = ParseSession(body, hex.EncodeToString(sum[:]))
			return err
		}},
		{"gateway event log entry", func() error {
			// Every entry of the log, in the top-level attestation and in
			// its all_attestations copy, gets the alias, so the two stay
			// equal.
			body := bytes.ReplaceAll(gateway, []byte(`\"imr\":0`), []byte(`\"imr\":0,\"IMR\":3`))
			if bytes.Equal(body, gateway) {
				t.Fatal("gateway fixture changed shape")
			}
			_, err := Parse(ctx, body, "phalacloud")
			return err
		}},
		{"receipt event type", func() error {
			body := bytes.Replace(receipt, []byte(`"type":"request.received"}`), []byte(`"type":"request.received","Type":"response.returned"}`), 1)
			if bytes.Equal(body, receipt) {
				t.Fatal("receipt fixture changed shape")
			}
			_, err := ParseReceipt(body)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			aliastest.Refused(t, tc.parse())
		})
	}
}
