package nearroute

import (
	"strings"
	"testing"
)

func TestConfiguredOrigin(t *testing.T) {
	for _, tt := range []struct {
		origin, authority, canonical string
		index                        uint64
		indexed, static, invalid     bool
	}{
		{origin: "https://API.NEAR.AI:443", authority: "api.near.ai"},
		{origin: "https://completions.near.ai", authority: "completions.near.ai"},
		{origin: "https://model.completions.near.ai", authority: "model.completions.near.ai", canonical: "model.completions.near.ai"},
		{origin: "https://model-i0.completions.near.ai", authority: "model-i0.completions.near.ai", canonical: "model.completions.near.ai", indexed: true},
		{origin: "https://model-i18446744073709551615.completions.near.ai", authority: "model-i18446744073709551615.completions.near.ai", canonical: "model.completions.near.ai", index: ^uint64(0), indexed: true},
		{origin: "https://model-i01.completions.near.ai", invalid: true},
		{origin: "https://model-i-1.completions.near.ai", invalid: true},
		{origin: "https://model-i18446744073709551616.completions.near.ai", invalid: true},
		{origin: "https://model-i.completions.near.ai", invalid: true},
		{origin: "https://model-instruct.completions.near.ai", authority: "model-instruct.completions.near.ai", canonical: "model-instruct.completions.near.ai"},
		{origin: "https://model-i01.completions.near.ai:8443", authority: "model-i01.completions.near.ai:8443", static: true},
		{origin: "https://example.com", authority: "example.com", static: true},
		{origin: "https://[::1]:8443", authority: "[::1]:8443", static: true},
		{origin: "http://api.near.ai", invalid: true},
	} {
		t.Run(tt.origin, func(t *testing.T) {
			got, err := ParseOrigin(tt.origin)
			if tt.invalid {
				if err == nil {
					t.Fatal("accepted invalid origin")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Authority != tt.authority || got.Canonical != tt.canonical || got.Index != tt.index || got.Indexed != tt.indexed || got.Static != tt.static {
				t.Fatalf("unexpected origin: %+v", got)
			}
		})
	}
}

func TestIndexedAuthorityDNSLimit(t *testing.T) {
	for _, size := range []int{41, 42} {
		_, err := IndexedAuthority(strings.Repeat("a", size)+".completions.near.ai", ^uint64(0))
		if (err == nil) != (size == 41) {
			t.Fatalf("label size %d: %v", size, err)
		}
	}
}

func TestModelIdentifierBounds(t *testing.T) {
	for _, tt := range []struct {
		model string
		valid bool
	}{
		{"", false}, {strings.Repeat("a", 256), true}, {strings.Repeat("a", 257), false},
		{strings.Repeat("é", 128), true}, {strings.Repeat("é", 129), false},
		{"a\x00", false}, {"a\x1f", false}, {"a\x7f", false}, {"provider/model", true},
	} {
		if (ValidateModel(tt.model) == nil) != tt.valid {
			t.Errorf("validation differs for %d bytes", len(tt.model))
		}
	}
}
