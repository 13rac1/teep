package main

import (
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
)

func TestFactorRegistryCount(t *testing.T) {
	if len(factorRegistry) != 23 {
		t.Errorf("factor registry has %d entries, want 23", len(factorRegistry))
	}
}

func TestFactorRegistryTiers(t *testing.T) {
	for i, f := range factorRegistry {
		var wantTier int
		switch {
		case i < 7:
			wantTier = 1
		case i < 16:
			wantTier = 2
		default: // 16..22 = Tier 3
			wantTier = 3
		}
		if f.Tier != wantTier {
			t.Errorf("factor[%d] %q: tier=%d, want %d", i, f.Name, f.Tier, wantTier)
		}
	}
}

func TestFactorRegistryNamesMatchReport(t *testing.T) {
	nonce := attestation.NewNonce()
	raw := &attestation.RawAttestation{
		Nonce:      nonce.Hex(),
		Model:      "test",
		IntelQuote: "dGVzdA==",
		SigningKey: "04" + strings.Repeat("ab", 64), // dummy uncompressed key
	}
	report := attestation.BuildReport("test", "test", raw, nonce, nil, nil, nil, nil, nil, nil, nil)

	if len(report.Factors) != len(factorRegistry) {
		t.Fatalf("report has %d factors, registry has %d", len(report.Factors), len(factorRegistry))
	}
	for i, f := range factorRegistry {
		if f.Name != report.Factors[i].Name {
			t.Errorf("factor[%d]: registry=%q, report=%q", i, f.Name, report.Factors[i].Name)
		}
	}
}

func TestFactorRegistryDescriptions(t *testing.T) {
	for i, f := range factorRegistry {
		if f.Summary == "" {
			t.Errorf("factor[%d] %q: Summary is empty", i, f.Name)
		}
		if f.Description == "" {
			t.Errorf("factor[%d] %q: Description is empty", i, f.Name)
		}
	}
}

func TestTierRegistryCount(t *testing.T) {
	if len(tierRegistry) != 3 {
		t.Errorf("tier registry has %d entries, want 3", len(tierRegistry))
	}
}

func TestFindFactorByName(t *testing.T) {
	f, ok := findFactorByName("tls_key_binding")
	if !ok {
		t.Fatal("tls_key_binding not found")
	}
	if f.Tier != 3 {
		t.Errorf("tls_key_binding tier: got %d, want 3", f.Tier)
	}

	_, ok = findFactorByName("nonexistent_factor")
	if ok {
		t.Error("nonexistent_factor should not be found")
	}
}

func TestWrapText(t *testing.T) {
	text := "This is a moderately long string that should be wrapped at a reasonable width for terminal display purposes."
	wrapped := wrapText(text, 4, 40)
	for i, line := range strings.Split(wrapped, "\n") {
		if len(line) > 40 {
			t.Errorf("line %d exceeds 40 chars (%d): %q", i, len(line), line)
		}
		if i > 0 && !strings.HasPrefix(line, "    ") {
			t.Errorf("line %d missing 4-space indent: %q", i, line)
		}
	}
}

func TestWrapTextEmpty(t *testing.T) {
	if got := wrapText("", 0, 80); got != "" {
		t.Errorf("wrapText empty: got %q, want empty", got)
	}
}

func TestWrapTextSingleWord(t *testing.T) {
	got := wrapText("hello", 2, 80)
	if got != "  hello" {
		t.Errorf("wrapText single word: got %q, want %q", got, "  hello")
	}
}
