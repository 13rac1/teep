package main

import (
	"os"
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

// --------------------------------------------------------------------------
// Help printer tests — capture stdout via os.Pipe
// --------------------------------------------------------------------------

// captureStdout runs fn while capturing stdout. Returns the captured output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = origStdout

	buf := make([]byte, 64*1024)
	n, _ := r.Read(buf)
	r.Close()
	return string(buf[:n])
}

func TestPrintOverview(t *testing.T) {
	out := captureStdout(t, printOverview)
	t.Logf("output length: %d", len(out))

	for _, want := range []string{"teep", "Usage:", "serve", "verify", "help"} {
		if !strings.Contains(out, want) {
			t.Errorf("printOverview missing %q", want)
		}
	}
}

func TestPrintServeHelp(t *testing.T) {
	out := captureStdout(t, printServeHelp)
	t.Logf("output length: %d", len(out))

	for _, want := range []string{"teep serve", "--provider", "--offline"} {
		if !strings.Contains(out, want) {
			t.Errorf("printServeHelp missing %q", want)
		}
	}
}

func TestPrintVerifyHelp(t *testing.T) {
	out := captureStdout(t, printVerifyHelp)
	t.Logf("output length: %d", len(out))

	for _, want := range []string{"teep verify", "--provider", "--model"} {
		if !strings.Contains(out, want) {
			t.Errorf("printVerifyHelp missing %q", want)
		}
	}
}

func TestPrintTiersHelp(t *testing.T) {
	out := captureStdout(t, printTiersHelp)
	t.Logf("output length: %d", len(out))

	for _, want := range []string{"Verification Tiers", "Tier 1", "Tier 2", "Tier 3"} {
		if !strings.Contains(out, want) {
			t.Errorf("printTiersHelp missing %q", want)
		}
	}
}

func TestPrintFactorsHelp(t *testing.T) {
	out := captureStdout(t, printFactorsHelp)
	t.Logf("output length: %d", len(out))

	for _, want := range []string{"Verification Factors", "nonce_match", "tdx_quote_present"} {
		if !strings.Contains(out, want) {
			t.Errorf("printFactorsHelp missing %q", want)
		}
	}
}

func TestPrintFactorHelp(t *testing.T) {
	f, ok := findFactorByName("tls_key_binding")
	if !ok {
		t.Fatal("tls_key_binding not found")
	}

	out := captureStdout(t, func() { printFactorHelp(f) })
	t.Logf("output length: %d", len(out))

	for _, want := range []string{"tls_key_binding", "Tier 3"} {
		if !strings.Contains(out, want) {
			t.Errorf("printFactorHelp missing %q", want)
		}
	}
}

func TestRunHelp_NoArgs(t *testing.T) {
	out := captureStdout(t, func() { runHelp(nil) })
	if !strings.Contains(out, "teep") {
		t.Error("runHelp(nil) should print overview")
	}
}

func TestRunHelp_Serve(t *testing.T) {
	out := captureStdout(t, func() { runHelp([]string{"serve"}) })
	if !strings.Contains(out, "teep serve") {
		t.Error("runHelp(serve) should print serve help")
	}
}

func TestRunHelp_Verify(t *testing.T) {
	out := captureStdout(t, func() { runHelp([]string{"verify"}) })
	if !strings.Contains(out, "teep verify") {
		t.Error("runHelp(verify) should print verify help")
	}
}

func TestRunHelp_Tiers(t *testing.T) {
	out := captureStdout(t, func() { runHelp([]string{"tiers"}) })
	if !strings.Contains(out, "Verification Tiers") {
		t.Error("runHelp(tiers) should print tiers help")
	}
}

func TestRunHelp_Factors(t *testing.T) {
	out := captureStdout(t, func() { runHelp([]string{"factors"}) })
	if !strings.Contains(out, "Verification Factors") {
		t.Error("runHelp(factors) should print factors help")
	}
}

func TestRunHelp_FactorName(t *testing.T) {
	out := captureStdout(t, func() { runHelp([]string{"nonce_match"}) })
	if !strings.Contains(out, "nonce_match") {
		t.Error("runHelp(nonce_match) should print factor help")
	}
}

func TestRunHelp_UnknownTopic(t *testing.T) {
	// Unknown topic prints error to stderr and overview to stdout.
	out := captureStdout(t, func() { runHelp([]string{"nonexistent"}) })
	// Overview should still be printed.
	if !strings.Contains(out, "teep") {
		t.Error("runHelp(nonexistent) should print overview as fallback")
	}
}
