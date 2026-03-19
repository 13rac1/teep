package main

import (
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
)

// --------------------------------------------------------------------------
// formatReport tests
// --------------------------------------------------------------------------

// buildTestReport constructs a VerificationReport with exactly 20 factors
// using the given per-factor inputs so we can verify formatting precisely.
func buildTestReport(provider, model string) *attestation.VerificationReport {
	factors := []attestation.FactorResult{
		// Tier 1 (0-6)
		{Name: "nonce_match", Status: attestation.Pass, Detail: "Nonce matches (64 hex chars)", Enforced: true},
		{Name: "tdx_quote_present", Status: attestation.Pass, Detail: "TDX quote present (1247 base64 chars)", Enforced: false},
		{Name: "tdx_quote_structure", Status: attestation.Pass, Detail: "Valid QuoteV4 structure", Enforced: false},
		{Name: "tdx_cert_chain", Status: attestation.Pass, Detail: "Certificate chain valid (Intel root CA)", Enforced: false},
		{Name: "tdx_quote_signature", Status: attestation.Pass, Detail: "Quote signature verified", Enforced: false},
		{Name: "tdx_debug_disabled", Status: attestation.Pass, Detail: "Debug bit is 0", Enforced: true},
		{Name: "signing_key_present", Status: attestation.Pass, Detail: "Signing key: 04a3b2...", Enforced: true},
		// Tier 2 (7-14)
		{Name: "tdx_reportdata_binding", Status: attestation.Pass, Detail: "REPORTDATA binds signing key + nonce", Enforced: true},
		{Name: "attestation_freshness", Status: attestation.Skip, Detail: "Quote age not determinable", Enforced: false},
		{Name: "tdx_tcb_current", Status: attestation.Pass, Detail: "TCB SVN: 03000000000000000000000000000000", Enforced: false},
		{Name: "nvidia_jwt_present", Status: attestation.Pass, Detail: "NVIDIA payload present (512 chars)", Enforced: false},
		{Name: "nvidia_jwt_signature", Status: attestation.Pass, Detail: "JWT signature valid (RS256)", Enforced: false},
		{Name: "nvidia_jwt_claims", Status: attestation.Pass, Detail: "Claims valid", Enforced: false},
		{Name: "nvidia_nonce_match", Status: attestation.Skip, Detail: "Nonce field not found in NVIDIA payload", Enforced: false},
		{Name: "e2ee_capable", Status: attestation.Pass, Detail: "E2EE key exchange possible", Enforced: false},
		// Tier 3 (15-19)
		{Name: "tls_key_binding", Status: attestation.Fail, Detail: "no TLS key in attestation", Enforced: false},
		{Name: "cpu_gpu_chain", Status: attestation.Fail, Detail: "CPU-GPU attestation not bound", Enforced: false},
		{Name: "measured_model_weights", Status: attestation.Fail, Detail: "no model weight hashes", Enforced: false},
		{Name: "build_transparency_log", Status: attestation.Fail, Detail: "no build transparency log", Enforced: false},
		{Name: "cpu_id_registry", Status: attestation.Fail, Detail: "no CPU ID registry check", Enforced: false},
	}

	passed, failed, skipped := 0, 0, 0
	for _, f := range factors {
		switch f.Status {
		case attestation.Pass:
			passed++
		case attestation.Fail:
			failed++
		case attestation.Skip:
			skipped++
		}
	}

	return &attestation.VerificationReport{
		Provider:  provider,
		Model:     model,
		Timestamp: time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC),
		Factors:   factors,
		Passed:    passed,
		Failed:    failed,
		Skipped:   skipped,
	}
}

func TestFormatReport_Header(t *testing.T) {
	r := buildTestReport("venice", "e2ee-qwen3")
	out := formatReport(r)

	if !strings.Contains(out, "Attestation Report: venice / e2ee-qwen3") {
		t.Errorf("header not found; output:\n%s", out)
	}
}

func TestFormatReport_Separator(t *testing.T) {
	r := buildTestReport("venice", "e2ee-qwen3")
	out := formatReport(r)

	// Separator is a line of U+2550 double-horizontal box characters.
	if !strings.Contains(out, "\u2550\u2550\u2550") {
		t.Errorf("separator line not found; output:\n%s", out)
	}
}

func TestFormatReport_TierLabels(t *testing.T) {
	r := buildTestReport("venice", "some-model")
	out := formatReport(r)

	for _, label := range []string{
		"Tier 1: Core Attestation",
		"Tier 2: Binding & Crypto",
		"Tier 3: Supply Chain & Channel Integrity",
	} {
		if !strings.Contains(out, label) {
			t.Errorf("tier label %q not found; output:\n%s", label, out)
		}
	}
}

func TestFormatReport_StatusIcons(t *testing.T) {
	r := buildTestReport("venice", "some-model")
	out := formatReport(r)

	if !strings.Contains(out, "\u2713") { // ✓ pass
		t.Error("pass icon ✓ not found in output")
	}
	if !strings.Contains(out, "\u2717") { // ✗ fail
		t.Error("fail icon ✗ not found in output")
	}
	if !strings.Contains(out, "?") { // ? skip
		t.Error("skip icon ? not found in output")
	}
}

func TestFormatReport_EnforcedTag(t *testing.T) {
	r := buildTestReport("venice", "some-model")
	out := formatReport(r)

	// nonce_match is enforced in our test report.
	if !strings.Contains(out, "[ENFORCED]") {
		t.Errorf("[ENFORCED] tag not found; output:\n%s", out)
	}
}

func TestFormatReport_ScoreLine(t *testing.T) {
	r := buildTestReport("venice", "some-model")
	out := formatReport(r)

	// Expect the score line: "Score: 12/20 passed, 2 skipped, 5 failed"
	// Our test report: 13 pass, 5 fail, 2 skip = 20 total.
	if !strings.Contains(out, "Score:") {
		t.Errorf("Score line not found; output:\n%s", out)
	}
	if !strings.Contains(out, "13/20 passed") {
		t.Errorf("expected '13/20 passed' in score line; output:\n%s", out)
	}
	if !strings.Contains(out, "2 skipped") {
		t.Errorf("expected '2 skipped' in score line; output:\n%s", out)
	}
	if !strings.Contains(out, "5 failed") {
		t.Errorf("expected '5 failed' in score line; output:\n%s", out)
	}
}

func TestFormatReport_FactorNamesPresent(t *testing.T) {
	r := buildTestReport("venice", "some-model")
	out := formatReport(r)

	factorNames := []string{
		"nonce_match",
		"tdx_quote_present",
		"tdx_reportdata_binding",
		"tls_key_binding",
		"cpu_id_registry",
	}
	for _, name := range factorNames {
		if !strings.Contains(out, name) {
			t.Errorf("factor name %q not found in output:\n%s", name, out)
		}
	}
}

func TestFormatReport_EmptyReport(t *testing.T) {
	// Ensure formatReport does not panic on an empty report.
	r := &attestation.VerificationReport{
		Provider:  "test",
		Model:     "test-model",
		Timestamp: time.Now(),
	}
	out := formatReport(r)

	if !strings.Contains(out, "Attestation Report: test / test-model") {
		t.Errorf("header missing from empty report output:\n%s", out)
	}
	if !strings.Contains(out, "Score: 0/0") {
		t.Errorf("score line for empty report should read '0/0'; output:\n%s", out)
	}
}

func TestFormatReport_AllFactorsTier1(t *testing.T) {
	// Verify the first 7 factors appear under Tier 1.
	r := buildTestReport("nearai", "llama-model")
	out := formatReport(r)

	tier1Idx := strings.Index(out, "Tier 1: Core Attestation")
	tier2Idx := strings.Index(out, "Tier 2: Binding & Crypto")

	if tier1Idx < 0 || tier2Idx < 0 {
		t.Fatalf("tier labels not found; output:\n%s", out)
	}

	tier1Block := out[tier1Idx:tier2Idx]

	for _, name := range []string{
		"nonce_match",
		"tdx_quote_present",
		"tdx_quote_structure",
		"tdx_cert_chain",
		"tdx_quote_signature",
		"tdx_debug_disabled",
		"signing_key_present",
	} {
		if !strings.Contains(tier1Block, name) {
			t.Errorf("Tier 1 factor %q not found in Tier 1 block:\n%s", name, tier1Block)
		}
	}
}

func TestFormatReport_AllFactorsTier3(t *testing.T) {
	// Verify the last 5 factors appear under Tier 3.
	r := buildTestReport("nearai", "llama-model")
	out := formatReport(r)

	tier3Idx := strings.Index(out, "Tier 3: Supply Chain & Channel Integrity")
	scoreIdx := strings.Index(out, "Score:")

	if tier3Idx < 0 || scoreIdx < 0 {
		t.Fatalf("Tier 3 label or Score line not found; output:\n%s", out)
	}

	tier3Block := out[tier3Idx:scoreIdx]

	for _, name := range []string{
		"tls_key_binding",
		"cpu_gpu_chain",
		"measured_model_weights",
		"build_transparency_log",
		"cpu_id_registry",
	} {
		if !strings.Contains(tier3Block, name) {
			t.Errorf("Tier 3 factor %q not found in Tier 3 block:\n%s", name, tier3Block)
		}
	}
}

// --------------------------------------------------------------------------
// statusIcon tests
// --------------------------------------------------------------------------

func TestStatusIcon(t *testing.T) {
	tests := []struct {
		status attestation.Status
		want   string
	}{
		{attestation.Pass, "\u2713"},
		{attestation.Fail, "\u2717"},
		{attestation.Skip, "?"},
		{attestation.Status(99), "?"},
	}
	for _, tc := range tests {
		got := statusIcon(tc.status)
		if got != tc.want {
			t.Errorf("statusIcon(%v): got %q, want %q", tc.status, got, tc.want)
		}
	}
}

// --------------------------------------------------------------------------
// Tier boundary correctness
// --------------------------------------------------------------------------

func TestTierBoundaries(t *testing.T) {
	for _, tb := range tierBoundaries {
		if tb.end > 20 {
			t.Errorf("tier boundary end %d exceeds 20", tb.end)
		}
	}
	last := tierBoundaries[len(tierBoundaries)-1].end
	if last != 20 {
		t.Errorf("final tier boundary end = %d, want 20", last)
	}
}

func TestFormatReport_FooterHint(t *testing.T) {
	r := buildTestReport("venice", "some-model")
	out := formatReport(r)
	if !strings.Contains(out, "teep help") {
		t.Errorf("footer hint not found; output:\n%s", out)
	}
}

func TestFormatReport_LineWidth(t *testing.T) {
	r := buildTestReport("venice", "some-model")
	out := formatReport(r)
	for i, line := range strings.Split(out, "\n") {
		if len([]rune(line)) > 80 {
			t.Errorf("line %d exceeds 80 chars (%d runes): %q", i+1, len([]rune(line)), line)
		}
	}
}

func TestFormatReport_MetadataBlock(t *testing.T) {
	r := buildTestReport("venice", "e2ee-qwen3")
	r.Metadata = map[string]string{
		"hardware":     "intel-tdx",
		"upstream":     "Qwen/Qwen3.5-122B-A10B",
		"app":          "dstack-nvidia-0.5.5",
		"compose_hash": "242a6272abcdef0123456789",
		"nonce_source": "client",
		"candidates":   "1/6 evaluated",
		"event_log":    "30 entries",
	}
	out := formatReport(r)

	for _, want := range []string{
		"Hardware:",
		"intel-tdx",
		"Upstream:",
		"Qwen/Qwen3.5-122B-A10B",
		"App:",
		"dstack-nvidia-0.5.5",
		"Compose hash:",
		"242a6272abcdef01...", // truncated to 16 chars
		"Nonce source:",
		"client",
		"Candidates:",
		"1/6 evaluated",
		"Event log:",
		"30 entries",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metadata %q not found in output:\n%s", want, out)
		}
	}

	// Ensure metadata appears before Tier 1.
	metaIdx := strings.Index(out, "Hardware:")
	tier1Idx := strings.Index(out, "Tier 1:")
	if metaIdx < 0 || tier1Idx < 0 || metaIdx > tier1Idx {
		t.Errorf("metadata should appear before Tier 1; meta=%d, tier1=%d", metaIdx, tier1Idx)
	}
}

func TestFormatReport_NoMetadataBlock(t *testing.T) {
	r := buildTestReport("nearai", "some-model")
	// No metadata set.
	out := formatReport(r)

	// "Hardware:" should not appear when metadata is nil/empty.
	if strings.Contains(out, "Hardware:") {
		t.Errorf("metadata block should not appear for empty metadata; output:\n%s", out)
	}
}

func TestFormatReport_MetadataLineWidth(t *testing.T) {
	r := buildTestReport("venice", "e2ee-qwen3")
	r.Metadata = map[string]string{
		"hardware":     "intel-tdx",
		"upstream":     "Qwen/Qwen3.5-122B-A10B",
		"app":          "dstack-nvidia-0.5.5",
		"compose_hash": "242a6272abcdef0123456789abcdef0123456789",
		"os_image":     "9b69bb16aabbccddaabbccddaabbccddaabbccdd",
		"device":       "aa781567bbccddeeffaabbccddeeffaabbccddeeff",
		"nonce_source": "client",
		"candidates":   "1/6 evaluated",
		"event_log":    "30 entries",
	}
	out := formatReport(r)
	for i, line := range strings.Split(out, "\n") {
		if len([]rune(line)) > 80 {
			t.Errorf("line %d exceeds 80 chars (%d runes): %q", i+1, len([]rune(line)), line)
		}
	}
}

// TestFormatReport_SeparatorLength verifies the separator is as long as the header.
func TestFormatReport_SeparatorLength(t *testing.T) {
	r := buildTestReport("venice", "some-model")
	out := formatReport(r)

	lines := strings.Split(out, "\n")
	if len(lines) < 2 {
		t.Fatalf("output too short to have a separator line: %q", out)
	}

	header := lines[0]
	separator := lines[1]

	// Separator uses U+2550 (multi-byte in UTF-8), so compare rune counts.
	headerRunes := []rune(header)
	sepRunes := []rune(separator)

	if len(headerRunes) != len(sepRunes) {
		t.Errorf("separator rune length %d != header rune length %d",
			len(sepRunes), len(headerRunes))
	}
}
