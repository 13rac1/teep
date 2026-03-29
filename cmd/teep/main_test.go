package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider/nanogpt"
	"github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/provider/venice"
)

// --------------------------------------------------------------------------
// formatReport tests
// --------------------------------------------------------------------------

// buildTestReport constructs a VerificationReport with test factors
// using the given per-factor inputs so we can verify formatting precisely.
func buildTestReport(provider, model string) *attestation.VerificationReport {
	factors := []attestation.FactorResult{
		// Tier 1
		{Name: "nonce_match", Status: attestation.Pass, Detail: "Nonce matches (64 hex chars)", Enforced: true, Tier: attestation.TierCore},
		{Name: "tdx_quote_present", Status: attestation.Pass, Detail: "TDX quote present (1247 base64 chars)", Tier: attestation.TierCore},
		{Name: "tdx_quote_structure", Status: attestation.Pass, Detail: "Valid QuoteV4 structure", Tier: attestation.TierCore},
		{Name: "tdx_cert_chain", Status: attestation.Pass, Detail: "cert chain valid (Intel root CA)", Tier: attestation.TierCore},
		{Name: "tdx_quote_signature", Status: attestation.Pass, Detail: "Quote signature verified", Tier: attestation.TierCore},
		{Name: "tdx_debug_disabled", Status: attestation.Pass, Detail: "Debug bit is 0", Enforced: true, Tier: attestation.TierCore},
		{Name: "signing_key_present", Status: attestation.Pass, Detail: "enclave pubkey present (04a3b2...)", Enforced: true, Tier: attestation.TierCore},
		// Tier 2
		{Name: "tdx_reportdata_binding", Status: attestation.Pass, Detail: "REPORTDATA binds signing key + nonce", Enforced: true, Tier: attestation.TierBinding},
		{Name: "intel_pcs_collateral", Status: attestation.Skip, Detail: "Quote age not determinable", Tier: attestation.TierBinding},
		{Name: "tdx_tcb_current", Status: attestation.Pass, Detail: "TCB is UpToDate per Intel PCS", Tier: attestation.TierBinding},
		{Name: "nvidia_payload_present", Status: attestation.Pass, Detail: "NVIDIA payload present (512 chars)", Tier: attestation.TierBinding},
		{Name: "nvidia_signature", Status: attestation.Pass, Detail: "JWT signature valid (RS256)", Tier: attestation.TierBinding},
		{Name: "nvidia_claims", Status: attestation.Pass, Detail: "Claims valid", Tier: attestation.TierBinding},
		{Name: "nvidia_nonce_client_bound", Status: attestation.Skip, Detail: "nonce not found in NVIDIA payload", Tier: attestation.TierBinding},
		{Name: "nvidia_nras_verified", Status: attestation.Skip, Detail: "offline mode; NRAS skipped", Tier: attestation.TierBinding},
		{Name: "e2ee_capable", Status: attestation.Pass, Detail: "E2EE key exchange possible", Tier: attestation.TierBinding},
		// Tier 3
		{Name: "tls_key_binding", Status: attestation.Fail, Detail: "no TLS key in attestation", Tier: attestation.TierSupplyChain},
		{Name: "cpu_gpu_chain", Status: attestation.Fail, Detail: "CPU-GPU attestation not bound", Tier: attestation.TierSupplyChain},
		{Name: "measured_model_weights", Status: attestation.Fail, Detail: "no model weight hashes", Tier: attestation.TierSupplyChain},
		{Name: "build_transparency_log", Status: attestation.Fail, Detail: "no build transparency log", Tier: attestation.TierSupplyChain},
		{Name: "cpu_id_registry", Status: attestation.Fail, Detail: "no CPU ID registry check", Tier: attestation.TierSupplyChain},
	}

	passed, failed, skipped := 0, 0, 0
	enforcedFailed, allowedFailed := 0, 0
	for _, f := range factors {
		switch f.Status {
		case attestation.Pass:
			passed++
		case attestation.Fail:
			failed++
			if f.Enforced {
				enforcedFailed++
			} else {
				allowedFailed++
			}
		case attestation.Skip:
			skipped++
		}
	}

	return &attestation.VerificationReport{
		Provider:       provider,
		Model:          model,
		Timestamp:      time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC),
		Factors:        factors,
		Passed:         passed,
		Failed:         failed,
		Skipped:        skipped,
		EnforcedFailed: enforcedFailed,
		AllowedFailed:  allowedFailed,
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
	// tdx_quote_present is not enforced, so it should show [ALLOWED].
	if !strings.Contains(out, "[ALLOWED]") {
		t.Errorf("[ALLOWED] tag not found; output:\n%s", out)
	}
}

func TestFormatReport_ScoreLine(t *testing.T) {
	r := buildTestReport("venice", "some-model")
	out := formatReport(r)

	// Expect the score line: "Score: 13/21 passed, 3 skipped, 5 failed (0 enforced, 5 allowed)"
	// Our test report: 13 pass, 5 fail (0 enforced, 5 allowed), 3 skip = 21 total.
	if !strings.Contains(out, "Score:") {
		t.Errorf("Score line not found; output:\n%s", out)
	}
	if !strings.Contains(out, "13/21 passed") {
		t.Errorf("expected '13/21 passed' in score line; output:\n%s", out)
	}
	if !strings.Contains(out, "3 skipped") {
		t.Errorf("expected '3 skipped' in score line; output:\n%s", out)
	}
	if !strings.Contains(out, "5 failed") {
		t.Errorf("expected '5 failed' in score line; output:\n%s", out)
	}
	if !strings.Contains(out, "0 enforced, 5 allowed") {
		t.Errorf("expected '0 enforced, 5 allowed' in score line; output:\n%s", out)
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
	if strings.Contains(out, "enforced") {
		t.Errorf("score line should omit breakdown when no failures; output:\n%s", out)
	}
}

func TestFormatReport_ScoreLineWithEnforcedFailures(t *testing.T) {
	r := &attestation.VerificationReport{
		Provider:  "test",
		Model:     "m",
		Timestamp: time.Now(),
		Factors: []attestation.FactorResult{
			{Name: "a", Status: attestation.Pass, Tier: attestation.TierCore},
			{Name: "b", Status: attestation.Fail, Enforced: true, Tier: attestation.TierCore},
			{Name: "c", Status: attestation.Fail, Enforced: false, Tier: attestation.TierSupplyChain},
		},
		Passed: 1, Failed: 2, EnforcedFailed: 1, AllowedFailed: 1,
	}
	out := formatReport(r)
	if !strings.Contains(out, "1 enforced, 1 allowed") {
		t.Errorf("expected '1 enforced, 1 allowed'; output:\n%s", out)
	}
}

func TestFormatReport_AllFactorsTier1(t *testing.T) {
	// Verify the first 7 factors appear under Tier 1.
	r := buildTestReport("neardirect", "llama-model")
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
	r := buildTestReport("neardirect", "llama-model")
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
// Tier consistency checks
// --------------------------------------------------------------------------

func TestFactorTiersMatchRegistry(t *testing.T) {
	// Every factor's Tier must have a corresponding tierRegistry entry.
	tierNumbers := make(map[int]bool)
	for _, tier := range tierRegistry {
		tierNumbers[tier.Number] = true
	}
	for _, f := range factorRegistry {
		if !tierNumbers[f.Tier] {
			t.Errorf("factor %q has tier %d which is not in tierRegistry", f.Name, f.Tier)
		}
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
	r := buildTestReport("neardirect", "some-model")
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

func TestFilterProviders_KeepNamedProvider(t *testing.T) {
	cfg := &config.Config{
		Providers: map[string]*config.Provider{
			"venice":     {Name: "venice"},
			"neardirect": {Name: "neardirect"},
		},
	}

	if err := filterProviders(cfg, "neardirect"); err != nil {
		t.Fatalf("filterProviders: %v", err)
	}

	if len(cfg.Providers) != 1 {
		t.Fatalf("providers len = %d, want 1", len(cfg.Providers))
	}
	if _, ok := cfg.Providers["neardirect"]; !ok {
		t.Fatalf("neardirect provider missing after filter")
	}
}

func TestFilterProviders_UnknownProvider(t *testing.T) {
	cfg := &config.Config{
		Providers: map[string]*config.Provider{
			"venice": {Name: "venice"},
		},
	}

	err := filterProviders(cfg, "neardirect")
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

// --------------------------------------------------------------------------
// extractProvider tests
// --------------------------------------------------------------------------

func TestExtractProvider(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantName string
		wantRest []string
	}{
		{"empty", []string{}, "", []string{}},
		{"flag_first", []string{"--offline"}, "", []string{"--offline"}},
		{"provider_only", []string{"venice"}, "venice", []string{}},
		{"provider_plus_flags", []string{"neardirect", "--model", "x"}, "neardirect", []string{"--model", "x"}},
		{"dash_flag_first", []string{"-v"}, "", []string{"-v"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, rest := extractProvider(tc.args)
			t.Logf("extractProvider(%v) = (%q, %v)", tc.args, name, rest)
			if name != tc.wantName {
				t.Errorf("name = %q, want %q", name, tc.wantName)
			}
			if len(rest) != len(tc.wantRest) {
				t.Fatalf("rest len = %d, want %d", len(rest), len(tc.wantRest))
			}
			for i, r := range rest {
				if r != tc.wantRest[i] {
					t.Errorf("rest[%d] = %q, want %q", i, r, tc.wantRest[i])
				}
			}
		})
	}
}

// --------------------------------------------------------------------------
// providerNotFoundError tests
// --------------------------------------------------------------------------

func TestProviderNotFoundError_KnownNoConfig(t *testing.T) {
	cfg := &config.Config{Providers: map[string]*config.Provider{}}
	err := providerNotFoundError("venice", cfg)
	t.Logf("error: %v", err)
	if !strings.Contains(err.Error(), "VENICE_API_KEY") {
		t.Errorf("error should mention VENICE_API_KEY: %v", err)
	}
	// Should not mention "known:" since no providers are configured.
	if strings.Contains(err.Error(), "known:") {
		t.Errorf("error should not mention 'known:' when no providers configured: %v", err)
	}
}

func TestProviderNotFoundError_KnownWithOtherProviders(t *testing.T) {
	cfg := &config.Config{Providers: map[string]*config.Provider{
		"neardirect": {Name: "neardirect"},
	}}
	err := providerNotFoundError("venice", cfg)
	t.Logf("error: %v", err)
	if !strings.Contains(err.Error(), "VENICE_API_KEY") {
		t.Errorf("error should mention VENICE_API_KEY: %v", err)
	}
	if !strings.Contains(err.Error(), "neardirect") {
		t.Errorf("error should mention existing provider 'neardirect': %v", err)
	}
}

func TestProviderNotFoundError_Unknown(t *testing.T) {
	cfg := &config.Config{Providers: map[string]*config.Provider{
		"venice": {Name: "venice"},
	}}
	err := providerNotFoundError("foobar", cfg)
	t.Logf("error: %v", err)
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should say 'not found': %v", err)
	}
	if !strings.Contains(err.Error(), "venice") {
		t.Errorf("error should mention known provider 'venice': %v", err)
	}
}

// --------------------------------------------------------------------------
// parseLogLevel tests
// --------------------------------------------------------------------------

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want slog.Level
	}{
		{"default", []string{}, slog.LevelInfo},
		{"debug_flag", []string{"--log-level", "debug"}, slog.LevelDebug},
		{"info_flag", []string{"--log-level", "info"}, slog.LevelInfo},
		{"warn_flag", []string{"--log-level", "warn"}, slog.LevelWarn},
		{"error_flag", []string{"--log-level", "error"}, slog.LevelError},
		{"equals_syntax", []string{"--log-level=warn"}, slog.LevelWarn},
		{"among_other_args", []string{"venice", "--log-level", "debug"}, slog.LevelDebug},
		{"case_insensitive", []string{"--log-level", "DEBUG"}, slog.LevelDebug},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseLogLevel(tc.args)
			if err != nil {
				t.Fatalf("parseLogLevel(%v) unexpected error: %v", tc.args, err)
			}
			if got != tc.want {
				t.Errorf("parseLogLevel(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestParseLogLevel_Invalid(t *testing.T) {
	_, err := parseLogLevel([]string{"--log-level", "verbose"})
	t.Logf("parseLogLevel(--log-level verbose) error: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid log level")
	}
	if !strings.Contains(err.Error(), "verbose") {
		t.Errorf("error should mention the invalid level: %v", err)
	}
}

// --------------------------------------------------------------------------
// newAttester / newReportDataVerifier tests
// --------------------------------------------------------------------------

func TestNewAttester(t *testing.T) {
	cp := &config.Provider{BaseURL: "http://localhost", APIKey: "key"}

	t.Run("venice", func(t *testing.T) {
		a, err := newAttester("venice", cp, false)
		if err != nil {
			t.Fatalf("newAttester(venice): %v", err)
		}
		if _, ok := a.(*venice.Attester); !ok {
			t.Errorf("newAttester(venice) returned %T, want *venice.Attester", a)
		}
	})

	t.Run("neardirect", func(t *testing.T) {
		a, err := newAttester("neardirect", cp, false)
		if err != nil {
			t.Fatalf("newAttester(neardirect): %v", err)
		}
		if _, ok := a.(*neardirect.Attester); !ok {
			t.Errorf("newAttester(neardirect) returned %T, want *neardirect.Attester", a)
		}
	})

	t.Run("nearcloud", func(t *testing.T) {
		a, err := newAttester("nearcloud", cp, false)
		if err != nil {
			t.Fatalf("newAttester(nearcloud): %v", err)
		}
		if _, ok := a.(*nearcloud.Attester); !ok {
			t.Errorf("newAttester(nearcloud) returned %T, want *nearcloud.Attester", a)
		}
	})

	t.Run("nanogpt", func(t *testing.T) {
		a, err := newAttester("nanogpt", cp, false)
		if err != nil {
			t.Fatalf("newAttester(nanogpt): %v", err)
		}
		if _, ok := a.(*nanogpt.Attester); !ok {
			t.Errorf("newAttester(nanogpt) returned %T, want *nanogpt.Attester", a)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		_, err := newAttester("bogus", cp, false)
		t.Logf("newAttester(bogus) error: %v", err)
		if err == nil {
			t.Fatal("expected error for unknown provider")
		}
		if !strings.Contains(err.Error(), "bogus") {
			t.Errorf("error should mention the provider name: %v", err)
		}
	})
}

func TestNewReportDataVerifier(t *testing.T) {
	tests := []struct {
		name     string
		wantType string
		wantNil  bool
	}{
		{"venice", "venice.ReportDataVerifier", false},
		{"neardirect", "neardirect.ReportDataVerifier", false},
		{"nanogpt", "venice.ReportDataVerifier", false},
		{"unknown", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := newReportDataVerifier(tc.name)
			if tc.wantNil {
				if got != nil {
					t.Errorf("newReportDataVerifier(%q) = %v, want nil", tc.name, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("newReportDataVerifier(%q) = nil, want non-nil", tc.name)
			}
		})
	}
}

// --------------------------------------------------------------------------
// saveFile / saveAttestationData tests
// --------------------------------------------------------------------------

func TestSaveFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	data := []byte("hello world")

	saveFile(path, data)

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("content = %q, want %q", got, data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("permissions = %o, want 600", perm)
	}
}

func TestSaveAttestationData(t *testing.T) {
	dir := t.TempDir()
	raw := &attestation.RawAttestation{
		RawBody:       []byte(`{"test":"body"}`),
		NvidiaPayload: `{"nvidia":"payload"}`,
		IntelQuote:    "AABBCCDD",
	}

	saveAttestationData(dir, "venice", raw)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	t.Logf("saved %d files:", len(entries))
	for _, e := range entries {
		t.Logf("  %s", e.Name())
	}

	if len(entries) != 3 {
		t.Fatalf("expected 3 files, got %d", len(entries))
	}

	// Check each file exists with the correct prefix.
	gotPrefixes := make([]string, 0, len(entries))
	for _, e := range entries {
		gotPrefixes = append(gotPrefixes, e.Name())
	}

	wantPrefixes := []string{"venice_attestation_", "venice_nvidia_payload_", "venice_intel_quote_"}
	for _, want := range wantPrefixes {
		found := false
		for _, got := range gotPrefixes {
			if strings.HasPrefix(got, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no file with prefix %q found in %v", want, gotPrefixes)
		}
	}
}

// --------------------------------------------------------------------------
// loadConfig tests
// --------------------------------------------------------------------------

func TestLoadConfig_UnknownProvider(t *testing.T) {
	_, _, err := loadConfig("nonexistent_provider_xyz")
	t.Logf("loadConfig(nonexistent) error: %v", err)
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

// --------------------------------------------------------------------------
// fetchAttestation tests
// --------------------------------------------------------------------------

// failAttester is a mock that always returns an error.
type failAttester struct{}

func (failAttester) FetchAttestation(_ context.Context, _ string, _ attestation.Nonce) (*attestation.RawAttestation, error) {
	return nil, errors.New("mock fetch error")
}

func TestFetchAttestation_Error(t *testing.T) {
	ctx := context.Background()
	nonce := attestation.NewNonce()

	_, err := fetchAttestation(ctx, failAttester{}, "test", "model", nonce)
	t.Logf("fetchAttestation error: %v", err)
	if err == nil {
		t.Fatal("expected error from failing attester")
	}
	if !strings.Contains(err.Error(), "mock fetch error") {
		t.Errorf("error should wrap the mock error: %v", err)
	}
}

func TestFetchAttestation_Success(t *testing.T) {
	ctx := context.Background()
	nonce := attestation.NewNonce()
	want := &attestation.RawAttestation{IntelQuote: "test-quote"}

	raw, err := fetchAttestation(ctx, successAttester{raw: want}, "test", "model", nonce)
	if err != nil {
		t.Fatalf("fetchAttestation unexpected error: %v", err)
	}
	if raw.IntelQuote != want.IntelQuote {
		t.Errorf("IntelQuote = %q, want %q", raw.IntelQuote, want.IntelQuote)
	}
}

// successAttester is a mock that returns a fixed RawAttestation.
type successAttester struct{ raw *attestation.RawAttestation }

func (a successAttester) FetchAttestation(_ context.Context, _ string, _ attestation.Nonce) (*attestation.RawAttestation, error) {
	return a.raw, nil
}

// --------------------------------------------------------------------------
// supplyChainPolicy tests
// --------------------------------------------------------------------------

func TestSupplyChainPolicy(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wantNil  bool
	}{
		{"venice", "venice", false},
		{"neardirect", "neardirect", false},
		{"nearcloud", "nearcloud", false},
		{"nanogpt", "nanogpt", false},
		{"unknown", "bogus", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := supplyChainPolicy(tc.provider)
			if tc.wantNil {
				if p != nil {
					t.Errorf("supplyChainPolicy(%q) = %v, want nil", tc.provider, p)
				}
				return
			}
			if p == nil {
				t.Fatalf("supplyChainPolicy(%q) = nil, want non-nil", tc.provider)
			}
			if len(p.Images) == 0 {
				t.Errorf("supplyChainPolicy(%q) returned policy with 0 images", tc.provider)
			}
			t.Logf("supplyChainPolicy(%q): %d images", tc.provider, len(p.Images))
		})
	}
}

// --------------------------------------------------------------------------
// E2EE helper function tests
// --------------------------------------------------------------------------

func TestE2EEEnabledByDefault(t *testing.T) {
	tests := []struct {
		provider string
		want     bool
	}{
		{"venice", true},
		{"nearcloud", true},
		{"neardirect", false},
		{"nanogpt", false},
		{"unknown", false},
	}
	for _, tc := range tests {
		if got := e2eeEnabledByDefault(tc.provider); got != tc.want {
			t.Errorf("e2eeEnabledByDefault(%q) = %v, want %v", tc.provider, got, tc.want)
		}
	}
}

func TestE2EEVersion(t *testing.T) {
	tests := []struct {
		provider string
		want     int
	}{
		{"venice", attestation.E2EEv1},
		{"nearcloud", attestation.E2EEv2},
		{"neardirect", 0},
		{"nanogpt", 0},
		{"unknown", 0},
	}
	for _, tc := range tests {
		if got := e2eeVersion(tc.provider); got != tc.want {
			t.Errorf("e2eeVersion(%q) = %d, want %d", tc.provider, got, tc.want)
		}
	}
}

func TestChatPathForProvider(t *testing.T) {
	tests := []struct {
		provider string
		want     string
	}{
		{"venice", "/api/v1/chat/completions"},
		{"nearcloud", "/v1/chat/completions"},
		{"neardirect", "/v1/chat/completions"},
		{"nanogpt", "/v1/chat/completions"},
		{"unknown", ""},
	}
	for _, tc := range tests {
		if got := chatPathForProvider(tc.provider); got != tc.want {
			t.Errorf("chatPathForProvider(%q) = %q, want %q", tc.provider, got, tc.want)
		}
	}
}

func TestSafePrefix(t *testing.T) {
	tests := []struct {
		s    string
		n    int
		want string
	}{
		{"hello", 3, "hel"},
		{"hi", 5, "hi"},
		{"", 3, ""},
		{"abcdef", 6, "abcdef"},
	}
	for _, tc := range tests {
		if got := safePrefix(tc.s, tc.n); got != tc.want {
			t.Errorf("safePrefix(%q, %d) = %q, want %q", tc.s, tc.n, got, tc.want)
		}
	}
}

func TestTestE2EE_SkipNonE2EEProvider(t *testing.T) {
	raw := &attestation.RawAttestation{SigningKey: "04aabb"}
	cp := &config.Provider{APIKey: "key"}
	got := testE2EE(context.Background(), raw, "neardirect", cp, "model", false)
	if got != nil {
		t.Errorf("testE2EE for neardirect should return nil, got %+v", got)
	}
}

func TestTestE2EE_SkipNoSigningKey(t *testing.T) {
	raw := &attestation.RawAttestation{SigningKey: ""}
	cp := &config.Provider{APIKey: "key"}
	got := testE2EE(context.Background(), raw, "venice", cp, "model", false)
	if got != nil {
		t.Errorf("testE2EE with no signing key should return nil, got %+v", got)
	}
}

func TestTestE2EE_SkipOffline(t *testing.T) {
	raw := &attestation.RawAttestation{SigningKey: "04aabb"}
	cp := &config.Provider{APIKey: "key"}
	got := testE2EE(context.Background(), raw, "venice", cp, "model", true)
	if got == nil {
		t.Fatal("testE2EE in offline mode should return non-nil result")
	}
	if got.Attempted {
		t.Error("should not be Attempted in offline mode")
	}
	if got.Detail == "" {
		t.Error("should have Detail explaining offline skip")
	}
}

func TestTestE2EE_NoAPIKey(t *testing.T) {
	raw := &attestation.RawAttestation{SigningKey: "04aabb"}
	cp := &config.Provider{APIKey: ""}
	got := testE2EE(context.Background(), raw, "venice", cp, "model", false)
	if got == nil {
		t.Fatal("testE2EE with no API key should return non-nil result")
	}
	if !got.NoAPIKey {
		t.Error("NoAPIKey should be true")
	}
	if got.APIKeyEnv != "VENICE_API_KEY" {
		t.Errorf("APIKeyEnv = %q, want %q", got.APIKeyEnv, "VENICE_API_KEY")
	}
}
