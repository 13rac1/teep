package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
)

// buildTestReport constructs a VerificationReport with test factors.
// Used by selfcheck_test.go and any other test needing a representative report.
func buildTestReport(prov, model string) *attestation.VerificationReport {
	factors := []attestation.FactorResult{
		{Name: "nonce_match", Status: attestation.Pass, Detail: "ok", Enforced: true, Tier: attestation.TierCore},
		{Name: "tdx_quote_present", Status: attestation.Pass, Detail: "ok", Tier: attestation.TierCore},
		{Name: "tdx_quote_structure", Status: attestation.Pass, Detail: "ok", Tier: attestation.TierCore},
		{Name: "tdx_debug_disabled", Status: attestation.Pass, Detail: "ok", Enforced: true, Tier: attestation.TierCore},
		{Name: "signing_key_present", Status: attestation.Pass, Detail: "ok", Enforced: true, Tier: attestation.TierCore},
		{Name: "tdx_reportdata_binding", Status: attestation.Pass, Detail: "ok", Enforced: true, Tier: attestation.TierBinding},
		{Name: "e2ee_capable", Status: attestation.Pass, Detail: "ok", Tier: attestation.TierBinding},
		{Name: "tls_key_binding", Status: attestation.Fail, Detail: "no TLS key", Tier: attestation.TierSupplyChain},
	}
	return &attestation.VerificationReport{
		Provider:  prov,
		Model:     model,
		Timestamp: time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC),
		Factors:   factors,
		Passed:    7,
		Failed:    1,
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

// --------------------------------------------------------------------------
// filterProviders tests
// --------------------------------------------------------------------------

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
// parseSlogLevel tests
// --------------------------------------------------------------------------

func TestParseSlogLevel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  slog.Level
	}{
		{"debug", "debug", slog.LevelDebug},
		{"info", "info", slog.LevelInfo},
		{"warn", "warn", slog.LevelWarn},
		{"error", "error", slog.LevelError},
		{"default_empty", "", slog.LevelInfo},
		{"default_unknown", "bogus", slog.LevelInfo},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSlogLevel(tc.input)
			t.Logf("parseSlogLevel(%q) = %v", tc.input, got)
			if got != tc.want {
				t.Errorf("parseSlogLevel(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
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
// extractObserved tests
// --------------------------------------------------------------------------

func TestExtractObserved_AllFields(t *testing.T) {
	report := &attestation.VerificationReport{
		Metadata: map[string]string{
			"mrseam":         "aabb",
			"mrtd":           "ccdd",
			"rtmr0":          "1111",
			"rtmr1":          "2222",
			"rtmr2":          "3333",
			"gateway_mrseam": "gw-mrseam",
			"gateway_mrtd":   "gw-mrtd",
			"gateway_rtmr0":  "gw-rtmr0",
			"gateway_rtmr1":  "gw-rtmr1",
			"gateway_rtmr2":  "gw-rtmr2",
		},
	}
	obs := extractObserved(report)
	if obs.MRSeam != "aabb" {
		t.Errorf("MRSeam = %q", obs.MRSeam)
	}
	if obs.MRTD != "ccdd" {
		t.Errorf("MRTD = %q", obs.MRTD)
	}
	if obs.RTMR0 != "1111" {
		t.Errorf("RTMR0 = %q", obs.RTMR0)
	}
	if obs.RTMR1 != "2222" {
		t.Errorf("RTMR1 = %q", obs.RTMR1)
	}
	if obs.RTMR2 != "3333" {
		t.Errorf("RTMR2 = %q", obs.RTMR2)
	}
	if obs.GatewayMRSeam != "gw-mrseam" {
		t.Errorf("GatewayMRSeam = %q", obs.GatewayMRSeam)
	}
	if obs.GatewayMRTD != "gw-mrtd" {
		t.Errorf("GatewayMRTD = %q", obs.GatewayMRTD)
	}
	if obs.GatewayRTMR0 != "gw-rtmr0" {
		t.Errorf("GatewayRTMR0 = %q", obs.GatewayRTMR0)
	}
	if obs.GatewayRTMR1 != "gw-rtmr1" {
		t.Errorf("GatewayRTMR1 = %q", obs.GatewayRTMR1)
	}
	if obs.GatewayRTMR2 != "gw-rtmr2" {
		t.Errorf("GatewayRTMR2 = %q", obs.GatewayRTMR2)
	}
}

func TestExtractObserved_MissingKeys(t *testing.T) {
	report := &attestation.VerificationReport{
		Metadata: map[string]string{
			"mrtd": "only-mrtd",
		},
	}
	obs := extractObserved(report)
	if obs.MRTD != "only-mrtd" {
		t.Errorf("MRTD = %q, want 'only-mrtd'", obs.MRTD)
	}
	if obs.MRSeam != "" {
		t.Errorf("MRSeam should be empty, got %q", obs.MRSeam)
	}
	if obs.GatewayMRTD != "" {
		t.Errorf("GatewayMRTD should be empty, got %q", obs.GatewayMRTD)
	}
}

func TestExtractObserved_EmptyMetadata(t *testing.T) {
	report := &attestation.VerificationReport{
		Metadata: map[string]string{},
	}
	obs := extractObserved(report)
	if obs.MRSeam != "" || obs.MRTD != "" || obs.RTMR0 != "" {
		t.Error("all fields should be empty for empty metadata")
	}
}

// --------------------------------------------------------------------------
// runVerify error returns (previously subprocess crasher tests)
// --------------------------------------------------------------------------

// TestRunVerify_CaptureOfflineMutuallyExclusive verifies that --capture and
// --offline are rejected together. Now an in-process test since runVerify
// returns error instead of calling os.Exit.
func TestRunVerify_CaptureOfflineMutuallyExclusive(t *testing.T) {
	err := runVerify(context.Background(), "someprovider", "m", os.TempDir(), true, false, "")
	t.Logf("runVerify(capture+offline) error: %v", err)
	if err == nil {
		t.Fatal("expected error for --capture + --offline")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected 'mutually exclusive' in error, got: %v", err)
	}
}

// TestRunVerify_ModelRequired verifies that an empty --model is rejected.
func TestRunVerify_ModelRequired(t *testing.T) {
	err := runVerify(context.Background(), "someprovider", "", "", false, false, "")
	t.Logf("runVerify(no model) error: %v", err)
	if err == nil {
		t.Fatal("expected error for missing --model")
	}
	if !strings.Contains(err.Error(), "--model is required") {
		t.Errorf("expected '--model is required' in error, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// rejectTrailingFlags tests
// --------------------------------------------------------------------------

func TestRejectTrailingFlags_NoFlags(t *testing.T) {
	err := rejectTrailingFlags("serve", []string{"venice"})
	if err != nil {
		t.Errorf("expected no error for single provider, got: %v", err)
	}
}

func TestRejectTrailingFlags_TrailingFlag(t *testing.T) {
	err := rejectTrailingFlags("serve", []string{"venice", "--offline"})
	t.Logf("rejectTrailingFlags error: %v", err)
	if err == nil {
		t.Fatal("expected error for trailing flag")
	}
	if !strings.Contains(err.Error(), "flags must precede") {
		t.Errorf("expected 'flags must precede' in error, got: %v", err)
	}
	// Error should suggest the correct order.
	if !strings.Contains(err.Error(), "teep serve --offline venice") {
		t.Errorf("expected suggested correct order in error, got: %v", err)
	}
}

func TestRejectTrailingFlags_ExtraPositional(t *testing.T) {
	err := rejectTrailingFlags("serve", []string{"venice", "neardirect"})
	t.Logf("rejectTrailingFlags error: %v", err)
	if err == nil {
		t.Fatal("expected error for extra positional arg")
	}
	if !strings.Contains(err.Error(), "expected one provider") {
		t.Errorf("expected 'expected one provider' in error, got: %v", err)
	}
}

func TestRejectTrailingFlags_ExtraPositionalAndFlag(t *testing.T) {
	// Extra positional + trailing flag: should not suggest a reordering since
	// it would include the extra positional in the suggestion.
	err := rejectTrailingFlags("serve", []string{"venice", "extra", "--offline"})
	t.Logf("rejectTrailingFlags error: %v", err)
	if err == nil {
		t.Fatal("expected error for extra positional + trailing flag")
	}
	if !strings.Contains(err.Error(), "expected one provider") {
		t.Errorf("expected 'expected one provider' in error, got: %v", err)
	}
	if strings.Contains(err.Error(), "flags must precede") {
		t.Errorf("should not suggest reordering when extra positionals are present, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// verifyArgsConflict tests
// --------------------------------------------------------------------------

func TestVerifyArgsConflict_ReverifyPlusProvider(t *testing.T) {
	err := verifyArgsConflict("/some/capture/dir", []string{"venice"})
	t.Logf("verifyArgsConflict error: %v", err)
	if err == nil {
		t.Fatal("expected error for --reverify + PROVIDER")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected 'mutually exclusive' in error, got: %v", err)
	}
}

func TestVerifyArgsConflict_ReverifyNoProvider(t *testing.T) {
	err := verifyArgsConflict("/some/capture/dir", nil)
	if err != nil {
		t.Errorf("expected no error for --reverify without provider, got: %v", err)
	}
}

func TestVerifyArgsConflict_ProviderNoReverify(t *testing.T) {
	err := verifyArgsConflict("", []string{"venice"})
	if err != nil {
		t.Errorf("expected no error for provider without --reverify, got: %v", err)
	}
}
