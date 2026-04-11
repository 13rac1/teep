package main

import (
	"log/slog"
	"os"
	"os/exec"
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

// TestRunVerify_CaptureOfflineMutuallyExclusive verifies that --capture and
// --offline are rejected together. Uses the subprocess "crasher" pattern
// because runVerify calls os.Exit.
func TestRunVerify_CaptureOfflineMutuallyExclusive(t *testing.T) {
	const envKey = "TEEP_TEST_CAPTURE_OFFLINE_CRASHER"
	if os.Getenv(envKey) == "1" {
		runVerify([]string{"someprovider", "--model", "m", "--capture", os.TempDir(), "--offline"})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestRunVerify_CaptureOfflineMutuallyExclusive", "-test.v")
	cmd.Env = append(os.Environ(), envKey+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("subprocess output: %s", out)
	if err == nil {
		t.Fatal("expected non-zero exit for --capture + --offline")
	}
	if !strings.Contains(string(out), "--capture and --offline are mutually exclusive") {
		t.Errorf("expected error message in output, got: %s", out)
	}
}
