package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peterbourgon/ff/v4"

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
// pruneInactiveProviders tests
// --------------------------------------------------------------------------

func TestPruneInactiveProviders_RemovesEmptyKey(t *testing.T) {
	cfg := &config.Config{
		Providers: map[string]*config.Provider{
			"venice":     {Name: "venice", APIKey: "key-v"},
			"neardirect": {Name: "neardirect", APIKey: ""},
		},
	}

	if err := pruneInactiveProviders(cfg.Providers); err != nil {
		t.Fatalf("pruneInactiveProviders: %v", err)
	}
	t.Logf("remaining providers: %v", knownProviders(cfg))
	if len(cfg.Providers) != 1 {
		t.Fatalf("providers len = %d, want 1", len(cfg.Providers))
	}
	if _, ok := cfg.Providers["venice"]; !ok {
		t.Fatal("venice provider missing after pruning")
	}
}

func TestPruneInactiveProviders_KeepsAll(t *testing.T) {
	cfg := &config.Config{
		Providers: map[string]*config.Provider{
			"venice":     {Name: "venice", APIKey: "key-v"},
			"neardirect": {Name: "neardirect", APIKey: "key-n"},
		},
	}

	if err := pruneInactiveProviders(cfg.Providers); err != nil {
		t.Fatalf("pruneInactiveProviders: %v", err)
	}
	t.Logf("remaining providers: %v", knownProviders(cfg))
	if len(cfg.Providers) != 2 {
		t.Fatalf("providers len = %d, want 2", len(cfg.Providers))
	}
}

func TestPruneInactiveProviders_AllEmpty(t *testing.T) {
	cfg := &config.Config{
		Providers: map[string]*config.Provider{
			"venice": {Name: "venice", APIKey: ""},
		},
	}

	err := pruneInactiveProviders(cfg.Providers)
	t.Logf("pruneInactiveProviders(all empty): %v", err)
	if err == nil {
		t.Fatal("expected error when all providers have empty API keys")
	}
}

func TestPruneInactiveProviders_NoProviders(t *testing.T) {
	cfg := &config.Config{
		Providers: map[string]*config.Provider{},
	}

	err := pruneInactiveProviders(cfg.Providers)
	t.Logf("pruneInactiveProviders(empty): %v", err)
	if err == nil {
		t.Fatal("expected error for empty providers map")
	}
}

func TestPruneInactiveProviders_NilProvider(t *testing.T) {
	cfg := &config.Config{
		Providers: map[string]*config.Provider{
			"venice": nil,
		},
	}

	err := pruneInactiveProviders(cfg.Providers)
	t.Logf("pruneInactiveProviders(nil provider): %v", err)
	if err == nil {
		t.Fatal("expected error for nil provider entry")
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

func TestLoadConfig_ProviderNotFound_ValidConfig(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "teep.toml")
	cfgContent := "[providers.venice]\nbase_url = \"https://api.venice.ai\"\napi_key = \"test-key\"\n"
	if err := os.WriteFile(cfgFile, []byte(cfgContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("TEEP_CONFIG", cfgFile)
	_, _, err := loadConfig("nonexistent")
	t.Logf("loadConfig(nonexistent, valid config): %v", err)
	if err == nil {
		t.Fatal("expected error for provider not in config")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error %q should mention the provider name", err)
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
// normalizeArgs tests
// --------------------------------------------------------------------------

// buildNormalizeFlagSets creates flag sets matching main() for use in
// normalizeArgs tests.
func buildNormalizeFlagSets() (rootFS *ff.FlagSet, subcmdFS map[string]*ff.FlagSet) {
	rootFS = ff.NewFlagSet("teep")
	_ = rootFS.StringEnumLong("log-level", "log verbosity", "info", "debug", "warn", "error")

	serveFS := ff.NewFlagSet("serve").SetParent(rootFS)
	_ = serveFS.BoolLong("offline", "skip external verification")
	_ = serveFS.BoolLong("force", "force requests")

	verifyFS := ff.NewFlagSet("verify").SetParent(rootFS)
	_ = verifyFS.StringLong("model", "", "model name")
	_ = verifyFS.StringLong("capture", "", "capture dir")
	_ = verifyFS.StringLong("reverify", "", "reverify dir")
	_ = verifyFS.BoolLong("offline", "skip external verification")
	_ = verifyFS.BoolLong("update-config", "update config")
	_ = verifyFS.StringLong("config-out", "", "config out path")

	subcmdFS = map[string]*ff.FlagSet{"serve": serveFS, "verify": verifyFS}
	return rootFS, subcmdFS
}

func TestNormalizeArgs(t *testing.T) {
	rootFS, subcmdFS := buildNormalizeFlagSets()
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			"serve_no_flags",
			[]string{"serve", "--offline"},
			[]string{"serve", "--offline"},
		},
		{
			"verify_trailing_bool_flag",
			[]string{"verify", "venice", "--offline"},
			[]string{"verify", "--offline", "venice"},
		},
		{
			"verify_trailing_value_flag",
			[]string{"verify", "venice", "--model", "qwen3-5b"},
			[]string{"verify", "--model", "qwen3-5b", "venice"},
		},
		{
			"verify_trailing_multiple_flags",
			[]string{"verify", "venice", "--offline", "--model", "qwen3-5b"},
			[]string{"verify", "--offline", "--model", "qwen3-5b", "venice"},
		},
		{
			"root_flag_before_subcmd",
			[]string{"--log-level", "debug", "verify", "venice", "--offline"},
			[]string{"--log-level", "debug", "verify", "--offline", "venice"},
		},
		{
			"flag_before_and_after_provider",
			[]string{"verify", "--offline", "venice", "--model", "qwen3-5b"},
			[]string{"verify", "--offline", "--model", "qwen3-5b", "venice"},
		},
		{
			"equals_form",
			[]string{"verify", "venice", "--model=qwen3-5b"},
			[]string{"verify", "--model=qwen3-5b", "venice"},
		},
		{
			"extra_positional",
			[]string{"verify", "venice", "nanogpt"},
			[]string{"verify", "venice", "nanogpt"},
		},
		{
			"verify_model_after_provider",
			[]string{"verify", "venice", "--model", "gpt-4o"},
			[]string{"verify", "--model", "gpt-4o", "venice"},
		},
		{
			"unknown_subcommand_passthrough",
			[]string{"foobar", "venice", "--offline"},
			[]string{"foobar", "venice", "--offline"},
		},
		{
			"empty_args",
			[]string{},
			[]string{},
		},
		{
			"end_of_flags_marker",
			[]string{"verify", "venice", "--", "--not-a-flag"},
			[]string{"verify", "venice", "--", "--not-a-flag"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeArgs(tc.in, rootFS, subcmdFS)
			t.Logf("normalizeArgs(%v) = %v", tc.in, got)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("got[%d] = %q, want %q (full: %v)", i, got[i], tc.want[i], got)
				}
			}
		})
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

// --------------------------------------------------------------------------
// runSelfCheck / runVersion / printSelfCheckHelp smoke tests
// --------------------------------------------------------------------------

func TestRunSelfCheck_Runs(t *testing.T) {
	// runSelfCheck reads BuildInfo from the test binary and prints a report.
	// In test binaries vcs_revision is not embedded (ENFORCED → fails),
	// so runSelfCheck returns errSilentExit. We verify it runs without panic
	// and returns either nil or errSilentExit (not some unexpected error).
	err := runSelfCheck()
	t.Logf("runSelfCheck() error: %v", err)
	if err != nil && !errors.Is(err, errSilentExit) {
		t.Errorf("runSelfCheck returned unexpected error: %v", err)
	}
}

func TestRunVersion_NoError(t *testing.T) {
	err := runVersion()
	t.Logf("runVersion() error: %v", err)
	if err != nil {
		t.Errorf("runVersion returned error: %v", err)
	}
}

func TestPrintSelfCheckHelp_NoError(t *testing.T) {
	// Just verify it doesn't panic.
	printSelfCheckHelp()
}

// --------------------------------------------------------------------------
// knownProviders tests
// --------------------------------------------------------------------------

func TestKnownProviders_Empty(t *testing.T) {
	cfg := &config.Config{Providers: map[string]*config.Provider{}}
	got := knownProviders(cfg)
	t.Logf("knownProviders(empty) = %q", got)
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestKnownProviders_Single(t *testing.T) {
	cfg := &config.Config{Providers: map[string]*config.Provider{
		"venice": {Name: "venice"},
	}}
	got := knownProviders(cfg)
	t.Logf("knownProviders(single) = %q", got)
	if got != "venice" {
		t.Errorf("got %q, want %q", got, "venice")
	}
}

func TestKnownProviders_Sorted(t *testing.T) {
	cfg := &config.Config{Providers: map[string]*config.Provider{
		"venice":     {Name: "venice"},
		"neardirect": {Name: "neardirect"},
		"nanogpt":    {Name: "nanogpt"},
	}}
	got := knownProviders(cfg)
	t.Logf("knownProviders(sorted) = %q", got)
	if got != "nanogpt, neardirect, venice" {
		t.Errorf("got %q, want %q", got, "nanogpt, neardirect, venice")
	}
}

// --------------------------------------------------------------------------
// runReverify error path tests
// --------------------------------------------------------------------------

func TestRunReverify_MissingDir(t *testing.T) {
	err := runReverify(context.Background(), "/nonexistent/capture/dir/xyz")
	t.Logf("runReverify(missing dir) error: %v", err)
	if err == nil {
		t.Fatal("expected error for missing capture directory")
	}
}

// TestRunReverify_Venice_Fixture exercises the full runReverify success path
// using the Venice capture fixture. The NRAS JWT expires within ~24 hours of
// capture; when it does, runReverify returns a report comparison failure
// (the replayed nvidia_nras_verified factor differs). That specific failure is
// accepted only when the JWT is confirmed expired. Any other error fails the test.
func TestRunReverify_Venice_Fixture(t *testing.T) {
	fdir := "../../internal/integration/testdata/venice_e2ee-qwen3-5-122b-a10b_20260424_015841"

	cfgFile := filepath.Join(t.TempDir(), "teep.toml")
	cfgContent := "[providers.venice]\nbase_url = \"https://api.venice.ai\"\napi_key = \"test-key\"\n"
	if err := os.WriteFile(cfgFile, []byte(cfgContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("TEEP_CONFIG", cfgFile)

	err := runReverify(context.Background(), fdir)
	t.Logf("runReverify(venice fixture): err=%v", err)
	switch {
	case err == nil, errors.Is(err, errSilentExit):
		// Success.
	case strings.Contains(err.Error(), "report comparison failed") && nrasJWTExpired(t, fdir):
		// NRAS JWT expired — report differs on nvidia_nras_verified, expected.
	default:
		t.Fatalf("runReverify returned unexpected error: %v", err)
	}
}

// nrasJWTExpired reports whether the NRAS JWT in the fixture's captured
// response is expired. It finds the NRAS attestation body, decodes the JWT
// payload (no signature check needed), and compares the exp claim to now.
func nrasJWTExpired(t *testing.T, fixtureDir string) bool {
	t.Helper()
	pattern := filepath.Join(fixtureDir, "responses", "*nras.attestation.nvidia.com*attest*gpu*.body")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		t.Logf("nrasJWTExpired: no NRAS body file found in %s", fixtureDir)
		return false
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Logf("nrasJWTExpired: read %s: %v", matches[0], err)
		return false
	}
	parts := strings.SplitN(strings.TrimSpace(string(data)), ".", 3)
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return false
	}
	exp := time.Unix(claims.Exp, 0)
	t.Logf("nrasJWTExpired: exp=%v expired=%v", exp, time.Now().After(exp))
	return time.Now().After(exp)
}

func TestRunReverify_NearCloud_Fixture(t *testing.T) {
	fdir := "../../internal/integration/testdata/nearcloud_qwen_qwen3.5-122b-a10b_20260424_020614"

	cfgFile := filepath.Join(t.TempDir(), "teep.toml")
	cfgContent := "[providers.nearcloud]\napi_key = \"test-key\"\n"
	if err := os.WriteFile(cfgFile, []byte(cfgContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("TEEP_CONFIG", cfgFile)

	err := runReverify(context.Background(), fdir)
	t.Logf("runReverify(nearcloud fixture): err=%v", err)
	switch {
	case err == nil, errors.Is(err, errSilentExit):
		// Success.
	case strings.Contains(err.Error(), "report comparison failed") && nrasJWTExpired(t, fdir):
		// NRAS JWT expired — report differs on nvidia_nras_verified, expected.
	default:
		t.Fatalf("runReverify returned unexpected error: %v", err)
	}
}

func TestRunReverify_NearDirect_Fixture(t *testing.T) {
	fdir := "../../internal/integration/testdata/neardirect_qwen_qwen3.5-122b-a10b_20260424_021037"

	cfgFile := filepath.Join(t.TempDir(), "teep.toml")
	cfgContent := "[providers.neardirect]\nbase_url = \"https://qwen35-122b.completions.near.ai\"\napi_key = \"test-key\"\n"
	if err := os.WriteFile(cfgFile, []byte(cfgContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("TEEP_CONFIG", cfgFile)

	err := runReverify(context.Background(), fdir)
	t.Logf("runReverify(neardirect fixture): err=%v", err)
	switch {
	case err == nil, errors.Is(err, errSilentExit):
		// Success.
	case strings.Contains(err.Error(), "report comparison failed") && nrasJWTExpired(t, fdir):
		// NRAS JWT expired — report differs on nvidia_nras_verified, expected.
	default:
		t.Fatalf("runReverify returned unexpected error: %v", err)
	}
}

func TestRunReverify_MissingReport(t *testing.T) {
	// Build a capture dir with manifest.json + responses/ but no report.txt.
	// verify.Replay should succeed, then capture.LoadReport should fail.
	srcDir := "../../internal/integration/testdata/venice_e2ee-qwen3-5-122b-a10b_20260424_015841"
	srcAbs, err := filepath.Abs(srcDir)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	tmpDir := t.TempDir()

	manifest, err := os.ReadFile(filepath.Join(srcAbs, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "manifest.json"), manifest, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.Symlink(filepath.Join(srcAbs, "responses"), filepath.Join(tmpDir, "responses")); err != nil {
		t.Fatalf("symlink responses: %v", err)
	}
	// Deliberately omit report.txt.

	cfgFile := filepath.Join(t.TempDir(), "teep.toml")
	cfgContent := "[providers.venice]\nbase_url = \"https://api.venice.ai\"\napi_key = \"test-key\"\n"
	if err := os.WriteFile(cfgFile, []byte(cfgContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("TEEP_CONFIG", cfgFile)

	err = runReverify(context.Background(), tmpDir)
	t.Logf("runReverify(missing report): %v", err)
	if err == nil || !strings.Contains(err.Error(), "read captured report") {
		t.Fatalf("expected 'read captured report' error, got: %v", err)
	}
}

func TestRunVerify_LoadConfigFails(t *testing.T) {
	ctx := context.Background()
	err := runVerify(ctx, "nonexistent-provider-xyz", "test-model", "", false, false, "")
	t.Logf("runVerify(nonexistent provider): err=%v", err)
	if err == nil {
		t.Fatal("expected error when provider config not found")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("error %q should mention 'verification failed'", err)
	}
}

func TestLoadConfig_SuccessPath(t *testing.T) {
	dir := t.TempDir()
	cfgFile := dir + "/teep.toml"
	content := `[providers.venice]
base_url = "https://api.venice.ai"
api_key = "test-key"
`
	if err := os.WriteFile(cfgFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("TEEP_CONFIG", cfgFile)

	cfg, cp, err := loadConfig("venice")
	t.Logf("loadConfig(venice): cfg=%v cp=%v err=%v", cfg != nil, cp != nil, err)
	if err != nil {
		t.Fatalf("loadConfig(venice): unexpected error: %v", err)
	}
	if cfg == nil {
		t.Error("expected non-nil config")
	}
	if cp == nil {
		t.Error("expected non-nil provider config")
	}
}

// --------------------------------------------------------------------------
// force_release.go — release-build no-op stubs
// --------------------------------------------------------------------------

func TestForceRelease_RegisterForceFlag_ReturnsNil(t *testing.T) {
	flags := ff.NewFlagSet("test")
	result := registerForceFlag(flags)
	t.Logf("registerForceFlag: result=%v", result)
	if result != nil {
		t.Error("expected nil from registerForceFlag in release build")
	}
}

func TestForceRelease_ForceValue_ReturnsFalse(t *testing.T) {
	result := forceValue(nil)
	t.Logf("forceValue: result=%v", result)
	if result {
		t.Error("expected false from forceValue in release build")
	}
}
