package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
)

// writeConfigFile creates a temporary TOML config file with the given content
// and the given permission bits. Returns the file path.
func writeConfigFile(t *testing.T, content string, perm os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatalf("writeConfigFile: %v", err)
	}
	return path
}

// setenv sets an environment variable for the duration of the test.
func setenv(t *testing.T, key, value string) {
	t.Helper()
	t.Setenv(key, value)
}

func unsetenv(t *testing.T, key string) {
	t.Helper()
	original, wasSet := os.LookupEnv(key)
	os.Unsetenv(key)
	t.Cleanup(func() {
		if wasSet {
			os.Setenv(key, original) //nolint:usetesting // os.Setenv is correct inside t.Cleanup
		} else {
			os.Unsetenv(key)
		}
	})
}

// clearProviderEnv unsets all provider API key env vars to isolate tests.
func clearProviderEnv(t *testing.T) {
	t.Helper()
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")
	unsetenv(t, "PHALA_API_KEY")
	unsetenv(t, "CHUTES_API_KEY")
}

// --- Default values ---

func TestLoadDefaults(t *testing.T) {
	unsetenv(t, "TEEP_CONFIG")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.ListenAddr != DefaultListenAddr {
		t.Errorf("ListenAddr: got %q, want %q", cfg.ListenAddr, DefaultListenAddr)
	}
	if len(cfg.Providers) != 0 {
		t.Errorf("Providers: got %d entries, want 0", len(cfg.Providers))
	}
	// AllowFail is nil when no TOML is loaded; MergedAllowFail falls back
	// to per-provider Go defaults or DefaultAllowFail.
	if cfg.AllowFail != nil {
		t.Errorf("AllowFail: got %v, want nil (no TOML loaded)", cfg.AllowFail)
	}
}

// --- TOML loading ---

func TestLoadTOMLProviders(t *testing.T) {
	toml := `
[providers.venice]
api_key = "test-venice-key"
base_url = "https://api.venice.ai"
e2ee = true

[providers.neardirect]
api_key = "test-neardirect-key"
base_url = "https://api.near.ai"
e2ee = false
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	venice, ok := cfg.Providers["venice"]
	if !ok {
		t.Fatal("venice provider missing from config")
	}
	if venice.APIKey != "test-venice-key" {
		t.Errorf("venice APIKey: got %q, want %q", venice.APIKey, "test-venice-key")
	}
	if venice.BaseURL != "https://api.venice.ai" {
		t.Errorf("venice BaseURL: got %q, want %q", venice.BaseURL, "https://api.venice.ai")
	}
	if !venice.E2EE {
		t.Error("venice E2EE: got false, want true")
	}

	neardirect, ok := cfg.Providers["neardirect"]
	if !ok {
		t.Fatal("neardirect provider missing from config")
	}
	if neardirect.APIKey != "test-neardirect-key" {
		t.Errorf("neardirect APIKey: got %q, want %q", neardirect.APIKey, "test-neardirect-key")
	}
	if neardirect.E2EE {
		t.Error("neardirect E2EE: got true, want false")
	}
}

func TestLoadTOMLPolicy(t *testing.T) {
	toml := `
[policy]
allow_fail = ["nonce_match", "tls_key_binding"]
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(cfg.AllowFail) != 2 {
		t.Fatalf("AllowFail: got %d entries, want 2", len(cfg.AllowFail))
	}
	if cfg.AllowFail[0] != "nonce_match" {
		t.Errorf("AllowFail[0]: got %q, want %q", cfg.AllowFail[0], "nonce_match")
	}
	if cfg.AllowFail[1] != "tls_key_binding" {
		t.Errorf("AllowFail[1]: got %q, want %q", cfg.AllowFail[1], "tls_key_binding")
	}
}

func TestLoadTOMLUnknownAllowFailFactor(t *testing.T) {
	toml := `
[policy]
allow_fail = ["nonce_match", "typo_factor"]
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for unknown allow_fail factor, got nil")
	}
	if !strings.Contains(err.Error(), "typo_factor") {
		t.Errorf("error should mention the unknown factor: %v", err)
	}
}

func TestLoadTOMLEmptyAllowFailEnforcesAll(t *testing.T) {
	// An explicitly empty allow_fail = [] means "enforce all factors" —
	// overrides the built-in defaults to an empty list.
	toml := `
allow_fail = []
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(cfg.AllowFail) != 0 {
		t.Errorf("AllowFail: got %d entries, want 0 (enforce all)", len(cfg.AllowFail))
	}
}

func TestLoadTOMLEmptyPolicyAllowFailEnforcesAll(t *testing.T) {
	// An explicitly empty [policy] allow_fail = [] also means "enforce all".
	toml := `
[policy]
allow_fail = []
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(cfg.AllowFail) != 0 {
		t.Errorf("AllowFail: got %d entries, want 0 (enforce all)", len(cfg.AllowFail))
	}
}

func TestLoadTOMLPerProviderEmptyAllowFailEnforcesAll(t *testing.T) {
	// An explicitly empty per-provider allow_fail = [] means "enforce all"
	// for that provider, overriding the global default.
	toml := `
[providers.venice]
api_key = "k"
base_url = "https://api.venice.ai"
allow_fail = []
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	// No global allow_fail in TOML → cfg.AllowFail stays nil;
	// MergedAllowFail falls back to DefaultAllowFail for non-overridden providers.
	if cfg.AllowFail != nil {
		t.Errorf("global AllowFail: got %v, want nil (TOML didn't set global allow_fail)", cfg.AllowFail)
	}
	// Per-provider allow_fail should be empty (enforce all).
	af := MergedAllowFail("venice", cfg, false)
	if len(af) != 0 {
		t.Errorf("MergedAllowFail(\"venice\"): got %d entries, want 0 (enforce all)", len(af))
	}
}

func TestLoadTOMLMeasurementPolicy(t *testing.T) {
	valid48 := strings.Repeat("ab", 48)
	toml := `
[policy]
mrtd_allow = ["` + valid48 + `"]
mrseam_allow = ["0x` + valid48 + `"]
rtmr0_allow = ["` + valid48 + `"]
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !cfg.MeasurementPolicy.HasMRTDPolicy() {
		t.Fatal("expected MRTD allowlist policy to be configured")
	}
	if !cfg.MeasurementPolicy.HasMRSeamPolicy() {
		t.Fatal("expected MRSEAM allowlist policy to be configured")
	}
	if !cfg.MeasurementPolicy.HasRTMRPolicy(0) {
		t.Fatal("expected RTMR0 allowlist policy to be configured")
	}
}

func TestLoadTOMLMeasurementPolicyExplicitlyEmpty(t *testing.T) {
	tomlCfg := `
[policy]
mrtd_allow = []
`
	path := writeConfigFile(t, tomlCfg, 0o600)
	setenv(t, "TEEP_CONFIG", path)

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for explicitly empty mrtd_allow, got nil")
	}
	t.Logf("got expected error: %v", err)
	if !strings.Contains(err.Error(), "mrtd_allow") {
		t.Errorf("error should mention mrtd_allow, got: %v", err)
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should mention 'empty', got: %v", err)
	}
}

func TestLoadTOMLMeasurementPolicyInvalidLength(t *testing.T) {
	toml := `
[policy]
mrtd_allow = ["abcd"]
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid measurement length")
	}
	if !strings.Contains(err.Error(), "mrtd_allow") {
		t.Fatalf("error should mention mrtd_allow, got: %v", err)
	}
}

func TestLoadTOMLEmptyPolicyKeepsDefaults(t *testing.T) {
	// A [policy] section with no allow_fail list must keep the built-in defaults.
	toml := `
[providers.venice]
api_key = "k"
base_url = "https://api.venice.ai"
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	// No allow_fail in TOML → cfg.AllowFail stays nil;
	// MergedAllowFail falls back to DefaultAllowFail for venice.
	if cfg.AllowFail != nil {
		t.Errorf("AllowFail after TOML with no [policy]: got %v, want nil", cfg.AllowFail)
	}
	af := MergedAllowFail("venice", cfg, false)
	if len(af) != len(DefaultAllowFail) {
		t.Errorf("MergedAllowFail(venice): got %d entries, want %d", len(af), len(DefaultAllowFail))
	}
}

func TestLoadTOMLPerProviderPolicy(t *testing.T) {
	valid48a := strings.Repeat("ab", 48)
	valid48b := strings.Repeat("cd", 48)
	tomlCfg := `
[policy]
mrtd_allow = ["` + valid48a + `"]

[providers.venice]
api_key = "k"
base_url = "https://api.venice.ai"

[providers.venice.policy]
mrtd_allow = ["` + valid48b + `"]
`
	path := writeConfigFile(t, tomlCfg, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	// Global policy should have valid48a.
	if !cfg.MeasurementPolicy.HasMRTDPolicy() {
		t.Fatal("global MeasurementPolicy should have MRTD allowlist")
	}
	// Per-provider policy should have valid48b.
	pp, ok := cfg.ProviderPolicies["venice"]
	if !ok {
		t.Fatal("ProviderPolicies[venice] should be set")
	}
	if !pp.HasMRTDPolicy() {
		t.Fatal("venice per-provider MRTD policy should be set")
	}
	if _, ok := pp.MRTDAllow[valid48b]; !ok {
		t.Error("venice per-provider MRTD allowlist should contain " + valid48b[:16] + "...")
	}
}

func TestMergedMeasurementPolicy(t *testing.T) {
	valid48a := strings.Repeat("aa", 48)
	valid48b := strings.Repeat("bb", 48)
	valid48c := strings.Repeat("cc", 48)

	goDefaults := attestation.MeasurementPolicy{
		MRTDAllow:   map[string]struct{}{valid48a: {}},
		MRSeamAllow: map[string]struct{}{valid48a: {}},
	}
	cfg := &Config{
		MeasurementPolicy: attestation.MeasurementPolicy{
			MRTDAllow: map[string]struct{}{valid48b: {}},
		},
		ProviderPolicies: map[string]attestation.MeasurementPolicy{
			"venice": {MRTDAllow: map[string]struct{}{valid48c: {}}},
		},
		ProviderGatewayPolicies: make(map[string]attestation.MeasurementPolicy),
	}

	// Per-provider > global > Go defaults.
	merged := MergedMeasurementPolicy("venice", cfg, goDefaults)
	if _, ok := merged.MRTDAllow[valid48c]; !ok {
		t.Error("per-provider MRTD should win over global and defaults")
	}
	// MRSeamAllow: no per-provider, no global → Go default.
	if _, ok := merged.MRSeamAllow[valid48a]; !ok {
		t.Error("Go default MRSeamAllow should be used when no per-provider or global override")
	}

	// For a provider without per-provider config, global > Go defaults.
	merged2 := MergedMeasurementPolicy("neardirect", cfg, goDefaults)
	if _, ok := merged2.MRTDAllow[valid48b]; !ok {
		t.Error("global MRTD should override Go defaults for neardirect")
	}
}

func TestLoadTOMLAPIKeyEnv(t *testing.T) {
	// api_key_env resolves the API key from the named env var.
	toml := `
[providers.venice]
api_key_env = "VENICE_API_KEY"
base_url = "https://api.venice.ai"
e2ee = true
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)
	setenv(t, "VENICE_API_KEY", "env-resolved-key")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	venice := cfg.Providers["venice"]
	if venice == nil {
		t.Fatal("venice provider missing")
	}
	if venice.APIKey != "env-resolved-key" {
		t.Errorf("APIKey from api_key_env: got %q, want %q", venice.APIKey, "env-resolved-key")
	}
}

func TestLoadTOMLAPIKeyEnvOverridesInline(t *testing.T) {
	// When both api_key and api_key_env are set, the env var value wins.
	toml := `
[providers.venice]
api_key = "toml-key"
api_key_env = "VENICE_API_KEY"
base_url = "https://api.venice.ai"
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)
	setenv(t, "VENICE_API_KEY", "env-key")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	venice := cfg.Providers["venice"]
	if venice.APIKey != "env-key" {
		t.Errorf("api_key_env should override api_key: got %q, want %q", venice.APIKey, "env-key")
	}
}

func TestLoadTOMLInvalidFile(t *testing.T) {
	path := writeConfigFile(t, "this is not valid toml ={}", 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with invalid TOML: expected error, got nil")
	}
}

func TestLoadTOMLMissingFile(t *testing.T) {
	setenv(t, "TEEP_CONFIG", "/nonexistent/path/teep.toml")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with missing file: expected error, got nil")
	}
}

// --- Env var overrides ---

func TestEnvListenAddr(t *testing.T) {
	unsetenv(t, "TEEP_CONFIG")
	setenv(t, "TEEP_LISTEN_ADDR", "127.0.0.1:9090")
	clearProviderEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:9090" {
		t.Errorf("ListenAddr: got %q, want %q", cfg.ListenAddr, "127.0.0.1:9090")
	}
}

func TestEnvVeniceAPIKey(t *testing.T) {
	unsetenv(t, "TEEP_CONFIG")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)
	setenv(t, "VENICE_API_KEY", "direct-venice-key")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	venice, ok := cfg.Providers["venice"]
	if !ok {
		t.Fatal("venice provider not created from VENICE_API_KEY env var")
	}
	if venice.APIKey != "direct-venice-key" {
		t.Errorf("venice APIKey: got %q, want %q", venice.APIKey, "direct-venice-key")
	}
	if venice.BaseURL != "https://api.venice.ai" {
		t.Errorf("venice BaseURL default: got %q, want %q", venice.BaseURL, "https://api.venice.ai")
	}
	if !venice.E2EE {
		t.Error("venice E2EE default: got false, want true")
	}
}

func TestEnvNearDirectAPIKey(t *testing.T) {
	unsetenv(t, "TEEP_CONFIG")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)
	setenv(t, "NEARAI_API_KEY", "direct-neardirect-key")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	neardirect, ok := cfg.Providers["neardirect"]
	if !ok {
		t.Fatal("neardirect provider not created from NEARAI_API_KEY env var")
	}
	if neardirect.APIKey != "direct-neardirect-key" {
		t.Errorf("neardirect APIKey: got %q, want %q", neardirect.APIKey, "direct-neardirect-key")
	}
	if neardirect.BaseURL != "https://completions.near.ai" {
		t.Errorf("neardirect BaseURL default: got %q, want %q", neardirect.BaseURL, "https://completions.near.ai")
	}
}

func TestEnvAPIKeyOverridesToml(t *testing.T) {
	// VENICE_API_KEY env var must override the API key from TOML.
	toml := `
[providers.venice]
api_key = "toml-key"
base_url = "https://api.venice.ai"
e2ee = true
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)
	setenv(t, "VENICE_API_KEY", "env-override-key")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	venice := cfg.Providers["venice"]
	if venice.APIKey != "env-override-key" {
		t.Errorf("VENICE_API_KEY env should override TOML api_key: got %q, want %q", venice.APIKey, "env-override-key")
	}
}

// --- File permission check ---

func TestCheckFilePermissionsSecure(t *testing.T) {
	path := writeConfigFile(t, "[policy]", 0o600)
	if err := checkFilePermissions(path); err != nil {
		t.Errorf("checkFilePermissions(0600): unexpected error: %v", err)
	}
}

func TestCheckFilePermissionsGroupReadable(t *testing.T) {
	path := writeConfigFile(t, "[policy]", 0o640)
	if err := checkFilePermissions(path); err == nil {
		t.Error("checkFilePermissions(0640): expected error, got nil")
	}
}

func TestCheckFilePermissionsWorldReadable(t *testing.T) {
	path := writeConfigFile(t, "[policy]", 0o644)
	if err := checkFilePermissions(path); err == nil {
		t.Error("checkFilePermissions(0644): expected error, got nil")
	}
}

func TestCheckFilePermissionsOwnerOnly(t *testing.T) {
	path := writeConfigFile(t, "[policy]", 0o700)
	// 0700 has no read bits for group/world, so it's fine (owner execute).
	if err := checkFilePermissions(path); err != nil {
		t.Errorf("checkFilePermissions(0700): unexpected error: %v", err)
	}
}

func TestCheckFilePermissionsGroupWritable(t *testing.T) {
	path := writeConfigFile(t, "[policy]", 0o600)
	// os.WriteFile is subject to umask; chmod explicitly.
	if err := os.Chmod(path, 0o620); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := checkFilePermissions(path); err == nil {
		t.Error("checkFilePermissions(0620): expected error for group-writable, got nil")
	}
}

func TestCheckFilePermissionsNotFound(t *testing.T) {
	if err := checkFilePermissions("/nonexistent/path/file.toml"); err == nil {
		t.Error("checkFilePermissions on nonexistent file: expected error, got nil")
	}
}

// --- API key redaction ---

func TestRedactKeyLong(t *testing.T) {
	got := RedactKey("abcdefghij")
	if got != "abcd****" {
		t.Errorf("RedactKey long: got %q, want %q", got, "abcd****")
	}
}

func TestRedactKeyExactlyFour(t *testing.T) {
	got := RedactKey("abcd")
	if got != "****" {
		t.Errorf("RedactKey exactly 4 chars: got %q, want %q", got, "****")
	}
}

func TestRedactKeyShort(t *testing.T) {
	got := RedactKey("ab")
	if got != "****" {
		t.Errorf("RedactKey short: got %q, want %q", got, "****")
	}
}

func TestRedactKeyEmpty(t *testing.T) {
	got := RedactKey("")
	if got != "****" {
		t.Errorf("RedactKey empty: got %q, want %q", got, "****")
	}
}

func TestRedactKeyDoesNotContainFullKey(t *testing.T) {
	key := "super-secret-api-key-12345"
	got := RedactKey(key)
	// The redacted string must not contain the full key.
	if strings.Contains(got, key) {
		t.Errorf("RedactKey output %q contains full key", got)
	}
	// It must not contain anything past the first four characters.
	if strings.Contains(got, key[4:]) {
		t.Errorf("RedactKey output %q leaks key suffix", got)
	}
}

// --- HTTP client ---

func TestNewAttestationClient(t *testing.T) {
	client := NewAttestationClient(false)
	if client == nil {
		t.Fatal("NewAttestationClient returned nil")
	}
	if client.Timeout != AttestationTimeout {
		t.Errorf("client Timeout: got %v, want %v", client.Timeout, AttestationTimeout)
	}
}

func TestNewAttestationClientOfflineDisablesCT(t *testing.T) {
	client := NewAttestationClient(true)
	if client == nil {
		t.Fatal("NewAttestationClient returned nil")
	}
	if client.Timeout != AttestationTimeout {
		t.Errorf("client Timeout: got %v, want %v", client.Timeout, AttestationTimeout)
	}
	if got := fmt.Sprintf("%T", client.Transport); strings.Contains(got, "ctRoundTripper") {
		t.Fatalf("offline client transport unexpectedly wrapped with CT checker: %s", got)
	}
}

// --- Non-loopback warning ---

// TestWarnNonLoopbackLoopback verifies that loopback addresses do not produce
// a warning. We call warnNonLoopback directly; the warning goes to log.Print
// which writes to os.Stderr — hard to capture without redirecting. We verify
// the function does not panic on valid inputs.
func TestWarnNonLoopbackLoopback(t *testing.T) {
	// These must not panic or cause issues.
	warnNonLoopback("127.0.0.1:8337")
	warnNonLoopback("[::1]:8337")
}

func TestWarnNonLoopbackNonLoopback(t *testing.T) {
	// Non-loopback should not panic, just log.
	warnNonLoopback("0.0.0.0:8337")
	warnNonLoopback("192.168.1.1:8337")
}

func TestWarnNonLoopbackUnparseable(t *testing.T) {
	// Unparseable address should not panic, just log.
	warnNonLoopback("not-an-address")
}

// rtFunc adapts a function to http.RoundTripper for RetryTransport tests.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// --- RetryTransport ---

func TestRetryTransport_SuccessFirstAttempt(t *testing.T) {
	calls := 0
	rt := &RetryTransport{
		Base: rtFunc(func(_ *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(nil))}, nil
		}),
		MaxAttempts: 3,
		MaxDelay:    time.Millisecond,
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", http.NoBody)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	t.Logf("calls: %d", calls)
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestRetryTransport_RetriesOn5xx(t *testing.T) {
	calls := 0
	rt := &RetryTransport{
		Base: rtFunc(func(_ *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(bytes.NewReader(nil))}, nil
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte("ok")))}, nil
		}),
		MaxAttempts: 3,
		MaxDelay:    time.Millisecond,
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", http.NoBody)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("calls: %d, body: %s", calls, body)
	if calls != 2 {
		t.Errorf("expected 2 calls, got %d", calls)
	}
	if string(body) != "ok" {
		t.Errorf("body = %q, want %q", body, "ok")
	}
}

func TestRetryTransport_RetriesOnNetworkError(t *testing.T) {
	calls := 0
	netErr := errors.New("connection refused")
	rt := &RetryTransport{
		Base: rtFunc(func(_ *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return nil, netErr
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(nil))}, nil
		}),
		MaxAttempts: 3,
		MaxDelay:    time.Millisecond,
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", http.NoBody)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	t.Logf("calls: %d", calls)
	if calls != 2 {
		t.Errorf("expected 2 calls, got %d", calls)
	}
}

func TestRetryTransport_ExhaustsMaxAttempts(t *testing.T) {
	calls := 0
	rt := &RetryTransport{
		Base: rtFunc(func(_ *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(bytes.NewReader(nil))}, nil
		}),
		MaxAttempts: 3,
		MaxDelay:    time.Millisecond,
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", http.NoBody)
	resp, err := rt.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	t.Logf("calls: %d, err: %v", calls, err)
	if err == nil {
		t.Fatal("expected error after exhausting all attempts")
	}
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error = %q, should mention 503", err)
	}
}

func TestRetryTransport_ContextCancelledDuringDelay(t *testing.T) {
	calls := 0
	rt := &RetryTransport{
		Base: rtFunc(func(_ *http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("transient")
		}),
		MaxAttempts: 3,
		MaxDelay:    time.Millisecond,
	}

	// Cancel before RoundTrip so the retry-delay select immediately fires ctx.Done.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", http.NoBody)
	resp, err := rt.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	t.Logf("calls: %d, err: %v", calls, err)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestRetryTransport_ResetsBodyBetweenRetries(t *testing.T) {
	// Verify the request body is readable on both attempts.
	var bodies []string
	rt := &RetryTransport{
		Base: rtFunc(func(req *http.Request) (*http.Response, error) {
			b, _ := io.ReadAll(req.Body)
			bodies = append(bodies, string(b))
			if len(bodies) == 1 {
				return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(bytes.NewReader(nil))}, nil
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(nil))}, nil
		}),
		MaxAttempts: 3,
		MaxDelay:    time.Millisecond,
	}

	payload := []byte(`{"nonce":"abc"}`)
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/attest", bytes.NewReader(payload))
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	t.Logf("bodies: %v", bodies)
	if len(bodies) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(bodies))
	}
	if bodies[0] != string(payload) {
		t.Errorf("attempt 1 body = %q, want %q", bodies[0], payload)
	}
	if bodies[1] != string(payload) {
		t.Errorf("attempt 2 body = %q, want %q (body should be reset)", bodies[1], payload)
	}
}

// TestLoadNonLoopbackEnvAddrLoads verifies Load succeeds even when the listen
// addr is non-loopback (the warning is logged but Load still returns a config).
func TestLoadNonLoopbackEnvAddrLoads(t *testing.T) {
	unsetenv(t, "TEEP_CONFIG")
	setenv(t, "TEEP_LISTEN_ADDR", "0.0.0.0:8337")
	clearProviderEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.ListenAddr != "0.0.0.0:8337" {
		t.Errorf("ListenAddr: got %q, want %q", cfg.ListenAddr, "0.0.0.0:8337")
	}
}

// --- Insecure permissions warning ---

// TestLoadInsecurePermissionsWarns verifies Load succeeds even when the config
// file has insecure permissions (warning is logged but no error returned).
func TestLoadInsecurePermissionsWarns(t *testing.T) {
	toml := `
[providers.venice]
api_key = "k"
base_url = "https://api.venice.ai"
`
	path := writeConfigFile(t, toml, 0o644)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	// Load must succeed — bad permissions are a warning, not a hard error.
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() with world-readable config: unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil config")
	}
}

// --- DefaultAllowFail isolation ---

// TestDefaultAllowFailImmutable verifies that mutating the slice returned by
// MergedAllowFail does not alter the package-level DefaultAllowFail.
func TestDefaultAllowFailImmutable(t *testing.T) {
	unsetenv(t, "TEEP_CONFIG")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	// MergedAllowFail for a provider without Go defaults uses DefaultAllowFail.
	af := MergedAllowFail("venice", cfg, false)
	if len(af) == 0 {
		t.Fatal("expected non-empty allow_fail for venice defaults")
	}
	af[0] = "mutated"

	// DefaultAllowFail must be unchanged.
	if DefaultAllowFail[0] == "mutated" {
		t.Error("mutating MergedAllowFail result affected DefaultAllowFail; must return a copy")
	}
}

// --- Per-provider Go defaults ---

func TestMergedAllowFailNearcloudGoDefaults(t *testing.T) {
	// When no TOML config is loaded, nearcloud should use its tighter
	// Go-level defaults instead of the global DefaultAllowFail.
	unsetenv(t, "TEEP_CONFIG")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "NEARAI_API_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	af := MergedAllowFail("nearcloud", cfg, false)
	want := attestation.NearcloudDefaultAllowFail
	if len(af) != len(want) {
		t.Fatalf("MergedAllowFail(\"nearcloud\"): got %d entries, want %d", len(af), len(want))
	}
	for i, name := range want {
		if af[i] != name {
			t.Errorf("MergedAllowFail(\"nearcloud\")[%d]: got %q, want %q", i, af[i], name)
		}
	}

	// Factors removed from nearcloud defaults must not be present.
	enforced := []string{
		"tdx_quote_present", "tdx_quote_structure",
		"intel_pcs_collateral", "tdx_tcb_current",
		"nvidia_payload_present", "nvidia_claims", "nvidia_nras_verified",
		"e2ee_capable", "tls_key_binding",
		"gateway_tdx_quote_present", "gateway_tdx_quote_structure",
	}
	afSet := make(map[string]bool, len(af))
	for _, name := range af {
		afSet[name] = true
	}
	for _, name := range enforced {
		if afSet[name] {
			t.Errorf("factor %q should be enforced (not in allow_fail) for nearcloud", name)
		}
	}
}

func TestMergedAllowFailNonNearcloudUsesGlobalDefaults(t *testing.T) {
	// Providers without per-provider Go defaults should still use the
	// global DefaultAllowFail.
	unsetenv(t, "TEEP_CONFIG")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "VENICE_API_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	af := MergedAllowFail("venice", cfg, false)
	if len(af) != len(DefaultAllowFail) {
		t.Errorf("MergedAllowFail(\"venice\"): got %d entries, want %d", len(af), len(DefaultAllowFail))
	}
}

func TestMergedAllowFailGlobalTOMLOverridesNearcloudDefaults(t *testing.T) {
	// A global TOML allow_fail should override nearcloud's Go-level defaults.
	toml := `allow_fail = ["cpu_gpu_chain"]`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "NEARAI_API_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	af := MergedAllowFail("nearcloud", cfg, false)
	if len(af) != 1 || af[0] != "cpu_gpu_chain" {
		t.Errorf("MergedAllowFail(\"nearcloud\"): got %v, want [cpu_gpu_chain]", af)
	}
}

func TestMergedAllowFailPerProviderTOMLOverridesAll(t *testing.T) {
	// Per-provider TOML allow_fail should take highest priority,
	// overriding both nearcloud Go defaults and global TOML.
	toml := `
allow_fail = ["e2ee_usable", "cpu_gpu_chain"]

[providers.nearcloud]
api_key = "k"
base_url = "https://cloud-api.near.ai"
allow_fail = ["tdx_hardware_config"]
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "NEARAI_API_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	af := MergedAllowFail("nearcloud", cfg, false)
	if len(af) != 1 || af[0] != "tdx_hardware_config" {
		t.Errorf("MergedAllowFail(\"nearcloud\"): got %v, want [tdx_hardware_config]", af)
	}
}

func TestMergedAllowFailNeardirectGoDefaults(t *testing.T) {
	// When no TOML config is loaded, neardirect should use its tighter
	// Go-level defaults instead of the global DefaultAllowFail.
	unsetenv(t, "TEEP_CONFIG")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "NEARAI_API_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	af := MergedAllowFail("neardirect", cfg, false)
	want := attestation.NeardirectDefaultAllowFail
	if len(af) != len(want) {
		t.Fatalf("MergedAllowFail(\"neardirect\"): got %d entries, want %d", len(af), len(want))
	}
	for i, name := range want {
		if af[i] != name {
			t.Errorf("MergedAllowFail(\"neardirect\")[%d]: got %q, want %q", i, af[i], name)
		}
	}

	// Factors removed from neardirect defaults must not be present.
	enforced := []string{
		"tdx_quote_present", "tdx_quote_structure",
		"intel_pcs_collateral", "tdx_tcb_current",
		"nvidia_payload_present", "nvidia_claims", "nvidia_nras_verified",
		"e2ee_capable", "tls_key_binding",
	}
	afSet := make(map[string]bool, len(af))
	for _, name := range af {
		afSet[name] = true
	}
	for _, name := range enforced {
		if afSet[name] {
			t.Errorf("factor %q should be enforced (not in allow_fail) for neardirect", name)
		}
	}
}

// --- Offline mode ---

func TestMergedAllowFailOfflineAddsOnlineFactors(t *testing.T) {
	// When cfg.Offline is true, MergedAllowFail should include all
	// OnlineFactors in the returned list.
	unsetenv(t, "TEEP_CONFIG")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "NEARAI_API_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	af := MergedAllowFail("nearcloud", cfg, true)
	afSet := make(map[string]bool, len(af))
	for _, name := range af {
		afSet[name] = true
	}
	for _, name := range attestation.OnlineFactors {
		if !afSet[name] {
			t.Errorf("offline mode: factor %q should be in allow_fail but is not", name)
		}
	}
}

func TestMergedAllowFailOnlineDoesNotAddOnlineFactors(t *testing.T) {
	// When cfg.Offline is false, nearcloud's tighter defaults should NOT
	// include online factors that were removed.
	unsetenv(t, "TEEP_CONFIG")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "NEARAI_API_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	// Offline is false by default.

	af := MergedAllowFail("nearcloud", cfg, false)
	afSet := make(map[string]bool, len(af))
	for _, name := range af {
		afSet[name] = true
	}
	// intel_pcs_collateral is an online factor that was removed from
	// NearcloudDefaultAllowFail; it should NOT be in the list.
	if afSet["intel_pcs_collateral"] {
		t.Error("online mode: intel_pcs_collateral should not be in allow_fail for nearcloud")
	}
}

func TestMergedAllowFailOfflinePerProviderTOML(t *testing.T) {
	// Even with a per-provider TOML override (enforce all), offline mode
	// should still add OnlineFactors.
	toml := `
[providers.venice]
api_key = "k"
base_url = "https://api.venice.ai"
allow_fail = []
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "VENICE_API_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	af := MergedAllowFail("venice", cfg, true)
	if len(af) != len(attestation.OnlineFactors) {
		t.Errorf("offline + empty TOML: got %d entries, want %d (OnlineFactors only)",
			len(af), len(attestation.OnlineFactors))
	}
	afSet := make(map[string]bool, len(af))
	for _, name := range af {
		afSet[name] = true
	}
	for _, name := range attestation.OnlineFactors {
		if !afSet[name] {
			t.Errorf("offline mode: factor %q should be in allow_fail but is not", name)
		}
	}
}

func TestMergedAllowFailProgrammaticAllowFail(t *testing.T) {
	// Programmatic configs that set AllowFail directly (without Load())
	// must be honored even for providers with Go-level defaults.
	cfg := &Config{
		AllowFail: attestation.KnownFactors,
	}
	af := MergedAllowFail("nearcloud", cfg, false)
	if len(af) != len(attestation.KnownFactors) {
		t.Errorf("programmatic AllowFail: got %d entries, want %d (KnownFactors)",
			len(af), len(attestation.KnownFactors))
	}

	// Also verify an explicitly empty AllowFail is honored (enforce all).
	cfg2 := &Config{
		AllowFail: []string{},
	}
	af2 := MergedAllowFail("nearcloud", cfg2, false)
	if len(af2) != 0 {
		t.Errorf("programmatic empty AllowFail: got %d entries, want 0", len(af2))
	}
}

func TestMergedAllowFailReturnsDefensiveCopy(t *testing.T) {
	// MergedAllowFail must return a distinct slice so callers cannot
	// mutate shared package-level defaults or Config fields.
	toml := `
[providers.nearcloud]
api_key = "k"
base_url = "https://api.near.ai"
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "NEARAI_API_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	a := MergedAllowFail("nearcloud", cfg, false)
	b := MergedAllowFail("nearcloud", cfg, false)
	if len(a) == 0 {
		t.Fatal("expected non-empty allow_fail for nearcloud defaults")
	}
	// Mutate the first result and verify the second is unaffected.
	a[0] = "MUTATED"
	if b[0] == "MUTATED" {
		t.Error("MergedAllowFail returned a shared slice; callers can mutate defaults")
	}
}

func TestMergedGatewayMeasurementPolicy_NoPerProvider(t *testing.T) {
	cfg := &Config{}
	defaults := attestation.MeasurementPolicy{MRTDAllow: map[string]struct{}{"aabbcc": {}}}
	p := MergedGatewayMeasurementPolicy("venice", cfg, defaults)
	if _, ok := p.MRTDAllow["aabbcc"]; !ok {
		t.Errorf("unexpected MRTDAllow: %v (want key aabbcc)", p.MRTDAllow)
	}
}

func TestMergedGatewayMeasurementPolicy_WithPerProvider(t *testing.T) {
	cfg := &Config{
		ProviderGatewayPolicies: map[string]attestation.MeasurementPolicy{
			"venice": {MRTDAllow: map[string]struct{}{"override": {}}},
		},
	}
	defaults := attestation.MeasurementPolicy{MRTDAllow: map[string]struct{}{"default": {}}}
	p := MergedGatewayMeasurementPolicy("venice", cfg, defaults)
	if _, ok := p.MRTDAllow["override"]; !ok {
		t.Errorf("unexpected MRTDAllow: %v (want key override)", p.MRTDAllow)
	}
	if _, ok := p.MRTDAllow["default"]; ok {
		t.Errorf("MRTDAllow should not contain 'default' after per-provider override")
	}
}

// --------------------------------------------------------------------------
// normalizeAllowlist / buildMeasurementPolicy / buildGatewayMeasurementPolicy
// error-path coverage
// --------------------------------------------------------------------------

func TestLoadTOMLMRSeamAllowInvalidHex(t *testing.T) {
	toml := `
[policy]
mrseam_allow = ["notvalidhex!"]
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	_, err := Load()
	t.Logf("mrseam_allow invalid hex: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid mrseam_allow hex")
	}
	if !strings.Contains(err.Error(), "mrseam_allow") {
		t.Errorf("error should mention mrseam_allow, got: %v", err)
	}
}

func TestLoadTOMLRTMR0AllowInvalidHex(t *testing.T) {
	toml := `
[policy]
rtmr0_allow = ["notvalidhex!"]
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	_, err := Load()
	t.Logf("rtmr0_allow invalid hex: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid rtmr0_allow hex")
	}
	if !strings.Contains(err.Error(), "rtmr0_allow") {
		t.Errorf("error should mention rtmr0_allow, got: %v", err)
	}
}

func TestLoadTOMLGatewayMRTDAllowInvalidHex(t *testing.T) {
	toml := `
[policy]
gateway_mrtd_allow = ["notvalidhex!"]
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	_, err := Load()
	t.Logf("gateway_mrtd_allow invalid hex: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid gateway_mrtd_allow hex")
	}
	if !strings.Contains(err.Error(), "gateway_mrtd_allow") {
		t.Errorf("error should mention gateway_mrtd_allow, got: %v", err)
	}
}

func TestLoadTOMLGatewayMRSeamAllowInvalidHex(t *testing.T) {
	toml := `
[policy]
gateway_mrseam_allow = ["notvalidhex!"]
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	_, err := Load()
	t.Logf("gateway_mrseam_allow invalid hex: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid gateway_mrseam_allow hex")
	}
	if !strings.Contains(err.Error(), "gateway_mrseam_allow") {
		t.Errorf("error should mention gateway_mrseam_allow, got: %v", err)
	}
}

func TestLoadTOMLGatewayRTMR0AllowInvalidHex(t *testing.T) {
	toml := `
[policy]
gateway_rtmr0_allow = ["notvalidhex!"]
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	_, err := Load()
	t.Logf("gateway_rtmr0_allow invalid hex: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid gateway_rtmr0_allow hex")
	}
	if !strings.Contains(err.Error(), "gateway_rtmr0_allow") {
		t.Errorf("error should mention gateway_rtmr0_allow, got: %v", err)
	}
}

func TestLoadTOMLPerProviderMRTDAllowInvalidHex(t *testing.T) {
	toml := `
[providers.venice]
api_key = "k"
[providers.venice.policy]
mrtd_allow = ["notvalidhex!"]
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	_, err := Load()
	t.Logf("per-provider mrtd_allow invalid hex: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid per-provider mrtd_allow hex")
	}
}

func TestLoadTOMLPerProviderGatewayMRTDAllowInvalidHex(t *testing.T) {
	toml := `
[providers.venice]
api_key = "k"
[providers.venice.policy]
gateway_mrtd_allow = ["notvalidhex!"]
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	_, err := Load()
	t.Logf("per-provider gateway_mrtd_allow invalid hex: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid per-provider gateway_mrtd_allow hex")
	}
}

func TestMergeAllowlists_MRSeamAndRTMR(t *testing.T) {
	valid48a := strings.Repeat("aa", 48)
	valid48b := strings.Repeat("bb", 48)

	base := attestation.MeasurementPolicy{}
	overlay := attestation.MeasurementPolicy{
		MRSeamAllow: map[string]struct{}{valid48a: {}},
		RTMRAllow: [4]map[string]struct{}{
			{valid48b: {}}, nil, nil, nil,
		},
	}
	merged := mergeAllowlists(base, overlay)
	t.Logf("merged MRSeamAllow: %v", merged.MRSeamAllow)
	t.Logf("merged RTMR0Allow: %v", merged.RTMRAllow[0])
	if _, ok := merged.MRSeamAllow[valid48a]; !ok {
		t.Error("overlay MRSeamAllow should win")
	}
	if _, ok := merged.RTMRAllow[0][valid48b]; !ok {
		t.Error("overlay RTMR0 should win")
	}
}

func TestRetryTransport_BodyCannotReset(t *testing.T) {
	// A request with a non-nil body but no GetBody function cannot be retried
	// after the first attempt consumes the body. The transport should return
	// the last error without attempting a reset.
	attempts := 0
	rt := &RetryTransport{
		Base: rtFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Body:       io.NopCloser(bytes.NewReader(nil)),
			}, nil
		}),
		MaxAttempts: 3,
		MaxDelay:    time.Millisecond,
	}

	// Manually create a request with body but no GetBody.
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/attest", http.NoBody)
	req.Body = io.NopCloser(bytes.NewReader([]byte(`{"nonce":"abc"}`)))
	req.GetBody = nil

	resp, err := rt.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	t.Logf("BodyCannotReset: err=%v attempts=%d", err, attempts)
	if attempts != 1 {
		t.Errorf("expected 1 attempt (body cannot be reset), got %d", attempts)
	}
	// The 503 triggers retry logic, but since GetBody==nil, the transport
	// gives up after the first attempt and returns the last error.
	if err == nil {
		t.Error("expected non-nil error when body cannot be reset")
	}
}

func TestLoadTOMLUnknownKey(t *testing.T) {
	tomlContent := `
unknown_setting = "value"

[providers.venice]
api_key = "k"
`
	path := writeConfigFile(t, tomlContent, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	_, err := Load()
	t.Logf("unknown key: %v", err)
	if err == nil {
		t.Fatal("expected error for unknown TOML key")
	}
	if !strings.Contains(err.Error(), "unknown config keys") {
		t.Errorf("error should mention 'unknown config keys', got: %v", err)
	}
}

func TestLoadTOMLPerProviderUnknownAllowFailFactor(t *testing.T) {
	tomlContent := `
[providers.venice]
api_key = "k"
allow_fail = ["nonexistent_factor_xyz"]
`
	path := writeConfigFile(t, tomlContent, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	_, err := Load()
	t.Logf("per-provider unknown allow_fail factor: %v", err)
	if err == nil {
		t.Fatal("expected error for unknown allow_fail factor")
	}
	if !strings.Contains(err.Error(), "nonexistent_factor_xyz") {
		t.Errorf("error should mention unknown factor name, got: %v", err)
	}
}

func TestLoadTOMLPerProviderGatewayPolicy(t *testing.T) {
	valid48 := strings.Repeat("ab", 48)
	tomlContent := fmt.Sprintf(`
[providers.venice]
api_key = "k"
[providers.venice.policy]
gateway_mrtd_allow = ["%s"]
`, valid48)
	path := writeConfigFile(t, tomlContent, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	cfg, err := Load()
	t.Logf("per-provider gateway policy: err=%v", err)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := cfg.ProviderGatewayPolicies["venice"]; !ok {
		t.Error("expected per-provider gateway policy to be stored")
	}
}
