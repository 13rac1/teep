package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	t.Setenv(key, "")
	os.Unsetenv(key)
}

// --- Default values ---

func TestLoadDefaults(t *testing.T) {
	unsetenv(t, "TEEP_CONFIG")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

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
	if len(cfg.AllowFail) != len(DefaultAllowFail) {
		t.Errorf("AllowFail: got %d entries, want %d", len(cfg.AllowFail), len(DefaultAllowFail))
	}
	for i, name := range DefaultAllowFail {
		if cfg.AllowFail[i] != name {
			t.Errorf("AllowFail[%d]: got %q, want %q", i, cfg.AllowFail[i], name)
		}
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
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

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
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

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
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

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
	// Global allow_fail should still be the defaults.
	if len(cfg.AllowFail) != len(DefaultAllowFail) {
		t.Errorf("global AllowFail: got %d entries, want %d", len(cfg.AllowFail), len(DefaultAllowFail))
	}
	// Per-provider allow_fail should be empty (enforce all).
	af := MergedAllowFail("venice", cfg)
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
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(cfg.AllowFail) != len(DefaultAllowFail) {
		t.Errorf("AllowFail after TOML with no [policy]: got %d entries, want %d", len(cfg.AllowFail), len(DefaultAllowFail))
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
	setenv(t, "VENICE_API_KEY", "env-resolved-key")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

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
	setenv(t, "VENICE_API_KEY", "env-key")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

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
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with invalid TOML: expected error, got nil")
	}
}

func TestLoadTOMLMissingFile(t *testing.T) {
	setenv(t, "TEEP_CONFIG", "/nonexistent/path/teep.toml")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() with missing file: expected error, got nil")
	}
}

// --- Env var overrides ---

func TestEnvListenAddr(t *testing.T) {
	unsetenv(t, "TEEP_CONFIG")
	setenv(t, "TEEP_LISTEN_ADDR", "127.0.0.1:9090")
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

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
	setenv(t, "VENICE_API_KEY", "direct-venice-key")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

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
	unsetenv(t, "VENICE_API_KEY")
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
	setenv(t, "VENICE_API_KEY", "env-override-key")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

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
	client := NewAttestationClient()
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

// TestLoadNonLoopbackEnvAddrLoads verifies Load succeeds even when the listen
// addr is non-loopback (the warning is logged but Load still returns a config).
func TestLoadNonLoopbackEnvAddrLoads(t *testing.T) {
	unsetenv(t, "TEEP_CONFIG")
	setenv(t, "TEEP_LISTEN_ADDR", "0.0.0.0:8337")
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

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
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

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

// TestDefaultAllowFailImmutable verifies that modifying the returned cfg.AllowFail
// slice does not alter DefaultAllowFail.
func TestDefaultAllowFailImmutable(t *testing.T) {
	unsetenv(t, "TEEP_CONFIG")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")
	unsetenv(t, "NANOGPT_API_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	// Mutate the returned slice.
	cfg.AllowFail[0] = "mutated"

	// DefaultAllowFail must be unchanged.
	if DefaultAllowFail[0] == "mutated" {
		t.Error("mutating cfg.AllowFail affected DefaultAllowFail; Load must return a copy")
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

	af := MergedAllowFail("nearcloud", cfg)
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
		"e2ee_capable", "e2ee_usable", "tls_key_binding",
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

	af := MergedAllowFail("venice", cfg)
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

	af := MergedAllowFail("nearcloud", cfg)
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

	af := MergedAllowFail("nearcloud", cfg)
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

	af := MergedAllowFail("neardirect", cfg)
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
	cfg.Offline = true

	af := MergedAllowFail("nearcloud", cfg)
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

	af := MergedAllowFail("nearcloud", cfg)
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
	cfg.Offline = true

	af := MergedAllowFail("venice", cfg)
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

	a := MergedAllowFail("nearcloud", cfg)
	b := MergedAllowFail("nearcloud", cfg)
	if len(a) == 0 {
		t.Fatal("expected non-empty allow_fail for nearcloud defaults")
	}
	// Mutate the first result and verify the second is unaffected.
	a[0] = "MUTATED"
	if b[0] == "MUTATED" {
		t.Error("MergedAllowFail returned a shared slice; callers can mutate defaults")
	}
}
