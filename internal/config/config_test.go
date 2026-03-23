package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if len(cfg.Enforced) != len(DefaultEnforced) {
		t.Errorf("Enforced: got %d entries, want %d", len(cfg.Enforced), len(DefaultEnforced))
	}
	for i, name := range DefaultEnforced {
		if cfg.Enforced[i] != name {
			t.Errorf("Enforced[%d]: got %q, want %q", i, cfg.Enforced[i], name)
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

[providers.nearai]
api_key = "test-nearai-key"
base_url = "https://api.near.ai"
e2ee = false
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")

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

	nearai, ok := cfg.Providers["nearai"]
	if !ok {
		t.Fatal("nearai provider missing from config")
	}
	if nearai.APIKey != "test-nearai-key" {
		t.Errorf("nearai APIKey: got %q, want %q", nearai.APIKey, "test-nearai-key")
	}
	if nearai.E2EE {
		t.Error("nearai E2EE: got true, want false")
	}
}

func TestLoadTOMLPolicy(t *testing.T) {
	toml := `
[policy]
enforce = ["nonce_match", "tls_key_binding"]
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(cfg.Enforced) != 2 {
		t.Fatalf("Enforced: got %d entries, want 2", len(cfg.Enforced))
	}
	if cfg.Enforced[0] != "nonce_match" {
		t.Errorf("Enforced[0]: got %q, want %q", cfg.Enforced[0], "nonce_match")
	}
	if cfg.Enforced[1] != "tls_key_binding" {
		t.Errorf("Enforced[1]: got %q, want %q", cfg.Enforced[1], "tls_key_binding")
	}
}

func TestLoadTOMLUnknownEnforceFactor(t *testing.T) {
	toml := `
[policy]
enforce = ["nonce_match", "typo_factor"]
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for unknown enforce factor, got nil")
	}
	if !strings.Contains(err.Error(), "typo_factor") {
		t.Errorf("error should mention the unknown factor: %v", err)
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
	// An [policy] section with no enforce list must keep the built-in defaults.
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

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(cfg.Enforced) != len(DefaultEnforced) {
		t.Errorf("Enforced after TOML with no [policy]: got %d entries, want %d", len(cfg.Enforced), len(DefaultEnforced))
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

func TestEnvNearAIAPIKey(t *testing.T) {
	unsetenv(t, "TEEP_CONFIG")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "VENICE_API_KEY")
	setenv(t, "NEARAI_API_KEY", "direct-nearai-key")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	nearai, ok := cfg.Providers["nearai"]
	if !ok {
		t.Fatal("nearai provider not created from NEARAI_API_KEY env var")
	}
	if nearai.APIKey != "direct-nearai-key" {
		t.Errorf("nearai APIKey: got %q, want %q", nearai.APIKey, "direct-nearai-key")
	}
	if nearai.BaseURL != "https://completions.near.ai" {
		t.Errorf("nearai BaseURL default: got %q, want %q", nearai.BaseURL, "https://completions.near.ai")
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

	// Load must succeed — bad permissions are a warning, not a hard error.
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() with world-readable config: unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil config")
	}
}

// --- DefaultEnforced isolation ---

// TestDefaultEnforcedImmutable verifies that modifying the returned cfg.Enforced
// slice does not alter DefaultEnforced.
func TestDefaultEnforcedImmutable(t *testing.T) {
	unsetenv(t, "TEEP_CONFIG")
	unsetenv(t, "TEEP_LISTEN_ADDR")
	unsetenv(t, "VENICE_API_KEY")
	unsetenv(t, "NEARAI_API_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	// Mutate the returned slice.
	cfg.Enforced[0] = "mutated"

	// DefaultEnforced must be unchanged.
	if DefaultEnforced[0] == "mutated" {
		t.Error("mutating cfg.Enforced affected DefaultEnforced; Load must return a copy")
	}
}
