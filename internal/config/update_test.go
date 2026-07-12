package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestUpdateConfigNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")

	obs := ObservedMeasurements{
		MRSeam: strings.Repeat("ab", 48),
		MRTD:   strings.Repeat("cd", 48),
		RTMR0:  strings.Repeat("ef", 48),
	}
	if err := UpdateConfig(path, "venice", &obs); err != nil {
		t.Fatalf("UpdateConfig error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	// Parse back and verify.
	var f updateFile
	if _, err := toml.Decode(string(data), &f); err != nil {
		t.Fatalf("parse output: %v", err)
	}
	prov, ok := f.Providers["venice"]
	if !ok {
		t.Fatal("missing providers.venice")
	}
	if len(prov.Policy.MRSEAMAllow) != 1 || prov.Policy.MRSEAMAllow[0] != obs.MRSeam {
		t.Errorf("mrseam_allow = %v, want [%s]", prov.Policy.MRSEAMAllow, obs.MRSeam)
	}
	if len(prov.Policy.MRTDAllow) != 1 || prov.Policy.MRTDAllow[0] != obs.MRTD {
		t.Errorf("mrtd_allow = %v, want [%s]", prov.Policy.MRTDAllow, obs.MRTD)
	}
	if len(prov.Policy.RTMR0Allow) != 1 || prov.Policy.RTMR0Allow[0] != obs.RTMR0 {
		t.Errorf("rtmr0_allow = %v, want [%s]", prov.Policy.RTMR0Allow, obs.RTMR0)
	}

	// No backup for new file.
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Error("backup should not exist for new file")
	}

	// File permissions.
	info, _ := os.Stat(path)
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file permissions = %o, want 600", perm)
	}
}

func TestUpdateConfigDedup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")

	val := strings.Repeat("ab", 48)
	obs := ObservedMeasurements{MRSeam: val}

	// Write twice with the same value.
	if err := UpdateConfig(path, "venice", &obs); err != nil {
		t.Fatalf("first UpdateConfig: %v", err)
	}
	if err := UpdateConfig(path, "venice", &obs); err != nil {
		t.Fatalf("second UpdateConfig: %v", err)
	}

	data, _ := os.ReadFile(path)
	var f updateFile
	toml.Decode(string(data), &f)
	if len(f.Providers["venice"].Policy.MRSEAMAllow) != 1 {
		t.Errorf("duplicate was not deduplicated: %v", f.Providers["venice"].Policy.MRSEAMAllow)
	}
}

func TestUpdateConfigBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")
	original := []byte("# original config\n[policy]\n")
	os.WriteFile(path, original, 0o600)

	obs := ObservedMeasurements{MRSeam: strings.Repeat("ab", 48)}
	if err := UpdateConfig(path, "venice", &obs); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	backup, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if !bytes.Equal(backup, original) {
		t.Error("backup content does not match original")
	}
}

func TestUpdateConfigPreservesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")
	existing := `[providers.venice]
api_key = "test-key"
base_url = "https://api.venice.ai"
`
	os.WriteFile(path, []byte(existing), 0o600)

	obs := ObservedMeasurements{MRTD: strings.Repeat("cd", 48)}
	if err := UpdateConfig(path, "venice", &obs); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	data, _ := os.ReadFile(path)
	var f updateFile
	toml.Decode(string(data), &f)
	prov := f.Providers["venice"]
	if prov.APIKey != "test-key" {
		t.Errorf("api_key lost: got %q", prov.APIKey)
	}
	if prov.BaseURL != "https://api.venice.ai" {
		t.Errorf("base_url lost: got %q", prov.BaseURL)
	}
	if len(prov.Policy.MRTDAllow) != 1 {
		t.Errorf("mrtd_allow not added: %v", prov.Policy.MRTDAllow)
	}
}

func TestUpdateConfigMultipleProviders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")

	val1 := strings.Repeat("aa", 48)
	val2 := strings.Repeat("bb", 48)

	if err := UpdateConfig(path, "venice", &ObservedMeasurements{MRSeam: val1}); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := UpdateConfig(path, "nanogpt", &ObservedMeasurements{MRSeam: val2}); err != nil {
		t.Fatalf("second: %v", err)
	}

	data, _ := os.ReadFile(path)
	var f updateFile
	toml.Decode(string(data), &f)
	if len(f.Providers) != 2 {
		t.Errorf("expected 2 providers, got %d", len(f.Providers))
	}
	if f.Providers["venice"].Policy.MRSEAMAllow[0] != val1 {
		t.Error("venice mrseam lost")
	}
	if f.Providers["nanogpt"].Policy.MRSEAMAllow[0] != val2 {
		t.Error("nanogpt mrseam lost")
	}
}

func TestUpdateConfigOmitsRTMR3(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")

	val := strings.Repeat("ab", 48)
	obs := ObservedMeasurements{
		RTMR2:        val,
		RTMR3:        val,
		GatewayRTMR2: val,
		GatewayRTMR3: val,
	}
	if err := UpdateConfig(path, "venice", &obs); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	data, _ := os.ReadFile(path)
	var f updateFile
	toml.Decode(string(data), &f)
	prov := f.Providers["venice"]
	if len(prov.Policy.RTMR2Allow) != 1 {
		t.Errorf("rtmr2_allow should have 1 entry, got %d", len(prov.Policy.RTMR2Allow))
	}
	if len(prov.Policy.RTMR3Allow) != 0 {
		t.Error("rtmr3_allow should be empty (RTMR3 is omitted by design)")
	}
	if len(prov.Policy.GatewayRTMR2Allow) != 1 {
		t.Errorf("gateway_rtmr2_allow should have 1 entry, got %d", len(prov.Policy.GatewayRTMR2Allow))
	}
	if len(prov.Policy.GatewayRTMR3Allow) != 0 {
		t.Error("gateway_rtmr3_allow should be empty (gateway RTMR3 is omitted by design)")
	}
}

func TestUpdateConfigPreservesTopLevelAllowFail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")
	existing := `allow_fail = ["tee_quote_present", "tee_boot_config"]

[providers.venice]
base_url = "https://api.venice.ai"
`
	os.WriteFile(path, []byte(existing), 0o600)

	obs := ObservedMeasurements{MRSeam: strings.Repeat("ab", 48)}
	if err := UpdateConfig(path, "venice", &obs); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	data, _ := os.ReadFile(path)
	var f updateFile
	toml.Decode(string(data), &f)
	if f.AllowFail == nil || len(*f.AllowFail) != 2 {
		t.Fatalf("top-level allow_fail lost: got %v", f.AllowFail)
	}
	af := *f.AllowFail
	if af[0] != "tee_quote_present" || af[1] != "tee_boot_config" {
		t.Errorf("top-level allow_fail changed: got %v", af)
	}
}

func TestUpdateConfigPreservesTopLevelMaxConns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")
	existing := `max_conns = 4321

[providers.venice]
base_url = "https://api.venice.ai"
`
	os.WriteFile(path, []byte(existing), 0o600)

	obs := ObservedMeasurements{MRSeam: strings.Repeat("ab", 48)}
	if err := UpdateConfig(path, "venice", &obs); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	data, _ := os.ReadFile(path)
	var f updateFile
	toml.Decode(string(data), &f)
	if f.MaxConns != 4321 {
		t.Fatalf("top-level max_conns lost/changed: got %d, want 4321", f.MaxConns)
	}
}

// TestUpdateConfigAbsentMaxConnsStaysAbsent is a regression test: the
// BurntSushi/toml encoder's "omitempty" does not treat a zero int as empty
// (only "omitzero" does), so an unset max_conns was previously always
// rewritten back as the literal `max_conns = 0`, which then failed strict
// validation on the next Load() ("max_conns must be a positive integer, got
// 0") — every --update-config invocation on a config without an explicit
// max_conns broke the next startup.
func TestUpdateConfigAbsentMaxConnsStaysAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")
	existing := "[providers.venice]\nbase_url = \"https://api.venice.ai\"\n"
	os.WriteFile(path, []byte(existing), 0o600)

	obs := ObservedMeasurements{MRSeam: strings.Repeat("ab", 48)}
	if err := UpdateConfig(path, "venice", &obs); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if strings.Contains(string(data), "max_conns") {
		t.Fatalf("max_conns should stay absent when never set; got:\n%s", data)
	}

	// The rewritten file must still load successfully.
	setenv(t, "TEEP_CONFIG", path)
	clearProviderEnv(t)
	if _, err := Load(); err != nil {
		t.Fatalf("Load() after update: %v", err)
	}
}

func TestUpdateConfigPreservesPerProviderAllowFail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")
	existing := `[providers.venice]
base_url = "https://api.venice.ai"
allow_fail = ["cpu_gpu_chain", "measured_model_weights"]
`
	os.WriteFile(path, []byte(existing), 0o600)

	obs := ObservedMeasurements{MRTD: strings.Repeat("cd", 48)}
	if err := UpdateConfig(path, "venice", &obs); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	data, _ := os.ReadFile(path)
	var f updateFile
	toml.Decode(string(data), &f)
	prov := f.Providers["venice"]
	if prov.AllowFail == nil || len(*prov.AllowFail) != 2 {
		t.Fatalf("per-provider allow_fail lost: got %v", prov.AllowFail)
	}
	af := *prov.AllowFail
	if af[0] != "cpu_gpu_chain" || af[1] != "measured_model_weights" {
		t.Errorf("per-provider allow_fail changed: got %v", af)
	}
}

func TestUpdateConfigCreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "subdir", "teep.toml")

	obs := ObservedMeasurements{MRSeam: strings.Repeat("ab", 48)}
	if err := UpdateConfig(path, "venice", &obs); err != nil {
		t.Fatalf("UpdateConfig error: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("config file not created: %v", err)
	}

	// Verify parent directory permissions.
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("parent dir stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("parent dir permissions = %o, want 700", perm)
	}
}

// TestUpdateConfigEmptyPath verifies that UpdateConfig with empty path writes
// TOML to stdout (used by the --dry-run / no-file workflow).
func TestUpdateConfigEmptyPath(t *testing.T) {
	// Capture stdout so the TOML output doesn't pollute test logs.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w

	obs := ObservedMeasurements{MRSeam: strings.Repeat("ab", 48)}
	updateErr := UpdateConfig("", "venice", &obs)

	w.Close()
	os.Stdout = orig

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	r.Close()

	t.Logf("UpdateConfig(empty path) error: %v", updateErr)
	t.Logf("stdout: %s", buf.String())
	if updateErr != nil {
		t.Errorf("UpdateConfig with empty path returned error: %v", updateErr)
	}
	if !strings.Contains(buf.String(), "mrseam_allow") {
		t.Error("expected TOML output to contain mrseam_allow")
	}
}

// --- allow_fail absent-vs-empty round-trip matrix ---
//
// These are regression tests for the finding that --update-config silently
// dropped an explicitly-empty `allow_fail = []` (meaning "enforce ALL
// factors") because the update structs used []string + omitempty, which
// cannot distinguish "absent" from "empty". A dropped key downgrades the
// user to the weaker Go-default allow_fail lists on next update.

// captureStderr redirects os.Stderr for the duration of fn and returns
// whatever was written to it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w

	fn()

	w.Close()
	os.Stderr = orig

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	r.Close()
	return buf.String()
}

func TestUpdateConfigRoundTripsEmptyTopLevelAllowFail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")
	original := "allow_fail = []\n\n[providers.venice]\nbase_url = \"https://api.venice.ai\"\n"
	os.WriteFile(path, []byte(original), 0o600)

	obs := ObservedMeasurements{MRSeam: strings.Repeat("ab", 48)}
	if err := UpdateConfig(path, "venice", &obs); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(data), "allow_fail = []") {
		t.Fatalf("explicit empty top-level allow_fail was not preserved verbatim; got:\n%s", data)
	}

	// Reload through the strict Load() path and confirm "enforce all" holds:
	// GlobalAllowFailDefined is true and MergedAllowFail returns an empty
	// list rather than falling back to Go defaults.
	setenv(t, "TEEP_CONFIG", path)
	clearProviderEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() after update: %v", err)
	}
	if !cfg.GlobalAllowFailDefined {
		t.Error("GlobalAllowFailDefined = false, want true (explicit empty allow_fail)")
	}
	if af := MergedAllowFail("venice", cfg, false); len(af) != 0 {
		t.Errorf("MergedAllowFail(venice) = %v, want empty (enforce all)", af)
	}
}

func TestUpdateConfigRoundTripsEmptyProviderAllowFail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")
	original := "[providers.venice]\nbase_url = \"https://api.venice.ai\"\nallow_fail = []\n"
	os.WriteFile(path, []byte(original), 0o600)

	obs := ObservedMeasurements{MRTD: strings.Repeat("cd", 48)}
	if err := UpdateConfig(path, "venice", &obs); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(data), "allow_fail = []") {
		t.Fatalf("explicit empty per-provider allow_fail was not preserved verbatim; got:\n%s", data)
	}

	setenv(t, "TEEP_CONFIG", path)
	clearProviderEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() after update: %v", err)
	}
	if af, ok := cfg.ProviderAllowFail["venice"]; !ok || len(af) != 0 {
		t.Errorf("ProviderAllowFail[venice] = %v (ok=%v), want empty slice defined", af, ok)
	}
	if af := MergedAllowFail("venice", cfg, false); len(af) != 0 {
		t.Errorf("MergedAllowFail(venice) = %v, want empty (enforce all)", af)
	}
}

func TestUpdateConfigRoundTripsEmptyPolicyAllowFail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")
	original := "[policy]\nallow_fail = []\n\n[providers.venice]\nbase_url = \"https://api.venice.ai\"\n"
	os.WriteFile(path, []byte(original), 0o600)

	obs := ObservedMeasurements{MRSeam: strings.Repeat("ab", 48)}
	if err := UpdateConfig(path, "venice", &obs); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(data), "allow_fail = []") {
		t.Fatalf("explicit empty [policy] allow_fail was not preserved verbatim; got:\n%s", data)
	}

	setenv(t, "TEEP_CONFIG", path)
	clearProviderEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() after update: %v", err)
	}
	if !cfg.GlobalAllowFailDefined {
		t.Error("GlobalAllowFailDefined = false, want true ([policy].allow_fail = [] is explicit)")
	}
	if af := MergedAllowFail("venice", cfg, false); len(af) != 0 {
		t.Errorf("MergedAllowFail(venice) = %v, want empty (enforce all)", af)
	}
}

func TestUpdateConfigAbsentAllowFailStaysAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")
	original := "[providers.venice]\nbase_url = \"https://api.venice.ai\"\n"
	os.WriteFile(path, []byte(original), 0o600)

	obs := ObservedMeasurements{MRSeam: strings.Repeat("ab", 48)}
	if err := UpdateConfig(path, "venice", &obs); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if strings.Contains(string(data), "allow_fail") {
		t.Fatalf("allow_fail should stay absent when never set; got:\n%s", data)
	}

	setenv(t, "TEEP_CONFIG", path)
	clearProviderEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() after update: %v", err)
	}
	if cfg.GlobalAllowFailDefined {
		t.Error("GlobalAllowFailDefined = true, want false (allow_fail was never set)")
	}
	if cfg.AllowFail != nil {
		t.Errorf("AllowFail = %v, want nil", cfg.AllowFail)
	}
	if _, ok := cfg.ProviderAllowFail["venice"]; ok {
		t.Error("ProviderAllowFail[venice] should not be defined")
	}
	// Go defaults (not empty) should apply.
	if af := MergedAllowFail("venice", cfg, false); len(af) == 0 {
		t.Error("MergedAllowFail(venice) = empty, want Go defaults to apply (allow_fail was never set)")
	}
}

func TestUpdateConfigUnknownKeyRefusesRewrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")
	original := "[providers.venice]\nbase_url = \"https://api.venice.ai\"\nbogus_future_field = \"x\"\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	obs := ObservedMeasurements{MRSeam: strings.Repeat("ab", 48)}
	err := UpdateConfig(path, "venice", &obs)
	if err == nil {
		t.Fatal("expected error for unknown config key, got nil")
	}
	if !strings.Contains(err.Error(), "bogus_future_field") {
		t.Errorf("error should name the unknown key: %v", err)
	}

	// File must be untouched and no backup created.
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("read config after failed update: %v", rerr)
	}
	if string(data) != original {
		t.Errorf("config file was modified despite refusal:\ngot:  %q\nwant: %q", data, original)
	}
	if _, statErr := os.Stat(path + ".bak"); !os.IsNotExist(statErr) {
		t.Error(".bak should not be created when the update refuses to proceed")
	}
}

func TestUpdateConfigCommentsTriggerNotice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")
	original := "# my hand-tuned config, do not lose these notes\n" +
		"[providers.venice]\n" +
		"base_url = \"https://api.venice.ai\" # pinned endpoint\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	obs := ObservedMeasurements{MRSeam: strings.Repeat("ab", 48)}
	var updateErr error
	stderr := captureStderr(t, func() {
		updateErr = UpdateConfig(path, "venice", &obs)
	})
	if updateErr != nil {
		t.Fatalf("UpdateConfig: %v", updateErr)
	}

	if !strings.Contains(stderr, "comments") {
		t.Errorf("expected a loud notice about lost comments on stderr, got: %q", stderr)
	}
	if !strings.Contains(stderr, path+".bak") {
		t.Errorf("expected notice to mention the .bak path, got: %q", stderr)
	}

	backup, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if !bytes.Equal(backup, []byte(original)) {
		t.Error(".bak should contain the original file, comments included")
	}
	if !strings.Contains(string(backup), "#") {
		t.Error(".bak should retain the comments")
	}
}

func TestUpdateConfigNoCommentsNoNotice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")
	original := "[providers.venice]\nbase_url = \"https://api.venice.ai\"\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	obs := ObservedMeasurements{MRSeam: strings.Repeat("ab", 48)}
	var updateErr error
	stderr := captureStderr(t, func() {
		updateErr = UpdateConfig(path, "venice", &obs)
	})
	if updateErr != nil {
		t.Fatalf("UpdateConfig: %v", updateErr)
	}
	if strings.Contains(stderr, "comments") {
		t.Errorf("did not expect a comment-loss notice for a config without comments, got: %q", stderr)
	}
}

func TestUpdateConfigCommentInStringValueNotMistakenForComment(t *testing.T) {
	// A literal '#' inside a quoted value (e.g. part of an API key or URL
	// fragment) must not be mistaken for a TOML comment.
	dir := t.TempDir()
	path := filepath.Join(dir, "teep.toml")
	original := "[providers.venice]\napi_key = \"has#hash-but-not-a-comment\"\n" +
		"base_url = \"https://api.venice.ai\"\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	obs := ObservedMeasurements{MRSeam: strings.Repeat("ab", 48)}
	var updateErr error
	stderr := captureStderr(t, func() {
		updateErr = UpdateConfig(path, "venice", &obs)
	})
	if updateErr != nil {
		t.Fatalf("UpdateConfig: %v", updateErr)
	}
	if strings.Contains(stderr, "comments") {
		t.Errorf("a '#' inside a quoted string should not trigger the comment-loss notice, got: %q", stderr)
	}
}
