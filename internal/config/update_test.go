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
	if prov.Policy.WarnMeasurements {
		t.Error("warn_measurements should be false after update")
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
