package main

import (
	"runtime/debug"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
)

// testBuildInfo returns a debug.BuildInfo with controlled settings for testing.
func testBuildInfo(goVersion, modulePath string, settings ...debug.BuildSetting) *debug.BuildInfo {
	return &debug.BuildInfo{
		GoVersion: goVersion,
		Path:      modulePath + "/cmd/teep",
		Main:      debug.Module{Path: modulePath},
		Settings:  settings,
	}
}

func cleanBuildInfo() *debug.BuildInfo {
	return testBuildInfo("go1.25.0", expectedModulePath,
		debug.BuildSetting{Key: "vcs.revision", Value: "abc123def456789"},
		debug.BuildSetting{Key: "vcs.modified", Value: "false"},
		debug.BuildSetting{Key: "vcs.time", Value: "2026-03-31T12:00:00Z"},
	)
}

// --------------------------------------------------------------------------
// buildSetting helper
// --------------------------------------------------------------------------

func TestBuildSetting(t *testing.T) {
	info := testBuildInfo("go1.25.0", "test",
		debug.BuildSetting{Key: "vcs.revision", Value: "abc123"},
		debug.BuildSetting{Key: "vcs.modified", Value: "false"},
	)

	if got := buildSetting(info, "vcs.revision"); got != "abc123" {
		t.Errorf("buildSetting(vcs.revision) = %q, want %q", got, "abc123")
	}
	if got := buildSetting(info, "vcs.modified"); got != "false" {
		t.Errorf("buildSetting(vcs.modified) = %q, want %q", got, "false")
	}
	if got := buildSetting(info, "nonexistent"); got != "" {
		t.Errorf("buildSetting(nonexistent) = %q, want empty", got)
	}
}

// --------------------------------------------------------------------------
// Individual evaluator tests
// --------------------------------------------------------------------------

func TestEvalBuildInfo_Pass(t *testing.T) {
	factors := evalBuildInfo(cleanBuildInfo(), true)
	if len(factors) != 1 {
		t.Fatalf("expected 1 factor, got %d", len(factors))
	}
	if factors[0].Status != attestation.Pass {
		t.Errorf("status = %v, want Pass", factors[0].Status)
	}
}

func TestEvalBuildInfo_Fail(t *testing.T) {
	factors := evalBuildInfo(nil, false)
	if len(factors) != 1 {
		t.Fatalf("expected 1 factor, got %d", len(factors))
	}
	if factors[0].Status != attestation.Fail {
		t.Errorf("status = %v, want Fail", factors[0].Status)
	}
}

func TestEvalVCSRevision_Pass(t *testing.T) {
	factors := evalVCSRevision(cleanBuildInfo(), true)
	if factors[0].Status != attestation.Pass {
		t.Errorf("status = %v, want Pass", factors[0].Status)
	}
	if !strings.Contains(factors[0].Detail, "commit abc123def456") {
		t.Errorf("detail = %q, want truncated commit", factors[0].Detail)
	}
}

func TestEvalVCSRevision_NoInfo(t *testing.T) {
	factors := evalVCSRevision(nil, false)
	if factors[0].Status != attestation.Fail {
		t.Errorf("status = %v, want Fail", factors[0].Status)
	}
}

func TestEvalVCSRevision_Empty(t *testing.T) {
	info := testBuildInfo("go1.25.0", expectedModulePath)
	factors := evalVCSRevision(info, true)
	if factors[0].Status != attestation.Fail {
		t.Errorf("status = %v, want Fail", factors[0].Status)
	}
	if !strings.Contains(factors[0].Detail, "go run") {
		t.Errorf("detail = %q, want mention of go run", factors[0].Detail)
	}
}

func TestEvalVCSClean_Pass(t *testing.T) {
	factors := evalVCSClean(cleanBuildInfo(), true)
	if factors[0].Status != attestation.Pass {
		t.Errorf("status = %v, want Pass", factors[0].Status)
	}
}

func TestEvalVCSClean_Dirty(t *testing.T) {
	info := testBuildInfo("go1.25.0", expectedModulePath,
		debug.BuildSetting{Key: "vcs.modified", Value: "true"},
	)
	factors := evalVCSClean(info, true)
	if factors[0].Status != attestation.Fail {
		t.Errorf("status = %v, want Fail", factors[0].Status)
	}
	if !strings.Contains(factors[0].Detail, "dirty") {
		t.Errorf("detail = %q, want mention of dirty", factors[0].Detail)
	}
}

func TestEvalVCSClean_NoSetting(t *testing.T) {
	info := testBuildInfo("go1.25.0", expectedModulePath)
	factors := evalVCSClean(info, true)
	if factors[0].Status != attestation.Skip {
		t.Errorf("status = %v, want Skip", factors[0].Status)
	}
}

func TestEvalVersionSet_Pass(t *testing.T) {
	orig := Version
	Version = "v0.3.0-dirty"
	defer func() { Version = orig }()

	factors := evalVersionSet(nil, false)
	if factors[0].Status != attestation.Pass {
		t.Errorf("status = %v, want Pass", factors[0].Status)
	}
}

func TestEvalVersionSet_Dev(t *testing.T) {
	orig := Version
	Version = "dev"
	defer func() { Version = orig }()

	factors := evalVersionSet(nil, false)
	if factors[0].Status != attestation.Fail {
		t.Errorf("status = %v, want Fail", factors[0].Status)
	}
}

func TestEvalVersionSet_Empty(t *testing.T) {
	orig := Version
	Version = ""
	defer func() { Version = orig }()

	factors := evalVersionSet(nil, false)
	if factors[0].Status != attestation.Fail {
		t.Errorf("status = %v, want Fail", factors[0].Status)
	}
}

func TestEvalCommitSet_Pass(t *testing.T) {
	orig := Commit
	Commit = "abc123def456789"
	defer func() { Commit = orig }()

	info := cleanBuildInfo()
	factors := evalCommitSet(info, true)
	t.Logf("commit_set pass: %v %q", factors[0].Status, factors[0].Detail)
	if factors[0].Status != attestation.Pass {
		t.Errorf("status = %v, want Pass", factors[0].Status)
	}
}

func TestEvalCommitSet_Unknown(t *testing.T) {
	orig := Commit
	Commit = "unknown"
	defer func() { Commit = orig }()

	factors := evalCommitSet(nil, false)
	t.Logf("commit_set unknown: %v %q", factors[0].Status, factors[0].Detail)
	if factors[0].Status != attestation.Fail {
		t.Errorf("status = %v, want Fail", factors[0].Status)
	}
}

func TestEvalCommitSet_Empty(t *testing.T) {
	orig := Commit
	Commit = ""
	defer func() { Commit = orig }()

	factors := evalCommitSet(nil, false)
	t.Logf("commit_set empty: %v %q", factors[0].Status, factors[0].Detail)
	if factors[0].Status != attestation.Fail {
		t.Errorf("status = %v, want Fail", factors[0].Status)
	}
}

func TestEvalCommitSet_Mismatch(t *testing.T) {
	orig := Commit
	Commit = "stale1234567890"
	defer func() { Commit = orig }()

	info := cleanBuildInfo()
	factors := evalCommitSet(info, true)
	t.Logf("commit_set mismatch: %v %q", factors[0].Status, factors[0].Detail)
	if factors[0].Status != attestation.Fail {
		t.Errorf("status = %v, want Fail", factors[0].Status)
	}
	if !strings.Contains(factors[0].Detail, "!=") {
		t.Errorf("detail should show mismatch: %q", factors[0].Detail)
	}
}

func TestEvalCommitSet_NoVCSRevision(t *testing.T) {
	orig := Commit
	Commit = "abc123def456789"
	defer func() { Commit = orig }()

	// BuildInfo with no vcs.revision — cross-check is skipped, should still pass.
	info := testBuildInfo("go1.25.0", expectedModulePath)
	factors := evalCommitSet(info, true)
	t.Logf("commit_set no vcs.revision: %v %q", factors[0].Status, factors[0].Detail)
	if factors[0].Status != attestation.Pass {
		t.Errorf("status = %v, want Pass", factors[0].Status)
	}
}

func TestEvalModulePath_Pass(t *testing.T) {
	factors := evalModulePath(cleanBuildInfo(), true)
	if factors[0].Status != attestation.Pass {
		t.Errorf("status = %v, want Pass", factors[0].Status)
	}
}

func TestEvalModulePath_Wrong(t *testing.T) {
	info := testBuildInfo("go1.25.0", "github.com/wrong/module")
	factors := evalModulePath(info, true)
	if factors[0].Status != attestation.Fail {
		t.Errorf("status = %v, want Fail", factors[0].Status)
	}
	if !strings.Contains(factors[0].Detail, "wrong/module") {
		t.Errorf("detail = %q, want actual module path", factors[0].Detail)
	}
}

func TestEvalModulePath_NoInfo(t *testing.T) {
	factors := evalModulePath(nil, false)
	if factors[0].Status != attestation.Fail {
		t.Errorf("status = %v, want Fail", factors[0].Status)
	}
}

func TestEvalGoVersion_Pass(t *testing.T) {
	factors := evalGoVersion(cleanBuildInfo(), true)
	if factors[0].Status != attestation.Pass {
		t.Errorf("status = %v, want Pass", factors[0].Status)
	}
	if factors[0].Detail != "go1.25.0" {
		t.Errorf("detail = %q, want go1.25.0", factors[0].Detail)
	}
}

func TestEvalGoVersion_Empty(t *testing.T) {
	info := testBuildInfo("", expectedModulePath)
	factors := evalGoVersion(info, true)
	if factors[0].Status != attestation.Fail {
		t.Errorf("status = %v, want Fail", factors[0].Status)
	}
}

func TestEvalGoVersion_NoInfo(t *testing.T) {
	factors := evalGoVersion(nil, false)
	if factors[0].Status != attestation.Fail {
		t.Errorf("status = %v, want Fail", factors[0].Status)
	}
}

// --------------------------------------------------------------------------
// selfFactor helper
// --------------------------------------------------------------------------

func TestSelfFactor(t *testing.T) {
	factors := selfFactor("test_name", attestation.Pass, "test detail")
	if len(factors) != 1 {
		t.Fatalf("expected 1 factor, got %d", len(factors))
	}
	f := factors[0]
	if f.Tier != tierSelfCheck {
		t.Errorf("tier = %q, want %q", f.Tier, tierSelfCheck)
	}
	if f.Name != "test_name" {
		t.Errorf("name = %q, want test_name", f.Name)
	}
	if f.Status != attestation.Pass {
		t.Errorf("status = %v, want Pass", f.Status)
	}
	if f.Detail != "test detail" {
		t.Errorf("detail = %q, want test detail", f.Detail)
	}
}

// --------------------------------------------------------------------------
// buildSelfCheckReport
// --------------------------------------------------------------------------

func TestBuildSelfCheckReport_AllPass(t *testing.T) {
	orig := Version
	Version = "v0.3.0"
	defer func() { Version = orig }()

	origCommit := Commit
	Commit = "abc123def456789"
	defer func() { Commit = origCommit }()

	report := buildSelfCheckReport(cleanBuildInfo(), true)

	if report.Title != "Self-Check Report" {
		t.Errorf("title = %q, want Self-Check Report", report.Title)
	}
	if report.Provider != "teep" {
		t.Errorf("provider = %q, want teep", report.Provider)
	}
	if report.Model != "v0.3.0" {
		t.Errorf("model = %q, want v0.3.0", report.Model)
	}
	if report.Passed != 7 {
		t.Errorf("passed = %d, want 7", report.Passed)
	}
	if report.Failed != 0 {
		t.Errorf("failed = %d, want 0", report.Failed)
	}
	if report.Blocked() {
		t.Error("report is blocked, want not blocked")
	}
}

func TestBuildSelfCheckReport_NoBuildInfo(t *testing.T) {
	report := buildSelfCheckReport(nil, false)

	// build_info, vcs_revision, module_path, go_version are enforced and should fail.
	if report.EnforcedFailed < 4 {
		t.Errorf("enforced_failed = %d, want >= 4", report.EnforcedFailed)
	}
	if !report.Blocked() {
		t.Error("report is not blocked, want blocked")
	}
}

func TestBuildSelfCheckReport_DirtyNotBlocking(t *testing.T) {
	info := testBuildInfo("go1.25.0", expectedModulePath,
		debug.BuildSetting{Key: "vcs.revision", Value: "abc123def456789"},
		debug.BuildSetting{Key: "vcs.modified", Value: "true"},
		debug.BuildSetting{Key: "vcs.time", Value: "2026-03-31T12:00:00Z"},
	)

	orig := Version
	Version = "v0.3.0"
	defer func() { Version = orig }()

	origCommit := Commit
	Commit = "abc123def456789"
	defer func() { Commit = origCommit }()

	report := buildSelfCheckReport(info, true)

	// vcs_clean should fail but is allowed, so not blocking.
	if report.Blocked() {
		t.Error("dirty tree should not block (vcs_clean is allowed)")
	}
	if report.AllowedFailed != 1 {
		t.Errorf("allowed_failed = %d, want 1", report.AllowedFailed)
	}
}

func TestBuildSelfCheckReport_DevVersionNotBlocking(t *testing.T) {
	orig := Version
	Version = "dev"
	defer func() { Version = orig }()

	report := buildSelfCheckReport(cleanBuildInfo(), true)

	// version_set and commit_set should fail but are allowed.
	if report.Blocked() {
		t.Error("dev version should not block (version_set and commit_set are allowed)")
	}
	if report.AllowedFailed != 2 {
		t.Errorf("allowed_failed = %d, want 2", report.AllowedFailed)
	}
}

// --------------------------------------------------------------------------
// Metadata
// --------------------------------------------------------------------------

func TestBuildSelfCheckMetadata(t *testing.T) {
	orig := Version
	Version = "v0.3.0"
	defer func() { Version = orig }()

	info := cleanBuildInfo()
	meta := buildSelfCheckMetadata(info, true)

	if meta["version"] != "v0.3.0" {
		t.Errorf("version = %q, want v0.3.0", meta["version"])
	}
	if meta["go_version"] != "go1.25.0" {
		t.Errorf("go_version = %q, want go1.25.0", meta["go_version"])
	}
	if meta["module"] != expectedModulePath {
		t.Errorf("module = %q, want %q", meta["module"], expectedModulePath)
	}
	if meta["vcs_revision"] != "abc123def456789" {
		t.Errorf("vcs_revision = %q, want abc123def456789", meta["vcs_revision"])
	}
	if meta["vcs_time"] != "2026-03-31T12:00:00Z" {
		t.Errorf("vcs_time = %q, want 2026-03-31T12:00:00Z", meta["vcs_time"])
	}
	if meta["binary"] == "" {
		t.Error("binary path should be set")
	}
}

func TestBuildSelfCheckMetadata_NoInfo(t *testing.T) {
	meta := buildSelfCheckMetadata(nil, false)

	if meta["version"] == "" {
		t.Error("version should always be set")
	}
	if _, ok := meta["go_version"]; ok {
		t.Error("go_version should not be set when no build info")
	}
}

// --------------------------------------------------------------------------
// formatReport with self-check Title
// --------------------------------------------------------------------------

func TestFormatReport_SelfCheckTitle(t *testing.T) {
	orig := Version
	Version = "v0.3.0"
	defer func() { Version = orig }()

	report := buildSelfCheckReport(cleanBuildInfo(), true)
	out := formatReport(report)

	if !strings.Contains(out, "Self-Check Report: teep / v0.3.0") {
		t.Errorf("header not found; output:\n%s", out)
	}
	if strings.Contains(out, "Attestation Report") {
		t.Errorf("should not contain Attestation Report; output:\n%s", out)
	}
}

func TestFormatReport_SelfCheckMetadata(t *testing.T) {
	orig := Version
	Version = "v0.3.0"
	defer func() { Version = orig }()

	report := buildSelfCheckReport(cleanBuildInfo(), true)
	out := formatReport(report)

	if !strings.Contains(out, "Version:") {
		t.Errorf("metadata block should contain Version; output:\n%s", out)
	}
	if !strings.Contains(out, "Go version:") {
		t.Errorf("metadata block should contain Go version; output:\n%s", out)
	}
	if !strings.Contains(out, "Module:") {
		t.Errorf("metadata block should contain Module; output:\n%s", out)
	}
}

func TestFormatReport_SelfCheckFactors(t *testing.T) {
	orig := Version
	Version = "v0.3.0"
	defer func() { Version = orig }()

	report := buildSelfCheckReport(cleanBuildInfo(), true)
	out := formatReport(report)

	expectedFactors := []string{"build_info", "vcs_revision", "vcs_clean", "version_set", "commit_set", "module_path", "go_version"}
	for _, name := range expectedFactors {
		if !strings.Contains(out, name) {
			t.Errorf("output should contain factor %q; output:\n%s", name, out)
		}
	}

	if !strings.Contains(out, "Self-Check: Build Provenance") {
		t.Errorf("output should contain tier name; output:\n%s", out)
	}
}

func TestFormatReport_DefaultTitleUnchanged(t *testing.T) {
	r := buildTestReport("venice", "e2ee-qwen3")
	out := formatReport(r)

	if !strings.Contains(out, "Attestation Report: venice / e2ee-qwen3") {
		t.Errorf("default title should be Attestation Report; output:\n%s", out)
	}
}
