package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/13rac1/teep/internal/attestation"
)

// Version and Commit are set by ldflags at build time.
// When unset (go run, go test), they default to "dev" and "unknown".
var (
	Version = "dev"
	Commit  = "unknown"
)

const tierSelfCheck = "Self-Check: Build Provenance"

const expectedModulePath = "github.com/13rac1/teep"

// selfCheckAllowFail lists self-check factors that are allowed to fail.
var selfCheckAllowFail = map[string]bool{
	"vcs_clean":   true,
	"version_set": true,
	"commit_set":  true,
}

func runSelfCheck(args []string) {
	if len(args) != 0 {
		fmt.Fprintf(os.Stderr, "teep self-check: unexpected arguments: %v\n", args)
		os.Exit(2)
	}
	info, ok := debug.ReadBuildInfo()
	report := buildSelfCheckReport(info, ok)
	fmt.Print(formatReport(report))
	if report.Blocked() {
		os.Exit(1)
	}
}

func runVersion(args []string) {
	if len(args) != 0 {
		fmt.Fprintf(os.Stderr, "teep version: unexpected arguments: %v\n", args)
		os.Exit(2)
	}
	info, ok := debug.ReadBuildInfo()
	goVer := "unknown"
	if ok {
		goVer = info.GoVersion
	}
	rev := Commit
	if ok {
		if r := buildSetting(info, "vcs.revision"); r != "" {
			rev = r
		}
	}
	fmt.Printf("teep %s (%s, %s)\n", Version, shortCommit(rev), goVer)
}

// selfCheckEvaluator evaluates one or more self-check factors.
type selfCheckEvaluator func(info *debug.BuildInfo, ok bool) []attestation.FactorResult

func buildSelfCheckReport(info *debug.BuildInfo, ok bool) *attestation.VerificationReport {
	evaluators := []selfCheckEvaluator{
		evalBuildInfo,
		evalVCSRevision,
		evalVCSClean,
		evalVersionSet,
		evalCommitSet,
		evalModulePath,
		evalGoVersion,
	}

	var factors []attestation.FactorResult
	for _, eval := range evaluators {
		for _, f := range eval(info, ok) {
			f.Enforced = !selfCheckAllowFail[f.Name]
			factors = append(factors, f)
		}
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

	model := Version
	if model == "" {
		model = "dev"
	}

	return &attestation.VerificationReport{
		Title:          "Self-Check Report",
		Provider:       "teep",
		Model:          model,
		Timestamp:      time.Now(),
		Factors:        factors,
		Passed:         passed,
		Failed:         failed,
		Skipped:        skipped,
		EnforcedFailed: enforcedFailed,
		AllowedFailed:  allowedFailed,
		Metadata:       buildSelfCheckMetadata(info, ok),
	}
}

func evalBuildInfo(_ *debug.BuildInfo, ok bool) []attestation.FactorResult {
	if !ok {
		return selfFactor("build_info", attestation.Fail, "debug.ReadBuildInfo() failed")
	}
	return selfFactor("build_info", attestation.Pass, "build info available")
}

func evalVCSRevision(info *debug.BuildInfo, ok bool) []attestation.FactorResult {
	if !ok {
		return selfFactor("vcs_revision", attestation.Fail, "no build info")
	}
	rev := buildSetting(info, "vcs.revision")
	if rev == "" {
		return selfFactor("vcs_revision", attestation.Fail, "not embedded (built with go run?)")
	}
	return selfFactor("vcs_revision", attestation.Pass, "commit "+shortCommit(rev))
}

func evalVCSClean(info *debug.BuildInfo, ok bool) []attestation.FactorResult {
	if !ok {
		return selfFactor("vcs_clean", attestation.Fail, "no build info")
	}
	modified := buildSetting(info, "vcs.modified")
	if modified == "" {
		return selfFactor("vcs_clean", attestation.Skip, "vcs.modified not embedded")
	}
	if modified == "true" {
		return selfFactor("vcs_clean", attestation.Fail, "built from dirty working tree")
	}
	return selfFactor("vcs_clean", attestation.Pass, "clean working tree")
}

func evalVersionSet(_ *debug.BuildInfo, _ bool) []attestation.FactorResult {
	if Version == "dev" || Version == "" {
		return selfFactor("version_set", attestation.Fail, fmt.Sprintf("version is %q (not set via ldflags)", Version))
	}
	return selfFactor("version_set", attestation.Pass, "version "+Version)
}

func evalCommitSet(info *debug.BuildInfo, ok bool) []attestation.FactorResult {
	if Commit == "unknown" || Commit == "" {
		return selfFactor("commit_set", attestation.Fail, fmt.Sprintf("commit is %q (not set via ldflags)", Commit))
	}
	// Cross-check against vcs.revision when available.
	if ok {
		if rev := buildSetting(info, "vcs.revision"); rev != "" && rev != Commit {
			return selfFactor("commit_set", attestation.Fail,
				fmt.Sprintf("ldflags commit %s != vcs.revision %s", shortCommit(Commit), shortCommit(rev)))
		}
	}
	return selfFactor("commit_set", attestation.Pass, "commit "+shortCommit(Commit))
}

func shortCommit(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func evalModulePath(info *debug.BuildInfo, ok bool) []attestation.FactorResult {
	if !ok {
		return selfFactor("module_path", attestation.Fail, "no build info")
	}
	modPath := info.Main.Path
	if modPath != expectedModulePath {
		return selfFactor("module_path", attestation.Fail, fmt.Sprintf("module %q, expected %q", modPath, expectedModulePath))
	}
	return selfFactor("module_path", attestation.Pass, modPath)
}

func evalGoVersion(info *debug.BuildInfo, ok bool) []attestation.FactorResult {
	if !ok {
		return selfFactor("go_version", attestation.Fail, "no build info")
	}
	if info.GoVersion == "" {
		return selfFactor("go_version", attestation.Fail, "Go version not embedded")
	}
	return selfFactor("go_version", attestation.Pass, info.GoVersion)
}

// selfFactor is a convenience constructor for self-check factors.
func selfFactor(name string, status attestation.Status, detail string) []attestation.FactorResult {
	return []attestation.FactorResult{{Tier: tierSelfCheck, Name: name, Status: status, Detail: detail}}
}

// buildSetting looks up a key in the BuildInfo settings.
func buildSetting(info *debug.BuildInfo, key string) string {
	for _, s := range info.Settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}

func buildSelfCheckMetadata(info *debug.BuildInfo, ok bool) map[string]string {
	m := make(map[string]string)
	m["version"] = Version
	m["commit"] = Commit
	if ok && info != nil {
		m["go_version"] = info.GoVersion
		m["module"] = info.Main.Path
		if rev := buildSetting(info, "vcs.revision"); rev != "" {
			m["vcs_revision"] = rev
		}
		if vcsTime := buildSetting(info, "vcs.time"); vcsTime != "" {
			m["vcs_time"] = vcsTime
		}
	}
	if exe, err := os.Executable(); err == nil {
		m["binary"] = exe
	}
	return m
}
