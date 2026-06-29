package integration

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/config"
)

// fixtureEnv holds shared state for a fixture integration test.
type fixtureEnv struct {
	manifest capture.Manifest
	entries  []capture.RecordedEntry
	client   *http.Client
	nonce    attestation.Nonce
}

// loadFixture finds the latest fixture for the given provider prefix,
// loads it, parses the nonce, sets up a replay HTTP client, and swaps
// in the TDX collateral getter.
func loadFixture(t *testing.T, prefix string) fixtureEnv {
	t.Helper()
	fdir := findFixtureDir(t, prefix)

	manifest, entries, err := capture.Load(fdir)
	if err != nil {
		t.Fatalf("load capture: %v", err)
	}
	t.Logf("fixture: %s (%d entries, captured %s)",
		fdir, len(entries), manifest.CapturedAt.Format(time.RFC3339))

	nonce, err := attestation.ParseNonce(manifest.NonceHex)
	if err != nil {
		t.Fatalf("parse nonce: %v", err)
	}

	// Fixtures may include an NRAS JWT from Proof-of-Cloud replay traffic.
	// This token is attestation evidence tied to the captured quote hash/nonce,
	// not a reusable API credential for model inference.
	client := &http.Client{Transport: capture.NewReplayTransport(entries)}

	return fixtureEnv{manifest: manifest, entries: entries, client: client, nonce: nonce}
}

func fixtureVerificationTime(env *fixtureEnv) time.Time {
	if env == nil {
		return time.Time{}
	}
	if env.manifest.CapturedAt.IsZero() {
		return time.Time{}
	}
	if env.manifest.DurationMS <= 0 {
		return env.manifest.CapturedAt
	}
	return env.manifest.CapturedAt.Add(time.Duration(env.manifest.DurationMS) * time.Millisecond)
}

// findFixtureDir returns the newest captured testdata directory matching the
// given provider prefix (e.g. "venice", "neardirect", "nearcloud").
func findFixtureDir(t *testing.T, prefix string) string {
	t.Helper()
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	var latest string
	var latestCapturedAt time.Time
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), prefix+"_") {
			continue
		}
		dir := filepath.Join("testdata", e.Name())
		manifest, _, err := capture.Load(dir)
		if err != nil {
			t.Fatalf("load fixture manifest %s: %v", dir, err)
		}
		if latest == "" || manifest.CapturedAt.After(latestCapturedAt) {
			latest = e.Name()
			latestCapturedAt = manifest.CapturedAt
		}
	}
	if latest == "" {
		t.Skipf("no %s fixture in testdata/; run: teep verify %s --capture testdata/", prefix, prefix)
	}
	return filepath.Join("testdata", latest)
}

func serveAllowFail(providerName string) []string {
	return config.MergedAllowFail(providerName, &config.Config{}, false)
}

func fixtureE2EEResult(o *capture.E2EEOutcome) *attestation.E2EETestResult {
	if o == nil {
		return nil
	}
	result := &attestation.E2EETestResult{
		Attempted: o.Attempted,
		NoAPIKey:  o.NoAPIKey,
		APIKeyEnv: o.APIKeyEnv,
		Detail:    o.Detail,
		KeyType:   o.KeyType,
	}
	if o.Failed {
		msg := o.ErrMsg
		if msg == "" {
			msg = "(error message lost across capture boundary)"
		}
		result.Err = errors.New(msg)
	}
	return result
}

// --- Assertion helpers ---

func assertMustPass(t *testing.T, r *attestation.VerificationReport, names []string) {
	t.Helper()
	for _, name := range names {
		f := findFactor(t, r, name)
		if f.Status != attestation.Pass {
			t.Errorf("factor %s: got %s, want Pass (detail: %s)", name, f.Status, f.Detail)
		}
	}
}

func assertMustFail(t *testing.T, r *attestation.VerificationReport, names []string, reason string) {
	t.Helper()
	for _, name := range names {
		f := findFactor(t, r, name)
		if f.Status != attestation.Fail {
			t.Errorf("factor %s: got %s, want Fail (%s)", name, f.Status, reason)
		}
	}
}

func assertFactorStatus(t *testing.T, r *attestation.VerificationReport, name string, want attestation.Status) {
	t.Helper()
	f := findFactor(t, r, name)
	if f.Status != want {
		t.Errorf("factor %s: got %s, want %s (detail: %s)", name, f.Status, want, f.Detail)
	}
}

func logFactorStatus(t *testing.T, r *attestation.VerificationReport, names ...string) {
	t.Helper()
	for _, name := range names {
		f := findFactor(t, r, name)
		t.Logf("%s: %s (%s)%s", name, f.Status, f.Detail, factorPolicySuffix(f))
	}
}

// commonModelAssertions checks factors shared across all providers:
// time-sensitive crypto factors (hard-asserted, not warn-only),
// not-implemented factors, and PoC status.
func commonModelAssertions(t *testing.T, r *attestation.VerificationReport) {
	t.Helper()

	// Time-sensitive crypto factors — must pass on fresh fixtures.
	// Previously warn-only (t.Logf); now hard-asserted per AGENTS.md fail-closed policy.
	assertMustPass(t, r, []string{
		"tee_cert_chain",
		"tee_quote_signature",
		"intel_pcs_collateral",
		"tee_tcb_current",
		"tee_tcb_not_revoked",
		"nvidia_signature",
		"nvidia_claims",
		"nvidia_nras_verified",
	})

	// Not implemented — expected fail.
	assertMustFail(t, r, []string{"cpu_gpu_chain", "measured_model_weights"}, "not implemented")

	// Allow-fail factors — log for visibility.
	logFactorStatus(t, r,
		"cpu_id_registry",
		"tee_hardware_config",
		"tee_boot_config",
	)
}

// assertRekorExercised verifies the Sigstore/Rekor supply chain paths
// were actually exercised and not silently skipped.
func assertRekorExercised(t *testing.T, sigstore []attestation.SigstoreResult, rekor []attestation.RekorProvenance) {
	t.Helper()
	if len(sigstore) == 0 {
		t.Errorf("sigstore: no digests checked; supply chain verification not exercised")
		return
	}
	var okCount int
	for _, sr := range sigstore {
		if sr.OK {
			okCount++
		}
	}
	if okCount == 0 {
		t.Errorf("sigstore: %d digests checked but none found in transparency log", len(sigstore))
		return
	}
	if len(rekor) == 0 {
		t.Errorf("rekor: %d sigstore entries verified but no provenance fetched", okCount)
	}
}

func total(r *attestation.VerificationReport) int {
	return r.Passed + r.Failed + r.Skipped
}

func logReportScore(t *testing.T, report *attestation.VerificationReport) {
	t.Helper()

	msg := "Score: %d/%d passed, %d skipped, %d failed"
	args := []any{report.Passed, total(report), report.Skipped, report.Failed}
	if report.Failed > 0 {
		msg += " (%d enforced, %d allowed)"
		args = append(args, report.EnforcedFailed, report.AllowedFailed)
	}
	if report.NotApplicableCount > 0 {
		msg += ", %d n/a"
		args = append(args, report.NotApplicableCount)
	}
	t.Logf(msg, args...)
}

func logReportResult(t *testing.T, report *attestation.VerificationReport) {
	t.Helper()

	logReportScore(t, report)
	t.Logf("RESULT: %d/%d factors passed", report.Passed, total(report))
	assertNoEnforcedFailures(t, report)
}

func assertNoEnforcedFailures(t *testing.T, report *attestation.VerificationReport) {
	t.Helper()

	blocked := report.BlockedFactors()
	if len(blocked) == 0 {
		return
	}
	for _, f := range blocked {
		t.Errorf("enforced factor failed: %s: %s", f.Name, f.Detail)
	}
}

func logReportFactors(t *testing.T, report *attestation.VerificationReport) {
	t.Helper()
	for _, f := range report.Factors {
		t.Logf("  [%s] %s: %s%s", f.Status, f.Name, f.Detail, factorPolicySuffix(f))
	}
}

func factorPolicySuffix(f attestation.FactorResult) string {
	tag := factorPolicyTag(f)
	if tag == "" {
		return ""
	}
	return "  " + tag
}

func factorPolicyTag(f attestation.FactorResult) string {
	if f.Status == attestation.NotApplicable {
		return ""
	}
	if f.Enforced {
		return "[ENFORCED]"
	}
	return "[ALLOWED]"
}

func findFactor(t *testing.T, report *attestation.VerificationReport, name string) attestation.FactorResult {
	t.Helper()
	for _, f := range report.Factors {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("factor %q not found in report (factors: %v)", name, factorNames(report))
	return attestation.FactorResult{}
}

func factorNames(r *attestation.VerificationReport) []string {
	names := make([]string, len(r.Factors))
	for i, f := range r.Factors {
		names[i] = f.Name
	}
	return names
}
