package integration

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
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

	client := &http.Client{Transport: capture.NewReplayTransport(entries)}
	orig := attestation.TDXCollateralGetter
	attestation.TDXCollateralGetter = attestation.NewCollateralGetter(client)
	t.Cleanup(func() { attestation.TDXCollateralGetter = orig })

	return fixtureEnv{manifest: manifest, entries: entries, client: client, nonce: nonce}
}

// findFixtureDir returns the lexicographically latest testdata directory
// matching the given provider prefix (e.g. "venice", "neardirect", "nearcloud").
func findFixtureDir(t *testing.T, prefix string) string {
	t.Helper()
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	var latest string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), prefix+"_") {
			if e.Name() > latest {
				latest = e.Name()
			}
		}
	}
	if latest == "" {
		t.Skipf("no %s fixture in testdata/; run: teep verify %s --capture testdata/", prefix, prefix)
	}
	return filepath.Join("testdata", latest)
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
		t.Logf("%s: %s (%s)", name, f.Status, f.Detail)
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
		"tdx_cert_chain",
		"tdx_quote_signature",
		"intel_pcs_collateral",
		"tdx_tcb_current",
		"tdx_tcb_not_revoked",
		"nvidia_signature",
		"nvidia_claims",
		"nvidia_nras_verified",
	})

	// Not implemented — expected fail.
	assertMustFail(t, r, []string{"cpu_gpu_chain", "measured_model_weights"}, "not implemented")

	// Allow-fail factors — log for visibility.
	logFactorStatus(t, r,
		"cpu_id_registry",
		"tdx_hardware_config",
		"tdx_boot_config",
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
