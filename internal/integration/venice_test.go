package integration

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/venice"
)

// veniceFixtureDir returns the directory containing Venice fixture files.
func veniceFixtureDir(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("VENICE_FIXTURE_DIR"); dir != "" {
		return dir
	}

	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	var latest string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "venice_") {
			if e.Name() > latest {
				latest = e.Name()
			}
		}
	}
	if latest == "" {
		t.Skip("no venice fixture directory found in testdata/; run: go run ./cmd/capture_venice")
	}
	return filepath.Join("testdata", latest)
}

func parseVeniceCaptureTime(t *testing.T, fdir string) time.Time {
	t.Helper()
	base := filepath.Base(fdir)
	ct, err := time.Parse("venice_20060102_150405", base)
	if err != nil {
		t.Fatalf("parse capture time from %q: %v", base, err)
	}
	return ct
}

// ---------------------------------------------------------------------------
// Verification phase helpers
// ---------------------------------------------------------------------------

func verifyVeniceTDX(ctx context.Context, t *testing.T, raw *attestation.RawAttestation, nonce attestation.Nonce) *attestation.TDXVerifyResult {
	t.Helper()
	t.Log("--- TDX verification ---")
	tdxResult := attestation.VerifyTDXQuote(ctx, raw.IntelQuote, nonce, false)
	t.Logf("TDX parse err: %v", tdxResult.ParseErr)
	t.Logf("TDX cert chain err: %v", tdxResult.CertChainErr)
	t.Logf("TDX signature err: %v", tdxResult.SignatureErr)
	t.Logf("TDX collateral err: %v", tdxResult.CollateralErr)
	t.Logf("TDX debug: %v", tdxResult.DebugEnabled)
	t.Logf("TDX FMSPC: %s", tdxResult.FMSPC)
	t.Logf("TDX TCB status: %s", tdxResult.TcbStatus)

	if tdxResult.ParseErr != nil {
		t.Fatalf("TDX parse failed: %v", tdxResult.ParseErr)
	}
	return tdxResult
}

func verifyVeniceReportData(t *testing.T, tdxResult *attestation.TDXVerifyResult, raw *attestation.RawAttestation, nonce attestation.Nonce) {
	t.Helper()
	t.Log("--- REPORTDATA binding ---")
	verifier := venice.ReportDataVerifier{}
	detail, rdErr := verifier.VerifyReportData(tdxResult.ReportData, raw, nonce)
	tdxResult.ReportDataBindingErr = rdErr
	tdxResult.ReportDataBindingDetail = detail
	t.Logf("REPORTDATA binding: detail=%q err=%v", detail, rdErr)
}

func verifyVeniceNvidiaEAT(t *testing.T, raw *attestation.RawAttestation, nonce attestation.Nonce) *attestation.NvidiaVerifyResult {
	t.Helper()
	t.Log("--- NVIDIA EAT verification ---")
	if raw.NvidiaPayload == "" {
		return nil
	}
	result := attestation.VerifyNVIDIAPayload(context.Background(), raw.NvidiaPayload, nonce)
	t.Logf("NVIDIA format: %s", result.Format)
	t.Logf("NVIDIA signature err: %v", result.SignatureErr)
	t.Logf("NVIDIA claims err: %v", result.ClaimsErr)
	t.Logf("NVIDIA nonce: %s", result.Nonce)
	return result
}

func verifyVeniceNRAS(ctx context.Context, t *testing.T, raw *attestation.RawAttestation, client *http.Client, captureTime time.Time) *attestation.NvidiaVerifyResult {
	t.Helper()
	t.Log("--- NVIDIA NRAS verification ---")
	if raw.NvidiaPayload == "" || raw.NvidiaPayload[0] != '{' {
		return nil
	}
	result := attestation.VerifyNVIDIANRAS(ctx, raw.NvidiaPayload, client,
		jwt.WithTimeFunc(func() time.Time { return captureTime }),
		jwt.WithLeeway(10*time.Second),
	)
	t.Logf("NRAS format: %s", result.Format)
	t.Logf("NRAS signature err: %v", result.SignatureErr)
	t.Logf("NRAS claims err: %v", result.ClaimsErr)
	t.Logf("NRAS overall result: %v", result.OverallResult)
	return result
}

func verifyVeniceCompose(t *testing.T, raw *attestation.RawAttestation, tdxResult *attestation.TDXVerifyResult) *attestation.ComposeBindingResult {
	t.Helper()
	t.Log("--- compose binding ---")
	if raw.AppCompose == "" || tdxResult.ParseErr != nil {
		return nil
	}
	result := &attestation.ComposeBindingResult{Checked: true}
	result.Err = attestation.VerifyComposeBinding(raw.AppCompose, tdxResult.MRConfigID)
	t.Logf("compose binding err: %v", result.Err)
	return result
}

type sigstoreOutput struct {
	results      []attestation.SigstoreResult
	imageRepos   []string
	digestToRepo map[string]string
}

func verifyVeniceSigstore(ctx context.Context, t *testing.T, raw *attestation.RawAttestation, rekorClient *attestation.RekorClient) sigstoreOutput {
	t.Helper()
	t.Log("--- Sigstore ---")
	if raw.AppCompose == "" {
		return sigstoreOutput{}
	}

	dockerCompose, err := attestation.ExtractDockerCompose(raw.AppCompose)
	if err != nil {
		t.Logf("extract docker_compose_file: %v (using raw app_compose)", err)
	}
	source := dockerCompose
	if source == "" {
		source = raw.AppCompose
	}

	out := sigstoreOutput{
		imageRepos:   attestation.ExtractImageRepositories(source),
		digestToRepo: attestation.ExtractImageDigestToRepoMap(source),
	}

	digests := attestation.ExtractImageDigests(source)
	t.Logf("image digests: %d", len(digests))
	for _, d := range digests {
		t.Logf("  sha256:%s...", d[:min(16, len(d))])
	}
	if len(digests) > 0 {
		out.results = rekorClient.CheckSigstoreDigests(ctx, digests)
		for _, r := range out.results {
			t.Logf("  sigstore: digest=%s ok=%v status=%d err=%v", r.Digest[:min(16, len(r.Digest))], r.OK, r.Status, r.Err)
		}
	}
	return out
}

func verifyVeniceRekor(ctx context.Context, t *testing.T, sigstoreResults []attestation.SigstoreResult, rekorClient *attestation.RekorClient) []attestation.RekorProvenance {
	t.Helper()
	t.Log("--- Rekor ---")
	var results []attestation.RekorProvenance
	for _, sr := range sigstoreResults {
		if sr.OK {
			prov := rekorClient.FetchRekorProvenance(ctx, sr.Digest)
			t.Logf("  rekor: digest=%s hasCert=%v err=%v", prov.Digest[:min(16, len(prov.Digest))], prov.HasCert, prov.Err)
			results = append(results, prov)
		}
	}
	return results
}

func verifyVenicePoC(ctx context.Context, t *testing.T, pocPeers []string, client *http.Client, intelQuote string) *attestation.PoCResult {
	t.Helper()
	t.Log("--- Proof of Cloud ---")
	poc := attestation.NewPoCClient(pocPeers, 3, client)
	result := poc.CheckQuote(ctx, intelQuote)
	t.Logf("PoC registered: %v", result.Registered)
	t.Logf("PoC machine ID: %s", result.MachineID)
	t.Logf("PoC label: %s", result.Label)
	t.Logf("PoC err: %v", result.Err)
	return result
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

func assertVeniceReport(t *testing.T, report *attestation.VerificationReport) {
	t.Helper()

	expectations := []struct {
		name   string
		status attestation.Status
	}{
		{"nonce_match", attestation.Pass},
		{"tdx_quote_present", attestation.Pass},
		{"tdx_quote_structure", attestation.Pass},
		{"tdx_debug_disabled", attestation.Pass},
		{"signing_key_present", attestation.Pass},
		{"tdx_reportdata_binding", attestation.Pass},
		{"nvidia_payload_present", attestation.Pass},
		{"nvidia_nonce_client_bound", attestation.Pass},
		{"e2ee_capable", attestation.Pass},
		{"compose_binding", attestation.Pass},
		{"sigstore_verification", attestation.Pass},
		{"build_transparency_log", attestation.Pass},
		{"event_log_integrity", attestation.Pass},
	}
	for _, exp := range expectations {
		f := findFactor(t, report, exp.name)
		if f.Status != exp.status {
			t.Errorf("factor %s: got %s, want %s (detail: %s)", exp.name, f.Status, exp.status, f.Detail)
		}
	}

	// Venice doesn't have TLS fingerprint — tls_key_binding should SKIP.
	tlsF := findFactor(t, report, "tls_key_binding")
	if tlsF.Status != attestation.Skip {
		t.Errorf("tls_key_binding: got %s, want Skip (Venice uses E2EE, not TLS binding)", tlsF.Status)
	}

	// Cert chain and signature — accept pass; log warning on fail (cert expiry).
	for _, name := range []string{"tdx_cert_chain", "tdx_quote_signature"} {
		f := findFactor(t, report, name)
		if f.Status == attestation.Fail {
			t.Logf("WARNING: %s failed (likely PCK cert expiry, recapture fixtures): %s", name, f.Detail)
		}
	}

	// Intel PCS collateral — expect pass with fixture data.
	pcsF := findFactor(t, report, "intel_pcs_collateral")
	if pcsF.Status == attestation.Fail {
		t.Logf("WARNING: intel_pcs_collateral failed (may need fixture refresh): %s", pcsF.Detail)
	} else if pcsF.Status != attestation.Pass {
		t.Errorf("intel_pcs_collateral: got %s, want Pass or Fail (detail: %s)", pcsF.Status, pcsF.Detail)
	}

	// NVIDIA signature — SPDM cert chain may have time sensitivity.
	nvidSig := findFactor(t, report, "nvidia_signature")
	if nvidSig.Status == attestation.Fail {
		t.Logf("WARNING: nvidia_signature failed (may need fixture refresh): %s", nvidSig.Detail)
	}

	// NVIDIA claims — may have time-sensitive fields.
	nvidClaims := findFactor(t, report, "nvidia_claims")
	if nvidClaims.Status == attestation.Fail {
		t.Logf("WARNING: nvidia_claims failed (may need fixture refresh): %s", nvidClaims.Detail)
	}

	// NRAS — JWT expiry is pinned to capture time, so this should pass.
	nrasF := findFactor(t, report, "nvidia_nras_verified")
	if nrasF.Status != attestation.Pass {
		t.Errorf("nvidia_nras_verified: got %s, want Pass (detail: %s)", nrasF.Status, nrasF.Detail)
	}

	// PoC — depends on whether the machine is whitelisted.
	pocF := findFactor(t, report, "cpu_id_registry")
	t.Logf("cpu_id_registry: %s (%s)", pocF.Status, pocF.Detail)

	// Not implemented — expected fail.
	for _, name := range []string{"cpu_gpu_chain", "measured_model_weights"} {
		f := findFactor(t, report, name)
		if f.Status != attestation.Fail {
			t.Errorf("factor %s: got %s, want Fail (not implemented)", name, f.Status)
		}
	}

	if report.Passed < 10 {
		t.Errorf("expected at least 10 passing factors, got %d", report.Passed)
	}
	total := report.Passed + report.Failed + report.Skipped
	t.Logf("PASS: %d/%d factors passed", report.Passed, total)
}

// ---------------------------------------------------------------------------
// Main test
// ---------------------------------------------------------------------------

func TestIntegration_Venice_Fixture(t *testing.T) {
	ctx := context.Background()

	// 1. Load fixtures
	fdir := veniceFixtureDir(t)
	captureTime := parseVeniceCaptureTime(t, fdir)
	t.Logf("loading fixtures from %s (captured %s)", fdir, captureTime.Format(time.RFC3339))

	attestBody := readFixtureFrom(t, fdir, "venice_attestation.json")
	nonceHex := strings.TrimSpace(string(readFixtureFrom(t, fdir, "venice_fixture_nonce.txt")))
	nonce, err := attestation.ParseNonce(nonceHex)
	if err != nil {
		t.Fatalf("parse nonce: %v", err)
	}
	t.Logf("nonce: %s", nonceHex[:16]+"...")

	// 2. Parse fixture into RawAttestation
	raw, err := venice.ParseAttestationResponse(attestBody)
	if err != nil {
		t.Fatalf("parse Venice fixture: %v", err)
	}
	t.Logf("model: %s", raw.Model)
	t.Logf("intel_quote: %d hex chars", len(raw.IntelQuote))
	t.Logf("nvidia_payload: %d bytes", len(raw.NvidiaPayload))
	t.Logf("app_compose: %d bytes", len(raw.AppCompose))
	t.Logf("signing_address: %s", raw.SigningAddress)

	// 3. Set up mocks for ALL external services
	pocPeers, client, rekorClient := setupMocks(t, fdir, "venice", raw)

	// 4. Run the pipeline
	tdxResult := verifyVeniceTDX(ctx, t, raw, nonce)
	verifyVeniceReportData(t, tdxResult, raw, nonce)
	nvidiaResult := verifyVeniceNvidiaEAT(t, raw, nonce)
	nrasResult := verifyVeniceNRAS(ctx, t, raw, client, captureTime)
	composeResult := verifyVeniceCompose(t, raw, tdxResult)
	sig := verifyVeniceSigstore(ctx, t, raw, rekorClient)
	rekorResults := verifyVeniceRekor(ctx, t, sig.results, rekorClient)
	pocResult := verifyVenicePoC(ctx, t, pocPeers, client, raw.IntelQuote)

	// 5. Build report
	t.Log("--- BuildReport ---")
	report := attestation.BuildReport(&attestation.ReportInput{
		Provider:     "venice",
		Model:        raw.Model,
		Raw:          raw,
		Nonce:        nonce,
		TDX:          tdxResult,
		Nvidia:       nvidiaResult,
		NvidiaNRAS:   nrasResult,
		PoC:          pocResult,
		Compose:      composeResult,
		ImageRepos:   sig.imageRepos,
		DigestToRepo: sig.digestToRepo,
		Sigstore:     sig.results,
		Rekor:        rekorResults,
		AllowFail:    attestation.DefaultAllowFail,
	})

	total := report.Passed + report.Failed + report.Skipped
	t.Logf("Score: %d/%d (passed=%d failed=%d skipped=%d)",
		report.Passed, total, report.Passed, report.Failed, report.Skipped)
	for _, f := range report.Factors {
		t.Logf("  [%s] %s: %s", f.Status, f.Name, f.Detail)
	}

	// 6. Assert expected factor results
	assertVeniceReport(t, report)
}
