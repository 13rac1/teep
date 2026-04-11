package integration

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/defaults"
	"github.com/13rac1/teep/internal/provider/venice"
)

func TestIntegration_Venice_Fixture(t *testing.T) {
	ctx := context.Background()
	env := loadFixture(t, "venice")

	// Fetch attestation through replay.
	attester := venice.NewAttester("https://api.venice.ai", "", true)
	attester.SetClient(env.client)
	raw, err := attester.FetchAttestation(ctx, env.manifest.Model, env.nonce)
	if err != nil {
		t.Fatalf("fetch attestation: %v", err)
	}
	t.Logf("model=%s intel_quote=%d nvidia_payload=%d app_compose=%d",
		raw.Model, len(raw.IntelQuote), len(raw.NvidiaPayload), len(raw.AppCompose))

	// TDX
	tdxResult := attestation.VerifyTDXQuoteOnline(ctx, raw.IntelQuote, attestation.NewCollateralGetter(env.client))
	if tdxResult.ParseErr != nil {
		t.Fatalf("TDX parse: %v", tdxResult.ParseErr)
	}
	t.Logf("TDX: cert_chain=%v sig=%v collateral=%v fmspc=%s tcb=%s",
		tdxResult.CertChainErr, tdxResult.SignatureErr, tdxResult.CollateralErr,
		tdxResult.FMSPC, tdxResult.TcbStatus)

	// REPORTDATA binding
	detail, rdErr := venice.ReportDataVerifier{}.VerifyReportData(tdxResult.ReportData, raw, env.nonce)
	tdxResult.ReportDataBindingErr = rdErr
	tdxResult.ReportDataBindingDetail = detail
	t.Logf("REPORTDATA: detail=%q err=%v", detail, rdErr)

	// NVIDIA EAT
	var nvidiaResult *attestation.NvidiaVerifyResult
	if raw.NvidiaPayload != "" {
		nvidiaResult = attestation.VerifyNVIDIAPayload(ctx, raw.NvidiaPayload, env.nonce)
		t.Logf("NVIDIA EAT: format=%s sig_err=%v claims_err=%v", nvidiaResult.Format, nvidiaResult.SignatureErr, nvidiaResult.ClaimsErr)
	}

	// NVIDIA NRAS (time-pinned for expired JWTs)
	var nrasResult *attestation.NvidiaVerifyResult
	if raw.NvidiaPayload != "" && raw.NvidiaPayload[0] == '{' {
		nrasResult = attestation.VerifyNVIDIANRAS(ctx, raw.NvidiaPayload, env.client,
			jwt.WithTimeFunc(func() time.Time { return env.manifest.CapturedAt }),
			jwt.WithLeeway(10*time.Second),
		)
		t.Logf("NRAS: format=%s sig_err=%v claims_err=%v result=%v",
			nrasResult.Format, nrasResult.SignatureErr, nrasResult.ClaimsErr, nrasResult.OverallResult)
	}

	// Compose binding
	var composeResult *attestation.ComposeBindingResult
	if raw.AppCompose != "" && tdxResult.ParseErr == nil {
		composeResult = &attestation.ComposeBindingResult{Checked: true}
		composeResult.Err = attestation.VerifyComposeBinding(raw.AppCompose, tdxResult.MRConfigID)
		t.Logf("compose binding: err=%v", composeResult.Err)
	}

	// Sigstore + Rekor
	modelCD := attestation.ExtractComposeDigests(raw.AppCompose)
	allDigests, digestToRepo := attestation.MergeComposeDigests(modelCD, attestation.ComposeDigests{})
	rc := attestation.NewRekorClient(env.client)
	sigstoreResults := rc.CheckSigstoreDigests(ctx, allDigests)
	t.Logf("sigstore: %d digests checked", len(sigstoreResults))
	var rekorResults []attestation.RekorProvenance
	for _, sr := range sigstoreResults {
		if sr.OK {
			prov := rc.FetchRekorProvenance(ctx, sr.Digest)
			t.Logf("  rekor: digest=%s hasCert=%v err=%v", prov.Digest[:min(16, len(prov.Digest))], prov.HasCert, prov.Err)
			rekorResults = append(rekorResults, prov)
		}
	}
	assertRekorExercised(t, sigstoreResults, rekorResults)

	// PoC
	poc := attestation.NewPoCClient(attestation.PoCPeers, attestation.PoCQuorum, env.client)
	pocResult := poc.CheckQuote(ctx, raw.IntelQuote)
	t.Logf("PoC: registered=%v err=%v", pocResult.Registered, pocResult.Err)

	// Build report with provider defaults.
	modelPolicy, _ := defaults.MeasurementDefaults("venice")
	report := attestation.BuildReport(&attestation.ReportInput{
		Provider:          "venice",
		Model:             env.manifest.Model,
		Raw:               raw,
		Nonce:             env.nonce,
		TDX:               tdxResult,
		Nvidia:            nvidiaResult,
		NvidiaNRAS:        nrasResult,
		PoC:               pocResult,
		Compose:           composeResult,
		ImageRepos:        modelCD.Repos,
		DigestToRepo:      digestToRepo,
		Sigstore:          sigstoreResults,
		Rekor:             rekorResults,
		Policy:            modelPolicy,
		SupplyChainPolicy: venice.SupplyChainPolicy(),
		AllowFail:         attestation.DefaultAllowFail,
	})

	t.Logf("Score: %d/%d (passed=%d failed=%d skipped=%d)", report.Passed, total(report), report.Passed, report.Failed, report.Skipped)
	for _, f := range report.Factors {
		t.Logf("  [%s] %s: %s", f.Status, f.Name, f.Detail)
	}

	assertVeniceReport(t, report)
}

func assertVeniceReport(t *testing.T, report *attestation.VerificationReport) {
	t.Helper()

	assertMustPass(t, report, []string{
		"nonce_match",
		"tdx_quote_present",
		"tdx_quote_structure",
		"tdx_debug_disabled",
		"tdx_mrseam_mrtd",
		"signing_key_present",
		"tdx_reportdata_binding",
		"nvidia_payload_present",
		"nvidia_nonce_client_bound",
		"e2ee_capable",
		"compose_binding",
		"sigstore_verification",
		"build_transparency_log",
		"event_log_integrity",
	})

	// Venice uses E2EE, not TLS binding.
	assertFactorStatus(t, report, "tls_key_binding", attestation.Skip)

	commonModelAssertions(t, report)

	if report.Passed < 10 {
		t.Errorf("expected at least 10 passing factors, got %d", report.Passed)
	}
	t.Logf("RESULT: %d/%d factors passed", report.Passed, total(report))
}
