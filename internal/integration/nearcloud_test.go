package integration

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/defaults"
	"github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

func TestIntegration_NearCloud_Fixture(t *testing.T) {
	ctx := context.Background()
	env := loadFixture(t, "nearcloud")

	// Fetch attestation through replay.
	attester := nearcloud.NewAttester("", true)
	attester.SetClient(env.client)
	raw, err := attester.FetchAttestation(ctx, env.manifest.Model, env.nonce)
	if err != nil {
		t.Fatalf("fetch attestation: %v", err)
	}
	t.Logf("model=%s intel_quote=%d nvidia_payload=%d app_compose=%d",
		raw.Model, len(raw.IntelQuote), len(raw.NvidiaPayload), len(raw.AppCompose))
	t.Logf("gateway: intel_quote=%d app_compose=%d tls_fingerprint=%s event_log=%d",
		len(raw.GatewayIntelQuote), len(raw.GatewayAppCompose),
		raw.GatewayTLSFingerprint[:min(16, len(raw.GatewayTLSFingerprint))]+"...",
		len(raw.GatewayEventLog))

	// --- Model TDX ---
	tdxResult := attestation.VerifyTDXQuoteOnline(ctx, raw.IntelQuote, attestation.NewCollateralGetter(env.client))
	if tdxResult.ParseErr != nil {
		t.Fatalf("TDX parse: %v", tdxResult.ParseErr)
	}
	t.Logf("TDX: cert_chain=%v sig=%v collateral=%v fmspc=%s tcb=%s",
		tdxResult.CertChainErr, tdxResult.SignatureErr, tdxResult.CollateralErr,
		tdxResult.FMSPC, tdxResult.TcbStatus)

	// Model REPORTDATA binding (neardirect scheme, since nearcloud
	// delegates model parsing to neardirect).
	detail, rdErr := neardirect.ReportDataVerifier{}.VerifyReportData(tdxResult.ReportData, raw, env.nonce)
	tdxResult.ReportDataBindingErr = rdErr
	tdxResult.ReportDataBindingDetail = detail
	t.Logf("REPORTDATA: detail=%q err=%v", detail, rdErr)

	// --- NVIDIA EAT ---
	var nvidiaResult *attestation.NvidiaVerifyResult
	if raw.NvidiaPayload != "" {
		nvidiaResult = attestation.VerifyNVIDIAPayload(ctx, raw.NvidiaPayload, env.nonce)
		t.Logf("NVIDIA EAT: format=%s sig_err=%v claims_err=%v", nvidiaResult.Format, nvidiaResult.SignatureErr, nvidiaResult.ClaimsErr)
	}

	// --- NVIDIA NRAS (time-pinned) ---
	var nrasResult *attestation.NvidiaVerifyResult
	if raw.NvidiaPayload != "" && raw.NvidiaPayload[0] == '{' {
		nrasResult = attestation.VerifyNVIDIANRAS(ctx, raw.NvidiaPayload, env.client,
			jwt.WithTimeFunc(func() time.Time { return env.manifest.CapturedAt }),
			jwt.WithLeeway(10*time.Second),
		)
		t.Logf("NRAS: format=%s sig_err=%v claims_err=%v result=%v",
			nrasResult.Format, nrasResult.SignatureErr, nrasResult.ClaimsErr, nrasResult.OverallResult)
	}

	// --- Model compose binding ---
	var composeResult *attestation.ComposeBindingResult
	var modelCD attestation.ComposeDigests
	if raw.AppCompose != "" && tdxResult.ParseErr == nil {
		composeResult = &attestation.ComposeBindingResult{Checked: true}
		composeResult.Err = attestation.VerifyComposeBinding(raw.AppCompose, tdxResult.MRConfigID)
		t.Logf("compose binding: err=%v", composeResult.Err)
		if composeResult.Err == nil {
			modelCD = attestation.ExtractComposeDigests(raw.AppCompose)
		}
	}

	// --- Gateway TDX ---
	var gatewayTDX *attestation.TDXVerifyResult
	var gatewayCompose *attestation.ComposeBindingResult
	var gatewayCD attestation.ComposeDigests
	if raw.GatewayIntelQuote != "" {
		gatewayTDX = attestation.VerifyTDXQuoteOnline(ctx, raw.GatewayIntelQuote, attestation.NewCollateralGetter(env.client))
		t.Logf("gateway TDX: parse=%v cert=%v sig=%v collateral=%v",
			gatewayTDX.ParseErr, gatewayTDX.CertChainErr, gatewayTDX.SignatureErr, gatewayTDX.CollateralErr)

		if gatewayTDX.ParseErr == nil {
			gwDetail, gwRDErr := nearcloud.GatewayReportDataVerifier{}.VerifyReportData(
				gatewayTDX.ReportData, raw, env.nonce)
			gatewayTDX.ReportDataBindingErr = gwRDErr
			gatewayTDX.ReportDataBindingDetail = gwDetail
			t.Logf("gateway REPORTDATA: detail=%q err=%v", gwDetail, gwRDErr)
		}

		if raw.GatewayAppCompose != "" && gatewayTDX.ParseErr == nil {
			gatewayCompose = &attestation.ComposeBindingResult{Checked: true}
			gatewayCompose.Err = attestation.VerifyComposeBinding(raw.GatewayAppCompose, gatewayTDX.MRConfigID)
			t.Logf("gateway compose binding: err=%v", gatewayCompose.Err)
			if gatewayCompose.Err == nil {
				gatewayCD = attestation.ExtractComposeDigests(raw.GatewayAppCompose)
			}
		}
	}

	// --- Sigstore + Rekor ---
	allDigests, digestToRepo := attestation.MergeComposeDigests(modelCD, gatewayCD)
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

	// --- PoC (model + gateway) ---
	poc := attestation.NewPoCClient(attestation.PoCPeers, attestation.PoCQuorum, env.client)
	pocResult := poc.CheckQuote(ctx, raw.IntelQuote)
	t.Logf("PoC model: registered=%v err=%v", pocResult.Registered, pocResult.Err)

	var gatewayPoC *attestation.PoCResult
	if raw.GatewayIntelQuote != "" {
		gatewayPoC = poc.CheckQuote(ctx, raw.GatewayIntelQuote)
		t.Logf("PoC gateway: registered=%v err=%v", gatewayPoC.Registered, gatewayPoC.Err)
	}

	// --- Build report with provider defaults ---
	modelPolicy, gatewayPolicy := defaults.MeasurementDefaults("nearcloud")
	report := attestation.BuildReport(&attestation.ReportInput{
		Provider:          "nearcloud",
		Model:             env.manifest.Model,
		Raw:               raw,
		Nonce:             env.nonce,
		TDX:               tdxResult,
		Nvidia:            nvidiaResult,
		NvidiaNRAS:        nrasResult,
		PoC:               pocResult,
		Compose:           composeResult,
		ImageRepos:        modelCD.Repos,
		GatewayImageRepos: gatewayCD.Repos,
		DigestToRepo:      digestToRepo,
		Sigstore:          sigstoreResults,
		Rekor:             rekorResults,
		GatewayTDX:        gatewayTDX,
		GatewayPoC:        gatewayPoC,
		GatewayNonceHex:   raw.GatewayNonceHex,
		GatewayNonce:      env.nonce,
		GatewayCompose:    gatewayCompose,
		GatewayEventLog:   raw.GatewayEventLog,
		Policy:            modelPolicy,
		GatewayPolicy:     gatewayPolicy,
		SupplyChainPolicy: nearcloud.SupplyChainPolicy(),
		AllowFail:         attestation.NearcloudDefaultAllowFail,
	})

	t.Logf("Score: %d/%d (passed=%d failed=%d skipped=%d)", report.Passed, total(report), report.Passed, report.Failed, report.Skipped)
	for _, f := range report.Factors {
		t.Logf("  [%s] %s: %s", f.Status, f.Name, f.Detail)
	}

	assertNearcloudReport(t, report)
}

func assertNearcloudReport(t *testing.T, report *attestation.VerificationReport) {
	t.Helper()

	// Model factors that must pass.
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
		"tls_key_binding",
		"compose_binding",
		"sigstore_verification",
		"build_transparency_log",
		"event_log_integrity",
	})

	// Gateway factors (Tier 4) that must pass.
	assertMustPass(t, report, []string{
		"gateway_nonce_match",
		"gateway_tdx_quote_present",
		"gateway_tdx_quote_structure",
		"gateway_tdx_cert_chain",
		"gateway_tdx_quote_signature",
		"gateway_tdx_debug_disabled",
		"gateway_tdx_mrseam_mrtd",
		"gateway_compose_binding",
		"gateway_event_log_integrity",
	})

	commonModelAssertions(t, report)

	// Gateway allow-fail factors — log for visibility.
	logFactorStatus(t, report,
		"gateway_tdx_reportdata_binding",
		"gateway_tdx_hardware_config",
		"gateway_tdx_boot_config",
		"gateway_cpu_id_registry",
	)

	if report.Passed < 20 {
		t.Errorf("expected at least 20 passing factors (model + gateway), got %d", report.Passed)
	}
	t.Logf("RESULT: %d/%d factors passed", report.Passed, total(report))
}
