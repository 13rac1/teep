package integration

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/defaults"
	"github.com/13rac1/teep/internal/provider/tinfoil"
)

func TestIntegration_Tinfoil_Fixture(t *testing.T) {
	ctx := context.Background()
	env := loadFixture(t, "tinfoil_v3_cloud")

	attester := tinfoil.NewAttester("https://inference.tinfoil.sh", "", true)
	attester.SetClient(env.client)
	raw, err := attester.FetchAttestation(ctx, "", env.nonce)
	if err != nil {
		t.Fatalf("fetch attestation: %v", err)
	}
	t.Logf("tee_hardware=%s intel_quote=%d sev_report=%d signing_key=%d",
		raw.TEEHardware, len(raw.IntelQuote), len(raw.SEVReportBytes), len(raw.SigningKey))

	// SEV-SNP verification: online — AMD KDS certs are served from the replay client.
	sevResult := attestation.VerifySEVReportOnline(ctx, raw.SEVReportBytes, attestation.NewSEVCertGetter(env.client))
	if sevResult.ParseErr != nil {
		t.Fatalf("SEV report parse: %v", sevResult.ParseErr)
	}
	t.Logf("SEV: debug=%v online=%v measurement=%x", sevResult.DebugEnabled, sevResult.OnlineVerified, sevResult.Measurement)

	// REPORTDATA binding via Tinfoil's verifier.
	detail, rdErr := tinfoil.ReportDataVerifier{}.VerifyReportData(sevResult.ReportData, raw, env.nonce)
	t.Logf("REPORTDATA: detail=%q err=%v", detail, rdErr)
	sevResult.ReportDataBindingErr = rdErr
	sevResult.ReportDataBindingDetail = detail

	// Build report via the full pipeline.
	modelPolicy, _ := defaults.MeasurementDefaults("tinfoil_v3_cloud")
	report := attestation.BuildReport(&attestation.ReportInput{
		Provider:               "tinfoil_v3_cloud",
		Model:                  env.manifest.Model,
		Raw:                    raw,
		Nonce:                  env.nonce,
		SEV:                    sevResult,
		Policy:                 modelPolicy,
		AllowFail:              attestation.TinfoilDefaultAllowFail,
		E2EEConfigured:         true,
		Inapplicable:           tinfoil.InapplicableFactors(),
		ProviderUsesTLSBinding: true,
	})

	t.Logf("Score: %d/%d (passed=%d failed=%d skipped=%d)", report.Passed, total(report), report.Passed, report.Failed, report.Skipped)
	for _, f := range report.Factors {
		t.Logf("  [%s] %s: %s", f.Status, f.Name, f.Detail)
	}

	assertTinfoilReport(t, report)
}

func TestIntegration_TinfoilDirect_Fixture(t *testing.T) {
	ctx := context.Background()
	env := loadFixture(t, "tinfoil_v3_direct")

	// Direct mode resolves model → backend enclave domain via the proxy
	// discovery endpoint, then fetches attestation from the resolved
	// enclave. Both the resolver and attester use the replay client.
	resolver := tinfoil.NewDirectResolver("", true)
	resolver.SetClient(env.client)
	attester := tinfoil.NewDirectAttester(resolver, "", true)
	attester.SetClient(env.client)

	raw, err := attester.FetchAttestation(ctx, env.manifest.Model, env.nonce)
	if err != nil {
		t.Fatalf("fetch attestation: %v", err)
	}
	t.Logf("tee_hardware=%s intel_quote=%d sev_report=%d signing_key=%d",
		raw.TEEHardware, len(raw.IntelQuote), len(raw.SEVReportBytes), len(raw.SigningKey))

	// The direct fixture uses a TDX backend enclave (e.g.
	// gemma4-31b-1.inf10.tinfoil.sh). Verify TDX quote and REPORTDATA.
	var tdxResult *attestation.TDXVerifyResult
	var sevResult *attestation.SEVVerifyResult
	var reportData [64]byte

	if raw.IntelQuote != "" {
		verifier := attestation.NewTDXVerifier(true, attestation.NewCollateralGetter(env.client))
		tdxResult = verifier(ctx, raw.IntelQuote)
		if tdxResult.ParseErr != nil {
			t.Fatalf("TDX quote parse: %v", tdxResult.ParseErr)
		}
		reportData = tdxResult.ReportData
		t.Logf("TDX: debug=%v measurement=%s", tdxResult.DebugEnabled, hex.EncodeToString(tdxResult.MRTD))
	} else {
		sevResult = attestation.VerifySEVReportOnline(ctx, raw.SEVReportBytes, attestation.NewSEVCertGetter(env.client))
		if sevResult.ParseErr != nil {
			t.Fatalf("SEV report parse: %v", sevResult.ParseErr)
		}
		reportData = sevResult.ReportData
		t.Logf("SEV: debug=%v online=%v measurement=%x", sevResult.DebugEnabled, sevResult.OnlineVerified, sevResult.Measurement)
	}

	// REPORTDATA binding via Tinfoil's verifier.
	detail, rdErr := tinfoil.ReportDataVerifier{}.VerifyReportData(reportData, raw, env.nonce)
	t.Logf("REPORTDATA: detail=%q err=%v", detail, rdErr)
	if tdxResult != nil {
		tdxResult.ReportDataBindingErr = rdErr
		tdxResult.ReportDataBindingDetail = detail
	}
	if sevResult != nil {
		sevResult.ReportDataBindingErr = rdErr
		sevResult.ReportDataBindingDetail = detail
	}

	// Build report via the full pipeline.
	modelPolicy, _ := defaults.MeasurementDefaults("tinfoil_v3_direct")
	report := attestation.BuildReport(&attestation.ReportInput{
		Provider:               "tinfoil_v3_direct",
		Model:                  env.manifest.Model,
		Raw:                    raw,
		Nonce:                  env.nonce,
		TDX:                    tdxResult,
		SEV:                    sevResult,
		Policy:                 modelPolicy,
		AllowFail:              attestation.TinfoilDefaultAllowFail,
		E2EEConfigured:         true,
		Inapplicable:           tinfoil.InapplicableFactors(),
		ProviderUsesTLSBinding: true,
	})

	t.Logf("Score: %d/%d (passed=%d failed=%d skipped=%d)", report.Passed, total(report), report.Passed, report.Failed, report.Skipped)
	for _, f := range report.Factors {
		t.Logf("  [%s] %s: %s", f.Status, f.Name, f.Detail)
	}

	// Direct fixture uses a real TDX inference enclave with GPU evidence.
	// This lower-level test verifies TDX quote, REPORTDATA binding (with
	// gpu_bound=true), and TLS key binding. Full supply chain and NVIDIA
	// SPDM verification are exercised by TestVerifyRun_TinfoilDirect_Fixture.
	assertMustPass(t, report, []string{
		"nonce_match",
		"tee_quote_present",
		"tee_quote_structure",
		"tee_cert_chain",
		"tee_quote_signature",
		"tee_debug_disabled",
		"tee_reportdata_binding",
		"signing_key_present",
		"e2ee_capable",
		"tls_key_binding",
		"nvidia_payload_present",
	})

	if report.Passed < 11 {
		t.Errorf("expected at least 11 passing factors, got %d", report.Passed)
	}
	t.Logf("RESULT: %d/%d factors passed", report.Passed, total(report))
}

func assertTinfoilReport(t *testing.T, report *attestation.VerificationReport) {
	t.Helper()

	// Must Pass: SEV-SNP TEE factors + signing key + e2ee + TLS.
	// tee_cert_chain and tee_quote_signature pass because AMD KDS
	// cert_chain and VCEK cert are captured in the fixture.
	// tee_boot_config passes because SEV-SNP boot config is covered by
	// the launch measurement (tee_measurement).
	assertMustPass(t, report, []string{
		"nonce_match",
		"tee_quote_present",
		"tee_quote_structure",
		"tee_cert_chain",
		"tee_quote_signature",
		"tee_debug_disabled",
		"tee_reportdata_binding",
		"tee_hardware_config",
		"tee_boot_config",
		"tee_tcb_current",
		"tee_tcb_not_revoked",
		"signing_key_present",
		"e2ee_capable",
		"tls_key_binding",
	})

	// Must Skip: factors not applicable to SEV-SNP (allowed to fail) and
	// deferred factors.
	for _, name := range []string{
		"intel_pcs_collateral",
		"e2ee_usable",
	} {
		assertFactorStatus(t, report, name, attestation.Skip)
	}

	// Must Fail: no measurement policy configured.
	assertMustFail(t, report, []string{
		"tee_measurement",
	}, "no measurement policy")

	// Must Fail: no NVIDIA payload.
	assertMustFail(t, report, []string{
		"nvidia_payload_present",
	}, "no NVIDIA payload")

	// Must Fail: not implemented / no Sigstore data in fixture.
	assertMustFail(t, report, []string{
		"cpu_gpu_chain",
		"measured_model_weights",
		"sigstore_code_verified",
		"nvswitch_binding",
	}, "not implemented / no supply chain data")

	// Not Applicable: factors handled by Tinfoil's applicability layer.
	for _, name := range []string{
		"compose_binding",
		"build_transparency_log",
		"sigstore_verification",
		"event_log_integrity",
		"nvidia_nonce_client_bound",
		"nvidia_nras_verified",
	} {
		assertFactorStatus(t, report, name, attestation.NotApplicable)
	}

	if report.Passed < 14 {
		t.Errorf("expected at least 14 passing factors, got %d", report.Passed)
	}
	t.Logf("RESULT: %d/%d factors passed", report.Passed, total(report))
}
