package integration

import (
	"context"
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
		Provider:       "tinfoil_v3_cloud",
		Model:          env.manifest.Model,
		Raw:            raw,
		Nonce:          env.nonce,
		SEV:            sevResult,
		Policy:         modelPolicy,
		AllowFail:      attestation.TinfoilDefaultAllowFail,
		E2EEConfigured: true,
	})

	t.Logf("Score: %d/%d (passed=%d failed=%d skipped=%d)", report.Passed, total(report), report.Passed, report.Failed, report.Skipped)
	for _, f := range report.Factors {
		t.Logf("  [%s] %s: %s", f.Status, f.Name, f.Detail)
	}

	assertTinfoilReport(t, report)
}

func assertTinfoilReport(t *testing.T, report *attestation.VerificationReport) {
	t.Helper()

	// Must Pass: SEV-SNP TEE factors + signing key + e2ee + TLS.
	// tee_cert_chain and tee_quote_signature pass because AMD KDS
	// cert_chain and VCEK cert are captured in the fixture.
	assertMustPass(t, report, []string{
		"nonce_match",
		"tee_quote_present",
		"tee_quote_structure",
		"tee_cert_chain",
		"tee_quote_signature",
		"tee_debug_disabled",
		"tee_reportdata_binding",
		"tee_hardware_config",
		"tee_tcb_current",
		"tee_tcb_not_revoked",
		"signing_key_present",
		"e2ee_capable",
		"tls_key_binding",
	})

	// Must Skip: factors not applicable to SEV-SNP (allowed to fail) and
	// deferred factors.
	for _, name := range []string{
		"tee_boot_config",
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

	// Must Fail: not implemented.
	assertMustFail(t, report, []string{
		"cpu_gpu_chain",
		"measured_model_weights",
	}, "not implemented")

	// Fail: no compose/sigstore/event_log data in SEV-SNP fixture.
	assertMustFail(t, report, []string{
		"compose_binding",
		"sigstore_verification",
		"event_log_integrity",
	}, "no data in SEV-SNP fixture")

	if report.Passed < 13 {
		t.Errorf("expected at least 13 passing factors, got %d", report.Passed)
	}
	t.Logf("RESULT: %d/%d factors passed", report.Passed, total(report))
}
