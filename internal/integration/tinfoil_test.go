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

	// SEV-SNP verification: parse the binary report and check structure.
	sevResult := attestation.VerifySEVReportOffline(ctx, raw.SEVReportBytes)
	if sevResult.ParseErr != nil {
		t.Fatalf("SEV report parse: %v", sevResult.ParseErr)
	}
	t.Logf("SEV: debug=%v measurement=%x", sevResult.DebugEnabled, sevResult.Measurement)

	// REPORTDATA binding via Tinfoil's verifier.
	detail, rdErr := tinfoil.ReportDataVerifier{}.VerifyReportData(sevResult.ReportData, raw, env.nonce)
	t.Logf("REPORTDATA: detail=%q err=%v", detail, rdErr)

	// Build report via the full pipeline.
	// The fixture is SEV-SNP, but BuildReport only has TDX evaluators,
	// so most tee_* factors will Fail.
	modelPolicy, _ := defaults.MeasurementDefaults("tinfoil_v3_cloud")
	report := attestation.BuildReport(&attestation.ReportInput{
		Provider:       "tinfoil_v3_cloud",
		Model:          env.manifest.Model,
		Raw:            raw,
		Nonce:          env.nonce,
		TDX:            nil, // SEV-SNP fixture, no TDX result
		Nvidia:         nil,
		NvidiaNRAS:     nil,
		PoC:            nil,
		Compose:        nil,
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

	// Must Pass: nonce, signing key, e2ee capable, TLS key binding.
	assertMustPass(t, report, []string{
		"nonce_match",
		"signing_key_present",
		"e2ee_capable",
		"tls_key_binding",
	})

	// Must Fail: no TDX quote available (SEV-SNP fixture).
	assertMustFail(t, report, []string{
		"tee_quote_present",
		"tee_quote_structure",
		"tee_cert_chain",
		"tee_quote_signature",
		"tee_debug_disabled",
		"tee_reportdata_binding",
	}, "no TDX quote (SEV-SNP fixture)")

	// Must Fail: no NVIDIA payload.
	assertMustFail(t, report, []string{
		"nvidia_payload_present",
	}, "no NVIDIA payload")

	// Must Fail: not implemented.
	assertMustFail(t, report, []string{
		"cpu_gpu_chain",
		"measured_model_weights",
	}, "not implemented")

	// Fail (enforced): no compose/sigstore/event_log data in SEV-SNP fixture.
	assertMustFail(t, report, []string{
		"compose_binding",
		"sigstore_verification",
		"event_log_integrity",
	}, "no data in SEV-SNP fixture (enforced)")

	// Skip: pending live test.
	assertFactorStatus(t, report, "e2ee_usable", attestation.Skip)

	if report.Passed < 4 {
		t.Errorf("expected at least 4 passing factors, got %d", report.Passed)
	}
	t.Logf("RESULT: %d/%d factors passed", report.Passed, total(report))
}
