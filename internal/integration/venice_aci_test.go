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

// TestIntegration_VeniceACI_Fixture replays a real, freshly-captured Venice
// ACI/1 attestation (GH #113). ACI/1 is a distinct backend format from the
// dstack format exercised by TestIntegration_Venice_Fixture in
// venice_test.go: no docker-compose manifest, no Sigstore/Rekor image
// digests, and workload provenance expressed instead via a cryptographically
// endorsed workload keyset (aci_keyset_endorsement) plus a git
// source_provenance. The fixture is selected via the "venice_aci" prefix so
// it never collides with (or hijacks) the dstack "venice" fixture lookup —
// see the "venice_aci_" exclusion in findFixtureDir (helpers_test.go).
func TestIntegration_VeniceACI_Fixture(t *testing.T) {
	ctx := context.Background()
	env := loadFixture(t, "venice_aci")

	// Fetch attestation through replay; format detection happens inside
	// FetchAttestation via venice.ParseAttestationResponse.
	attester := venice.NewAttester("https://api.venice.ai", "", true)
	attester.SetClient(env.client)
	raw, err := attester.FetchAttestation(ctx, env.manifest.Model, env.nonce)
	if err != nil {
		t.Fatalf("fetch attestation: %v", err)
	}
	t.Logf("model=%s backend_format=%s intel_quote=%d nvidia_payload=%d app_compose=%d",
		raw.Model, raw.BackendFormat, len(raw.IntelQuote), len(raw.NvidiaPayload), len(raw.AppCompose))

	if raw.BackendFormat != attestation.FormatACI1 {
		t.Fatalf("BackendFormat = %q, want %q (aci/1) — fixture no longer parses as ACI/1", raw.BackendFormat, attestation.FormatACI1)
	}

	// TDX
	tdxResult := attestation.VerifyTDXQuoteOnline(ctx, raw.IntelQuote, attestation.NewCollateralGetter(env.client), fixtureVerificationTime(&env))
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
		nrasResult = attestation.DefaultNVIDIAVerifier().VerifyNRAS(ctx, raw.NvidiaPayload, env.client,
			jwt.WithTimeFunc(func() time.Time { return env.manifest.CapturedAt }),
			jwt.WithLeeway(10*time.Second),
		)
		t.Logf("NRAS: format=%s sig_err=%v claims_err=%v result=%v",
			nrasResult.Format, nrasResult.SignatureErr, nrasResult.ClaimsErr, nrasResult.OverallResult)
	}

	// ACI/1 has no app_compose manifest at all, so compose binding is never
	// attempted (evalComposeBinding forces Fail directly from BackendFormat).
	var composeResult *attestation.ComposeBindingResult
	if raw.AppCompose != "" && tdxResult.ParseErr == nil {
		t.Fatalf("unexpected app_compose in ACI/1 fixture (%d bytes) — ACI/1 has no compose manifest", len(raw.AppCompose))
	}

	// Sigstore + Rekor: ACI/1 has no compose-derived image digests, so this
	// must be empty (matches the fixture's captured traffic — no Rekor/
	// Sigstore requests were made during capture).
	modelCD := attestation.ExtractComposeDigests(raw.AppCompose)
	allDigests, digestToRepo := attestation.MergeComposeDigests(modelCD, attestation.ComposeDigests{})
	rc := attestation.NewRekorClient(env.client)
	sigstoreResults := rc.CheckSigstoreDigests(ctx, allDigests)
	if len(sigstoreResults) != 0 {
		t.Errorf("expected no Sigstore digests for ACI/1 (no compose manifest), got %d", len(sigstoreResults))
	}
	var rekorResults []attestation.RekorProvenance

	// PoC
	poc := attestation.NewPoCClient(attestation.PoCPeers, attestation.PoCQuorum, env.client).
		WithVerificationTime(fixtureVerificationTime(&env))
	pocResult := poc.CheckQuote(ctx, raw.IntelQuote)
	t.Logf("PoC: registered=%v err=%v", pocResult.Registered, pocResult.Err)

	// ACI/1 keyset endorsement — the cryptographic substitute for compose
	// binding/Sigstore on this format (workload keyset bound to the
	// TDX-attested identity key via JCS digest + secp256k1 signature).
	aciKeyset := venice.VerifyACIKeyset(raw)
	if aciKeyset == nil {
		t.Fatal("VerifyACIKeyset returned nil for an ACI/1 attestation")
	}
	t.Logf("ACI keyset: valid=%v digest_match=%v workload_id_match=%v detail=%q err=%v",
		aciKeyset.EndorsementValid, aciKeyset.KeysetDigestMatch, aciKeyset.WorkloadIDMatch, aciKeyset.Detail, aciKeyset.Err)

	// Build report with provider defaults — same production allow_fail
	// policy (serveAllowFail("venice")) as the dstack venice test.
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
		ACIKeyset:         aciKeyset,
		Policy:            modelPolicy,
		SupplyChainPolicy: venice.SupplyChainPolicy(),
		AllowFail:         serveAllowFail("venice"),
		Inapplicable:      attestation.DefaultInapplicableFactors(),
	})

	logReportFactors(t, report)

	assertVeniceACIReport(t, report)
}

func assertVeniceACIReport(t *testing.T, report *attestation.VerificationReport) {
	t.Helper()

	// Core hardware/crypto attestation must pass, exactly as for dstack.
	// (tee_cert_chain, tee_quote_signature, nvidia_signature, nvidia_claims,
	// etc. are hard-asserted by commonModelAssertions below.)
	assertMustPass(t, report, []string{
		"nonce_match",
		"tee_quote_present",
		"tee_quote_structure",
		"tee_debug_disabled",
		"tee_measurement",
		"signing_key_present",
		"tee_reportdata_binding",
		"nvidia_payload_present",
		"nvidia_nonce_client_bound",
		"e2ee_capable",
		"event_log_integrity",
	})

	// ACI/1-specific: the keyset endorsement factor is the cryptographic
	// substitute for compose binding on this format. It must both pass and
	// be enforced — never waived — per evalACIKeysetEndorsement's contract.
	aciFactor := findFactor(t, report, "aci_keyset_endorsement")
	if aciFactor.Status != attestation.Pass {
		t.Errorf("aci_keyset_endorsement: got %s, want Pass (detail: %s)", aciFactor.Status, aciFactor.Detail)
	}
	if !aciFactor.Enforced {
		t.Errorf("aci_keyset_endorsement: expected Enforced=true, got false (detail: %s)", aciFactor.Detail)
	}

	// Venice uses E2EE, not TLS binding.
	assertFactorStatus(t, report, "tls_key_binding", attestation.Skip)

	// ACI/1 supply-chain gaps: these must Fail (a real, permanent absence —
	// see evalComposeBinding/evalSigstoreVerification) but must NOT be
	// enforced (waived via the global DefaultAllowFail policy), so ACI/1
	// keeps serving degraded-but-visible instead of being blocked.
	waivedNames := []string{"compose_binding", "sigstore_verification", "build_transparency_log"}
	assertMustFail(t, report, waivedNames, "ACI/1 has no compose manifest / image digests")
	for _, name := range waivedNames {
		if f := findFactor(t, report, name); f.Enforced {
			t.Errorf("factor %s: expected Enforced=false (waived), got true", name)
		}
	}
	// WaivedFactors() is the definitive "degraded" set (Fail && !Enforced);
	// every gap above must actually surface through it, matching the
	// dashboard's degraded badge.
	waivedSet := make(map[string]bool, len(report.WaivedFactors()))
	for _, f := range report.WaivedFactors() {
		waivedSet[f.Name] = true
	}
	for _, name := range waivedNames {
		if !waivedSet[name] {
			t.Errorf("expected %s in report.WaivedFactors(), not found", name)
		}
	}

	commonModelAssertions(t, report)

	if report.Blocked() {
		t.Errorf("expected Blocked()==false (ACI/1 serves degraded), but blocked factors: %v", report.BlockedFactors())
	}

	if report.Passed < 10 {
		t.Errorf("expected at least 10 passing factors, got %d", report.Passed)
	}
	logReportResult(t, report)
}
