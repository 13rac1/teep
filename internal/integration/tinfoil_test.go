package integration

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/verify"
)

func TestIntegration_Tinfoil_Fixture(t *testing.T) {
	env := loadFixture(t, "tinfoil_v3_cloud_tinfoil")
	baseURL := extractBaseURL(t, env.entries)
	cfg, cp := buildVerifyRunConfig(env.manifest.Provider, baseURL)

	report, err := verify.Run(context.Background(), &verify.Options{
		Config:           cfg,
		Provider:         cp,
		ProviderName:     env.manifest.Provider,
		ModelName:        env.manifest.Model,
		Offline:          false,
		Client:           env.client,
		Nonce:            env.nonce,
		CapturedE2EE:     fixtureE2EEResult(env.manifest.E2EE),
		VerificationTime: fixtureVerificationTime(&env),
	})
	if err != nil {
		t.Fatalf("verify.Run: %v", err)
	}

	logReportFactors(t, report)
	assertNoEnforcedFailures(t, report)
	// The router is a gateway, so its evidence is asserted on the gateway
	// factors. SEE: TestVerifyRun_Tinfoil_Fixture.
	assertMustPass(t, report, []string{
		"nonce_match",
		"gateway_tee_quote_present",
		"gateway_tee_reportdata_binding",
		"signing_key_present",
		"e2ee_capable",
		"e2ee_usable",
		"tls_key_binding",
	})
	logReportResult(t, report)
}

func TestIntegration_TinfoilDirect_Fixture(t *testing.T) {
	env := loadFixture(t, "tinfoil_v3_direct_tinfoil")
	cfg, cp := buildVerifyRunConfig(env.manifest.Provider, "https://inference.tinfoil.sh")

	report, err := verify.Run(context.Background(), &verify.Options{
		Config:           cfg,
		Provider:         cp,
		ProviderName:     env.manifest.Provider,
		ModelName:        env.manifest.Model,
		Offline:          false,
		Client:           env.client,
		Nonce:            env.nonce,
		CapturedE2EE:     fixtureE2EEResult(env.manifest.E2EE),
		VerificationTime: fixtureVerificationTime(&env),
	})
	if err != nil {
		t.Fatalf("verify.Run: %v", err)
	}

	logReportFactors(t, report)

	assertNoEnforcedFailures(t, report)
	assertMustPass(t, report, []string{
		"nonce_match",
		"tee_quote_present",
		"tee_reportdata_binding",
		"signing_key_present",
		"e2ee_capable",
		"e2ee_usable",
		"tls_key_binding",
	})
	logReportResult(t, report)
}
