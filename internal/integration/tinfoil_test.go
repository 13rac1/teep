package integration

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/verify"
)

func TestIntegration_Tinfoil_Fixture(t *testing.T) {
	env := loadFixture(t, "tinfoil_v3_cloud")
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
	assertMustPass(t, report, []string{"nonce_match", "tee_quote_present", "tee_reportdata_binding", "signing_key_present", "e2ee_capable", "e2ee_usable", "tls_key_binding"})
	logReportResult(t, report)
}

func TestIntegration_TinfoilDirect_Fixture(t *testing.T) {
	env := loadFixture(t, "tinfoil_v3_direct")
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
