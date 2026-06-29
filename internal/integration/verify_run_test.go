package integration

import (
	"context"
	"os"
	"testing"

	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/verify"
)

// buildVerifyRunConfig constructs a minimal config for verify.Run replay tests.
// No API key — the E2EE test will return NoAPIKey and skip live network calls.
func buildVerifyRunConfig(providerName, baseURL string) (*config.Config, *config.Provider) {
	cp := &config.Provider{
		Name:    providerName,
		BaseURL: baseURL,
		APIKey:  "",
	}
	return &config.Config{Providers: map[string]*config.Provider{providerName: cp}}, cp
}

func TestVerifyRun_Venice_Fixture(t *testing.T) {
	env := loadFixture(t, "venice")
	baseURL := extractBaseURL(t, env.entries)
	t.Logf("base URL: %s", baseURL)

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
	logReportScore(t, report)
	assertNoEnforcedFailures(t, report)

	assertMustPass(t, report, []string{"nonce_match", "tee_quote_present", "signing_key_present"})

	if report.Passed < 5 {
		t.Errorf("expected at least 5 passing factors, got %d", report.Passed)
	}
}

func TestVerifyRun_NearDirect_Fixture(t *testing.T) {
	env := loadFixture(t, "neardirect")
	baseURL := extractBaseURL(t, env.entries)
	t.Logf("base URL: %s", baseURL)

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
	logReportScore(t, report)
	assertNoEnforcedFailures(t, report)

	assertMustPass(t, report, []string{"nonce_match", "tee_quote_present"})

	if report.Passed < 5 {
		t.Errorf("expected at least 5 passing factors, got %d", report.Passed)
	}
}

func TestVerifyReplay_Venice_Fixture(t *testing.T) {
	fdir := findFixtureDir(t, "venice")

	_, entries, err := capture.Load(fdir)
	if err != nil {
		t.Fatalf("load capture: %v", err)
	}
	baseURL := extractBaseURL(t, entries)

	cfgLoader := func(providerName string) (*config.Config, *config.Provider, error) {
		cfg, cp := buildVerifyRunConfig(providerName, baseURL)
		return cfg, cp, nil
	}

	report, reportText, err := verify.Replay(context.Background(), fdir, cfgLoader)
	if err != nil {
		t.Fatalf("verify.Replay: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if reportText == "" {
		t.Error("expected non-empty report text")
	}
	logReportScore(t, report)
	assertNoEnforcedFailures(t, report)

	assertMustPass(t, report, []string{"nonce_match", "tee_quote_present"})
}

func TestVerifyRun_WithCapture_Venice(t *testing.T) {
	env := loadFixture(t, "venice")
	baseURL := extractBaseURL(t, env.entries)
	cfg, cp := buildVerifyRunConfig(env.manifest.Provider, baseURL)

	captureDir := t.TempDir()

	report, err := verify.Run(context.Background(), &verify.Options{
		Config:           cfg,
		Provider:         cp,
		ProviderName:     env.manifest.Provider,
		ModelName:        env.manifest.Model,
		Offline:          false,
		Client:           env.client,
		Nonce:            env.nonce,
		CaptureDir:       captureDir,
		CapturedE2EE:     fixtureE2EEResult(env.manifest.E2EE),
		VerificationTime: fixtureVerificationTime(&env),
	})
	if err != nil {
		t.Fatalf("verify.Run with capture: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	logReportScore(t, report)
	assertNoEnforcedFailures(t, report)

	dirs, readErr := os.ReadDir(captureDir)
	if readErr != nil {
		t.Fatalf("read capture dir: %v", readErr)
	}
	if len(dirs) == 0 {
		t.Error("expected at least one capture subdirectory")
	}
	t.Logf("capture dir: %d subdirectory(ies)", len(dirs))
}

func TestVerifyRun_Tinfoil_Fixture(t *testing.T) {
	env := loadFixture(t, "tinfoil_v3_cloud")
	baseURL := extractBaseURL(t, env.entries)
	t.Logf("base URL: %s", baseURL)

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
	logReportScore(t, report)
	assertNoEnforcedFailures(t, report)

	// Tinfoil fixture is SEV-SNP with AMD KDS responses captured.
	// verify.Run uses online SEV verifier; replay client serves KDS certs.
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

	if report.Passed < 13 {
		t.Errorf("expected at least 13 passing factors, got %d", report.Passed)
	}
}

func TestVerifyRun_TinfoilDirect_Fixture(t *testing.T) {
	env := loadFixture(t, "tinfoil_v3_direct")

	// Direct mode uses the proxy discovery endpoint on inference.tinfoil.sh
	// to resolve model → backend enclave domain, then fetches attestation
	// from the resolved enclave.
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
	logReportScore(t, report)
	assertNoEnforcedFailures(t, report)

	// Tinfoil direct fixture is TDX with Intel PCS collateral, NVIDIA GPU
	// evidence, and Tinfoil Sigstore supply-chain evidence captured.
	assertMustPass(t, report, []string{
		"nonce_match",
		"tee_quote_present",
		"tee_quote_structure",
		"tee_cert_chain",
		"tee_quote_signature",
		"tee_debug_disabled",
		"tee_measurement",
		"tee_boot_config",
		"tee_reportdata_binding",
		"tee_tcb_current",
		"tee_tcb_not_revoked",
		"signing_key_present",
		"e2ee_capable",
		"e2ee_usable",
		"tls_key_binding",
		"nvidia_payload_present",
		"nvidia_signature",
		"nvidia_claims",
		"cpu_gpu_chain",
		"measured_model_weights",
		"build_transparency_log",
		"component_recognition",
		"provider_signer_recognition",
		"component_signature_recognition",
		"sigstore_code_verified",
	})

	if report.Passed < 24 {
		t.Errorf("expected at least 24 passing factors, got %d", report.Passed)
	}
}
