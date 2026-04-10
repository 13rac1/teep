package integration

import (
	"context"
	"os"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
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
		Config:       cfg,
		Provider:     cp,
		ProviderName: env.manifest.Provider,
		ModelName:    env.manifest.Model,
		Offline:      false,
		Client:       env.client,
		Nonce:        env.nonce,
	})
	if err != nil {
		t.Fatalf("verify.Run: %v", err)
	}
	t.Logf("Score: %d/%d (passed=%d failed=%d skipped=%d)",
		report.Passed, report.Passed+report.Failed+report.Skipped,
		report.Passed, report.Failed, report.Skipped)

	assertMustPass(t, report, []string{"nonce_match", "tdx_quote_present", "signing_key_present"})

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
		Config:       cfg,
		Provider:     cp,
		ProviderName: env.manifest.Provider,
		ModelName:    env.manifest.Model,
		Offline:      false,
		Client:       env.client,
		Nonce:        env.nonce,
	})
	if err != nil {
		t.Fatalf("verify.Run: %v", err)
	}
	t.Logf("Score: %d/%d (passed=%d failed=%d skipped=%d)",
		report.Passed, report.Passed+report.Failed+report.Skipped,
		report.Passed, report.Failed, report.Skipped)

	assertMustPass(t, report, []string{"nonce_match", "tdx_quote_present"})

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

	origGetter := attestation.TDXCollateralGetter
	t.Cleanup(func() { attestation.TDXCollateralGetter = origGetter })

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
	t.Logf("Score: %d/%d", report.Passed, report.Passed+report.Failed+report.Skipped)

	assertMustPass(t, report, []string{"nonce_match", "tdx_quote_present"})
}

func TestVerifyRun_WithCapture_Venice(t *testing.T) {
	env := loadFixture(t, "venice")
	baseURL := extractBaseURL(t, env.entries)
	cfg, cp := buildVerifyRunConfig(env.manifest.Provider, baseURL)

	captureDir := t.TempDir()

	report, err := verify.Run(context.Background(), &verify.Options{
		Config:       cfg,
		Provider:     cp,
		ProviderName: env.manifest.Provider,
		ModelName:    env.manifest.Model,
		Offline:      false,
		Client:       env.client,
		Nonce:        env.nonce,
		CaptureDir:   captureDir,
	})
	if err != nil {
		t.Fatalf("verify.Run with capture: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	t.Logf("Score: %d/%d", report.Passed, report.Passed+report.Failed+report.Skipped)

	dirs, readErr := os.ReadDir(captureDir)
	if readErr != nil {
		t.Fatalf("read capture dir: %v", readErr)
	}
	if len(dirs) == 0 {
		t.Error("expected at least one capture subdirectory")
	}
	t.Logf("capture dir: %d subdirectory(ies)", len(dirs))
}
