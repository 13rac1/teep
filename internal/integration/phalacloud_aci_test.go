package integration

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/13rac1/teep/internal/provider/phalacloud"
	"github.com/13rac1/teep/internal/verify"
)

// TestVerifyRun_PhalaCloudACI_Fixture replays a live Phala Cloud capture of
// the private-ai-gateway's ACI/1 gateway variant through verify.Run with the
// production policy. The gateway evidence, the key custody chain to the
// shared gateway pins and the evidence-bound client nonce must pass; the
// factors that describe the inference host and the unnamed backend are
// allowed failures.
func TestVerifyRun_PhalaCloudACI_Fixture(t *testing.T) {
	env := loadFixture(t, "phalacloud_aci")
	baseURL := extractBaseURL(t, env.entries)
	if baseURL != "https://tee.redpill.ai" {
		t.Fatalf("fixture base URL = %q, want the TEE-only domain https://tee.redpill.ai", baseURL)
	}
	cfg, cp := buildVerifyRunConfig(env.manifest.Provider, baseURL)
	report, err := verify.Run(context.Background(), &verify.Options{
		Config:           cfg,
		Provider:         cp,
		ProviderName:     env.manifest.Provider,
		ModelName:        env.manifest.Model,
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
	assertMustPass(t, report, []string{
		"nonce_match",
		"signing_key_present",
		"aci_key_custody",
		"nvidia_signature",
		"nvidia_nonce_client_bound",
		"gateway_nonce_match",
		"gateway_tee_quote_present",
		"gateway_tee_quote_structure",
		"gateway_tee_cert_chain",
		"gateway_tee_quote_signature",
		"gateway_tee_debug_disabled",
		"gateway_tee_measurement",
		"gateway_tee_reportdata_binding",
		"gateway_compose_binding",
		"gateway_event_log_integrity",
	})
	for _, name := range []string{"tee_quote_present", "tee_reportdata_binding", "aci_backend_named"} {
		f := findFactor(t, report, name)
		if f.Status != attestation.Fail || f.Enforced {
			t.Errorf("%s: status=%s enforced=%v, want an allowed Fail", name, f.Status, f.Enforced)
		}
	}
	if f := findFactor(t, report, "nonce_match"); !strings.Contains(f.Detail, "no echoed nonce") {
		t.Errorf("nonce_match detail = %q, want the evidence-bound nonce", f.Detail)
	}
}

// A gateway identity outside the pins fails the key custody chain: the
// accepted KMS root and app id decide which gateway teep accepts.
func TestPhalaCloudACI_PinsDecideCustody(t *testing.T) {
	env := loadFixture(t, "phalacloud_aci")
	raw, err := phalacloud.ParseAttestationResponse(context.Background(), env.entries[0].Body)
	if err != nil {
		t.Fatalf("parse fixture attestation: %v", err)
	}
	at := fixtureVerificationTime(&env)
	if r := aci.VerifyKeyset(raw, at, aci.GatewayPins()); r == nil || !r.CustodyChainValid {
		t.Fatalf("custody with the gateway pins: %+v", r)
	}
	pins := aci.GatewayPins()
	for _, tc := range []struct {
		name string
		pins aci.Pins
	}{
		{"other KMS root", aci.Pins{KMSRoots: []string{"03" + strings.Repeat("11", 32)}, GatewayAppIDs: pins.GatewayAppIDs}},
		{"other app id", aci.Pins{KMSRoots: pins.KMSRoots, GatewayAppIDs: []string{strings.Repeat("22", 20)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := aci.VerifyKeyset(raw, at, tc.pins)
			if r == nil || r.CustodyChainValid {
				t.Fatalf("custody with %s passed: %+v", tc.name, r)
			}
		})
	}
}

// Concurrent verification of the Venice and Phala Cloud ACI/1 fixtures keeps
// each provider's policy: both reach the same gateway with the shared pins,
// and only Venice binds its E2EE key through the gateway REPORTDATA factor.
func TestVerifyRun_ConcurrentACIProviders(t *testing.T) {
	venice := loadFixture(t, "venice_aci")
	phala := loadFixture(t, "phalacloud_aci")
	type result struct {
		provider string
		report   *attestation.VerificationReport
		err      error
	}
	results := make(chan result, 4)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 2 {
		for _, env := range []fixtureEnv{venice, phala} {
			cfg, cp := buildVerifyRunConfig(env.manifest.Provider, extractBaseURL(t, env.entries))
			wg.Go(func() {
				<-start
				report, err := verify.Run(context.Background(), &verify.Options{
					Config:           cfg,
					Provider:         cp,
					ProviderName:     env.manifest.Provider,
					ModelName:        env.manifest.Model,
					Client:           &http.Client{Transport: capture.NewReplayTransport(env.entries)},
					Nonce:            env.nonce,
					CapturedE2EE:     fixtureE2EEResult(env.manifest.E2EE),
					VerificationTime: fixtureVerificationTime(&env),
				})
				results <- result{env.manifest.Provider, report, err}
			})
		}
	}
	close(start)
	wg.Wait()
	close(results)
	for got := range results {
		if got.err != nil {
			t.Errorf("verify %s: %v", got.provider, got.err)
			continue
		}
		assertNoEnforcedFailures(t, got.report)
		if got.report.Provider != got.provider {
			t.Errorf("report provider = %q, want %q", got.report.Provider, got.provider)
		}
		if f := findFactor(t, got.report, "aci_key_custody"); f.Status != attestation.Pass {
			t.Errorf("%s: aci_key_custody = %v %q", got.provider, f.Status, f.Detail)
		}
		// Only Venice encrypts to the gateway key; Phala Cloud has no E2EE.
		if gatewayBound := got.report.E2EEBindingFactor == attestation.FactorGWReportData; gatewayBound != (got.provider == "venice") {
			t.Errorf("%s: E2EEBindingFactor = %q", got.provider, got.report.E2EEBindingFactor)
		}
	}
}
