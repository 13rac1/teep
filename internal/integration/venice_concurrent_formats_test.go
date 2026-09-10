package integration

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/verify"
)

// Different models of one provider must select policy and key binding from
// their own evidence, even when verification shares the provider configuration.
func TestVerifyRun_ConcurrentVeniceFormats(t *testing.T) {
	dstack := loadFixture(t, "venice")
	aci := loadFixture(t, "venice_aci")
	baseURL := extractBaseURL(t, dstack.entries)
	if extractBaseURL(t, aci.entries) != baseURL {
		t.Fatal("fixtures must use the same provider origin")
	}
	cfg, cp := buildVerifyRunConfig("venice", baseURL)
	type result struct {
		model   string
		binding string
		report  *attestation.VerificationReport
		err     error
	}
	results := make(chan result, 4)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 2 {
		for _, tc := range []struct {
			env     fixtureEnv
			binding string
		}{
			{dstack, attestation.FactorTEEReportData},
			{aci, attestation.FactorGWReportData},
		} {
			wg.Go(func() {
				<-start
				report, err := verify.Run(context.Background(), &verify.Options{
					Config:           cfg,
					Provider:         cp,
					ProviderName:     "venice",
					ModelName:        tc.env.manifest.Model,
					Client:           &http.Client{Transport: capture.NewReplayTransport(tc.env.entries)},
					Nonce:            tc.env.nonce,
					CapturedE2EE:     fixtureE2EEResult(tc.env.manifest.E2EE),
					VerificationTime: fixtureVerificationTime(&tc.env),
				})
				results <- result{tc.env.manifest.Model, tc.binding, report, err}
			})
		}
	}
	close(start)
	wg.Wait()
	close(results)
	for got := range results {
		if got.err != nil {
			t.Errorf("verify %s: %v", got.model, got.err)
			continue
		}
		assertNoEnforcedFailures(t, got.report)
		if got.report.Model != got.model || got.report.E2EEBindingFactor != got.binding {
			t.Errorf("%s: authorization used another model or binding factor", got.model)
		}
		core := findFactor(t, got.report, attestation.FactorTEEReportData)
		gatewayOnly := got.binding == attestation.FactorGWReportData
		if gatewayOnly && (core.Status != attestation.Fail || core.Enforced) {
			t.Error("ACI report must retain the visible, allowed model binding failure")
		}
		if !gatewayOnly && (core.Status != attestation.Pass || !core.Enforced) {
			t.Error("dstack report must enforce and pass model binding")
		}
	}
}
