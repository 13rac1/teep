package verify

import (
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
)

func unprobedReport(blocked bool) *attestation.VerificationReport {
	r := &attestation.VerificationReport{Factors: []attestation.FactorResult{
		{Name: attestation.FactorE2EEUsable, Status: attestation.Skip, Enforced: true, Deferred: true},
	}}
	if blocked {
		r.Factors = append(r.Factors, attestation.FactorResult{Name: attestation.FactorTEEReportData, Status: attestation.Fail, Enforced: true})
	}
	return r
}

func e2eeFactor(r *attestation.VerificationReport) attestation.FactorResult {
	for _, f := range r.Factors {
		if f.Name == attestation.FactorE2EEUsable {
			return f
		}
	}
	return attestation.FactorResult{}
}

// A listed non-chat NEAR model keeps e2ee_usable as a deferred, enforced
// Skip with the full detail, and gets no probe; any other model, a blocked
// report, the TLS-only mode, another provider and a replay with a captured
// probe outcome keep their path.
func TestMarkUnprobedModel(t *testing.T) {
	opts := func(provider, model string, e2ee bool) *Options {
		return &Options{ProviderName: provider, ModelName: model, Provider: &config.Provider{Name: provider, E2EE: e2ee}}
	}
	for _, provider := range []string{"neardirect", "nearcloud"} {
		r := unprobedReport(false)
		if !markUnprobedModel(opts(provider, "Qwen/Qwen3-Embedding-0.6B", true), r) {
			t.Fatalf("%s: listed model was probed", provider)
		}
		f := e2eeFactor(r)
		want := "not probed: the model serves embeddings; the verify probe sends a chat completion"
		if f.Status != attestation.Skip || !f.Deferred || !f.Enforced || f.Detail != want {
			t.Errorf("%s: e2ee_usable %v deferred=%v enforced=%v %q, want deferred enforced Skip %q",
				provider, f.Status, f.Deferred, f.Enforced, f.Detail, want)
		}
		if r.Blocked() || r.NotApplicableCount != 0 {
			t.Errorf("%s: blocked=%v n/a=%d", provider, r.Blocked(), r.NotApplicableCount)
		}
	}
	for _, tc := range []struct {
		name    string
		opts    *Options
		blocked bool
	}{
		{"chat model", opts("nearcloud", "z-ai/glm-5.3-flash", true), false},
		{"blocked report", opts("nearcloud", "Qwen/Qwen3-Embedding-0.6B", true), true},
		{"TLS-only neardirect", opts("neardirect", "Qwen/Qwen3-Embedding-0.6B", false), false},
		{"other provider", opts("phalacloud", "Qwen/Qwen3-Embedding-0.6B", true), false},
		{"replay with a captured probe outcome", func() *Options {
			o := opts("nearcloud", "Qwen/Qwen3-Embedding-0.6B", true)
			o.CapturedE2EE = &attestation.E2EETestResult{Attempted: true}
			return o
		}(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := unprobedReport(tc.blocked)
			if markUnprobedModel(tc.opts, r) {
				t.Fatal("model skipped the probe")
			}
			if f := e2eeFactor(r); f.Status != attestation.Skip || f.Detail != "" {
				t.Errorf("e2ee_usable changed to %v %q", f.Status, f.Detail)
			}
		})
	}
}
