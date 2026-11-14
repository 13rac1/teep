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

// A model in its provider's unprobed-model table keeps e2ee_usable as a
// deferred, enforced Skip with the full detail, and gets no probe; any other
// model, a blocked report, E2EE off, a provider without a table and a replay
// with a captured probe outcome keep their path.
func TestMarkUnprobedModel(t *testing.T) {
	opts := func(provider, model string, e2ee bool) *Options {
		return &Options{ProviderName: provider, ModelName: model, Provider: &config.Provider{Name: provider, E2EE: e2ee}}
	}
	for _, tc := range []struct{ provider, model, kind string }{
		{"neardirect", "Qwen/Qwen3-Embedding-0.6B", "embeddings"},
		{"nearcloud", "Qwen/Qwen3-Embedding-0.6B", "embeddings"},
		{"tinfoil_v3_cloud", "nomic-embed-text", "/v1/embeddings"},
		{"tinfoil_v3_cloud", "voxtral-mini-4b-realtime", "/v1/realtime"},
		{"phalacloud", "jaredpalmer/kev-4b", "/v1/systemone"},
	} {
		provider := tc.provider
		r := unprobedReport(false)
		if !markUnprobedModel(opts(provider, tc.model, true), r) {
			t.Fatalf("%s: listed model %s was probed", provider, tc.model)
		}
		f := e2eeFactor(r)
		want := unprobedDetail(tc.kind)
		if want != "not probed: the model serves "+tc.kind+"; the verify probe sends a chat completion" {
			t.Fatalf("detail %q", want)
		}
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
		{"tinfoil with E2EE off", opts("tinfoil_v3_cloud", "nomic-embed-text", false), false},
		{"tinfoil chat model", opts("tinfoil_v3_cloud", "gpt-oss-120b", true), false},
		{"model of another provider's table", opts("tinfoil_v3_cloud", "Qwen/Qwen3-Embedding-0.6B", true), false},
		{"phalacloud chat model", opts("phalacloud", "z-ai/glm-5.3", true), false},
		{"provider without a table", opts("chutes", "Qwen/Qwen3-Embedding-0.6B", true), false},
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

// For an ACI/1 report, a skipped probe also states in the deferred
// aci_receipt_verified Skip that no probe ran and why.
func TestMarkUnprobedModelReceipt(t *testing.T) {
	r := unprobedReport(false)
	r.Factors = append(r.Factors, attestation.FactorResult{
		Name: attestation.FactorACIReceiptVerified, Status: attestation.Skip, Enforced: true, Deferred: true,
		Detail: "no probe: teep serve checks the receipt of every response",
	})
	opts := &Options{ProviderName: "phalacloud", ModelName: "jaredpalmer/kev-4b", Provider: &config.Provider{Name: "phalacloud", E2EE: true}}
	if !markUnprobedModel(opts, r) {
		t.Fatal("listed model was probed")
	}
	want := "no probe: the model serves /v1/systemone; the verify probe sends a chat completion"
	for _, f := range r.Factors {
		if f.Name == attestation.FactorACIReceiptVerified &&
			(f.Status != attestation.Skip || !f.Deferred || !f.Enforced || f.Detail != want) {
			t.Errorf("aci_receipt_verified = %+v, want deferred enforced Skip %q", f, want)
		}
	}
	if r.Blocked() {
		t.Error("report blocked")
	}
}
