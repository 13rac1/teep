package verify

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/chutes"
	"github.com/13rac1/teep/internal/provider/chutes/chutestest"
)

// nvidiaClaimsOf returns the nvidia_claims result of a report on raw.
func nvidiaClaimsOf(t *testing.T, raw *attestation.RawAttestation, nonce attestation.Nonce, nv *attestation.NvidiaVerifyResult) attestation.FactorResult {
	t.Helper()
	report := attestation.BuildReport(&attestation.ReportInput{Provider: "chutes", Model: "m", Raw: raw, Nonce: nonce, Nvidia: nv, Inapplicable: chutes.InapplicableFactors()})
	for _, f := range report.Factors {
		if f.Name == attestation.FactorNvidiaClaims {
			return f
		}
	}
	t.Fatal("no nvidia_claims factor")
	return attestation.FactorResult{}
}

// GPU evidence that does not verify, before or during the SPDM check, has
// no claims that teep checked: nvidia_claims fails.
func TestVerifyNVIDIA_UnverifiedGPUEvidence_ClaimsFail(t *testing.T) {
	const want = "NVIDIA evidence was not verified; claims not checked"
	nonce := attestation.NewNonce()
	noKey := &attestation.RawAttestation{
		BackendFormat: attestation.FormatChutes,
		GPUEvidence:   []attestation.GPUEvidence{{Arch: "HOPPER", Certificate: "c", Evidence: "e"}},
	}
	eat, _ := verifyNVIDIA(context.Background(), noKey, nonce, nil, true, attestation.DefaultNVIDIAVerifier())
	if f := nvidiaClaimsOf(t, noKey, nonce, eat); f.Status != attestation.Fail || f.Detail != want {
		t.Errorf("no instance key: nvidia_claims = %s %q", f.Status, f.Detail)
	}

	c := chutestest.Captures(t, "../integration/testdata")[0]
	raw := *c.Raw
	raw.GPUEvidence = append([]attestation.GPUEvidence(nil), c.Raw.GPUEvidence...)
	if len(raw.GPUEvidence) == 0 || len(raw.GPUEvidence[0].Evidence) < 4 {
		t.Fatalf("%s: no GPU evidence to change", c.Name)
	}
	raw.GPUEvidence[0].Evidence = "AAAA" + raw.GPUEvidence[0].Evidence[4:]
	eat, _ = verifyNVIDIA(context.Background(), &raw, c.Nonce, nil, true, attestation.DefaultNVIDIAVerifier())
	if eat == nil || eat.SignatureErr == nil || eat.Format != "SPDM" {
		t.Fatalf("changed SPDM evidence: result %+v, want an SPDM signature error", eat)
	}
	if f := nvidiaClaimsOf(t, &raw, c.Nonce, eat); f.Status != attestation.Fail || f.Detail != want {
		t.Errorf("changed SPDM evidence: nvidia_claims = %s %q", f.Status, f.Detail)
	}
}
