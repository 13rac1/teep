package nanogpt

import "github.com/13rac1/teep/internal/attestation"

// DefaultMeasurementPolicy returns the default TDX measurement allowlists for
// NanoGPT. NanoGPT runs on varied dstack configurations (0.5.4.1 and 0.5.5)
// with multiple hardware profiles, so the RTMR allowlists are broader than
// single-deployment providers. Ships WarnOnly: true.
func DefaultMeasurementPolicy() attestation.MeasurementPolicy {
	p := attestation.DstackBaseMeasurementPolicy()
	p.RTMRAllow[0] = map[string]struct{}{
		// dstack-nvidia-0.5.4.1 hardware profile
		"6ffe4a2c12f07eccb857f70f370a5af848a7062905cd95adc43abb1f62c39e330aa3c8aeb8f162656c025f3f527600f1": {},
		// dstack-nvidia-0.5.5 hardware profile
		"fb14dc139f33d6fcf474bc8332cac001259fb31cfbcb6b34d4ceeb552a2c4466884a0cbde45ad98a05c5c060c23ad65a": {},
	}
	p.RTMRAllow[1] = map[string]struct{}{
		"c0445b704e4c48139496ae337423ddb1dcee3a673fd5fb60a53d562f127d235f11de471a7b4ee12c9027c829786757dc": {},
		"6e1afb7464ed0b941e8f5bf5b725cf1df9425e8105e3348dca52502f27c453f3018a28b90749cf05199d5a17820101a7": {},
		"920eb831509b58bf83a554b5377dd5ce26d3f5182f14d33622ac24c1d343a0fa3c7bde746e55098ca30baf784dfd2556": {},
		"a7b523278d4f914ee8df0ec80cd1c3d498cbf1152b0c5eaf65bad9425072874a3fcf891e8b01713d3d9937e3e0d26c15": {},
	}
	p.RTMRAllow[2] = map[string]struct{}{
		"54a76ae236a9ab1699379c54d70252cd8e6d20ae398fd8cdb240e39bf3a51074aeeee255a375772b8b431421a5435a0d": {},
		"f1d5f8b1fd4a198f42468cbf26d9394ae59f4cb7f7b0664dd65e40086def32e943e2b352485eab35a76eb1f890745e7b": {},
		"dad4e81e61ca324c09ecc048a166403f69e71a8ac31dbe29eefc89a940112ff0f8d4ca101894886eea1e9b1da6ae436f": {},
		"056e8b649fdb9bb9cd2bfa6d5686121f770593613f923c777394d2a608e4dc3816191ad3a64b5a0a2f9a0a86d154c70b": {},
		"24847f5c5a2360d030bc4f7b8577ce32e87c4d051452c937e91220cab69542daef83433947c492b9c201182fc9769bbe": {},
	}
	return p
}

// SupplyChainPolicy returns the supply chain policy for NanoGPT.
// All images use tag-based references (no @sha256: pinning), so security
// relies on the compose manifest being bound to MRConfigID via compose_binding.
func SupplyChainPolicy() *attestation.SupplyChainPolicy {
	return &attestation.SupplyChainPolicy{Images: []attestation.ImageProvenance{
		{Repo: "alpine", ModelTier: true, Provenance: attestation.ComposeBindingOnly},
		{Repo: "dstacktee/dstack-ingress", ModelTier: true, Provenance: attestation.ComposeBindingOnly},
		{Repo: "dstacktee/vllm-proxy", ModelTier: true, Provenance: attestation.ComposeBindingOnly},
		{Repo: "haproxy", ModelTier: true, Provenance: attestation.ComposeBindingOnly},
		{Repo: "lmsysorg/sglang", ModelTier: true, Provenance: attestation.ComposeBindingOnly},
		{Repo: "mondaylord/vllm-openai", ModelTier: true, Provenance: attestation.ComposeBindingOnly},
		{Repo: "phalanetwork/vllm-proxy", ModelTier: true, Provenance: attestation.ComposeBindingOnly},
		{Repo: "python", ModelTier: true, Provenance: attestation.ComposeBindingOnly},
		{Repo: "redis", ModelTier: true, Provenance: attestation.ComposeBindingOnly},
		{Repo: "vllm/vllm-openai", ModelTier: true, Provenance: attestation.ComposeBindingOnly},
	}}
}
