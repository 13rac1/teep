package nanogpt

import "github.com/13rac1/teep/internal/attestation"

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
