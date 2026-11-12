package neardirect

import "github.com/13rac1/teep/internal/attestation"

// GithubOIDC is the GitHub Actions OIDC issuer URL used in Fulcio certificates.
const GithubOIDC = "https://token.actions.githubusercontent.com"

// DefaultMeasurementPolicy returns the default TDX measurement allowlists for
// the neardirect provider, built from the shared dstack baselines plus
// neardirect-observed RTMR values.
func DefaultMeasurementPolicy() attestation.MeasurementPolicy {
	p := attestation.DstackBaseMeasurementPolicy()
	p.RTMRAllow[0] = map[string]struct{}{
		"bc122d143ab768565ba5c3774ff5f03a63c89a4df7c1f5ea38d3bd173409d14f8cbdcc36d40e703cccb996a9d9687590": {},
	}
	p.RTMRAllow[1] = map[string]struct{}{
		"c0445b704e4c48139496ae337423ddb1dcee3a673fd5fb60a53d562f127d235f11de471a7b4ee12c9027c829786757dc": {},
		// dstack-nvidia-0.5.11.
		"ff61e68fa04516b1813d2d478397a97a58f9ccc402b6d96fb73f5e5104a4acf155913caec99a0c19afc16ae0f3a77726": {},
	}
	p.RTMRAllow[2] = map[string]struct{}{
		"564622c7ddc55a53272cc9f0956d29b3f7e0dd18ede432720b71fd89e5b5d76cb0b99be7b7ff2a6a92b89b6b01643135": {},
		// dstack-nvidia-0.5.11.
		"4d662c04766145dfe084fd014969b19c387afe9bb1d4f972c6968d28a7a8b4937c414603a2cf446105eddce67a86f9ce": {},
	}
	return p
}

// SupplyChainPolicy returns the supply chain policy for the neardirect
// provider. Venice shares this policy.
func SupplyChainPolicy() *attestation.SupplyChainPolicy {
	return &attestation.SupplyChainPolicy{Images: []attestation.ImageProvenance{
		{Repo: "datadog/agent", ModelTier: true, Provenance: attestation.SigstorePresent,
			KeyFingerprint: "25bcab4ec8eede1e3091a14692126798c23986832ae6e5948d6f7eb0a928ab0b"},
		{Repo: "certbot/dns-cloudflare", ModelTier: true, Provenance: attestation.ComposeBindingOnly},
		{Repo: "otel/opentelemetry-collector-contrib", ModelTier: true, Provenance: attestation.SigstorePresent,
			KeyFingerprint: "a8bd282038915eaf2ca9ac7d4cc2605ce6e7ae8aed5b19b06370e285f8a9d72e"},
		{Repo: "nearaidev/compose-manager", ModelTier: true, Provenance: attestation.FulcioSigned,
			// Rekor stores signatures and payload hashes, but not the full
			// envelope required by teep's DSSE verifier. This exception does
			// not establish independent publisher-signature verification.
			// SEE: docs/providers/near/near_attestation.md#teep-publisher-verification-defect
			NoDSSE:     true,
			OIDCIssuer: GithubOIDC,
			OIDCIdentities: []string{
				"https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master",
				"https://github.com/nearai/compose-manager/.github/workflows/promote.yml@refs/heads/master",
			},
			SourceRepos: []string{
				"nearai/compose-manager",
				"https://github.com/nearai/compose-manager",
			}},
		{Repo: "nearaidev/compose-manager-launcher", ModelTier: true, Provenance: attestation.FulcioSigned,
			// The same Rekor envelope limitation applies to the launcher.
			NoDSSE:     true,
			OIDCIssuer: GithubOIDC,
			OIDCIdentities: []string{
				"https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master",
				"https://github.com/nearai/compose-manager/.github/workflows/promote.yml@refs/heads/master",
			},
			SourceRepos: []string{
				"nearai/compose-manager",
				"https://github.com/nearai/compose-manager",
			}},
	}}
}
