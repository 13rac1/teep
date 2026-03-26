package neardirect

import "github.com/13rac1/teep/internal/attestation"

// GithubOIDC is the GitHub Actions OIDC issuer URL used in Fulcio certificates.
const GithubOIDC = "https://token.actions.githubusercontent.com"

// SupplyChainPolicy returns the supply chain policy for the neardirect
// provider. Venice shares this policy.
func SupplyChainPolicy() *attestation.SupplyChainPolicy {
	return &attestation.SupplyChainPolicy{Images: []attestation.ImageProvenance{
		{Repo: "datadog/agent", ModelTier: true, Provenance: attestation.SigstorePresent,
			KeyFingerprint: "25bcab4ec8eede1e3091a14692126798c23986832ae6e5948d6f7eb0a928ab0b"},
		{Repo: "certbot/dns-cloudflare", ModelTier: true, Provenance: attestation.ComposeBindingOnly},
		{Repo: "nearaidev/compose-manager", ModelTier: true, Provenance: attestation.FulcioSigned,
			NoDSSE:       true, // Rekor DSSE envelope has no signatures as of 2026-03
			OIDCIssuer:   GithubOIDC,
			OIDCIdentity: "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master",
			SourceRepos: []string{
				"nearai/compose-manager",
				"https://github.com/nearai/compose-manager",
			}},
	}}
}
