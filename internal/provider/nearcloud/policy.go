package nearcloud

import (
	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

// SupplyChainPolicy returns the supply chain policy for nearcloud.
// Starts from the neardirect base (model tier) and adds gateway images.
func SupplyChainPolicy() *attestation.SupplyChainPolicy {
	p := neardirect.SupplyChainPolicy()
	// datadog/agent is also a gateway image in nearcloud.
	for i := range p.Images {
		if p.Images[i].Repo == "datadog/agent" {
			p.Images[i].GatewayTier = true
		}
	}
	p.Images = append(p.Images,
		attestation.ImageProvenance{Repo: "nearaidev/dstack-vpc-client", GatewayTier: true, Provenance: attestation.FulcioSigned,
			NoDSSE:       true,
			OIDCIssuer:   neardirect.GithubOIDC,
			OIDCIdentity: "https://github.com/nearai/dstack-vpc-client/.github/workflows/build.yml@refs/heads/main",
			SourceRepos:  []string{"nearai/dstack-vpc-client", "https://github.com/nearai/dstack-vpc-client"}},
		attestation.ImageProvenance{Repo: "nearaidev/dstack-vpc", GatewayTier: true, Provenance: attestation.FulcioSigned,
			NoDSSE:       true,
			OIDCIssuer:   neardirect.GithubOIDC,
			OIDCIdentity: "https://github.com/nearai/dstack-vpc/.github/workflows/build.yml@refs/heads/main",
			SourceRepos:  []string{"nearai/dstack-vpc", "https://github.com/nearai/dstack-vpc"}},
		// alpine: third-party image built by Docker across varying CI
		// systems (GitHub Actions, Google Cloud Build) with unstable
		// branch refs. Only transparency-log presence is verifiable.
		attestation.ImageProvenance{Repo: "alpine", GatewayTier: true, Provenance: attestation.SigstorePresent},
		attestation.ImageProvenance{Repo: "nearaidev/cloud-api", GatewayTier: true, Provenance: attestation.FulcioSigned,
			NoDSSE:       true,
			OIDCIssuer:   neardirect.GithubOIDC,
			OIDCIdentity: "https://github.com/nearai/cloud-api/.github/workflows/build.yml@refs/heads/main",
			SourceRepos:  []string{"nearai/cloud-api", "https://github.com/nearai/cloud-api"}},
		attestation.ImageProvenance{Repo: "nearaidev/cvm-ingress", GatewayTier: true, Provenance: attestation.FulcioSigned,
			NoDSSE:       true,
			OIDCIssuer:   neardirect.GithubOIDC,
			OIDCIdentity: "https://github.com/nearai/cvm-ingress/.github/workflows/build-push.yml@refs/heads/main",
			SourceRepos:  []string{"nearai/cvm-ingress", "https://github.com/nearai/cvm-ingress"}},
	)
	return p
}
