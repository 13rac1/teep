package nearcloud

import (
	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

// DefaultMeasurementPolicy returns the default TDX measurement allowlists for
// the nearcloud model backend. Nearcloud load-balances across multiple hardware
// configurations, producing two known RTMR0 values.
func DefaultMeasurementPolicy() attestation.MeasurementPolicy {
	p := attestation.DstackBaseMeasurementPolicy()
	p.RTMRAllow[0] = map[string]struct{}{
		// Hardware config shared with venice.
		"0cb94dba1a9773d741efad49370e1e909557409a904a24a4620b6305651360952cb8111f851b03fc2a35a6c3b7bb05f6": {},
		// Hardware config shared with neardirect.
		"bc122d143ab768565ba5c3774ff5f03a63c89a4df7c1f5ea38d3bd173409d14f8cbdcc36d40e703cccb996a9d9687590": {},
	}
	p.RTMRAllow[1] = map[string]struct{}{
		"c0445b704e4c48139496ae337423ddb1dcee3a673fd5fb60a53d562f127d235f11de471a7b4ee12c9027c829786757dc": {},
		// dstack-nvidia-0.5.11.
		"ff61e68fa04516b1813d2d478397a97a58f9ccc402b6d96fb73f5e5104a4acf155913caec99a0c19afc16ae0f3a77726": {},
		// Model CVMs with os_image_hash 91fd5d69..., in live NEAR AI quotes since 2026-11-04.
		"4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec": {},
	}
	p.RTMRAllow[2] = map[string]struct{}{
		"564622c7ddc55a53272cc9f0956d29b3f7e0dd18ede432720b71fd89e5b5d76cb0b99be7b7ff2a6a92b89b6b01643135": {},
		// dstack-nvidia-0.5.11.
		"4d662c04766145dfe084fd014969b19c387afe9bb1d4f972c6968d28a7a8b4937c414603a2cf446105eddce67a86f9ce": {},
		// Model CVMs with os_image_hash 91fd5d69..., in live NEAR AI quotes since 2026-11-04.
		"bd67ab7554dc27ab03a077bc1447a1a67d0624ff547c4c809a8626f12d6a89712f8ec60e781e99b98208574065d21a71": {},
	}
	return p
}

// DefaultGatewayMeasurementPolicy returns the default TDX measurement
// allowlists for the nearcloud gateway CVM. Gateway RTMR values are from
// observed dstack gateway deployments (shared infrastructure with nanogpt).
func DefaultGatewayMeasurementPolicy() attestation.MeasurementPolicy {
	p := attestation.DstackBaseMeasurementPolicy()
	// The gateway with os_image_hash 8db40cb2..., in live NEAR AI quotes since 2026-11-04.
	p.MRTDAllow["7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173"] = struct{}{}
	p.RTMRAllow[0] = map[string]struct{}{
		"fb14dc139f33d6fcf474bc8332cac001259fb31cfbcb6b34d4ceeb552a2c4466884a0cbde45ad98a05c5c060c23ad65a": {},
		// os_image_hash 8db40cb2....
		"d090162bff4b1d1dc74dc59dc548838efc4b811b173da8536efa8e2a9c045da70ee092301293ad90afebee448bcd0211": {},
	}
	p.RTMRAllow[1] = map[string]struct{}{
		"a7b523278d4f914ee8df0ec80cd1c3d498cbf1152b0c5eaf65bad9425072874a3fcf891e8b01713d3d9937e3e0d26c15": {},
		// os_image_hash 8db40cb2....
		"4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec": {},
	}
	p.RTMRAllow[2] = map[string]struct{}{
		"24847f5c5a2360d030bc4f7b8577ce32e87c4d051452c937e91220cab69542daef83433947c492b9c201182fc9769bbe": {},
		// os_image_hash 8db40cb2....
		"764489f277a8540189761e72b4238ba36d4d647e11bd958d8ab5522af2a4867b0ff63e06b0c4967f1857236244040a5d": {},
	}
	return p
}

// SupplyChainPolicy returns the supply chain policy for nearcloud.
// Starts from the neardirect base (model tier) and adds gateway images.
func SupplyChainPolicy() *attestation.SupplyChainPolicy {
	p := neardirect.SupplyChainPolicy()
	// datadog/agent and otel/opentelemetry-collector-contrib are also
	// gateway images in nearcloud.
	for i := range p.Images {
		switch p.Images[i].Repo {
		case "datadog/agent", "otel/opentelemetry-collector-contrib":
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
		attestation.ImageProvenance{Repo: "alpine", GatewayTier: true, Provenance: attestation.FulcioSigned,
			NoDSSE:     true,
			OIDCIssuer: neardirect.GithubOIDC,
			OIDCIdentities: []string{
				"https://github.com/docker/github-builder-experimental/.github/workflows/bake.yml@refs/heads/build-distributed",
				"https://github.com/crazy-max/docker-github-builder/.github/workflows/bake.yml@refs/heads/main",
			},
			SourceRepos: []string{
				"docker/github-builder-experimental",
				"https://github.com/docker/github-builder-experimental",
				"crazy-max/docker-github-builder",
				"https://github.com/crazy-max/docker-github-builder",
			}},
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
