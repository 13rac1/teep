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
	}
	p.RTMRAllow[2] = map[string]struct{}{
		"564622c7ddc55a53272cc9f0956d29b3f7e0dd18ede432720b71fd89e5b5d76cb0b99be7b7ff2a6a92b89b6b01643135": {},
	}
	return p
}

// DefaultGatewayMeasurementPolicy returns the default TDX measurement
// allowlists for the nearcloud gateway CVM. Gateway RTMR values are from
// observed dstack gateway deployments (shared infrastructure with nanogpt).
func DefaultGatewayMeasurementPolicy() attestation.MeasurementPolicy {
	p := attestation.DstackBaseMeasurementPolicy()
	p.RTMRAllow[0] = map[string]struct{}{
		"fb14dc139f33d6fcf474bc8332cac001259fb31cfbcb6b34d4ceeb552a2c4466884a0cbde45ad98a05c5c060c23ad65a": {},
	}
	p.RTMRAllow[1] = map[string]struct{}{
		"a7b523278d4f914ee8df0ec80cd1c3d498cbf1152b0c5eaf65bad9425072874a3fcf891e8b01713d3d9937e3e0d26c15": {},
	}
	p.RTMRAllow[2] = map[string]struct{}{
		"24847f5c5a2360d030bc4f7b8577ce32e87c4d051452c937e91220cab69542daef83433947c492b9c201182fc9769bbe": {},
	}
	return p
}

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
