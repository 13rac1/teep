package phalacloud

import (
	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/aci"
)

// SupplyChainPolicy returns the supply chain policy for Phala Cloud. Phala
// Cloud answers with the ACI/1 attestation of the private-ai-gateway, so the
// policy lists the gateway images (SEE: aci.GatewayImages). It lists no
// model-tier image: a dstack-format backend response fails component
// recognition until its images are added.
func SupplyChainPolicy() *attestation.SupplyChainPolicy {
	return &attestation.SupplyChainPolicy{Images: aci.GatewayImages()}
}
