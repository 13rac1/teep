package venice

import (
	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

// DefaultMeasurementPolicy returns the default TDX measurement allowlists for
// Venice. Venice runs on the same dstack platform as neardirect but deploys on
// different hardware, producing different RTMR0/2 values.
func DefaultMeasurementPolicy() attestation.MeasurementPolicy {
	p := attestation.DstackBaseMeasurementPolicy()
	p.RTMRAllow[0] = map[string]struct{}{
		"0cb94dba1a9773d741efad49370e1e909557409a904a24a4620b6305651360952cb8111f851b03fc2a35a6c3b7bb05f6": {},
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
// allowlists for the Venice ACI/1 private-ai-gateway CVM. The gateway runs a
// dstack image, so MRTD/MRSEAM come from the shared dstack base list; the
// enforced gateway_tee_measurement factor checks those. RTMR allowlists are
// filled from captured gateway values as they are observed —
// gateway_tee_hardware_config and gateway_tee_boot_config are waived by
// default (SEE: attestation.VeniceACIDefaultAllowFail) because the
// private-ai-gateway-dev channel redeploys often and its RTMRs churn with
// each image.
func DefaultGatewayMeasurementPolicy() attestation.MeasurementPolicy {
	return attestation.DstackBaseMeasurementPolicy()
}

// SupplyChainPolicy returns the supply chain policy for Venice. The model
// tier uses the same container images as neardirect (dstack models). The
// gateway tier lists the images from the ACI/1 private-ai-gateway compose
// manifest; the manifest pins each by sha256 digest and the quote's
// MRConfigID measures the manifest, so ComposeBindingOnly is the evidence
// level the platform provides.
func SupplyChainPolicy() *attestation.SupplyChainPolicy {
	p := neardirect.SupplyChainPolicy()
	p.Images = append(p.Images,
		attestation.ImageProvenance{Repo: "dstacktee/dstack-ingress", GatewayTier: true,
			Provenance: attestation.ComposeBindingOnly},
		attestation.ImageProvenance{Repo: "ghcr.io/redpill-ai/private-ai-launcher", GatewayTier: true,
			Provenance: attestation.ComposeBindingOnly},
		attestation.ImageProvenance{Repo: "dstacktee/dstack-verifier", GatewayTier: true,
			Provenance: attestation.ComposeBindingOnly},
		attestation.ImageProvenance{Repo: "prom/node-exporter", GatewayTier: true,
			Provenance: attestation.ComposeBindingOnly},
	)
	return p
}
