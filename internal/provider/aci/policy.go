package aci

import "github.com/13rac1/teep/internal/attestation"

// GatewayMeasurementPolicy returns the default TDX measurement allowlists for
// the private-ai-gateway CVM. The gateway runs a dstack image, so MRTD and
// MRSEAM come from the shared dstack base list; the enforced
// gateway_tee_measurement factor checks those. gateway_tee_hardware_config
// and gateway_tee_boot_config are waived by default (SEE:
// attestation.ACIDefaultAllowFail) because the dev-channel gateway image
// redeploys often and its RTMRs change with each image.
func GatewayMeasurementPolicy() attestation.MeasurementPolicy {
	return attestation.DstackBaseMeasurementPolicy()
}

// GatewayImages returns the supply chain policy entries for the images of
// the private-ai-gateway compose manifest. The manifest pins each image by
// sha256 digest and the gateway quote's MRConfigID measures the manifest, so
// ComposeBindingOnly is the evidence level the deployment provides.
//
// ghcr.io/edgelesssys/privatemode/privatemode-proxy is the Edgeless
// Privatemode proxy that the gateway runs as an upstream client. It is
// compose-pinned like the other images; its own attestation is not part of
// the gateway's evidence (SEE: docs/attestation_gaps/venice_aci_gateway.md).
//
// The list matches the gateway compose deployed on 2026-10-27, observed in
// live Venice, Phala Cloud and NanoGPT attestations. The earlier
// dstacktee/dstack-ingress and dstacktee/dstack-verifier names are not
// listed: no deployed compose uses them.
func GatewayImages() []attestation.ImageProvenance {
	return []attestation.ImageProvenance{
		{Repo: "ghcr.io/dstack-tee/dstack-ingress", GatewayTier: true, Provenance: attestation.ComposeBindingOnly},
		{Repo: "ghcr.io/redpill-ai/private-ai-launcher", GatewayTier: true, Provenance: attestation.ComposeBindingOnly},
		{Repo: "ghcr.io/dstack-tee/dstack-verifier", GatewayTier: true, Provenance: attestation.ComposeBindingOnly},
		{Repo: "ghcr.io/edgelesssys/privatemode/privatemode-proxy", GatewayTier: true, Provenance: attestation.ComposeBindingOnly},
		{Repo: "prom/node-exporter", GatewayTier: true, Provenance: attestation.ComposeBindingOnly},
	}
}
