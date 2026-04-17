package chutes

import (
	"maps"

	"github.com/13rac1/teep/internal/attestation"
)

// Sek8s TDX measurement defaults for the Chutes provider. Chutes runs sek8s
// (a custom Kubernetes distribution) inside Intel TDX VMs. Unlike dstack
// providers, MRCONFIGID is not used for application binding; instead, sek8s
// gates LUKS disk decryption on full measurement verification.
//
// These baselines are derived from captured production attestation data; see
// docs/attestation_gaps/sek8s_integrity.md for the trust model and provenance.

// Sek8sMRSEAMAllow extends the shared dstack MRSEAM allowlist with additional TDX
// module versions observed on the Chutes sek8s fleet. These older module
// versions are only allowed for Chutes, not for dstack providers.
var Sek8sMRSEAMAllow = func() map[string]struct{} {
	base := attestation.DstackBaseMeasurementPolicy()
	m := base.MRSeamAllow // already a copy
	// TDX module 1.5.0d — Sapphire/Emerald Rapids (observed on Chutes sek8s fleet)
	m["489e585f1c54bc5a02066c8c6ec21619ff0334ec6f21e07e2a35202c59183789c8057e7d97dd591bb08314b185819e72"] = struct{}{}
	// TDX module 2.0.06 — Granite Rapids (observed on Chutes sek8s fleet)
	m["5b38e33a6487958b72c3c12a938eaa5e3fd4510c51aeeab58c7d5ecee41d7c436489d6c8e4f92f160b7cad34207b00c1"] = struct{}{}
	return m
}()

// Sek8sMRTDAllow contains the TD virtual firmware (OVMF) measurement for the
// sek8s image. This is distinct from the dstack OVMF.
var Sek8sMRTDAllow = map[string]struct{}{
	// sek8s OVMF — observed across all captured Chutes attestation quotes
	"ddc6efcdd2309e10837f8a7f64b71272b7ef003b129460410fe715bdfffec38c7c0c1686dddb2a23d4fd623d145e8455": {},
}

// DefaultMeasurementPolicy returns the default TDX measurement allowlists for
// the Chutes provider. MRSEAM extends the shared Intel TDX module allowlist
// with additional module versions observed on the sek8s fleet.
// MRTD and RTMR0-2 are specific to the sek8s platform.
func DefaultMeasurementPolicy() attestation.MeasurementPolicy {
	return attestation.MeasurementPolicy{
		MRSeamAllow: copyMap(Sek8sMRSEAMAllow),
		MRTDAllow:   copyMap(Sek8sMRTDAllow),
		RTMRAllow: [4]map[string]struct{}{
			// RTMR0 — ACPI tables, early boot firmware; deterministic per deployment class
			{
				// 8xH200 deployment class (observed from production)
				"798ec49f6a912c4d3f69cb0089a01774193d26f2f50b6f37d491f028fe6dd852774e993f33964c9be5fb6ad9b05238f9": {},
			},
			// RTMR1 — kernel + initramfs; deterministic per sek8s image build
			{
				"76f43bc5601feaffb83af1aab0c1758dbe07d579ccdcdab0a3da1f477c3b96a7c360c5f40fea27106fb943de4ccf6755": {},
			},
			// RTMR2 — kernel command line; deterministic per deployment class
			{
				"77bbaf9a7c3833d4b3dd9bb2293200d961df36ebb614dfd030466036121838a5ebbb1438fc9e43208228e25918d9c419": {},
			},
			nil, // RTMR3 — runtime IMA; not enforced (validator-side only)
		},
	}
}

// copyMap returns a shallow copy of m so callers cannot mutate package-level maps.
func copyMap(m map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(m))
	maps.Copy(out, m)
	return out
}
