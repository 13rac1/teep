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
// The MRSEAM values are from Intel's table of TDX module hashes. The MRTD and
// RTMR values are from captured Chutes quotes and from NEAR's reviewed mirror
// of Chutes' unsigned measurement feed (SEE: DefaultMeasurementPolicy). See
// docs/measurement_allowlists.md for the procedure and
// docs/attestation_gaps/sek8s_integrity.md for the trust model.

// Sek8sMRSEAMAllow extends the shared dstack MRSEAM allowlist with additional TDX
// module versions observed on the Chutes sek8s fleet. These module versions
// are only allowed for Chutes, not for dstack providers. Version labels and
// values are from Intel, "TDX Module Releases and Hashes"
// (github.com/intel/confidential-computing.tdx.tdx-module).
var Sek8sMRSEAMAllow = func() map[string]struct{} {
	base := attestation.DstackBaseMeasurementPolicy()
	m := base.MRSeamAllow // already a copy
	// TDX module 1.5.06 — Sapphire/Emerald Rapids (observed on Chutes sek8s fleet)
	m["5b38e33a6487958b72c3c12a938eaa5e3fd4510c51aeeab58c7d5ecee41d7c436489d6c8e4f92f160b7cad34207b00c1"] = struct{}{}
	// TDX module 1.5.28 — Sapphire/Emerald Rapids (observed on Chutes sek8s fleet)
	m["346bc77a1846cac214dd2e8edeb9ee4349449d6c3f9ff2c52149a634c27b7fd1bd314c2ef6b973eeebd55742952531a1"] = struct{}{}
	// TDX module 1.5.34 — Sapphire/Emerald Rapids (observed on Chutes sek8s fleet)
	m["ab62561a173acbd18ee50ff37750db44184c6cf5e886df74247cc575e163b04c34b9e18374757c235affa614d4127f6b"] = struct{}{}
	return m
}()

// Sek8sMRTDAllow contains the TD virtual firmware (OVMF) measurement for the
// sek8s image. This is distinct from the dstack OVMF.
var Sek8sMRTDAllow = map[string]struct{}{
	// sek8s 1.3.0 OVMF (NEAR mirror; also in the Chutes captures of 2026-05
	// and 2026-06)
	"ddc6efcdd2309e10837f8a7f64b71272b7ef003b129460410fe715bdfffec38c7c0c1686dddb2a23d4fd623d145e8455": {},
	// sek8s 1.3.1, 1.4.0 and 1.4.1 OVMF (NEAR mirror)
	"261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d": {},
}

// DefaultMeasurementPolicy returns the default TDX measurement allowlists for
// the Chutes provider. MRSEAM extends the shared Intel TDX module allowlist
// with additional module versions observed on the sek8s fleet.
// MRTD and RTMR0-2 are specific to the sek8s platform. By default teep
// enforces only MRTD and MRSEAM for Chutes: tee_hardware_config (RTMR0) and
// tee_boot_config (RTMR1, RTMR2) are in ChutesDefaultAllowFail.
//
// Values marked "NEAR mirror" are from NEAR's reviewed mirror of Chutes'
// unsigned measurement feed:
// nearai/cloud-api@8e708a64bd097905720760da40ecaf0b556be3eb crates/services/src/attestation/chutes_golden_measurements.json.
// A row label is Chutes' row name: the GPU count and type, then in brackets
// a version token that the feed does not define and the topology (flat or
// NUMA), vCPU count and memory; a parenthesised value is the first 12 hex
// digits of the row's fingerprint in Chutes' feed, which tells apart two
// rows with the same name.
func DefaultMeasurementPolicy() attestation.MeasurementPolicy {
	return attestation.MeasurementPolicy{
		MRSeamAllow: copyMap(Sek8sMRSEAMAllow),
		MRTDAllow:   copyMap(Sek8sMRTDAllow),
		RTMRAllow: [4]map[string]struct{}{
			// RTMR0 — ACPI tables, early boot firmware; deterministic per deployment class
			{
				// sek8s 1.3.0 hardware rows (NEAR mirror)
				// sek8s 1.3.0, 8xRTX_PRO_6000
				"5064826bfd530ca9f823ceecb74899d7dbd014b60897a77317a14200c8706f2368ecbbc0a04cec8ceef90474b8c955e1": {},
				// sek8s 1.3.0, 8xb200
				"734628b9a715ec492c2b14b409907f32d91847f439ba8bac2fa985b41c01245536348fefb2e021ed574c290c8c50347a": {},
				// sek8s 1.3.0, 8xb200-eth
				"724c1d0d20c11a479d2874fa543b0f1b920be32f2a5b9707fa5bcf6176fff31aeac9436e541e1125f78a0b61f7c2e165": {},
				// sek8s 1.3.0, 8xb300
				"31f6446add906b7d56132c600549270a8ea780193e0c89586f784b20b25136de441ca715d5ecf86ae72f0b40f7a47f39": {},
				// sek8s 1.3.0, 8xh200
				"2864b11878e8129095d62a5dd7c3e3aae178d3a077606a825617324768f189ad05aed08376947df92d6c75865d915cbf": {},
				// sek8s 1.3.0, 8xh200-r2
				"c0466500b034f7b51be7ea0fcc477e60b54833d927db96e4826ac37c60ec02dc28703a16af551f46be17035157b474da": {},
				// sek8s 1.4.x hardware rows (NEAR mirror)
				// sek8s 1.4.0 and 1.4.1, 8xh200 [10.2.1, flat-188c-1128g-nvsw4]
				"b72208e4b39593a82bbdbc394569bd6f8395f76bdcff5bce2bc72f4e2ca0b3202238d3b78952b497d725e04999e45435": {},
				// sek8s 1.4.0 and 1.4.1, 8xh200 [10.2.1, numa-124c-1128g-nvsw-node1]
				"5b509103a3bf3c10dbf27a7da030a3d7ba93a81c0c8844de20e5dfee77611644a39cc7236313e9d0a99a8a8a703bbfc9": {},
				// sek8s 1.4.1, 8xb200 [10.2.1, flat-272c-1536g]
				"44efeea3a647090c2969cca7f29963dde696d99542c28536a20ad3586a639ef7e230d8d4e325c55f3597dc7b58b30903": {},
				// sek8s 1.4.1, 8xb300 [10.2.1, flat-252c-1944g]
				"fc71a5a8edcb1f6d307d59e62ce257365df0f233ae2334691f99d2136832d911f8be975b92f88036db8a4906574519c4": {},
				// sek8s 1.4.1, 8xb300 [10.2.1, numa-flatpci-252c-2304g]
				"e861504d4a05ba1e949618ef759d6fbf0c69e4774b667e9fb876b664cb1bb70e3094d2cddc9ac6c52d4b5d352ba2e1d3": {},
				// sek8s 1.4.1, 8xh200 [10.2.1, numa-188c-1128g-nvsw-node0]
				"052183ad6cca5ad4aef7e31dc3f6c47be2ba90c288a55420bf432301374f1bd9932ea7d6b5da999c4fecf578c4b0a21a": {},
				// sek8s 1.4.1, 8xh200 [10.2.1, numa-188c-1128g-nvsw-node1]
				"ba81dbf034d968fd4be0975c031cbe6451295d63cb509cd857372fc915dada1b24fc4e1b0486db4a276a9efb49d415e6": {},
				// sek8s 1.4.1, 8xh200 [10.2.1, numa-236c-1128g-nvsw-node1]
				"a9cac743d296a96c7a0d6348f03be1e1a407f18ec215f0039e3dc1ea4c132eb1e4a5fe3783022ff3d252d4b30f1dbf9f": {},
				// sek8s 1.4.1, 8xpro_6000 [10.2.1, numa-124c-768g] (58443435b208)
				"bacb4abf7b19aba4a8307ebc7244706745de4fa627e669e7f06fd35c3303eea1903f58dc143d27b557da1a986e0e95f6": {},
				// sek8s 1.4.1, 8xpro_6000 [10.2.1, numa-124c-768g] (f2ab1d61fa64)
				"5e939a6213a6751f162617c6e9a50461786b3f9a6a679ebf7706fa705e7934180825b2fae43a60877ea9117a1e4d4f60": {},
				// sek8s 1.4.1, 8xpro_6000 [10.2.1, numa-204c-768g]
				"a5488b5f4cf1484da23001e013a5ad3ff177836bf2cfdbde55dacded21b3eece5de43d4c4a2d5279f8ed8d24b9e072d6": {},
			},
			// RTMR1 — kernel + initramfs; deterministic per sek8s image build
			{
				// sek8s 1.3.0 (NEAR mirror)
				"f858ed2aecba4ecd29084352c6b5c6e403c0bec89b8c852f90fa5a8cee796ffa095518c5cd8b92c25c1856e932a95877": {},
				// sek8s 1.4.0 and 1.4.1 (NEAR mirror)
				"d3a862ff47357f374fc72c7f02a480a13790d1805e24aaa8de1f03994256625ce0f593ae35ea8f0c24d09f7df36cb0ed": {},
			},
			// RTMR2 — kernel command line; deterministic per deployment class
			{
				// sek8s 1.3.0 (NEAR mirror)
				"7719f4fde518994a5dd6767a8b8b87a38168cc0f3480e7498d4ace99e49319be6a7fed26c21ad43310d2d488fc68ab1c": {},
				// sek8s 1.4.0 (NEAR mirror)
				"8feee49b83c0f912f9ab9366a7423f65417bb60223c1871a5d55e84d92d741c80017b3f856317c45295255db70f8dc3e": {},
				// sek8s 1.4.1 (NEAR mirror)
				"da23f73e0fddeb8128f706ecfbecbcf8cee34af7e4907d8fbc85e9b216acee27bf6cc3655eaf4d33cab76adea79fa153": {},
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
