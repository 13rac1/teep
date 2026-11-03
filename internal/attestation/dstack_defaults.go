package attestation

import "maps"

// Dstack TDX measurement defaults for providers running on the dstack TEE
// platform. These baselines are derived from captured attestation data; see
// docs/attestation_gaps/dstack_integrity.md for provenance details.

// dstackMRSEAMAllow contains the Intel TDX module measurement hashes observed
// across all dstack providers. Each entry corresponds to a known TDX module
// version on Sapphire/Emerald/Granite Rapids platforms.
var dstackMRSEAMAllow = map[string]struct{}{
	// TDX module 1.5.08 — Sapphire/Emerald Rapids
	"49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6": {},
	// TDX module 1.5.16 — Sapphire/Emerald Rapids
	"7bf063280e94fb051f5dd7b1fc59ce9aac42bb961df8d44b709c9b0ff87a7b4df648657ba6d1189589feab1d5a3c9a9d": {},
	// TDX module 2.0.08 — Granite Rapids
	"476a2997c62bccc78370913d0a80b956e3721b24272bc66c4d6307ced4be2865c40e26afac75f12df3425b03eb59ea7c": {},
	// TDX module 2.0.02 — Granite Rapids
	"685f891ea5c20e8fa27b151bf34bf3b50fbaf7143cc53662727cbdb167c0ad8385f1f6f3571539a91e104a1c96d75e04": {},
	// TDX module 1.5.20 — Sapphire/Emerald Rapids
	"d0d80c085166ba78ccc69af268e5753cf0f3394523cb4ff7c50b08d9265c82489c099c377be6a400e4d2b57da924012c": {},
	// TDX module 1.5.24 — Sapphire/Emerald Rapids (Intel, TDX Module Releases and Hashes)
	"489e585f1c54bc5a02066c8c6ec21619ff0334ec6f21e07e2a35202c59183789c8057e7d97dd591bb08314b185819e72": {},
	// TDX module 2.0.18 — Granite Rapids / Clearwater Forest (Intel, TDX Module Releases and Hashes)
	"2d2de102461684f14c8d0984a09d895e3e9e15944ce020a03b977e1f114d5e1ed32ef666a47fd19a5851b3800eda3afa": {},
}

// dstackMRTDAllow contains the TD virtual firmware measurement hashes for
// known dstack-nvidia image versions.
var dstackMRTDAllow = map[string]struct{}{
	// dstack-nvidia-0.5.4.1 (os_image_hash 9b69bb...)
	"b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217": {},
	// dstack-nvidia-0.5.5 (os_image_hash da9a3d...)
	"f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077": {},
	// dstack-nvidia-0.5.11 (os_image_hash a6eafc...); 0.5.12 has the same MRTD
	"df4d77c857de652bd0fafa343a2026b51071ee03773d076d283abf1a7d36ff91ffa279ee4a617ac664f7e2a2c8d5891b": {},
}

// DstackBaseMeasurementPolicy returns a MeasurementPolicy with the shared
// MRSEAM and MRTD allowlists for dstack providers.
// Callers should overlay provider-specific RTMR values.
func DstackBaseMeasurementPolicy() MeasurementPolicy {
	return MeasurementPolicy{
		MRSeamAllow: copyMap(dstackMRSEAMAllow),
		MRTDAllow:   copyMap(dstackMRTDAllow),
	}
}

// copyMap returns a shallow copy of m so callers cannot mutate the package-level maps.
func copyMap(m map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(m))
	maps.Copy(out, m)
	return out
}
