# Section 05 — TDX Measurement Fields & Policy Expectations (Gateway and Model)

## Scope

Audit extraction, integrity checks, and policy enforcement for TDX quote measurement fields for BOTH the gateway CVM and the model backend CVM, including documented residual risk when golden baselines are unavailable.

In the gateway inference model, two separate CVMs produce TDX quotes with independent measurement registers. The audit MUST cover all measurement fields for both the gateway and the model backend, and verify whether separate measurement policies can be specified for each.

## Primary Files

- [`internal/attestation/tdx.go`](../../../internal/attestation/tdx.go)
- [`internal/attestation/measurement_policy.go`](../../../internal/attestation/measurement_policy.go)
- [`internal/attestation/report.go`](../../../internal/attestation/report.go)

## Required Field Coverage

Your report MUST cover all fields for BOTH the gateway AND the model backend:
- `MRTD`
- `RTMR0`, `RTMR1`, `RTMR2`, `RTMR3`
- `MRSEAM`
- `MRSIGNERSEAM`
- `MROWNER`
- `MROWNERCONFIG`
- `MRCONFIGID`
- `REPORTDATA`

For each field, classify as:
- extraction/visibility only,
- structural integrity checks,
- policy enforcement (allowlist/expected-value match).

## What Each Register Measures

Understanding the security semantics of each register is critical for assessing attestation completeness. The following describes the trust-chain role of each register, based on Intel TDX architecture and the dstack CVM implementation used by inference providers:

**MRSEAM** — Measurement of the TDX module (SEAM firmware). This 48-byte hash represents the identity and integrity of the Intel TDX module running in Secure Arbitration Mode. Intel signs and guarantees TDX module integrity; the MRSEAM value should correspond to a known Intel-released TDX module version. Without MRSEAM verification, an attacker who compromises the hypervisor could potentially load a modified TDX module that subverts TD isolation guarantees.

**MRTD** — Measurement Register for Trust Domain. This 48-byte hash captures the initial memory contents and configuration of the TD at creation time, specifically the virtual firmware (OVMF/TDVF) measurement. MRTD is the root-of-trust anchor for the entire guest boot chain. Without MRTD verification, an attacker could substitute a different virtual firmware while preserving the correct compose hash and RTMR3 values.

**RTMR0** — Runtime firmware configuration measurement. Records the CVM's virtual hardware setup, including CPU count, memory size, device configuration, secure boot policy variables. Without RTMR0 verification, a malicious VMM could alter the virtual hardware configuration without detection.

**RTMR1** — Runtime OS loader measurement. Records the Linux kernel measurement, GPT partition table, and boot loader code. Without RTMR1 verification, a modified kernel could be loaded that bypasses security controls.

**RTMR2** — Runtime OS component measurement. Records the kernel command line (including rootfs hash), initrd binary, and grub configuration/modules. Without RTMR2 verification, the kernel command line could be altered to disable security features.

**RTMR3** — Application-specific runtime measurement. Records the compose hash, instance ID, app ID, and key provider. Verified by replaying the event log: if replayed RTMR3 matches the quoted RTMR3, the event log content is authentic. The existing compose binding check (MRConfigID) partially overlaps with RTMR3 for compose hash verification.

## How Thorough Verification Should Work

For complete attestation of a dstack-based CVM — applicable to BOTH the gateway CVM and the model backend CVM — the verification process should:

1. **Obtain golden values**: The inference provider MUST publish reference values for MRTD, RTMR0, RTMR1, and RTMR2 corresponding to each released CVM image version, for both the gateway and model backend deployments.

2. **Verify MRSEAM against Intel's published values**: MRSEAM should match a known Intel TDX module release.

3. **Verify MRTD, RTMR0, RTMR1, RTMR2 against golden values**: These four registers, taken together, attest that the firmware, kernel, initrd, rootfs, and boot configuration all match the expected dstack OS image.

4. **Verify RTMR3 via event log replay**: RTMR3 contains runtime-specific measurements that cannot be pre-calculated. See Section 06 for event log replay details.

5. **Verify MRSEAM + MRTD + RTMR0-2 as a set**: These five values form a complete chain-of-trust. Verifying only a subset leaves significant gaps.

## Current Stopgaps and Residual Gaps

The code supports an allowlist-based `MeasurementPolicy` for MRTD, MRSEAM, and RTMR0-3 for both the gateway and the model backend. If gateway inference provider does not publish authenticated measurement baselines in-band, teep provides Go-coded stopgap defaults and operator tooling to partially close this gap:

**MRSEAM — Go-coded defaults from Intel releases.** `DstackBaseMeasurementPolicy()` in `internal/attestation/dstack_defaults.go` ships an allowlist of four Intel-published MRSEAM values corresponding to TDX module versions 1.5.08, 1.5.16, 2.0.08, and 2.0.02. The `tdx_mrseam_mrtd` and `gateway_tdx_mrseam_mrtd` factors are enforced by default for nearcloud (they are NOT in `NearcloudDefaultAllowFail`).

**MRTD — Go-coded defaults from dstack reproducible builds.** The same base policy ships two MRTD values corresponding to dstack-nvidia image versions 0.5.4.1 and 0.5.5. These apply to both the model backend and gateway CVMs.

**RTMR0, RTMR1, RTMR2 — Per-tier observed-value defaults.** NearCloud uses separate measurement policies for the model backend and the gateway:
- `DefaultMeasurementPolicy()` in `internal/provider/nearcloud/policy.go` provides model backend RTMR values,
- `DefaultGatewayMeasurementPolicy()` provides gateway CVM RTMR values (which differ from model backend values due to different hardware configurations and compose manifests).

The `tdx_hardware_config` / `gateway_tdx_hardware_config` (RTMR0) and `tdx_boot_config` / `gateway_tdx_boot_config` (RTMR1/RTMR2) factors are in `NearcloudDefaultAllowFail` — meaning they are computed and reported but do not block traffic by default.

**Measurement policy merge.** Policies are resolved via a three-tier precedence: per-provider TOML config → global TOML config → Go-coded defaults. Gateway measurement policies use separate TOML fields (`gateway_mrtd_allow`, `gateway_rtmr0_allow`, etc.) to allow independent configuration of gateway and model backend allowlists.

**Operator bootstrapping.** The `teep verify <provider> --model <model> --update-config` command runs a full attestation verification and appends newly observed measurement values to the per-provider policy section. For nearcloud, this captures both model backend and gateway measurements.

**Residual risk.** Despite these stopgaps:
- MRSEAM and MRTD defaults are independently verifiable from Intel and dstack sources — these are the strongest stopgaps.
- RTMR0-2 defaults are pinned from observed attestation data and cannot distinguish a legitimate provider infrastructure change from a compromised lower stack.
- No signed measurement manifest exists for automated consumption.
- These risks apply independently to both the gateway CVM and the model backend CVM.

**The audit MUST flag the remaining residual risk** and recommend that the inference provider publish authenticated measurement baselines. See `docs/attestation_gaps/dstack_integrity.md` for the detailed analysis.

## Current Gateway-Provider Expectation Summary

**Model backend attestation (Tier 1–3):**
- MRCONFIGID is expected to be cryptographically checked via compose binding,
- RTMR fields are expected to be consistency-checked via event log replay when event logs are present,
- REPORTDATA is expected to be cryptographically verified via the nearai binding scheme (`sha256(signing_address + tls_fingerprint) + nonce`),
- MRSEAM and MRTD are enforced by default via Go-coded allowlists — the `tdx_mrseam_mrtd` factor is enforced (not in `NearcloudDefaultAllowFail`),
- RTMR0 is checked via `tdx_hardware_config` against per-provider observed values — allowed to fail by default,
- RTMR1 and RTMR2 are checked via `tdx_boot_config` against per-provider observed values — allowed to fail by default,
- MRSIGNERSEAM, MROWNER, MROWNERCONFIG are expected to be all-zeros.

**Gateway attestation (Tier 4):**
- MRCONFIGID is expected to be cryptographically checked via gateway compose binding,
- RTMR fields are expected to be consistency-checked via gateway event log replay when gateway event logs are present,
- REPORTDATA is expected to be cryptographically verified via the gateway binding scheme (`sha256(tls_fingerprint) + nonce` — note: no signing_address for the gateway),
- MRSEAM and MRTD are enforced by default via the same Go-coded allowlists — `gateway_tdx_mrseam_mrtd` is enforced,
- RTMR0 is checked via `gateway_tdx_hardware_config` — allowed to fail by default,
- RTMR1 and RTMR2 are checked via `gateway_tdx_boot_config` — allowed to fail by default,
- MRSIGNERSEAM, MROWNER, MROWNERCONFIG are expected to be all-zeros.

> **Known divergence**: Venice does not have gateway TEE attestation — there is no gateway TDX quote, no gateway measurement policy, and no Tier 4 factors. These are server-side limitations that cannot be fixed in teep.

## Required Checks

### Field Extraction and Policy Verification

Verify and report:
- where each field is parsed and exposed in the verification report, for BOTH gateway and model quotes,
- whether expected-value policies exist for MRTD/MRSEAM/RTMR0-3,
- whether separate `MeasurementPolicy` instances can be configured for gateway vs model backend,
- input validation for allowlist values (encoding/length/parse failures),
- mismatch behavior (fail-closed vs informational),
- whether fields expected to be all-zero in standard dstack deployments (MRSIGNERSEAM, MROWNER, MROWNERCONFIG) are actually checked or only logged,
- whether MRCONFIGID and REPORTDATA controls are enforced elsewhere but correctly reflected here,
- that each 48-byte measurement field is validated for correct length upon extraction from the quote body.

### RTMR Extension Semantics

The RTMR registers use an extend-only mechanism:
- extend formula: `RTMR_new = SHA-384(RTMR_old || digest)`,
- initial RTMR state: 48 zero bytes,
- hash algorithm: SHA-384 (producing 48-byte / 384-bit digests).

The audit MUST verify that any code performing RTMR replay or comparison correctly implements these semantics. For RTMR3 event log replay specifically, verify that:
- short digests in event log entries are padded to 48 bytes before extension,
- the IMR index in each event log entry is validated to be within [0, 3],
- a malformed event log entry causes the entire replay to fail (not silently skipped).

### Measurement Policy Configuration

Verify and report:
- how allowlists are represented in code,
- where `MeasurementPolicy` is instantiated and which caller configures it,
- whether allowlist population is static (compiled-in) or dynamic (config file, API response, environment variable),
- whether an empty allowlist means "skip check" (permissive) or "reject all" (restrictive),
- whether there is a mechanism for operators to add custom measurement allowlists without code changes,
- how allowlist entries are matched against quote values (exact match, prefix match, or set membership),
- whether the comparison is byte-level or string-level (hex canonicalization),
- **whether separate policies can be specified for the gateway CVM vs model backend CVM** (this is gateway-specific).

The audit MUST verify:
- how MRTD/MRSEAM/RTMR allowlists are configured via the three-tier merge (per-provider TOML > global TOML > Go defaults),
- whether separate `MeasurementPolicy` instances exist for gateway vs model backend (`DefaultMeasurementPolicy()` and `DefaultGatewayMeasurementPolicy()`),
- that separate TOML fields exist for gateway measurement policies (`gateway_mrtd_allow`, `gateway_rtmr0_allow`, etc.),
- input validation rules for allowlist values (length/encoding),
- whether allowlist mismatches are enforced fail-closed or informational (depends on whether the factor is in `allow_fail`),
- the `--update-config` bootstrapping flow and that it correctly captures both model and gateway measurements.

## Mandatory Residual-Risk Analysis

You MUST explicitly evaluate the known baseline-publication gap for BOTH the gateway and model backend:
- if provider golden values for MRSEAM/MRTD/RTMR0-2 are absent,
- whether these fields become informational-only,
- why this leaves system-level integrity gaps despite compose binding and RTMR3/event-log consistency checks.

You MUST quantify realistic attacker capability under this gap (hypervisor-level substitution of firmware/kernel/initrd/rootfs while preserving application-layer bindings). This applies independently to both the gateway CVM and the model backend CVM.

**The audit MUST recommend** that the inference provider (NearCloud / NEAR AI) publish:
1. The specific dstack OS version and TDX module version used in their gateway and model backend deployments,
2. Reproducible build instructions or source references for both CVM images,
3. Pre-computed golden values for MRTD, RTMR0, RTMR1, and RTMR2 for each supported CPU/RAM configuration, for both gateway and model backend,
4. The expected MRSEAM value for the Intel TDX module version deployed on their hardware,
5. A versioned manifest or API endpoint that maps deployment configurations to expected measurement values.

## Best-Practice Audit Points

### Go (Golang) Best Practices

- **Type safety for measurement values**: Verify that 48-byte measurement registers are represented as fixed-size arrays (`[48]byte`) where possible.
- **Hex encoding/decoding**: Verify that `encoding/hex` is used and `hex.DecodeString` errors are handled.
- **Interface usage for policy**: If `MeasurementPolicy` uses interfaces, verify that nil/zero-value implementations behave safely.
- **Map vs slice for allowlists**: Verify appropriate data structure for allowlist lookups. Constant-time considerations apply.

### Cryptography Best Practices

- **Constant-time comparison for measurements**: Verify that measurement value comparisons use `subtle.ConstantTimeCompare`.
- **SHA-384 for RTMR extension**: Verify `crypto/sha512.Sum384` is used (not SHA-256 or another algorithm).
- **No measurement value truncation**: Verify 48-byte values are never truncated for comparison.

### General Security Audit Practices

- **Trust boundary**: No measurement-based security decisions before quote signature verification completes.
- **Fail-secure for empty policy**: When no golden values are configured, the report must clearly distinguish "not checked" from "checked and matched."
- **Configuration injection prevention**: If allowlists are configurable via external input, verify strict format validation.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. per-field classification (extraction / structural / enforcement) covering BOTH gateway and model,
3. residual-risk analysis for absent golden values (gateway and model independently),
4. explicit recommendation for provider to publish golden values for both CVM types,
5. measurement policy configuration assessment (including gateway vs model policy separation),
6. include at least one concrete positive control and one concrete negative/residual-risk observation,
7. source citations for all claims.
