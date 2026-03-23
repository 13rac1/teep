# Section 05 — TDX Measurement Fields & Policy Expectations

## Scope

Audit extraction, integrity checks, and policy enforcement for TDX quote measurement fields, including documented residual risk when golden baselines are unavailable.

## Primary Files

- [`internal/attestation/tdx.go`](../../../internal/attestation/tdx.go)
- [`internal/attestation/measurement_policy.go`](../../../internal/attestation/measurement_policy.go)
- [`internal/attestation/report.go`](../../../internal/attestation/report.go)

## Required Field Coverage

Your report MUST cover all fields:
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

**MRSEAM** — Measurement of the TDX module (SEAM firmware). This 48-byte hash represents the identity and integrity of the Intel TDX module running in Secure Arbitration Mode. Intel signs and guarantees TDX module integrity; the MRSEAM value should correspond to a known Intel-released TDX module version. Verification of MRSEAM ensures the TDX firmware has not been tampered with and is a recognised, trusted version. Without MRSEAM verification, an attacker who compromises the hypervisor could potentially load a modified TDX module that subverts TD isolation guarantees.

**MRTD** — Measurement Register for Trust Domain. This 48-byte hash captures the initial memory contents and configuration of the TD at creation time, specifically the virtual firmware (OVMF/TDVF) measurement. MRTD is measured by the TDX module in SEAM mode before any guest code executes, making it the root-of-trust anchor for the entire guest boot chain. In dstack's architecture, MRTD corresponds to TPM PCR[0] (FirmwareCode). MRTD can be pre-calculated from the built dstack OS image. Without MRTD verification, an attacker could substitute a different virtual firmware (e.g., one that leaks secrets or skips subsequent measured boot steps) while preserving the correct compose hash and RTMR3 values.

**RTMR0** — Runtime firmware configuration measurement. RTMR0 records the CVM's virtual hardware setup as measured by OVMF, including CPU count, memory size, device configuration, secure boot policy variables (PK, KEK, db, dbx), boot variables, and TdHob/CFV data provided by the VMM. Corresponds to TPM PCR[1,7]. While dstack uses fixed devices, CPU and memory specifications can vary, so RTMR0 can be computed from the dstack image given specific CPU and RAM parameters. Without RTMR0 verification, a malicious VMM could alter the virtual hardware configuration (e.g., inject rogue devices or disable secure boot) without detection.

**RTMR1** — Runtime OS loader measurement. RTMR1 records the Linux kernel measurement as extended by OVMF, along with the GPT partition table and boot loader (shim/grub) code. Corresponds to TPM PCR[2,3,4,5]. RTMR1 can be pre-calculated from the built dstack OS image. Without RTMR1 verification, a modified kernel could be loaded that bypasses security controls while leaving application-level measurements intact.

**RTMR2** — Runtime OS component measurement. RTMR2 records the kernel command line (including the rootfs hash), initrd binary, and grub configuration/modules as measured by the boot loader. Corresponds to TPM PCR[8-15]. RTMR2 can be pre-calculated from the built dstack OS image. Without RTMR2 verification, the kernel command line could be altered (e.g., to disable security features or change the root filesystem hash) without detection.

**RTMR3** — Application-specific runtime measurement. In dstack's implementation, RTMR3 records application-level details including the compose hash, instance ID, app ID, and key provider. Unlike RTMR0-2, RTMR3 cannot be pre-calculated from the image alone because it contains runtime information. It is verified by replaying the event log: if replayed RTMR3 matches the quoted RTMR3, the event log content is authentic, and the compose hash, key provider, and other details can be extracted and verified from the event log entries. The existing compose binding check (MRConfigID) partially overlaps with RTMR3 for compose hash verification.

## How Thorough Verification Should Work

For complete attestation of a dstack-based CVM, the verification process should:

1. **Obtain golden values**: The inference provider MUST publish reference values for MRTD, RTMR0, RTMR1, and RTMR2 corresponding to each released CVM image version. These values can be computed using reproducible build tooling (e.g., dstack's `dstack-mr` tool) from the source-built image given the specific CPU and RAM configuration of the deployment.

2. **Verify MRSEAM against Intel's published values**: MRSEAM should match a known Intel TDX module release. Intel publishes TDX module versions; the expected MRSEAM value can be derived from the specific TDX module version running on the platform.

3. **Verify MRTD, RTMR0, RTMR1, RTMR2 against golden values**: These four registers, taken together, attest that the firmware, kernel, initrd, rootfs, and boot configuration all match the expected dstack OS image for the provider's declared CPU/RAM configuration. This is the only way to establish that the base operating environment is the expected one.

4. **Verify RTMR3 via event log replay**: RTMR3 contains runtime-specific measurements that cannot be pre-calculated. Replay the event log, compare the replayed RTMR3 against the quoted value, and then inspect the event log entries for expected compose hash, app ID, and key provider values.

5. **Verify MRSEAM + MRTD + RTMR0-2 as a set**: These five values together form a complete chain-of-trust from the TDX module through firmware, kernel, and OS components. Verifying only a subset (e.g., only compose binding via MRConfigID + RTMR3 event log replay) leaves significant gaps where the base system could be substituted.

## Current Gap: Inference Provider Has Not Published Golden Values

The code currently supports an allowlist-based `MeasurementPolicy` for MRTD, MRSEAM, and RTMR0-3, but the current direct inference provider (NearAI) does not publish:
- reproducible build instructions or pre-built images for their CVM,
- golden/reference values for MRTD, MRSEAM, RTMR0, RTMR1, or RTMR2,
- documentation of their specific CPU/RAM configuration (needed to compute RTMR0),
- the dstack OS version or TDX module version deployed.

Because these reference values are unavailable, the code does not currently enforce checking MRSEAM, MRTD, or RTMR0-2 against any baseline. The `MeasurementPolicy` allowlists remain empty, meaning these fields are extracted and logged but not policy-enforced. This is the correct behavior given the absence of reference data — enforcing against fabricated or unverified golden values would provide false assurance.

**The audit MUST flag this as a residual risk**: without MRSEAM/MRTD/RTMR0-2 verification, the attestation trusts any TDX module version and any VM image that happens to produce the correct compose hash (MRConfigID) and valid RTMR3 event log. This means:
- A compromised or outdated TDX module would not be detected (MRSEAM gap),
- A substituted virtual firmware could bypass measured boot (MRTD gap),
- A modified kernel, initrd, or rootfs could go undetected (RTMR0-2 gap),
- Only the application-layer compose binding (MRConfigID) and event log replay (RTMR3) provide assurance, which is insufficient for full CVM integrity.

## Current Direct-Provider Expectation Summary

- MRCONFIGID is expected to be cryptographically checked via compose binding,
- RTMR fields are expected to be consistency-checked via event log replay when event logs are present,
- REPORTDATA is expected to be cryptographically verified via the provider-specific binding scheme,
- MRSEAM, MRTD, RTMR0, RTMR1, and RTMR2 are currently informational-only due to the absence of provider-published golden values — this MUST be documented as a gap with high residual risk,
- MRSIGNERSEAM, MROWNER, MROWNERCONFIG are expected to be all-zeros for standard dstack deployments and should be documented as informational-only.

## Required Checks

Verify and report:
- where each field is parsed and exposed in the verification report,
- whether expected-value policies exist for MRTD/MRSEAM/RTMR0-3,
- input validation for allowlist values (encoding/length/parse failures),
- mismatch behavior (fail-closed vs informational),
- whether fields expected to be all-zero in standard dstack deployments are actually checked or only logged,
- whether MRCONFIGID and REPORTDATA controls are enforced elsewhere but correctly reflected here.

When allowlist policy exists (i.e., when the inference provider eventually publishes golden values), the audit MUST verify:
- how MRTD/MRSEAM/RTMR allowlists are configured,
- input validation rules for allowlist values (length/encoding),
- whether allowlist mismatches are enforced fail-closed or informational.

## Mandatory Residual-Risk Analysis

You MUST explicitly evaluate the known baseline-publication gap:
- if provider golden values for MRSEAM/MRTD/RTMR0-2 are absent,
- whether these fields become informational-only,
- why this leaves system-level integrity gaps despite compose binding and RTMR3/event-log consistency checks.

You MUST quantify realistic attacker capability under this gap (for example, hypervisor-level substitution of firmware/kernel/initrd/rootfs while preserving application-layer bindings).

**The audit MUST recommend** that the inference provider (NearAI) publish:
1. The specific dstack OS version (or equivalent CVM image) and TDX module version used in their deployments,
2. Reproducible build instructions or source references for their CVM image,
3. Pre-computed golden values for MRTD, RTMR0, RTMR1, and RTMR2 for each supported CPU/RAM configuration,
4. The expected MRSEAM value for the Intel TDX module version deployed on their hardware,
5. A versioned manifest or API endpoint that maps deployment configurations to expected measurement values, so that verifiers like teep can populate `MeasurementPolicy` allowlists automatically.

Until this information is provided, the attestation provides application-layer assurance (compose hash and RTMR3) but not full system-level assurance. The auditor MUST quantify this gap by noting that an attacker with hypervisor-level access could substitute the firmware/kernel/initrd while preserving compose binding, and report it as a high-severity residual risk.

## Section Deliverable

Provide:
1. field-by-field matrix (field × extraction/structural/policy × enforcement status),
2. findings-first list ordered by severity,
3. explicit high-severity residual-risk statement if baseline policy is absent,
4. include at least one concrete positive control and one concrete negative/residual-risk observation,
5. source citations for all claims.
