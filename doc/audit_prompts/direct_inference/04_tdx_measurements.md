# Section 04 — TDX Measurement Fields & Policy Expectations

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

## Required Checks

Verify and report:
- where each field is parsed and exposed in the verification report,
- whether expected-value policies exist for MRTD/MRSEAM/RTMR0-3,
- input validation for allowlist values (encoding/length/parse failures),
- mismatch behavior (fail-closed vs informational),
- whether fields expected to be all-zero in standard dstack deployments are actually checked or only logged,
- whether MRCONFIGID and REPORTDATA controls are enforced elsewhere but correctly reflected here.

## Mandatory Residual-Risk Analysis

You MUST explicitly evaluate the known baseline-publication gap:
- if provider golden values for MRSEAM/MRTD/RTMR0-2 are absent,
- whether these fields become informational-only,
- why this leaves system-level integrity gaps despite compose binding and RTMR3/event-log consistency checks.

You MUST quantify realistic attacker capability under this gap (for example, hypervisor-level substitution of firmware/kernel/initrd/rootfs while preserving application-layer bindings).

## Required Recommendations

If golden baselines are missing, provide concrete recommendations that include:
1. published CVM image and TDX module version identifiers,
2. reproducible build references,
3. golden values for MRTD/RTMR0/RTMR1/RTMR2 by hardware profile,
4. expected MRSEAM value by deployed TDX module version,
5. machine-readable versioned manifest endpoint for verifier policy ingestion.

## Section Deliverable

Provide:
1. field-by-field matrix (field × extraction/structural/policy × enforcement status),
2. findings-first list ordered by severity,
3. explicit high-severity residual-risk statement if baseline policy is absent,
4. include at least one concrete positive control and one concrete negative/residual-risk observation,
5. source citations for all claims.
