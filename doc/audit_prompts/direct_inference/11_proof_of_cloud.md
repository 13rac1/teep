# Section 11 — Proof-of-Cloud Verification

## Scope

Audit Proof-of-Cloud (PoC) identity verification flow and its enforcement semantics.

Ensure that the code verifies that the machine ID from the attestation is covered in proof-of-cloud.

## Primary Files

- [`internal/attestation/poc.go`](../../../internal/attestation/poc.go)

## Secondary Context Files

- [`internal/attestation/report.go`](../../../internal/attestation/report.go)

## Required Checks

Verify and report:
- machine identity derivation inputs (for example, PPID from the PCK certificate),
- remote PoC registry/trust-server verification flow,
- quorum/threshold requirements if multiple trust servers are used (expected: 3-of-3 nonce collection, then chained partial signatures),
- behavior when PoC backend is unavailable (hard fail vs advisory skip),
- caching behavior for PoC results and re-query conditions,
- whether PoC outcomes are wired into enforcement or reported informationally.

Track future expansion items separately (for example, DCEA and TPM quote integration), but keep this audit focused on checks currently implemented and required for production security decisions.

Also explicitly separate:
- currently implemented PoC checks,
- future expansion ideas (for example DCEA/TPM quote integration) that should not be treated as present controls.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. PoC flow summary with trust assumptions,
3. enforcement classification for PoC-related factors,
4. include at least one concrete positive control and one concrete negative/residual-risk observation,
5. source citations for all claims.
