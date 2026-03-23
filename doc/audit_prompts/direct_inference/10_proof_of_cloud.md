# Section 10 — Proof-of-Cloud Verification

## Scope

Audit Proof-of-Cloud (PoC) identity verification flow and its enforcement semantics.

## Primary Files

- [`internal/attestation/poc.go`](../../../internal/attestation/poc.go)

## Secondary Context Files

- [`internal/attestation/report.go`](../../../internal/attestation/report.go)

## Required Checks

Verify and report:
- machine identity derivation inputs (for example PPID extraction from PCK-related material),
- remote PoC registry/trust-server verification flow,
- quorum/threshold requirements if multiple trust servers are used,
- behavior when PoC backend is unavailable (hard fail vs advisory skip),
- caching behavior for PoC results and re-query conditions,
- whether PoC outcomes are wired into enforcement or reported informationally.

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
