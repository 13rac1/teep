# Section 03 — TDX Quote Structure & Signature Verification

## Scope

Audit Intel TDX quote verification pipeline: parsing, certificate chain validation, signature checks, debug status checks, and collateral currency behavior.

## Primary Files

- [`internal/attestation/tdx.go`](../../../internal/attestation/tdx.go)
- [`internal/attestation/crypto.go`](../../../internal/attestation/crypto.go)

## Secondary Context Files

- [`internal/attestation/report.go`](../../../internal/attestation/report.go)

## Required Checks

Verify and report:
- quote structure parsing and supported quote versions,
- PCK certificate chain validation to Intel trust roots,
- quote signature verification behavior,
- debug-bit evaluation and enforcement behavior,
- online collateral checks and TCB currency classification,
- trust-root acquisition model (embedded/provisioned/network) and update assumptions,
- third-party verification library invocation boundaries and interpretation of return values,
- two-pass architecture (offline cryptographic pass then online collateral pass) if present,
- policy behavior for Pass-1-only outcomes (blocking vs advisory).

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. explicit statement of cryptographic-verification boundary vs collateral-dependent checks,
3. enforcement classification for each verification factor,
4. include at least one concrete positive control and one concrete negative/residual-risk observation,
5. source citations for all claims.
