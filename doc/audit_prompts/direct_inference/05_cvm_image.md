# Section 05 — CVM Image Binding & Component Provenance

## Scope

Audit CVM image binding to TDX evidence and verification of compose-listed component images using Sigstore/Rekor trust signals.

## Primary Files

- [`internal/attestation/compose.go`](../../../internal/attestation/compose.go)
- [`internal/attestation/sigstore.go`](../../../internal/attestation/sigstore.go)
- [`internal/attestation/rekor.go`](../../../internal/attestation/rekor.go)

## Secondary Context Files

- [`internal/attestation/report.go`](../../../internal/attestation/report.go)
- [`internal/provider/nearai/nearai.go`](../../../internal/provider/nearai/nearai.go)

## Required Checks

Verify and report:
- exact compose-hash-to-`MRCONFIGID` binding format (including byte layout / prefix semantics),
- `app_compose` extraction path and support for double-encoded JSON in `tcb_info`,
- assurance that hash input is the raw extracted compose content (not re-serialized),
- digest extraction logic from compose content (structured parse vs regex),
- handling/rejection of non-`sha256` digest formats,
- deduplication behavior for extracted digests,
- provider allowlist enforcement for all compose sub-images,
- Sigstore query behavior and failure semantics (timeout/outage as hard fail or advisory),
- Rekor provenance extraction and trust classification behavior,
- accepted signer identity model (OIDC issuer / Fulcio cert identity expectations),
- behavior when digest appears in Sigstore but lacks Fulcio cert (raw-key signature path),
- default policy during Sigstore/Rekor outage conditions and resulting residual risk.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. explicit enforcement classification for compose binding vs provenance checks,
3. residual-risk statement for any soft-fail transparency/provenance behavior,
4. include at least one concrete positive control and one concrete negative/residual-risk observation,
5. source citations for all claims.
