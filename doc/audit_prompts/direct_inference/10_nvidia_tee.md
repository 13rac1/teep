# Section 10 — NVIDIA TEE Verification Depth

## Scope

Audit NVIDIA evidence verification depth across both local evidence validation (EAT/SPDM) and remote NVIDIA NRAS validation.

The audit MUST verify both layers when present: local NVIDIA evidence verification (EAT/SPDM) performs direct cryptographic validation of GPU attestation tokens, while remote NRAS verification delegates validation to NVIDIA's attestation service and verifies the resulting JWT.

## Primary Files

- [`internal/attestation/nvidia_eat.go`](../../../internal/attestation/nvidia_eat.go)
- [`internal/attestation/nvidia.go`](../../../internal/attestation/nvidia.go)

## Secondary Context Files

- [`internal/attestation/report.go`](../../../internal/attestation/report.go)

## Required Checks

### Local NVIDIA Evidence (EAT/SPDM)

Verify and report:
- EAT JSON parsing behavior and top-level nonce validation,
- constant-time behavior for nonce comparison,
- per-GPU certificate chain verification to pinned NVIDIA root CA,
- root CA pinning method (embedded cert, fingerprint checks, trust-store bypass behavior),
- SPDM message parse robustness (GET_MEASUREMENTS request/response structure, variable-length field handling),
- SPDM signature verification algorithm (ECDSA P-384 with SHA-384 is expected),
- signed-data construction (must include both request and response-minus-signature, in order),
- all-or-nothing semantics when one GPU fails,
- extraction/reporting of GPU count and architecture metadata.

### Remote NRAS Verification

Verify and report:
- JWT signature verification using a cached JWKS endpoint (accepted algorithms: ES256, ES384, ES512 only — HS256 MUST be rejected),
- JWKS caching behavior (auto-refresh, rate-limited unknown-kid fallback),
- JWT claims validation (expiration, issuer, overall attestation result),
- nonce forwarding to NRAS (is it the same client-generated nonce?),
- the exact NRAS endpoint URL and whether it is configurable or hardcoded.

### Offline Behavior

If offline mode exists, identify exactly which NVIDIA checks remain active and which are skipped.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. local-vs-remote NVIDIA verification matrix with enforcement status,
3. outage/offline residual risk statement,
4. include at least one concrete positive control and one concrete negative/residual-risk observation,
5. source citations for all claims.
