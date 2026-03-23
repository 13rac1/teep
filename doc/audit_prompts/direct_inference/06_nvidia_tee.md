# Section 06 — NVIDIA TEE Verification Depth

## Scope

Audit NVIDIA evidence verification depth across both local evidence validation (EAT/SPDM) and remote NVIDIA NRAS validation.

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
- SPDM message parse robustness (GET_MEASUREMENTS framing and variable-length field handling),
- SPDM signature verification algorithm and parameter expectations,
- signed-data construction (request + response-without-signature ordering),
- all-or-nothing semantics when one GPU fails,
- extraction/reporting of GPU count and architecture metadata.

### Remote NRAS Verification

Verify and report:
- JWT signature validation via JWKS (accepted algorithms must exclude HS256),
- JWKS caching behavior, refresh policy, and unknown-kid fallback controls,
- JWT claims checks (issuer, expiry, attestation result),
- nonce forwarding and binding consistency,
- NRAS endpoint configuration model (hardcoded vs configurable).

### Offline Behavior

If offline mode exists, identify exactly which NVIDIA checks remain active and which are skipped.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. local-vs-remote NVIDIA verification matrix with enforcement status,
3. outage/offline residual risk statement,
4. include at least one concrete positive control and one concrete negative/residual-risk observation,
5. source citations for all claims.
