# Section 09 — Enforcement Policy, Caching, Negative Cache & Offline Mode

## Scope

Audit verification enforcement boundary and failure semantics, plus all cache layers that influence attestation and forwarding decisions.

## Primary Files

- [`internal/attestation/report.go`](../../../internal/attestation/report.go)
- [`internal/proxy/proxy.go`](../../../internal/proxy/proxy.go)
- [`internal/config/config.go`](../../../internal/config/config.go)

## Required Checks

### Verification Factor Enforcement

Verify and report:
- complete verification-factor table with pass/fail/skip semantics,
- whether each factor is enforced by policy,
- whether failure blocks forwarding,
- whether failure degrades confidentiality/integrity without blocking traffic,
- how enforced factors are configured (hardcoded/config/env),
- startup behavior for unknown/misspelled factor names (must identify reject vs silent ignore),
- existence and usage of a pre-forwarding block gate (`Blocked()` or equivalent) on every forwarded request.

Expected currently-enforced defaults to validate in code:
- `nonce_match`
- `tdx_cert_chain`
- `tdx_quote_signature`
- `tdx_debug_disabled`
- `signing_key_present`
- `tdx_reportdata_binding`
- `compose_binding`
- `nvidia_signature`
- `nvidia_nonce_match`
- `event_log_integrity`

Also evaluate whether controls such as `tdx_tcb_current`, `sigstore_verification`, or `build_transparency_log` should be enforced by default.

### Cache-Layer Safety

Audit each cache layer and produce this table in your output:

| Cache | Keys | TTL | Bounds/Eviction | Stale Behavior | Security-Critical Notes |
|------|------|-----|-----------------|----------------|-------------------------|
| Attestation report cache | provider, model | (actual code value) | ... | ... | Signing key freshness expectation |
| Negative cache | provider, model | (actual code value) | ... | ... | Upstream hammering prevention |
| SPKI pin cache | domain, spkiHash | (actual code value) | ... | ... | Must only populate after successful attestation |
| Endpoint mapping cache | model→domain | (actual code value) | ... | ... | Stale mapping must not bypass attestation |

Verify and report:
- cache miss semantics (must trigger re-attestation, never pass-through),
- eviction behavior under pressure and whether it can silently weaken security,
- stale-serving behavior and guardrails.

### Negative Cache Recovery Semantics

Verify and report:
- failed attestation records a negative entry,
- negative entries expire on bounded TTL,
- negative cache size is bounded with eviction behavior,
- negative-cache hit returns explicit client error (not fail-open forwarding).

### Offline Mode Safety

If offline mode exists, produce an offline matrix with:
- skipped network-dependent checks,
- locally-executed checks that remain active,
- pinned-handler offline flag propagation behavior,
- residual risk statement for offline operation.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. verification-factor matrix,
3. cache-layer table,
4. offline-mode matrix (if applicable),
5. include at least one concrete positive control and one concrete negative/residual-risk observation,
6. source citations for all claims.
