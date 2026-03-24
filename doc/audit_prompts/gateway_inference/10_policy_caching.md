# Section 10 — Enforcement Policy, Caching, Negative Cache & Offline Mode

## Scope

Audit verification enforcement boundary and failure semantics, plus all cache layers that influence attestation and forwarding decisions, covering BOTH gateway factors (Tier 4) and model factors (Tier 1–3).

This section is required to prevent regressions where checks continue to be reported but are no longer security-enforcing.

The necessary verification information MAY be cached locally. However, the attestation report MUST be verified against either cached or live data, for EACH new TLS connection to the gateway.

The audit MUST classify every security check in the system as one of:
- **`enforced fail-closed`** — failure blocks request forwarding,
- **`computed but non-blocking`** — result is computed and reported but does not block traffic,
- **`skipped/advisory`** — check is not performed or is purely informational.

## Primary Files

- [`internal/attestation/report.go`](../../../internal/attestation/report.go)
- [`internal/proxy/proxy.go`](../../../internal/proxy/proxy.go)
- [`internal/config/config.go`](../../../internal/config/config.go)

## Secondary Context Files

- [`internal/attestation/measurement_policy.go`](../../../internal/attestation/measurement_policy.go)
- [`internal/config/config_test.go`](../../../internal/config/config_test.go)
- [`internal/provider/nearcloud/pinned.go`](../../../internal/provider/nearcloud/pinned.go)

## Required Checks

### Verification Factor Enforcement

Verify and report:
- complete verification-factor table with pass/fail/skip semantics — covering BOTH model (Tier 1–3) and gateway (Tier 4) factors,
- whether each factor is enforced by policy,
- whether failure blocks forwarding,
- whether failure degrades confidentiality/integrity without blocking traffic,
- how enforced factors are configured (hardcoded/config/env),
- startup behavior for unknown/misspelled factor names (must reject vs silent ignore),
- existence and usage of a pre-forwarding block gate (`Blocked()` or equivalent) on every forwarded request.

#### `Blocked()` Gate Implementation

Verify:
- that `Blocked()` is invoked on every code path that forwards traffic (not just the happy path),
- that the return value is checked — a `true` result MUST return an error response (e.g., HTTP 503) to the client,
- that `Blocked()` cannot be bypassed by error handling or fallback code paths,
- that there is no TOCTOU gap between calling `Blocked()` and actually forwarding the request,
- that `Blocked()` checks BOTH model and gateway enforcement factors.

#### Factor Configuration Mechanism

Enforcement is configured via a three-layer mechanism:
1. **Hardcoded defaults** — `DefaultEnforced` in `report.go`, copied at startup,
2. **TOML config file** — `[policy] enforce = [...]` overrides the default list entirely when present,
3. **No per-factor env var override** — individual factors cannot be toggled via environment.

Verify:
- that `DefaultEnforced` is copied (not shared by reference),
- that the TOML list **replaces** (not appends to) the default,
- that unknown factor names in the TOML enforce list are rejected at startup by checking against `KnownFactors`.

#### Expected Default Enforced Factors

Validate the actual `DefaultEnforced` list in code against these expected factors:

**Model backend factors (Tier 1–3):**
- `nonce_match` — prevents replay of stale model attestations,
- `tdx_cert_chain` — validates model PCK chain to Intel roots,
- `tdx_quote_signature` — validates model quote signature,
- `tdx_debug_disabled` — prevents model debug enclaves from being trusted,
- `signing_key_present` — ensures the model enclave provided a public key for E2EE,
- `tdx_reportdata_binding` — prevents key-substitution MITM on the model backend's E2EE key,
- `compose_binding` — enforces model image/config binding to MRConfigID,
- `nvidia_signature` — enforces local NVIDIA signature validation when NVIDIA evidence exists,
- `nvidia_nonce_match` — enforces NVIDIA nonce freshness binding,
- `build_transparency_log` — enforces provenance for attested container images,
- `sigstore_verification` — enforces Sigstore presence for image digests,
- `event_log_integrity` — enforces model RTMR replay consistency when event logs are present.

**Gateway factors (Tier 4):**
- `gateway_nonce_match` — prevents replay of stale gateway attestations,
- `gateway_tdx_cert_chain` — validates gateway PCK chain to Intel roots,
- `gateway_tdx_quote_signature` — validates gateway quote signature,
- `gateway_tdx_debug_disabled` — prevents gateway debug enclaves from being trusted,
- `gateway_tdx_reportdata_binding` — binds gateway TLS certificate to its TDX quote,
- `gateway_compose_binding` — enforces gateway image/config binding to MRConfigID,
- `gateway_event_log_integrity` — enforces gateway RTMR replay consistency when event logs are present.

Evaluate whether additional factors should be enforced by default (e.g., `tdx_tcb_current`, gateway Sigstore/Rekor checks), and document the rationale.

#### Complete Factor Inventory

Cross-reference `KnownFactors` to produce a complete matrix. For each factor, document:
- its enforcement status (default-enforced vs non-enforced),
- what a `Pass`, `Fail`, and `Skip` result means,
- what threat it mitigates,
- what residual risk exists if non-enforced or skipped.

### Cache-Layer Safety

Audit each cache layer and produce this table:

| Cache | Keys | TTL | Bounds/Eviction | Stale Behavior | Security-Critical Notes |
|-------|------|-----|-----------------|----------------|-------------------------|
| Attestation report cache | provider, model | ~minutes | ... | ... | Signing key MUST NOT be cached; must be fetched fresh for each E2EE session |
| Negative cache | provider, model | ~seconds | ... | ... | Must prevent upstream hammering; must expire so recovery is possible |
| SPKI pin cache | gateway domain, spkiHash | ~hour | ... | ... | Must be populated only after successful attestation of BOTH gateway and model; eviction must force re-attestation |
| Signing key cache | provider, model | ~minute | ... | ... | Shorter than attestation cache; holds REPORTDATA-verified signing key for E2EE |
| PCS collateral cache | platform FMSPC | ~hours | ... | ... | TCB info and CRL freshness |
| CT log cache | domain | ~hours | ... | ... | CT check is for the gateway TLS cert |
| JWKS cache | JWKS URL | ~1 hour | ... | ... | Keyfunc auto-refresh with rate-limited unknown-kid fallback |

Verify:
- cache miss semantics (must trigger re-attestation of BOTH gateway and model, never pass-through),
- eviction behavior under pressure and whether it can silently weaken security,
- stale-serving behavior and guardrails,
- whether any cache uses unbounded maps (potential memory exhaustion),
- maximum entry limits and whether they are configurable,
- that the SPKI pin cache uses the gateway's domain and SPKI (since the proxy connects to the gateway).

### Negative Cache Recovery Semantics

Verify and report:
- failed attestation (for either gateway or model) records a negative entry,
- negative entries expire on bounded TTL,
- negative cache size is bounded with eviction,
- negative-cache hit returns explicit client error (e.g., HTTP 503) rather than fail-open,
- negative cache key specificity (domain + SPKI or model + provider).

### Offline Mode Safety

If the system supports an offline mode, enumerate exactly which checks are skipped and which remain active — for BOTH gateway and model attestation:

**Expected skipped (network-dependent):**
- Intel PCS collateral checks,
- NRAS cloud verification,
- Sigstore/Rekor checks,
- Proof-of-Cloud checks,
- Certificate Transparency checks.

**Expected active (local cryptographic):**
- Quote parsing and signature verification (both gateway and model),
- PCK chain validation against embedded root,
- REPORTDATA binding (both gateway and model),
- SPKI extraction and comparison (gateway),
- Event log replay (both gateway and model),
- Local NVIDIA EAT verification.

Verify:
- that the offline flag is propagated to all verification code paths,
- that local cryptographic verification remains active in offline mode for both gateway and model,
- produce residual risk statement for offline operation.

### Sensitive Data Handling

Verify:
- API keys never logged in plaintext (`RedactKey()` redaction),
- config file permission checks classified as warning-only or hard-fail,
- ephemeral E2EE session keys zeroed after use (with GC limitations noted),
- attestation nonces not reused across requests,
- model backend signing key only used for ECDH after REPORTDATA binding verification.

## Best-Practice Audit Points

### Go (Golang) Best Practices

- **Map concurrency safety**: All cache maps protected by appropriate synchronization.
- **Slice copy for defaults**: `DefaultEnforced` copied, not shared by reference.
- **Error wrapping**: Errors from cache operations and enforcement checks use `%w`.
- **Bounded iteration**: Factor evaluation iterates a fixed set, no input-controlled count.

### Cryptography Best Practices

- **Constant-time comparison**: Factor comparisons use `subtle.ConstantTimeCompare` consistently.
- **No signing key caching across E2EE sessions**: Each session requires a fresh key exchange.
- **Nonce entropy**: `crypto/rand` only, hard abort on failure.

### General Security Audit Practices

- **Fail-secure defaults**: If `DefaultEnforced` is empty, the proxy should refuse to start or refuse all traffic.
- **Defense in depth for caching**: Cache corruption or eviction must always result in re-verification.
- **Audit trail**: Enforcement decisions logged with sufficient detail for forensic analysis.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. verification-factor matrix (all factors, covering both model and gateway, with enforcement status),
3. cache-layer table (all cache layers populated),
4. offline-mode matrix (active vs skipped checks),
5. negative cache recovery assessment,
6. sensitive-data handling assessment,
7. include at least one concrete positive control and one concrete negative/residual-risk observation,
8. source citations for all claims.
