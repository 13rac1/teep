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

Teep uses an **inverted enforcement model**: any factor NOT in the provider's `DefaultAllowFail` list is enforced by default. Adding a new factor automatically enforces it unless explicitly added to the allow-fail list. The nearcloud provider uses `NearcloudDefaultAllowFail` (defined in `internal/attestation/report.go`), which is stricter than the global `DefaultAllowFail`.

Enforcement is configured via a three-layer mechanism:
1. **Hardcoded defaults** — `DefaultAllowFail` and provider-specific `NearcloudDefaultAllowFail` in `report.go`,
2. **TOML config file** — `[policy] allow_fail = [...]` overrides the default allow-fail list when present,
3. **No per-factor env var override** — individual factors cannot be toggled via environment.

Verify:
- that `DefaultAllowFail` / `NearcloudDefaultAllowFail` are copied (not shared by reference),
- that the TOML `allow_fail` list **replaces** (not appends to) the default,
- that unknown factor names in the TOML enforce/allow_fail list are rejected at startup by checking against `KnownFactors`.

#### Nearcloud Allowed-to-Fail Factors

The current `NearcloudDefaultAllowFail` factors are:
- `tdx_hardware_config` — model RTMR0 (varies per deployment hardware),
- `tdx_boot_config` — model RTMR1/RTMR2,
- `e2ee_usable` — chicken-and-egg problem (see Section 08),
- `cpu_gpu_chain` — not yet implemented,
- `measured_model_weights` — not yet implemented,
- `cpu_id_registry` — Proof-of-Cloud hardware registry,
- `gateway_tdx_hardware_config` — gateway RTMR0,
- `gateway_tdx_boot_config` — gateway RTMR1/RTMR2,
- `gateway_tdx_reportdata_binding` — gateway REPORTDATA binding (the audit MUST document whether this is a deliberate design choice or a gap),
- `gateway_cpu_id_registry` — gateway Proof-of-Cloud.

All other factors are enforced by default for nearcloud, including:

**Model backend factors (Tier 1–3):**
- `nonce_match`, `tdx_quote_present`, `tdx_quote_structure`, `tdx_cert_chain`, `tdx_quote_signature`, `tdx_debug_disabled`,
- `tdx_mrseam_mrtd` — enforces model MRSEAM and MRTD allowlists,
- `signing_key_present`, `tdx_reportdata_binding`,
- `tdx_tcb_not_revoked`, `intel_pcs_collateral`, `tdx_tcb_current`,
- `nvidia_payload_present`, `nvidia_signature`, `nvidia_claims`, `nvidia_nonce_client_bound`, `nvidia_nras_verified`,
- `e2ee_capable`, `tls_key_binding`,
- `compose_binding`, `sigstore_verification`, `build_transparency_log`, `event_log_integrity`.

**Gateway factors (Tier 4):**
- `gateway_nonce_match`, `gateway_tdx_quote_present`, `gateway_tdx_quote_structure`,
- `gateway_tdx_cert_chain`, `gateway_tdx_quote_signature`, `gateway_tdx_debug_disabled`,
- `gateway_tdx_mrseam_mrtd` — enforces gateway MRSEAM and MRTD allowlists,
- `gateway_compose_binding`, `gateway_event_log_integrity`.

The audit MUST evaluate whether additional factors should be enforced and document the rationale for the current enforcement boundary.

> **Known divergence**: Venice currently uses the global `DefaultAllowFail` (less strict than `NearcloudDefaultAllowFail`), has no gateway factors, and does not enforce `tdx_mrseam_mrtd` or `build_transparency_log` by default. Venice may have its own allow_fail list in the future.

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
- **Slice copy for defaults**: `DefaultAllowFail` and `NearcloudDefaultAllowFail` copied, not shared by reference.
- **Error wrapping**: Errors from cache operations and enforcement checks use `%w`.
- **Bounded iteration**: Factor evaluation iterates a fixed set, no input-controlled count.

### Cryptography Best Practices

- **Constant-time comparison**: Factor comparisons use `subtle.ConstantTimeCompare` consistently.
- **No signing key caching across E2EE sessions**: Each session requires a fresh key exchange.
- **Nonce entropy**: `crypto/rand` only, hard abort on failure.

### General Security Audit Practices

- **Fail-secure defaults**: With the inverted enforcement model, an empty `DefaultAllowFail` means ALL factors are enforced — verify this is the desired fail-secure behavior.
- **Defense in depth for caching**: Cache corruption or eviction must always result in re-verification.
- **Audit trail**: Enforcement decisions logged with sufficient detail for forensic analysis.

## Known Divergence: Chutes/Sek8s

Chutes uses a separate enforcement configuration (`ChutesDefaultAllowFail`) with significantly more factors in allow-fail compared to nearcloud.

### Chutes Enforcement Model

**Enforced factors** (NOT in `ChutesDefaultAllowFail`):
- `nonce_match`, `tdx_quote_present`, `tdx_quote_structure`, `tdx_cert_chain`, `tdx_quote_signature`, `tdx_debug_disabled`
- `tdx_mrseam_mrtd`, `tdx_reportdata_binding`
- `intel_pcs_collateral`, `tdx_tcb_not_revoked`, `tdx_tcb_current`
- `e2ee_capable`, `signing_key_present`

**Allow-fail factors** (in `ChutesDefaultAllowFail`):
- `compose_binding`, `sigstore_verification`, `build_transparency_log`, `event_log_integrity`
- `tls_key_binding`, `nvidia_signature`, `nvidia_nras_verified`, `cpu_gpu_chain`
- `measured_model_weights`, `cpu_id_registry`, `e2ee_usable`

No `gateway_*` factors exist for chutes (the Chutes gateway is unattested and produces no TDX quote).

### Chutes Cache Model

Chutes uses different caching mechanisms:
- **Nonce pool** (`noncepool.go`): Pre-generated nonces for attestation freshness. Auditors should verify pool size bounds, nonce entropy, and that pool exhaustion fails closed.
- **Model resolver** (`models.go`): Maps model names to chute IDs. Verify cache TTL/bounds.
- **No SPKI pin cache**: Chutes does not use attestation-bound TLS pinning.
- **Attestation report cache**: Chutes attestation results may be cached per chute ID. Verify TTL and cache-miss re-attestation behavior.

Primary reference: `internal/provider/chutes/policy.go`, `internal/provider/chutes/noncepool.go`.

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
