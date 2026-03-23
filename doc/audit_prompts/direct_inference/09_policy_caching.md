# Section 09 — Enforcement Policy, Caching, Negative Cache & Offline Mode

## Scope

Audit verification enforcement boundary and failure semantics, plus all cache layers that influence attestation and forwarding decisions.

This section is required to prevent regressions where checks continue to be reported but are no longer security-enforcing.

The necessary verification information MAY be cached locally so that Sigstore and Rekor do not need to be queried on every single connection attempt. However, the attestation report MUST be verified against either cached or live data, for EACH new TLS connection to the API provider.

The audit MUST classify every security check in the system as one of:
- **`enforced fail-closed`** — failure blocks request forwarding,
- **`computed but non-blocking`** — result is computed and reported but does not block traffic,
- **`skipped/advisory`** — check is not performed or is purely informational.

## Primary Files

- [`internal/attestation/report.go`](../../../internal/attestation/report.go)
- [`internal/proxy/proxy.go`](../../../internal/proxy/proxy.go)
- [`internal/config/config.go`](../../../internal/config/config.go)

## Secondary Context Files

- [`internal/attestation/measurement_policy.go`](../../../internal/attestation/measurement_policy.go) — `MeasurementPolicy` allowlist structure
- [`internal/config/config_test.go`](../../../internal/config/config_test.go) — enforcement config validation tests

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

#### `Blocked()` Gate Implementation

The [`Blocked()`](../../../internal/attestation/report.go:63) method on `VerificationReport` iterates all factor results and returns `true` if any factor with `Enforced=true` has `Status==Fail`. The proxy MUST call this method before forwarding every request. Verify:
- that `Blocked()` is invoked on every code path that forwards traffic (not just the happy path),
- that the return value is checked — a `true` result MUST return an error response (e.g., HTTP 503) to the client,
- that `Blocked()` cannot be bypassed by error handling or fallback code paths,
- that there is no TOCTOU gap between calling `Blocked()` and actually forwarding the request.

#### Factor Configuration Mechanism

Enforcement is configured via a three-layer mechanism:
1. **Hardcoded defaults** — [`DefaultEnforced`](../../../internal/attestation/report.go:76) in `report.go`, copied at startup,
2. **TOML config file** — `[policy] enforce = [...]` overrides the default list entirely when present,
3. **No per-factor env var override** — individual factors cannot be toggled via environment.

The audit MUST verify:
- that `DefaultEnforced` is copied (not shared by reference) so runtime mutations cannot affect the default,
- that the `[policy] enforce` list in TOML **replaces** (not appends to) the default, and whether this behavior is clearly documented,
- that unknown factor names in the TOML enforce list are rejected at startup by checking against [`KnownFactors`](../../../internal/attestation/report.go:93) (the code uses a `map[string]bool` lookup for this validation in [`config.go`](../../../internal/config/config.go:140-149)).

#### Expected Currently-Enforced Defaults

Validate the actual [`DefaultEnforced`](../../../internal/attestation/report.go:76) list in code. Note that the code may include additional factors beyond this expected set:
- `nonce_match`
- `tdx_cert_chain`
- `tdx_quote_signature`
- `tdx_debug_disabled`
- `signing_key_present`
- `tdx_reportdata_binding`
- `compose_binding`
- `nvidia_signature`
- `nvidia_nonce_match`
- `build_transparency_log`
- `sigstore_verification`
- `event_log_integrity`

Also evaluate whether controls such as `tdx_tcb_current` should be enforced by default, and document the rationale for the current enforcement boundary.

#### Complete Factor Inventory

Cross-reference [`KnownFactors`](../../../internal/attestation/report.go:93) to produce a complete matrix covering all 24 factors. For each factor, document:
- its enforcement status (default-enforced vs non-enforced),
- what a `Pass`, `Fail`, and `Skip` result means,
- what threat it mitigates,
- what residual risk exists if the factor is non-enforced or skipped.

### Measurement Policy Allowlist Configuration

The [`MeasurementPolicy`](../../../internal/attestation/measurement_policy.go) structure enables optional allowlists for TDX measurements (MRTD, MRSEAM, RTMR0-3). Verify:
- that empty allowlists (no TOML config) result in informational-only measurement reporting and do not block traffic,
- that the [`normalizeAllowlist()`](../../../internal/config/config.go:184) function validates hex encoding and byte length (48 bytes for TDX registers),
- that an explicitly set but empty `[]` allowlist is treated as a configuration error (not as "allow-all"),
- that the `0x` prefix is stripped during normalization,
- that allowlist matching is case-insensitive (hex is lowercased before comparison).

### Cache-Layer Safety

Audit each cache layer and produce this table in your output:

| Cache | Keys | TTL | Bounds/Eviction | Stale Behavior | Security-Critical Notes |
|------|------|-----|-----------------|----------------|-------------------------|
| Attestation report cache | provider, model | ~minutes | ... | ... | Signing key MUST NOT be cached; must be fetched fresh for each E2EE session |
| Negative cache | provider, model | ~seconds | ... | ... | Must prevent upstream hammering; must expire so recovery is possible |
| SPKI pin cache | domain, spkiHash | ~hour | ... | ... | Must be populated only after successful attestation; eviction must force re-attestation |
| Endpoint mapping cache | model→domain | ~minutes | ... | ... | Stale mapping must not bypass attestation |
| PCS collateral cache | platform FMSPC | ~hours | ... | ... | TCB info and CRL freshness bounds Intel-mandated revocation windows |
| CT log cache | domain | ~hours | ... | ... | CT check is for the model router and model endpoint TLS certs |
| JWKS cache | JWKS URL | ~1 hour | ... | ... | Keyfunc auto-refresh with rate-limited unknown-kid fallback; hard max age via `jwksCacheTTL` |

The audit MUST verify that cache eviction under memory pressure does not silently allow unattested connections. A cache miss MUST trigger re-attestation, never a pass-through.

Verify and report:
- cache miss semantics (must trigger re-attestation, never pass-through),
- eviction behavior under pressure and whether it can silently weaken security,
- stale-serving behavior and guardrails,
- whether any cache uses unbounded maps (potential memory exhaustion under adversarial load),
- maximum entry limits on each cache and whether they are configurable.

### Negative Cache Recovery Semantics

Verify and report:
- failed attestation records a negative entry,
- negative entries expire on bounded TTL,
- negative cache size is bounded with eviction behavior,
- negative-cache hit returns explicit client error (e.g., HTTP 503) rather than fail-open forwarding,
- that the negative cache key includes sufficient specificity (domain + SPKI or model + provider) to avoid overly broad blocking.

### Connection Lifetime and Re-Attestation

TLS connections to the model server MUST be closed after each request-response cycle to ensure each new request triggers a fresh attestation or SPKI cache check. Verify:
- that the response body wrapper closes the underlying TCP connection when the body is consumed or closed (`Connection: close` header behavior),
- that connection read/write timeouts are set and reasonable (preventing indefinite hangs),
- that a half-closed or errored connection cannot be mistakenly reused for a subsequent request,
- that if connection reuse is permitted, re-attestation is correctly triggered on every new request (not just on new connections).

### Offline Mode Safety

If the system supports an offline mode, the audit MUST enumerate exactly which checks are skipped (for example, Intel PCS collateral, NRAS, Sigstore, Rekor, Proof-of-Cloud, Certificate Transparency) and which checks still execute locally (for example, quote parsing/signature checks, report-data binding, event-log replay, local NVIDIA EAT verification).

For the pinned connection path, the audit MUST verify whether offline mode is honored (the PinnedHandler receives an `offline` flag). The offline flag must suppress only network-dependent checks — all local cryptographic verification must remain active.

The [`Config.Offline`](../../../internal/config/config.go:95) flag is set via `--offline` at runtime. Verify:
- that the offline flag is propagated to all verification code paths,
- that [`NewAttestationClient()`](../../../internal/config/config.go:303) disables CT checks in offline mode,
- that local cryptographic verification (quote signature, cert chain, SPDM signatures, event log replay) remains active in offline mode.

Produce an offline matrix with:
- skipped network-dependent checks,
- locally-executed checks that remain active,
- pinned-handler offline flag propagation behavior,
- residual risk statement for offline operation.

### Sensitive Data Handling

Verify and report:
- that API keys are never logged in plaintext — [`RedactKey()`](../../../internal/config/config.go:291) shows first 4 chars + `"****"`,
- that config file permission checks warn on group/world-readable files (current behavior is warning-only, not hard-fail; classify this),
- that ephemeral cryptographic key material (E2EE session keys) is zeroed after use, with acknowledgment of Go GC limitations (GC may copy objects, preventing reliable zeroing),
- that attestation nonces are not reused across requests.

## Best-Practice Audit Points

### Go (Golang) Best Practices

- **Map concurrency safety**: Verify that all cache maps are protected by appropriate synchronization (`sync.Mutex`, `sync.RWMutex`, or `sync.Map`). Unsynchronized `map` access from multiple goroutines causes data races and potential panics.
- **Slice copy for defaults**: [`DefaultEnforced`](../../../internal/attestation/report.go:76) is a package-level `var` slice. Verify that callers copy it (`append([]string(nil), DefaultEnforced...)`) rather than sharing the backing array, to prevent mutation from one caller affecting another.
- **Error wrapping**: Verify that errors from cache operations and enforcement checks use `%w` wrapping to preserve sentinel error matching (e.g., `errors.Is`) through the call chain.
- **Interface usage for caching**: Check whether cache layers use interfaces that allow test substitution (mock caches for unit testing eviction behavior and race conditions).
- **Bounded iteration**: Factor evaluation in [`BuildReport()`](../../../internal/attestation/report.go:135) iterates a fixed set of factors. Verify there is no input-controlled iteration count that could cause performance degradation.

### Cryptography Best Practices

- **Constant-time comparison**: Nonce and factor comparisons in [`report.go`](../../../internal/attestation/report.go) use `subtle.ConstantTimeCompare`. Verify this is used consistently for all security-critical comparisons (not just nonce matching).
- **No signing key caching**: The attestation report cache MUST NOT cache the enclave's signing/ECDH public key across E2EE sessions. Each session requires a fresh key exchange. Verify that cached attestation reports do not cause key reuse.
- **Nonce entropy**: Verify that nonce generation uses `crypto/rand` and that failure to read random bytes causes a hard abort (no fallback to `math/rand` or weak sources).

### General Security Audit Practices

- **Fail-secure defaults**: If `DefaultEnforced` is empty or misconfigured, the proxy should refuse to start or refuse all traffic — never default to allowing everything.
- **Defense in depth for caching**: Cache corruption or eviction must always result in re-verification, never in silent trust.
- **Trust boundary at cache boundaries**: Cached data that originated from untrusted sources (attestation responses, NRAS JWTs) must be re-validated on use if the cache format could be corrupted.
- **Audit trail**: Verify that enforcement decisions (blocked or allowed) are logged with sufficient detail for post-incident forensic analysis, including which factors passed/failed and whether the result was from cache or fresh verification.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. verification-factor matrix (all 24 factors with enforcement status, pass/fail/skip semantics, and threat-mitigation mapping),
3. cache-layer table (with all 7+ cache layers populated),
4. offline-mode matrix (active vs skipped checks),
5. sensitive-data handling assessment,
6. include at least one concrete positive control and one concrete negative/residual-risk observation,
7. source citations for all claims.
