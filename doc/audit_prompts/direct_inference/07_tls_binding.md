# Section 07 — REPORTDATA Binding, TLS Pinning & Connection Lifetime

## Scope

Audit cryptographic channel binding (`REPORTDATA`), attestation-bound TLS pinning, pin-cache safety, and per-request connection lifecycle integrity.

## Primary Files

- [`internal/provider/nearai/reportdata.go`](../../../internal/provider/nearai/reportdata.go)
- [`internal/attestation/spki.go`](../../../internal/attestation/spki.go)
- [`internal/proxy/proxy.go`](../../../internal/proxy/proxy.go)

## Secondary Context Files

- [`internal/provider/venice/reportdata.go`](../../../internal/provider/venice/reportdata.go)
- [`internal/provider/nearai/pinned.go`](../../../internal/provider/nearai/pinned.go)

## Required Checks

### REPORTDATA Scheme Validation

For NEAR AI, verify and report byte-level behavior:
- `REPORTDATA[0:32] = SHA256(signing_address_bytes || tls_fingerprint_bytes)`
- `REPORTDATA[32:64] = raw_client_nonce_32_bytes`

Also verify:
- signing address hex decoding and optional `0x` handling,
- TLS fingerprint hex-decoding before hashing,
- input length validation and ambiguity/collision residual risk if absent,
- strict concatenation order and no separators/length prefixes,
- validation of both REPORTDATA halves,
- constant-time comparison behavior,
- fail-closed enforcement on mismatch,
- provider-pluggable verifier model,
- fail-safe behavior when verifier is missing/unconfigured.

### TLS Pinning & TOCTOU Safety

Verify and report:
- SPKI hash extraction from the same live TLS connection used for attestation,
- SPKI hash algorithm used (expected SHA-256 over DER SubjectPublicKeyInfo),
- comparison semantics between attested fingerprint and live SPKI,
- constant-time properties (or explicit justification if not),
- attestation fetch and inference occurring on one TLS connection,
- response-body close semantics closing underlying TCP connection,
- behavior and cryptographic compensation if CA verification is bypassed,
- `ServerName` SNI behavior when custom TLS verification is used.

### Pin Cache & Connection Lifetime

Verify and report:
- pin-cache keys, TTL, max entries, and eviction strategy,
- cache miss behavior (must re-attest, never pass-through),
- singleflight/concurrency collapse behavior with post-win double-check,
- whether singleflight key includes both domain and SPKI,
- connection reuse policy (`Connection: close` expectations),
- read/write timeout settings,
- protection against reuse of half-closed/errored connections.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. REPORTDATA byte-level verification summary,
3. pin-cache + connection-lifetime enforcement classification,
4. include at least one concrete positive control and one concrete negative/residual-risk observation,
5. source citations for all claims.
