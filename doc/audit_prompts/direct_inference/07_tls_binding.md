# Section 07 — REPORTDATA Binding, TLS Pinning & Connection Lifetime

## Scope

Audit cryptographic channel binding (`REPORTDATA`), attestation-bound TLS pinning, pin-cache safety, Certificate Transparency enforcement, and per-request connection lifecycle integrity.

The attestation report must bind channel identity and key material in a way that prevents key-substitution attacks. For each provider, the audit MUST document the exact REPORTDATA scheme and verify it byte-for-byte.

TLS connections to the model server MUST be closed after each request-response cycle (`Connection: close`) to ensure each new request triggers a fresh attestation or SPKI cache check. If the implementation reuses connections, the audit MUST verify that re-attestation is correctly triggered on every new request, not just on new connections.

Certificate Transparency MUST be consulted for the TLS certificate of the model endpoint. This CT log report SHOULD be cached. The audit MUST document how CT checking is integrated into the attestation flow and whether a CT failure is enforced or advisory.

## Primary Files

- [`internal/provider/neardirect/reportdata.go`](../../../internal/provider/neardirect/reportdata.go)
- [`internal/attestation/spki.go`](../../../internal/attestation/spki.go)
- [`internal/proxy/proxy.go`](../../../internal/proxy/proxy.go)

## Secondary Context Files

- [`internal/provider/neardirect/pinned.go`](../../../internal/provider/neardirect/pinned.go)
- [`internal/provider/neardirect/ct.go`](../../../internal/provider/neardirect/ct.go)
- [`internal/tlsct/checker.go`](../../../internal/tlsct/checker.go)
- [`internal/attestation/spki_test.go`](../../../internal/attestation/spki_test.go)

## Background: TLS Binding in the Attestation Chain

The TLS binding is a critical link in the overall attestation chain:

1. The client connects over TLS to the model server and extracts the SPKI hash from the live connection.
2. The client fetches the attestation report from the same TLS connection.
3. The attestation report's `REPORTDATA` field cryptographically binds the TLS fingerprint (SPKI) to the TEE's identity and the client's nonce.
4. The TDX quote signature over the report (including `REPORTDATA`) proves the TEE generated these bindings.

If any link in this chain is broken (e.g., SPKI extracted from a different connection, or `REPORTDATA` comparison is non-constant-time, or certificate rotation not detected), a man-in-the-middle can substitute their own TLS certificate. The audit MUST trace this full chain and identify any gaps.

## Required Checks

### REPORTDATA Scheme Validation

For NEAR AI, verify and report byte-level behavior:
- `REPORTDATA[0:32] = SHA256(signing_address_bytes || tls_fingerprint_bytes)`
- `REPORTDATA[32:64] = raw_client_nonce_32_bytes`

Also verify:
- signing address hex decoding and optional `0x` prefix stripping,
- TLS fingerprint is decoded from hex before hashing (not hashed as ASCII hex),
- decoded input lengths are validated where applicable (or residual collision/ambiguity risk is documented — the concatenation of `signing_address || tls_fingerprint` has no separator or length prefix, so if field lengths are not validated, different splits of the same byte sequence produce the same hash),
- strict concatenation order `(address || fingerprint)` and no separators/length prefixes,
- validation of both REPORTDATA halves (not just the first half),
- constant-time comparison behavior (`subtle.ConstantTimeCompare` or equivalent),
- fail-closed enforcement on mismatch (blocks forwarding, not merely logged),
- provider-pluggable verifier model (different providers can use different binding schemes),
- fail-safe behavior when verifier is missing/unconfigured (no default pass-through).

The `tdx_reportdata_binding` factor is one of the default enforced factors. The audit MUST verify that a REPORTDATA mismatch triggers failure through the enforcement code path.

### TLS Pinning & TOCTOU Safety

Verify and report:
- SPKI hash extraction from the same live TLS connection used for attestation (via `ComputeSPKIHash()` which computes SHA-256 of the DER-encoded `RawSubjectPublicKeyInfo`),
- SPKI hash algorithm used (expected SHA-256 over DER SubjectPublicKeyInfo — the code returns lowercase hex encoding),
- comparison semantics between attested fingerprint and live SPKI (exact string comparison of hex-encoded hashes),
- constant-time properties (or explicit justification if not constant-time — document whether the SPKI comparison uses `subtle.ConstantTimeCompare` or direct string equality),
- attestation fetch and inference occurring on one TLS connection (preventing TOCTOU where a different server is contacted for inference),
- response-body close semantics closing underlying TCP connection (preventing connection reuse for a different unattested host),
- behavior and cryptographic compensation if CA verification is bypassed (any `InsecureSkipVerify` or custom pinning replacing CA checks MUST be justified and cryptographically compensated by attestation checks),
- `ServerName` SNI behavior when custom TLS verification is used (must still be set for SNI even when CA verification is bypassed).

### Certificate Transparency (CT) Integration

Verify and report:
- whether CT log checking is performed for the model server TLS certificate,
- CT cache keying and TTL behavior,
- whether CT failure blocks the connection or is advisory-only,
- whether CT checks cover all domains in the attestation flow (model routing endpoint and model server endpoint).

### Pin Cache & Connection Lifetime

The SPKI cache implementation uses per-domain hash maps with the following expected parameters:
- maximum of 16 SPKI hashes per domain (`maxSPKIsPerDomain`),
- default TTL of 1 hour (`defaultSPKITTL`),
- oldest-entry eviction when per-domain limit is exceeded (after pruning expired entries).

Verify and report:
- pin-cache keys (domain → spkiHex), TTL (1 hour), max entries (16 per domain), and eviction strategy (prune expired first, then evict oldest) and whether total domain count is bounded,
- cache miss behavior (must re-attest, never pass-through),
- singleflight/concurrency collapse behavior with post-win double-check,
- whether singleflight key includes both domain and SPKI (so a certificate rotation triggers a new attestation rather than coalescing with the old one),
- connection reuse policy (`Connection: close` expectations),
- that the response body wrapper closes the underlying TCP connection when the body is consumed or closed,
- read/write timeout settings (preventing indefinite hangs),
- that a half-closed or errored connection cannot be mistakenly reused for a subsequent request.

The audit MUST verify that cache eviction under memory pressure does not silently allow unattested connections. A cache miss MUST trigger re-attestation, never a pass-through.

### Offline Mode for Pinned Connections

For the pinned connection path, the audit MUST verify whether offline mode is honored (the `PinnedHandler` receives an `offline` flag). The offline flag must suppress only network-dependent checks — all local cryptographic verification (REPORTDATA binding, SPKI extraction, quote signature checks) must remain active.

### HTTP Request Construction Safety

For direct inference providers that construct raw HTTP requests on the underlying TLS connection (bypassing Go's `http.Client` connection pooling), the audit MUST verify:
- that the `Host` header is always set and matches the attested domain,
- that `Content-Length` is derived from the actual body length (not caller-supplied),
- that no user-supplied data is interpolated into HTTP request lines or headers without sanitization (HTTP header injection prevention),
- that header values reject CR/LF characters (or equivalent canonicalization/sanitization is applied),
- that the request path is constructed from trusted constants plus URL-encoded query parameters.

## Go Best-Practice Audit Points

- **`sync.RWMutex` correctness**: the `SPKICache` uses `RWMutex` — verify that `Contains()` takes a read lock and `Add()` takes a write lock, and that no lock is held across blocking operations (potential deadlock).
- **`time.Since` race**: `time.Since(entry.addedAt) <= c.ttl` is evaluated under the lock — verify there is no TOCTOU between checking expiry and using the result.
- **Map iteration during mutation**: `Add()` iterates `c.domains[domain]` and deletes within the same loop — this is safe in Go but auditor should confirm the implementation does not rely on iteration order.
- **Interface-based provider pluggability**: verify that the REPORTDATA verifier is pluggable per provider via an interface or function type, and that a missing verifier for a provider fails closed (not a nil-pointer panic or silent pass).
- **Error wrapping**: verify that TLS and SPKI errors are wrapped with `%w` for proper error chain inspection by callers.
- **Goroutine safety**: if singleflight is used for concurrent attestation attempts, verify that the singleflight result is not shared in a way that allows one goroutine to observe an incomplete attestation state.

## Cryptography Best-Practice Audit Points

- **SPKI hash computation**: confirm that `ComputeSPKIHash()` hashes `cert.RawSubjectPublicKeyInfo` (the DER-encoded SubjectPublicKeyInfo, including the algorithm identifier — not just the raw public key bytes). This matches the standard SPKI fingerprinting used by browsers.
- **SHA-256 for SPKI, SHA-256 for REPORTDATA[0:32]**: confirm correct hash algorithm selection for each context.
- **Constant-time comparison**: all security-critical comparisons (REPORTDATA halves, SPKI match) SHOULD use `subtle.ConstantTimeCompare`. Document any that use direct equality and assess timing side-channel risk.
- **Certificate parsing with `x509.ParseCertificate`**: verify that only the leaf certificate DER is passed (not the full chain), and that parse errors are handled as hard failures.
- **No hash truncation**: verify that SHA-256 output is compared in full (32 bytes / 64 hex chars) with no prefix-only matching.

## General Security Audit Points

- **Trust boundary identification**: the TLS connection terminates at the model server, which is inside the TEE. The SPKI hash extraction and REPORTDATA binding together create a cryptographic proof that the TLS peer is the attested TEE. Any gap in this chain (e.g., connection reuse, certificate caching separate from SPKI cache) is a trust boundary violation.
- **Defense in depth**: even with attestation-bound TLS pinning, CA verification bypass (`InsecureSkipVerify`) removes a layer of defense. The audit MUST document whether this is justified and what compensating controls exist (the attestation chain itself is the compensation).
- **Fail-secure defaults**: verify that a new provider added without a REPORTDATA verifier implementation cannot silently pass verification.
- **Connection isolation**: verify that the `Transport` or connection mechanism ensures that the same TCP/TLS connection used for attestation fetch is used for inference — no connection pooling that could route inference to a different backend.
- **Timeout enforcement**: verify that TLS handshake, attestation fetch, and inference request all have bounded timeouts to prevent resource exhaustion from a slow-loris attack by a malicious model server.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. REPORTDATA byte-level verification summary (covering NEAR AI scheme)
3. SPKI hash computation and comparison correctness summary,
4. pin-cache + connection-lifetime enforcement classification,
5. CT integration status and enforcement level,
6. offline-mode behavior for pinned connections,
7. include at least one concrete positive control and one concrete negative/residual-risk observation,
8. source citations for all claims.
