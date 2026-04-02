# Section 07 — REPORTDATA Binding & TLS Pinning (Gateway and Model)

## Scope

Audit cryptographic channel binding (`REPORTDATA`) for both the gateway and model backend, attestation-bound TLS pinning to the gateway, SPKI pin-cache safety, Certificate Transparency enforcement, and per-request connection lifecycle integrity.

The gateway inference model has two distinct REPORTDATA binding schemes:
- **Model backend**: `REPORTDATA[0:32] = SHA256(signing_address || tls_fingerprint)`, `REPORTDATA[32:64] = nonce`
- **Gateway**: `REPORTDATA[0:32] = SHA256(tls_fingerprint)`, `REPORTDATA[32:64] = nonce` (no signing_address)

The TLS pinning targets the gateway's certificate (since the proxy connects to the gateway, not the model backend). The model backend's TLS fingerprint is embedded in its REPORTDATA but cannot be directly checked against a live connection.

## Primary Files

- [`internal/provider/nearcloud/reportdata.go`](../../../internal/provider/nearcloud/reportdata.go)
- [`internal/attestation/spki.go`](../../../internal/attestation/spki.go)
- [`internal/proxy/proxy.go`](../../../internal/proxy/proxy.go)

## Secondary Context Files

- [`internal/provider/nearcloud/pinned.go`](../../../internal/provider/nearcloud/pinned.go)
- [`internal/provider/nearcloud/nearcloud.go`](../../../internal/provider/nearcloud/nearcloud.go)
- [`internal/tlsct/checker.go`](../../../internal/tlsct/checker.go)
- [`internal/attestation/spki_test.go`](../../../internal/attestation/spki_test.go)
- [`internal/provider/nearcloud/reportdata_test.go`](../../../internal/provider/nearcloud/reportdata_test.go)

## Background: Two REPORTDATA Schemes

### Model Backend REPORTDATA

The model backend's REPORTDATA binds the E2EE signing key and TLS fingerprint:
- `REPORTDATA[0:32]` = `SHA256(signing_address_bytes || tls_fingerprint_bytes)`
- `REPORTDATA[32:64]` = raw_client_nonce_32_bytes

For nearcloud, the `signing_address` is derived from the Ed25519 public key used for E2EE key exchange. The `tls_fingerprint` is the model backend's own TLS certificate fingerprint. Since the proxy connects to the gateway (not the model backend directly), the proxy cannot verify the model backend's TLS fingerprint against a live TLS connection — this fingerprint is verified only as part of the REPORTDATA binding to the TDX quote.

> **Known divergence**: Venice uses a different REPORTDATA scheme — the signing address is derived from a keccak256 hash of a secp256k1 public key, occupying bytes [0:20] with zeros in [20:32]. See `internal/provider/venice/reportdata.go` for the Venice-specific scheme.

### Gateway REPORTDATA

The gateway's REPORTDATA binds only the TLS fingerprint (no signing key):
- `REPORTDATA[0:32]` = `SHA256(tls_fingerprint_bytes)` — note: NO signing_address
- `REPORTDATA[32:64]` = raw_client_nonce_32_bytes

The gateway's TLS fingerprint IS verified against the live TLS connection (since the proxy connects to the gateway).

### Trust Chain

```
Live TLS connection → SPKI hash matches gateway tls_fingerprint (from gateway REPORTDATA)
Gateway TDX quote → binds gateway tls_fingerprint via gateway REPORTDATA
Model TDX quote → binds signing_key + model tls_fingerprint via model REPORTDATA
signing_key → used for E2EE with model backend (bypassing gateway)
```

## Required Checks

### Model Backend REPORTDATA Scheme Validation

Verify and report:
- `signing_address` hex decoding and optional `0x` prefix stripping,
- `tls_fingerprint` is decoded from hex before hashing (not hashed as ASCII hex),
- decoded input lengths are validated where applicable (or residual collision/ambiguity risk is documented — the concatenation of `signing_address || tls_fingerprint` has no separator or length prefix, so if field lengths are not validated, different splits of the same byte sequence produce the same hash),
- strict concatenation order `(address || fingerprint)` and no separators/length prefixes,
- validation of both REPORTDATA halves (not just the first half),
- constant-time comparison behavior (`subtle.ConstantTimeCompare`),
- fail-closed enforcement on mismatch (blocks forwarding, not merely logged),
- the model backend REPORTDATA verifier is the shared nearai `ReportDataVerifier` (not a different implementation),
- a missing or unconfigured verifier fails safely (no default pass-through).

The `tdx_reportdata_binding` factor is one of the default enforced factors. The audit MUST verify that a model REPORTDATA mismatch triggers failure through the enforcement code path.

### Gateway REPORTDATA Scheme Validation

Verify and report:
- `tls_fingerprint` is decoded from hex before hashing (not hashed as ASCII),
- an absent `tls_cert_fingerprint` in the gateway attestation results in a hard failure (not a skip),
- both halves of the 64-byte REPORTDATA are verified,
- the binding comparison uses constant-time comparison,
- failure of this check is enforced (blocks the request),
- the gateway REPORTDATA verifier is a **separate** implementation from the model REPORTDATA verifier (because the binding scheme differs — no signing address for the gateway),
- the correct verifier is used for each quote (model vs gateway).

The `gateway_tdx_reportdata_binding` factor is a separate enforcement factor. Verify that it is in the default enforced set.

### Trust Delegation for Model TLS Fingerprint

The model backend's `tls_cert_fingerprint` in REPORTDATA refers to the model backend's own TLS certificate, not the gateway's. Since the proxy connects to the gateway (not the model backend), the proxy CANNOT directly verify the model backend's TLS fingerprint against a live connection. The audit MUST document:
- that the model backend's TLS fingerprint is present in REPORTDATA binding but verified only cryptographically (via quote, not against a live TLS connection),
- that the gateway's TLS attestation is the link that binds the live TLS connection to the overall attestation chain,
- the trust delegation: the proxy trusts the gateway (attested) to route to the correct model backend (also attested, but not directly connected),
- whether there is a binding between the gateway and the specific model backend that prevents the gateway from routing to an unattested machine.

### TLS Pinning & TOCTOU Safety

Verify and report:
- SPKI hash extraction from the same live TLS connection to the **gateway** (not the model backend),
- SPKI hash algorithm (expected SHA-256 over DER SubjectPublicKeyInfo),
- the gateway's attested `tls_cert_fingerprint` matches the live connection SPKI using constant-time hex comparison,
- this comparison is a hard error if it fails (not a skip),
- attestation fetch and inference request occur on one TLS connection (preventing TOCTOU),
- response-body close semantics closing underlying TCP connection,
- `InsecureSkipVerify` justification and cryptographic compensation,
- `ServerName` SNI behavior when custom TLS verification is used,
- there is NO code path that confuses the gateway and model TLS fingerprints.

### Certificate Transparency (CT) Integration

Verify and report:
- whether CT log checking is performed for the gateway TLS certificate,
- CT cache keying and TTL behavior,
- whether CT failure blocks the connection or is advisory-only.

### Pin Cache & Connection Lifetime

Verify and report:
- pin-cache keys (gateway domain → spkiHex), TTL, max entries per domain, eviction strategy, and whether total domain count is bounded,
- that the SPKI pin cache uses the gateway's domain and SPKI (since the proxy connects to the gateway, not the model backend directly),
- cache miss behavior (must trigger full re-attestation of BOTH gateway and model, never pass-through),
- singleflight/concurrency collapse behavior with post-win double-check,
- whether singleflight key includes both domain and SPKI (so a certificate rotation triggers a new attestation),
- connection reuse policy (`Connection: close` on chat request),
- that the response body wrapper closes the underlying TCP connection,
- that cache eviction under memory pressure does not silently allow unattested connections.

### Offline Mode for Pinned Connections

For the pinned connection path, verify whether offline mode is honored. The offline flag must suppress only network-dependent checks — all local cryptographic verification (REPORTDATA binding, SPKI extraction, quote signature checks) must remain active for both gateway and model.

## Go Best-Practice Audit Points

- **`sync.RWMutex` correctness**: Verify that `SPKICache` operations use correct lock modes.
- **Interface-based provider pluggability**: Verify that REPORTDATA verifiers are pluggable per provider and that a missing verifier fails closed.
- **Error wrapping**: Verify TLS and SPKI errors are wrapped with `%w`.

## Cryptography Best-Practice Audit Points

- **SPKI hash computation**: Confirm `ComputeSPKIHash()` hashes `cert.RawSubjectPublicKeyInfo` (DER-encoded SubjectPublicKeyInfo including algorithm identifier).
- **SHA-256 for SPKI and REPORTDATA**: Confirm correct hash algorithm selection for each context.
- **Constant-time comparison**: All security-critical comparisons (REPORTDATA halves, SPKI match) should use `subtle.ConstantTimeCompare`.
- **No hash truncation**: SHA-256 output compared in full (32 bytes / 64 hex chars).

## General Security Audit Points

- **Trust boundary identification**: The gateway TLS connection + gateway REPORTDATA binding creates the cryptographic proof that the TLS peer is the attested gateway TEE. The model REPORTDATA binding independently proves the signing key belongs to the attested model TEE. Both chains must be intact.
- **Defense in depth**: Even with attestation-bound TLS pinning, CA verification bypass removes a layer of defense. Document whether this is justified.
- **Fail-secure defaults**: A new provider added without REPORTDATA verifier implementations cannot silently pass verification.
- **Connection isolation**: Same TCP/TLS connection used for attestation fetch and inference.

## Known Divergence: Chutes/Sek8s

Chutes/sek8s uses a fundamentally different REPORTDATA scheme. The Chutes gateway is unattested, so there is no gateway REPORTDATA, no attestation-bound TLS pinning, and no SPKI cache.

### Chutes REPORTDATA Scheme

- `REPORTDATA[0:32]` = `SHA256(nonce_hex + e2e_pubkey_base64)` — the nonce as lowercase hex string concatenated with the ML-KEM-768 public key as base64, then SHA-256 hashed.
- `REPORTDATA[32:64]` = zero bytes.
- The binding combines the attestation nonce AND the E2EE public key in a single commitment, unlike nearcloud which splits nonce and key binding across the two REPORTDATA halves.

Audit focus:
- Verify the concatenation format: `hex(nonce) + base64(pubkey)` with no separator.
- Verify constant-time comparison for the first 32 bytes.
- Verify the second half is checked to be all zeros (or document if it is not checked).
- The `tdx_reportdata_binding` factor is enforced for chutes.

Primary reference: `internal/provider/chutes/reportdata.go`.

### No Gateway REPORTDATA, TLS Pinning, or SPKI Cache

The Chutes gateway (`api.chutes.ai`/`llm.chutes.ai`) is unattested and produces no TDX quote. Therefore:
- No `gateway_tdx_reportdata_binding` factor exists.
- No SPKI pin cache is maintained for chutes providers.
- No `tls_key_binding` enforcement — `tls_key_binding` is in `ChutesDefaultAllowFail`.
- Standard HTTPS is used without attestation-bound TLS pinning.
- Certificate Transparency checks do not apply.

The audit should verify that the chutes code path does not attempt to use SPKI pinning or gateway REPORTDATA logic.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. model REPORTDATA byte-level verification summary,
3. gateway REPORTDATA byte-level verification summary,
4. trust delegation analysis (gateway ↔ model TLS fingerprint),
5. SPKI hash computation and gateway TLS pinning correctness,
6. pin-cache enforcement classification,
7. CT integration status,
8. include at least one concrete positive control and one concrete negative/residual-risk observation,
9. source citations for all claims.
