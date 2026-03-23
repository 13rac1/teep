# Section 03 — HTTP Request Construction, Resource Limits & Sensitive Data

## Scope

Audit transport-layer request construction safety, bounded-resource handling, and sensitive-data hygiene in direct inference proxy paths.

For direct inference providers that construct raw HTTP requests on the underlying TLS connection (bypassing Go's `http.Client` connection pooling), these checks are particularly important as the proxy takes responsibility for correct HTTP framing.

## Primary Files

- [`internal/proxy/proxy.go`](../../../internal/proxy/proxy.go)
- [`internal/proxy/decrypt.go`](../../../internal/proxy/decrypt.go)
- [`internal/config/config.go`](../../../internal/config/config.go)

## Required Checks

### HTTP Request Construction Safety

Verify and report:
- Host header is always set and matches attested destination domain,
- Content-Length is derived from actual request body length,
- no unsanitized user-controlled interpolation into request line/headers,
- header value CR/LF rejection or equivalent canonicalization,
- request path construction from trusted constants plus URL-encoded parameters.

### Response Size & Resource Bounds

Verify and report explicit limits on all untrusted external data reads:
- attestation responses (recommended: ≤1 MiB),
- endpoint discovery responses (recommended: ≤1 MiB),
- SSE streaming buffers (bounded scanner buffer sizes with pooling),
- Sigstore/Rekor/NRAS/PCS or other remote verification payloads.

Unbounded reads from untrusted sources represent a denial-of-service vector and MUST be flagged.

### Sensitive Data Handling

Verify and report:
- that API keys are not logged in plaintext (redaction to first-N characters),
- that the config file permission check behavior is clearly classified as warning-only or hard-fail,
- that ephemeral cryptographic key material (E2EE session keys) is zeroed after use, with acknowledgment of language-level limitations (GC may copy),
- that attestation nonces are not reused across requests.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. transport safety control inventory with enforcement classification,
3. bounded-resource coverage summary and DoS residual-risk notes,
4. include at least one concrete positive control and one concrete negative/residual-risk observation,
5. source citations for all claims.
