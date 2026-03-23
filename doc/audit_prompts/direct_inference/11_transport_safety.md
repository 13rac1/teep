# Section 11 — HTTP Request Construction, Resource Limits & Sensitive Data

## Scope

Audit transport-layer request construction safety, bounded-resource handling, and sensitive-data hygiene in direct inference proxy paths.

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
- attestation responses,
- endpoint discovery responses,
- SSE streaming buffers (scanner bounds, pooling behavior),
- Sigstore/Rekor/NRAS/PCS or other remote verification payloads.

Flag any unbounded read path as a potential DoS vector.

### Sensitive Data Handling

Verify and report:
- API key redaction behavior in logs,
- config-file permission check semantics (warning-only vs hard fail),
- ephemeral key-material zeroing behavior and language/runtime caveats,
- nonce reuse prevention.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. transport safety control inventory with enforcement classification,
3. bounded-resource coverage summary and DoS residual-risk notes,
4. include at least one concrete positive control and one concrete negative/residual-risk observation,
5. source citations for all claims.
