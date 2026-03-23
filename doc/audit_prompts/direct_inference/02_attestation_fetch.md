# Section 02 — Attestation Fetch, Parsing & Nonce Freshness

## Scope

Audit attestation retrieval, response parsing, model entry selection, and nonce freshness/replay resistance.

Upon connection to the model server, the attestation API of this model server MUST be queried and fully validated before any inference request is sent to the model server.

Certificate Transparency MUST be consulted for the TLS certificate of this model endpoint. This CT log report SHOULD be cached.

The attestation information is provided by an API endpoint as a JSON object that includes the Intel TEE attestation, NVIDIA TEE attestation, and auxiliary information such as docker compose contents and event log metadata.

## Primary Files

- [`internal/provider/nearai/nearai.go`](../../../internal/provider/nearai/nearai.go)
- [`internal/attestation/attestation.go`](../../../internal/attestation/attestation.go)
- [`internal/jsonstrict/unmarshal.go`](../../../internal/jsonstrict/unmarshal.go)

## Secondary Context Files

- [`internal/tlsct/checker.go`](../../../internal/tlsct/checker.go)
- [`internal/attestation/attestation_test.go`](../../../internal/attestation/attestation_test.go)
- [`internal/jsonstrict/unmarshal_test.go`](../../../internal/jsonstrict/unmarshal_test.go)

## Required Checks

### Attestation Response Retrieval

Verify and report:
- attestation response body size bounds (recommended: ≤1 MiB; verify `io.LimitReader` or equivalent is applied),
- that the attestation API is queried and the response is fully validated **before** any inference request is forwarded on the same TLS connection (no TOCTOU gap),
- HTTP client timeout configuration for the attestation fetch (connect, read, overall),
- HTTP response status code validation before body parsing,
- that the Host header and request path are constructed from trusted values (not user-supplied).

### Response Parsing

Verify and report:
- strict JSON unmarshalling behavior for unknown fields (via [`internal/jsonstrict/unmarshal.go`](../../../internal/jsonstrict/unmarshal.go)),
- whether unknown-field warnings are rate-limited/deduplicated to prevent log flooding,
- support for polymorphic response formats (flat object vs arrays — some providers return a single attestation object, others return arrays),
- explicit bounds checks on array lengths (e.g., `model_attestations`, `all_attestations`) to cap iteration and prevent resource exhaustion,
- model selection logic when multiple attestation entries exist (exact match, prefix match, or fuzzy — and whether failure to find a matching model is a hard error),
- failure behavior when no model match is found (must be fail-closed, not silent pass-through),
- malformed nested element handling for event-log or nested arrays (fail-whole-response vs silently drop element — silent drops MUST be flagged),
- whether provider-asserted "verified" booleans are ignored unless independently verified (trusting a provider's self-asserted "verified" field would defeat the purpose of client-side attestation),
- whether the `tcb_info` field supports double-encoded JSON (string-within-JSON), as some providers embed JSON as an escaped string within the response,
- endpoint CT checks for attestation endpoint certificates and any caching behavior.

### Nonce Freshness and Replay Resistance

For nonce handling, verify:
- fresh cryptographic 32-byte nonce generation per attestation attempt using `crypto/rand.Read`,
- fail-closed behavior if the cryptographic randomness source fails — the recommended behavior is to panic or abort; NEVER fall back to a weaker entropy source such as `math/rand`,
- constant-time nonce equality checks using `subtle.ConstantTimeCompare` (flag any use of `==` or `bytes.Equal` for nonce comparison),
- that the nonce is transmitted to the attestation endpoint by the proxy, not delegated to the server — the nonce MUST originate solely from the client and not be sourced from or influenced by the server response,
- that the nonce comparison verifies both halves of the 64-byte REPORTDATA (the nonce typically occupies `REPORTDATA[32:64]`; the first half binds other data),
- that nonces are never reused across attestation attempts (a new nonce per connection, not per session),
- that the nonce is compared against the value embedded in the TDX quote's REPORTDATA field (not against a separate provider-asserted field that could be forged independently of the quote).

## Go Best-Practice Audit Points

- **`io.LimitReader` for body size bounding**: Verify that the attestation response body is wrapped in `io.LimitReader` before reading, not just checked after the fact. A post-read check is insufficient if the entire oversized body is already in memory.
- **`json.Decoder` vs `json.Unmarshal`**: If using `json.Decoder`, verify that `DisallowUnknownFields()` is configured. If using a custom strict unmarshaller, verify it covers all code paths (not just the primary attestation parse but also nested structures).
- **Error wrapping with sentinel errors**: Verify that parse failures, nonce mismatches, and model-not-found conditions return distinct error types or wrapped sentinel errors so callers can distinguish between transient failures (retry-safe) and permanent failures (must reject).
- **`crypto/rand` for nonce generation**: Verify via code inspection that `crypto/rand.Read` (not `math/rand`) is the sole entropy source. Check that the return value from `crypto/rand.Read` is verified (both the error and the number of bytes read).
- **Context and cancellation**: Verify that `context.Context` is propagated through the attestation fetch so that client disconnection or timeouts cancel in-flight attestation requests promptly.
- **No deferred mutations on error paths**: Verify that if attestation fetching fails partway through, no partial/corrupt state is written to caches or shared data structures.

## Cryptography Best-Practice Audit Points

- **Nonce entropy**: 32 bytes from `crypto/rand` provides 256 bits of entropy, which is sufficient for replay resistance. Verify no truncation of the nonce between generation and embedding in the request.
- **Constant-time comparison for all security values**: Beyond the nonce, all byte-level comparisons of attestation data (measurement hashes, REPORTDATA binding values) should be evaluated for constant-time behavior.
- **Encoding consistency**: Verify that the nonce is transmitted and compared in the same encoding (raw bytes vs hex-encoded vs base64). Encoding mismatches between what is sent to the server and what is compared in the quote would cause false rejections or, worse, allow a trivially different nonce to pass.
- **No nonce in logs**: The nonce itself is not secret, but its uniqueness is security-critical. Verify that logging nonces does not enable a caching/replay vector (e.g., a log reader resubmitting a logged nonce to obtain a valid attestation for a past state).

## Security Audit Points

- **Trust boundary**: Everything from the attestation API response is untrusted until cryptographically verified via the TDX quote chain. The JSON structure, field values, and attestation blobs could all be attacker-controlled. Verify that the code treats the entire response as adversarial.
- **TOCTOU between fetch and use**: The attestation fetch and the inference request MUST occur on the same TLS connection to prevent an attacker from swapping the backend server between attestation and inference. Verify that no connection pooling or reuse breaks this binding.
- **Defense in depth for parsing**: Verify that strict JSON unmarshalling is the default path, not an opt-in annotation. A single parsing path that bypasses strict mode would allow field injection.
- **Fail-closed on ambiguity**: If the response format is ambiguous (e.g., partially valid JSON, unexpected array nesting, or missing required fields), the parser MUST reject the entire response rather than attempting best-effort extraction.
- **Response replay detection**: Beyond nonce matching, consider whether an attacker could replay an entire valid attestation response from a cached state. The TLS connection binding (SPKI pinning) addresses this, but the auditor should verify this binding is checked before the attestation response is considered valid.
- **Resource exhaustion**: Verify that deeply nested JSON structures, extremely long string fields, or large array sizes in the attestation response cannot cause stack overflow, excessive memory allocation, or CPU-bound parsing delays.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. parse-path and nonce-check classification by enforcement mode,
3. clear replay-resistance conclusion,
4. include at least one concrete positive control and one concrete negative/residual-risk observation,
5. source citations for all claims.
