# Section 02 — Attestation Fetch, Response Parsing & Nonce Freshness

## Scope

Audit attestation retrieval, combined gateway+model response parsing, model entry selection, gateway-specific double-encoded field handling, and nonce freshness/replay resistance.

Upon connection to the gateway, the attestation API MUST be queried and fully validated before any inference request is sent. A single attestation request returns a combined response containing both the gateway attestation and the model attestation.

## Primary Files

- [`internal/provider/nearcloud/nearcloud.go`](../../../internal/provider/nearcloud/nearcloud.go)
- [`internal/attestation/attestation.go`](../../../internal/attestation/attestation.go)
- [`internal/jsonstrict/unmarshal.go`](../../../internal/jsonstrict/unmarshal.go)

## Secondary Context Files

- [`internal/tlsct/checker.go`](../../../internal/tlsct/checker.go)
- [`internal/provider/nearcloud/nearcloud_test.go`](../../../internal/provider/nearcloud/nearcloud_test.go)
- [`internal/attestation/attestation_test.go`](../../../internal/attestation/attestation_test.go)
- [`internal/jsonstrict/unmarshal_test.go`](../../../internal/jsonstrict/unmarshal_test.go)

## Background: Combined Gateway + Model Response

The gateway attestation response is a JSON object containing two sections:
- a `gateway_attestation` section with the gateway's own TDX quote, event log, TLS certificate fingerprint, and `tcb_info` (containing `app_compose`),
- a `model_attestations` array with per-model Intel TDX attestation, NVIDIA TEE attestation, signing key, and auxiliary information.

Both sections are parsed from a single HTTP response body. The gateway-specific fields have unique parsing requirements (double-encoded JSON, string-encoded event logs) that differ from the model attestation fields.

## Required Checks

### Attestation Response Retrieval

Verify and report:
- attestation response body size bounds (recommended: ≤2 MiB for gateway responses, which are expected to be larger than direct inference responses due to the presence of two attestation payloads — verify `io.LimitReader` or equivalent is applied),
- that the attestation API is queried and the response is fully validated **before** any inference request is forwarded on the same TLS connection (no TOCTOU gap),
- HTTP client timeout configuration for the attestation fetch (connect, read, overall),
- HTTP response status code validation before body parsing,
- that the Host header and request path are constructed from trusted values (not user-supplied).

### Combined Response Parsing

Verify and report:
- strict JSON unmarshalling behavior for unknown fields (via [`internal/jsonstrict/unmarshal.go`](../../../internal/jsonstrict/unmarshal.go)) — this applies to BOTH the top-level gateway response AND the inner model attestation,
- whether unknown-field warnings are rate-limited/deduplicated to prevent log flooding,
- support for polymorphic model attestation formats (flat object vs arrays — some providers return a single attestation object, others return arrays),
- explicit bounds checks on array lengths (e.g., `model_attestations`, `all_attestations`) to cap iteration and prevent resource exhaustion,
- that the `gateway_attestation` section is required (not optional) — a missing gateway attestation MUST be a hard error.

### Gateway-Specific Field Parsing

The gateway attestation section has unique parsing requirements:

- **Event log as JSON string**: The gateway `event_log` field is a JSON string (not a native array). Verify that the code correctly double-parses this field: first as a JSON string from the gateway attestation, then parsing the string contents as a JSON array of event log entries.
- **`tcb_info` double-encoded JSON**: The gateway's `tcb_info` field may contain a JSON string that itself contains JSON (string-within-JSON). Verify that the code correctly extracts `app_compose` from this double-encoded format.
- **Bounds on gateway event log entries**: Verify that the number of event log entries parsed from the gateway event log is bounded (e.g., `maxGatewayEventLogEntries`) to prevent resource exhaustion from a malicious response.
- **Malformed-element behavior**: Verify whether a malformed gateway event log entry or nested field causes the entire response to be rejected (fail-whole-response) or the element to be silently dropped (which MUST be flagged as a finding).

### Model Attestation Selection

Verify and report:
- model selection logic when the response contains multiple attestation entries (exact match, prefix match, or fuzzy),
- whether failure to find a matching model is a hard error (must be fail-closed, not silent pass-through),
- failure behavior when no model match is found,
- whether provider-asserted "verified" booleans are ignored unless independently verified (trusting a provider's self-asserted "verified" field would defeat the purpose of client-side attestation).

### Nonce Freshness and Replay Resistance

In the gateway model, a single nonce is sent to the gateway, which shares it with the model backend. Both the gateway and the model backend echo the same nonce back. Verify:
- fresh cryptographic 32-byte nonce generation per attestation attempt using `crypto/rand.Read`,
- fail-closed behavior if the cryptographic randomness source fails — the recommended behavior is to panic or abort; NEVER fall back to a weaker entropy source such as `math/rand`,
- that exactly one nonce is generated per attestation attempt (not separate nonces for gateway and model),
- that the single nonce is transmitted to the gateway endpoint by the proxy, not delegated to the server,
- that the gateway's echoed nonce is verified using constant-time comparison (`subtle.ConstantTimeCompare`) against the client-generated nonce,
- that the model's echoed nonce is verified using constant-time comparison against the **same** client-generated nonce,
- that both nonce checks fail closed on mismatch,
- that the nonce originates solely from the client and is not sourced from or influenced by the server response,
- that nonces are never reused across attestation attempts (a new nonce per connection, not per session),
- that the nonce is compared against the value embedded in the TDX quote's REPORTDATA field (not against a separate provider-asserted field that could be forged independently of the quote).

## Go Best-Practice Audit Points

- **`io.LimitReader` for body size bounding**: Verify that the attestation response body is wrapped in `io.LimitReader` before reading, not just checked after the fact. The gateway response includes dual payloads, so the limit should be higher than direct inference (≤2 MiB suggested).
- **`json.Decoder` vs `json.Unmarshal`**: If using `json.Decoder`, verify that `DisallowUnknownFields()` is configured. If using a custom strict unmarshaller, verify it covers all code paths (both gateway attestation and model attestation parsing).
- **Error wrapping with sentinel errors**: Verify that parse failures, nonce mismatches, and model-not-found conditions return distinct error types or wrapped sentinel errors so callers can distinguish between transient failures (retry-safe) and permanent failures (must reject).
- **`crypto/rand` for nonce generation**: Verify via code inspection that `crypto/rand.Read` (not `math/rand`) is the sole entropy source. Check that the return value from `crypto/rand.Read` is verified (both the error and the number of bytes read).
- **Context and cancellation**: Verify that `context.Context` is propagated through the attestation fetch so that client disconnection or timeouts cancel in-flight attestation requests promptly.
- **No deferred mutations on error paths**: Verify that if attestation fetching fails partway through, no partial/corrupt state is written to caches or shared data structures.

## Cryptography Best-Practice Audit Points

- **Nonce entropy**: 32 bytes from `crypto/rand` provides 256 bits of entropy, which is sufficient for replay resistance. Verify no truncation of the nonce between generation and embedding in the request.
- **Constant-time comparison for all security values**: Beyond the nonce, all byte-level comparisons of attestation data (measurement hashes, REPORTDATA binding values) should be evaluated for constant-time behavior.
- **Encoding consistency**: Verify that the nonce is transmitted and compared in the same encoding (raw bytes vs hex-encoded vs base64). Encoding mismatches between what is sent to the server and what is compared in the quote would cause false rejections or, worse, allow a trivially different nonce to pass.

## Security Audit Points

- **Trust boundary**: Everything from the attestation API response is untrusted until cryptographically verified via the TDX quote chain. The JSON structure, field values, and attestation blobs could all be attacker-controlled (including a compromised gateway). Verify that the code treats the entire response as adversarial.
- **TOCTOU between fetch and use**: The attestation fetch and the inference request MUST occur on the same TLS connection to prevent an attacker from swapping the backend server between attestation and inference. Verify that no connection pooling or reuse breaks this binding.
- **Defense in depth for parsing**: Verify that strict JSON unmarshalling is the default path, not an opt-in annotation. A single parsing path that bypasses strict mode would allow field injection.
- **Fail-closed on ambiguity**: If the response format is ambiguous (e.g., partially valid JSON, unexpected array nesting, or missing required fields), the parser MUST reject the entire response rather than attempting best-effort extraction.
- **Resource exhaustion**: Verify that deeply nested JSON structures, extremely long string fields, or large array sizes in the combined gateway+model response cannot cause stack overflow, excessive memory allocation, or CPU-bound parsing delays.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. parse-path and nonce-check classification by enforcement mode,
3. gateway-specific parsing correctness assessment (double-encoded JSON, string event logs),
4. clear replay-resistance conclusion covering both gateway and model nonce checks,
5. include at least one concrete positive control and one concrete negative/residual-risk observation,
6. source citations for all claims.
