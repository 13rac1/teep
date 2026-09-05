# Section 03 — HTTP Request Construction, Resource Limits & Sensitive Data

## Scope

Audit transport-layer request construction safety, bounded-resource handling, sensitive-data hygiene, and connection lifecycle management in gateway inference proxy paths.

The gateway provider uses a standard HTTP transport with attestation-bound pools. Go owns HTTP framing and multiplexing. Request code must not set `Connection: close` or `Connection: keep-alive`.

## Primary Files

- [`internal/proxy/proxy.go`](../../../internal/proxy/proxy.go)
- [`internal/proxy/decrypt.go`](../../../internal/proxy/decrypt.go)
- [`internal/config/config.go`](../../../internal/config/config.go)

## Secondary Context Files

- [`internal/proxy/authorized_inference.go`](../../../internal/proxy/authorized_inference.go)

## Required Checks

### HTTP Request Construction Safety

Verify and report:
- Host header is always set to the gateway domain (not the model backend domain),
- Content-Length is derived from actual request body length (not caller-supplied or externally influenced),
- no unsanitized user-controlled interpolation into request line/headers,
- header value CR/LF rejection or equivalent canonicalization (HTTP header injection prevention),
- request path construction from trusted constants plus URL-encoded parameters,
- that the HTTP method used is restricted to expected values (e.g., POST for inference endpoints),
- that any query parameters appended to the request URL are properly URL-encoded,
- that neither attestation nor inference sets a `Connection` header,
- that the Authorization header is set correctly for both the attestation and chat requests.

### Response Handling Safety

Verify and report:
- HTTP status code validation before processing response bodies (non-2xx treated as errors with appropriate handling),
- Content-Type response header validation before JSON parsing (unexpected types rejected or flagged),
- that error responses from upstream do not leak internal proxy state or attestation details to the client,
- that response headers from the attested server are sanitized before being forwarded to the client (no hop-by-hop header forwarding).

### Response Size & Resource Bounds

Verify and report explicit limits on all untrusted external data reads:
- gateway attestation responses (recommended: ≤2 MiB, larger than direct inference due to dual gateway+model payloads),
- SSE streaming buffers (bounded scanner buffer sizes with pooling),
- Sigstore/Rekor/NRAS/PCS or other remote verification payloads.

Specifically verify that `io.LimitReader` (or equivalent) is applied to **every** `http.Response.Body` read from an untrusted source. Check for patterns where the response body is read directly via `io.ReadAll` or `ioutil.ReadAll` without a wrapping size limit — these represent denial-of-service vectors and MUST be flagged.

For SSE streaming paths, verify that `bufio.Scanner` buffer sizes are explicitly bounded (e.g., via `Scanner.Buffer()`) and that buffer memory is pooled or released promptly.

Unbounded reads from untrusted sources represent a denial-of-service vector and MUST be flagged.

### Connection Lifetime Safety

TLS connections may be reused only within a provider, authority, and attested SPKI scope.

Verify and report:
- each request acquires a complete, currently valid authorization,
- cache misses initiate or join full verification of gateway and model evidence,
- changed keys replace the selectable pool and close its idle connections,
- every new connection verifies the attested pin before sending request bytes,
- HTTP/2 response cancellation does not cancel another stream,
- physical connections and verification work have finite limits,
- connection setup, request, and authenticated-evidence deadlines bound waits,
- buffered POST requests have no replay callback or idempotency headers,
- a consumed POST followed by a protocol reset is not replayed,
- redirects and ambiguous failures cannot enable application retries.

### TLS Configuration Safety

Verify and report:
- inference TLS requires TLS 1.3 and system WebPKI,
- CT remains enforced online and SPKI comparison runs before transmission,
- `InsecureSkipVerify` and custom production roots are absent,
- TLS session resumption is disabled on SPKI-bound pools,
- handshake trust failures stop the request and invalidate only its authorization generation.

### Sensitive Data Handling

Verify and report:
- that API keys are not logged in plaintext (redaction to first-N characters),
- that the config file permission check behavior is clearly classified as warning-only or hard-fail,
- that ephemeral cryptographic key material (E2EE session keys) is zeroed after use, with acknowledgment of language-level limitations (GC may copy),
- that attestation nonces are not reused across requests,
- that error messages returned to clients do not leak internal server addresses, attestation state, or cryptographic material,
- that debug/verbose logging modes do not inadvertently log full request/response bodies containing user inference data,
- that the model backend's signing key is only used for ECDH key exchange after REPORTDATA binding verification.

## Best-Practice Audit Points

### Go (Golang) Best Practices

- **`io.LimitReader` discipline**: Every `http.Response.Body` from an untrusted source must be wrapped in `io.LimitReader` before reading. Verify no code path reads an unbounded body.
- **`defer` for cleanup**: Verify that `resp.Body.Close()` and `conn.Close()` are always deferred immediately after successful creation, preventing resource leaks on error paths.
- **Error wrapping**: Verify that transport errors are wrapped with `fmt.Errorf("context: %w", err)` to preserve the error chain for debugging while not exposing internals to clients.
- **`http.MaxBytesReader`**: For any proxy paths that accept client request bodies, verify that `http.MaxBytesReader` is used to bound incoming request sizes.
- **`bufio.Scanner` buffer limits**: Verify that any `bufio.Scanner` used for SSE streaming has an explicit maximum buffer size set via `Scanner.Buffer()`, as the default 64 KiB may be insufficient or too large depending on context.
- **Context cancellation**: Verify that HTTP requests to upstream servers use `context.Context` with timeouts, and that context cancellation ends the affected request without canceling unrelated HTTP/2 streams.
- **No `panic` in request paths**: Verify that transport error handling uses returned errors, not panics, which would crash the proxy process.

### Cryptography Best Practices

- **Nonce uniqueness**: Verify that attestation nonces are generated from `crypto/rand.Read` and never reused. If `crypto/rand.Read` fails, the code MUST fail closed (panic or abort), never fall back to a weak source.
- **Constant-time comparison**: Verify that nonce comparison and any SPKI hash comparison use `subtle.ConstantTimeCompare` to prevent timing side-channels.
- **Key material zeroing**: For E2EE session keys, verify that `for i := range key { key[i] = 0 }` or equivalent zeroing is performed in a `defer` block, with documentation noting Go's GC may retain copies.
- **TLS certificate extraction**: Verify that the TLS peer certificate is extracted from `tls.ConnectionState()` on the **same** connection used for the request, not from a cached or previously observed connection.

### General Security Audit Practices

- **Input validation at trust boundaries**: HTTP headers, response bodies, and connection metadata from the attested server are still untrusted input — verify validation is applied consistently.
- **Defense in depth**: Even though attestation provides strong guarantees, verify that standard HTTP safety controls (size limits, header sanitization, timeout enforcement) are still applied as defense-in-depth measures.
- **Fail-secure defaults**: Verify that any transport error (timeout, TLS failure, malformed response) results in the request being rejected, not silently forwarded or retried without re-attestation.
- **Resource exhaustion prevention**: Verify that a malicious attested server cannot cause resource exhaustion by sending extremely large headers, slow responses (slowloris-style), or unbounded SSE streams.
- **Connection isolation**: Verify that connection state from one client request cannot leak into another client's request through connection reuse, shared buffers, or cached connection metadata.

## Known Divergence: Chutes/Sek8s

Chutes providers do **not** use attestation-bound TLS pinning or the nearcloud attested transport scope. The Chutes gateway (`api.chutes.ai`/`llm.chutes.ai`) is unattested and routes requests to sek8s TEE instances. Key differences:

- **No raw HTTP construction**: Chutes uses standard Go `http.Client` for all requests to the Chutes gateway (instances endpoint, evidence endpoint, inference endpoint). There is no raw TLS connection management.
- **No `Connection: keep-alive` / `Connection: close` lifecycle**: Each chutes HTTP request to the gateway is independent. The attestation fetch (instances + evidence) and inference request are separate HTTP calls, not pipelined on a single TLS connection.
- **No SPKI pinning**: Standard HTTPS with system CA verification to the Chutes gateway. No `InsecureSkipVerify` override.
- **No certificate extraction**: The chutes code path does not extract TLS peer certificates from the gateway connection for SPKI comparison.
- **Standard response handling**: Responses from the gateway are read via `http.Response.Body` through Go's standard library.

However, the following transport safety checks still apply to chutes:
- Response body size limits (`io.LimitReader`) on attestation and inference responses.
- SSE streaming buffer bounds for encrypted streaming (`e2e_init`, `e2e` event types).
- Sensitive data handling (API key redaction, no inference data logging).
- No request-level `Connection` header; each encrypted request uses a currently attested backend key.

The audit should verify that chutes transport paths apply the same bounded-read discipline as nearcloud even though the connection lifecycle is simpler.

Primary reference: `internal/provider/chutes/chutes.go`, `internal/e2ee/relay_chutes.go`.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. transport safety control inventory with enforcement classification,
3. connection lifecycle safety assessment (attested scope, multiplexing, deadlines, and invalidation),
4. bounded-resource coverage summary and DoS residual-risk notes,
5. TLS configuration assessment (version, cipher suites, SNI, InsecureSkipVerify justification),
6. include at least one concrete positive control and one concrete negative/residual-risk observation,
7. source citations for all claims.
