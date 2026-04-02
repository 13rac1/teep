# Section 03 — HTTP Request Construction, Resource Limits & Sensitive Data

## Scope

Audit transport-layer request construction safety, bounded-resource handling, sensitive-data hygiene, and connection lifecycle management in gateway inference proxy paths.

For gateway providers that construct raw HTTP requests on the underlying TLS connection (bypassing Go's `http.Client` connection pooling), these checks are particularly important as the proxy takes responsibility for correct HTTP framing. The gateway provider has a unique connection lifecycle: the attestation request uses `Connection: keep-alive` (to allow the chat request on the same connection) while the chat request uses `Connection: close`.

## Primary Files

- [`internal/proxy/proxy.go`](../../../internal/proxy/proxy.go)
- [`internal/proxy/decrypt.go`](../../../internal/proxy/decrypt.go)
- [`internal/config/config.go`](../../../internal/config/config.go)

## Secondary Context Files

- [`internal/provider/nearcloud/pinned.go`](../../../internal/provider/nearcloud/pinned.go)

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
- that the attestation request uses `Connection: keep-alive` while the chat request uses `Connection: close`,
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

TLS connections to the gateway MUST be closed after each request-response cycle to ensure each new request triggers a fresh attestation or SPKI cache check. The gateway connection has a unique lifecycle:
1. TLS handshake → attestation request (keep-alive) → attestation response validated → chat request (close) → response streamed → connection closed.

Verify and report:
- that the response body wrapper closes the underlying TCP connection when the body is consumed or closed (e.g., via a custom `io.ReadCloser` that calls `conn.Close()`),
- that `Connection: close` is set on the chat (inference) request,
- that `Connection: keep-alive` is set on the attestation request (to allow the chat request on the same TLS connection),
- that connection read/write timeouts are set and reasonable (noting that gateway connections may need longer timeouts due to two attestation payloads),
- that a half-closed or errored connection cannot be mistakenly reused for a subsequent request,
- that Go's default `http.Transport` connection pooling is disabled or bypassed for attested connections (since connection reuse would skip re-attestation),
- that `net.Conn.SetDeadline()`, `SetReadDeadline()`, or `SetWriteDeadline()` are used on the raw TLS connection where appropriate.

### TLS Configuration Safety

For gateway providers that bypass standard Go `http.Client` TLS handling:

Verify and report:
- whether `InsecureSkipVerify` is used on the `tls.Config`, and if so, that it is justified and cryptographically compensated by attestation-based SPKI pinning,
- that `ServerName` is still set on the `tls.Config` for correct SNI even when CA verification is bypassed,
- that the TLS minimum version is set appropriately (TLS 1.2 minimum, TLS 1.3 preferred),
- that cipher suite selection is not weakened (no custom cipher suite list that enables weak ciphers),
- that TLS handshake errors are handled as hard failures (not silently retried with weaker parameters).

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
- **Context cancellation**: Verify that HTTP requests to upstream servers use `context.Context` with timeouts, and that context cancellation properly tears down the underlying connection.
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

Chutes providers do **not** use attestation-bound TLS pinning or the nearcloud keep-alive/close connection lifecycle. The Chutes gateway (`api.chutes.ai`/`llm.chutes.ai`) is unattested and routes requests to sek8s TEE instances. Key differences:

- **No raw HTTP construction**: Chutes uses standard Go `http.Client` for all requests to the Chutes gateway (instances endpoint, evidence endpoint, inference endpoint). There is no raw TLS connection management.
- **No `Connection: keep-alive` / `Connection: close` lifecycle**: Each chutes HTTP request to the gateway is independent. The attestation fetch (instances + evidence) and inference request are separate HTTP calls, not pipelined on a single TLS connection.
- **No SPKI pinning**: Standard HTTPS with system CA verification to the Chutes gateway. No `InsecureSkipVerify` override.
- **No certificate extraction**: The chutes code path does not extract TLS peer certificates from the gateway connection for SPKI comparison.
- **Standard response handling**: Responses from the gateway are read via `http.Response.Body` through Go's standard library.

However, the following transport safety checks still apply to chutes:
- Response body size limits (`io.LimitReader`) on attestation and inference responses.
- SSE streaming buffer bounds for encrypted streaming (`e2e_init`, `e2e` event types).
- Sensitive data handling (API key redaction, no inference data logging).
- `Connection: close` header on inference requests to prevent TLS session reuse across attestation boundaries.

The audit should verify that chutes transport paths apply the same bounded-read discipline as nearcloud even though the connection lifecycle is simpler.

Primary reference: `internal/provider/chutes/fetch.go`, `internal/e2ee/relay_chutes.go`.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. transport safety control inventory with enforcement classification,
3. connection lifecycle safety assessment (keep-alive for attestation, close-after-inference, timeout, reuse prevention),
4. bounded-resource coverage summary and DoS residual-risk notes,
5. TLS configuration assessment (version, cipher suites, SNI, InsecureSkipVerify justification),
6. include at least one concrete positive control and one concrete negative/residual-risk observation,
7. source citations for all claims.
