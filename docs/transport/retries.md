# Inference retry contracts

The shared proxy and standalone inference loop permits at most two attempts
(one retry) under one caller deadline. Each attempt obtains valid
authorization and creates a fresh encryption session. Clean up the rejected
attempt before starting the next one. Connection-establishment retries apply to TLS-only probes as well as encrypted
requests. They reuse the current evidence; key-rejection replay remains
restricted to E2EE attempts. An HTTP error alone does not prove that
the provider did not process inference.

## Retry and invalidation decisions

| Outcome | Retry this request? | Shared authorization action |
| --- | --- | --- |
| Typed DNS error marked temporary or timed out, or a dial error, before any `GotConn` | At most once, if the context remains valid | Retain; acquire valid authorization again |
| Exact supported key rejection before inference, E2EE attempt | At most once | Conditionally remove the generation used; acquire authorization again |
| Exact NearCloud chat 421 stale-key rejection, TLS-only attempt | No | Conditionally remove the generation used; the next request acquires authorization |
| Origin TLS WebPKI, CT, or SPKI authentication failure | No | Conditionally remove the generation used |
| HTTPS forward-proxy handshake failure | No | Retain origin authorization, including replacement generations |
| Response authentication, decryption, or encryption-policy failure | No | Conditionally remove the generation used and record a negative-cache cooldown |
| Cancellation, deadline, ordinary I/O failure, ambiguous EOF or connection reset, or protocol error after connection assignment | No | Retain; evidence expiration does not invalidate authorization |
| Local outbound socket capacity exhausted | No | Retain; return HTTP 503 with `Retry-After: 1` before response headers |
| Redirect, generic service error, or malformed rejection envelope | No | No invalidation solely for this outcome |

Malformed JSON, invalid SSE structure, and response size limits fail the
request without invalidating authorization. Only an authentication,
decryption, or encryption-policy failure uses the decryption-failure
classification. Re-attestation cannot repair an ordinary response schema
error. NEAR non-streaming SSE reassembly decrypts each delta once and uses
that same result for content and tool-call metadata.

Response authentication failures record the configured negative-cache cooldown
atomically with generation removal. Concurrent failures of that generation do
not extend the cooldown, and late failures cannot affect a replacement. After
the cooldown, acquisition requires full verification. A zero negative-cache TTL
disables this throttle. Exact pre-inference key rejection retains its immediate
recovery contract. TLS-binding providers expose these failures through request
errors and the negative cache, rather than the legacy sticky `e2ee_failures`
panel.

An HTTPS forward proxy and the origin have separate TLS identities. Failure
of the outer proxy handshake blocks the request before CONNECT or origin TLS.
It does not invalidate the origin's attested keys. Preserve the failure's peer
scope through error wrapping; full origin attestation cannot repair proxy trust.

The attempt records whether the transport assigned a connection at any point,
including during internal transport activity. Do not classify errors by text
or infer replay safety from an EOF. `GetBody` remains nil for encrypted
inference requests: successful HTTP/2 negotiation must not enable automatic
replay of a POST whose body the transport already consumed.

Implementation:
[attempt classification and loop](../../internal/tlsct/inference_retry.go),
[proxy attempts](../../internal/proxy/authorized_inference.go), and
[rejection parsing](../../internal/provider/key_rejection.go).

## Attestation and collateral retrieval

Collateral retrieval and inference have different retry contracts. The
proxy and standalone verifier use the
[attestation client factory](README.md#request-and-response-ownership) to
construct clients with shared socket admission and independently owned pools.
Intel PCS and AMD KDS getters delegate retries
to that client; they must not add a second retry loop. The client permits up
to three attempts for eligible transport errors and HTTP 5xx responses, under
one HTTP timeout and the enclosing verification deadline. Local socket
capacity exhaustion does not retry.

An intermediate collateral failure does not establish that verification has
failed. Finish the bounded retrieval operation before recording a negative
entry for a terminal verification failure. Concurrent requests for the same
evidence scope join that verification instead of starting separate retry
sequences. A waiting client's cancellation must neither cancel shared
verification nor negatively cache it. Cancellation of the shared operation
and local capacity errors also do not create negative entries.

Keep valid authorization after ordinary inference I/O errors. A new connection
does not require full attestation when valid authorization already covers its
identity. These rules avoid unnecessary verification and early negative
caching while preserving fail-closed acquisition: a cache miss still requires
successful complete verification.

## Recognized provider responses

Responses arrive over the authorized TLS transport, including any explicit factor
allowance. The existing NEAR decryption-rejection contract requires HTTP 400,
media type `application/json`, and the exact message `Decryption failed`.
Key recovery applies only when the attempt used an E2EE session. A TLS-only
request handles the same envelope as an ordinary upstream error: it does not
invalidate authorization or retry.

| Provider | Endpoint under `/v1/` | Required `error.type` |
| --- | --- | --- |
| NEAR direct | `chat/completions`, `embeddings`, `images/generations`, `rerank`, `score` | `bad_request` |
| NEAR cloud | `chat/completions` | `invalid_request_error` |
| NEAR cloud | `embeddings` | `provider_error` |
| NEAR cloud | `images/generations`, `rerank`, `score` | No recognized retry contract |

Tinfoil direct and cloud require HTTP 422, media type
`application/problem+json`, and problem `type` exactly
`urn:ietf:params:ehbp:error:key-config`.

The presence of `Ehbp-Response-Nonce`, including an empty value, excludes the
response from plaintext rejection parsing. The client must authenticate
encrypted HTTP 422 and 500 responses through the normal response processing
path. These responses do not authorize replay. The proxy rejects an empty
nonce and multiple nonce headers. After key-rejection handling, a non-2xx
EHBP response without a nonce retains its upstream status and body, limited
to 10 MiB, as TLS-authenticated
diagnostics. It does not establish E2EE success, trigger retry, or invalidate
authorization. Every 2xx response and every response with a nonce must pass
EHBP authentication. Redirects remain subject to the separate redirect policy.

Unknown provider names return an error from rejection parsing. Provider-wide
TLS/E2EE flags do not establish an endpoint-specific rejection contract.

The parser uses strict validation and a 64 KiB size limit. It rejects duplicate
object members at every depth, including names with equivalent JSON escapes.
An ambiguous envelope must not invalidate authorization or authorize replay.
It returns an error for unknown fields, missing required fields, invalid JSON,
or an invalid content type in a candidate rejection response. It also returns an
error if the body exceeds the size limit or cannot be read. A well-formed response with
another type or message is not a key rejection. Do not search raw body strings
or recursively parse nested error text to expand these contracts.

## NearCloud stale routing key

NearCloud chat (`/v1/chat/completions`) additionally recognizes HTTP 421 with
one `Content-Type: application/json` header and this exact envelope:

```json
{"error":{"type":"provider_error","message":"The encryption key is no longer valid. Please refresh your attestation report and retry.","param":null,"code":null}}
```

`param` and `code` may be absent or null; every non-null value is rejected.
The same strict parsing, duplicate checks, encrypted-error exclusion, and
64 KiB limit apply. Other statuses, endpoints, types, or messages establish no
stale-key contract.

Both E2EE and TLS-only attempts conditionally remove only the generation whose
routing key they sent. An E2EE attempt may retry once with acquired authorization
and a fresh session, including a replacement already published by another
request. TLS-only returns HTTP 421 without replay. Its next request fully
verifies on a cache miss. Standalone TLS-only verification fails the probe
without replay or automatic re-attestation. These failures create no cooldown
and do not close gateway pools whose transport identity remains valid.

Image HTTP 404/500 responses and nested stale-key text do not authorize replay
or invalidation. Generic errors can describe request failures with a valid key.
Automatic image key-retirement recovery is unsupported; see the
[NEAR limitations](../providers/near/near_attestation.md#nearcloud-model-routing).

## NEAR contract evidence

The contract review used these source revisions:

- [inference-proxy at `43bb027f`](https://github.com/nearai/inference-proxy/tree/43bb027f064b400a0613673e339041e98d7919b3):
  `src/routes/chat.rs` calls `decrypt_request_fields` before dispatch.
  `src/routes/passthrough.rs` uses the same operation in
  `json_passthrough_encrypted` before upstream calls. `src/encryption.rs` and
  `src/error.rs` map decryption failure to `AppError::BadRequest`.
- [cloud-api at `07798f89`](https://github.com/nearai/cloud-api/tree/07798f899accaf519dae0d572913c86aa31c4622):
  `crates/inference_providers/src/attested/nearai/mod.rs` extracts backend error
  messages. `crates/services/src/completions/mod.rs` maps chat HTTP 400 to
  `InvalidParams`; `crates/api/src/conversions.rs` emits `invalid_request_error`.
  The embeddings service preserves `CompletionError::ProviderError`, which
  emits `provider_error`. Image, rerank, and score retain raw backend response
  strings and do not establish the same outer JSON response contract.

The stale-key contract uses [cloud-api at `1c8057f3`](https://github.com/nearai/cloud-api/tree/1c8057f3620a77d0aef9f3a16c5711fd2e6ee21c):
`retry_with_fallback_caps` rejects a missing chat key before dispatch;
`crates/services/src/completions/mod.rs` and the API conversions produce the
421 envelope above. Image conversions do not provide an equivalent contract.

A provider protocol change requires new evidence and tests before changing the
recognizer. Keep the exact accepted response and endpoint set visible here.
See [required regression coverage](testing.md).

## NearDirect lifetime selection

Retry and invalidation decisions retain the model's selected indexed authority.
A failed SPKI handshake sends no inference bytes and does not replay the request.
The next full verification uses a fresh attestation pool on that same authority.
Metadata expiry, backend failure, key change, or authorization eviction cannot
trigger rediscovery for an established model or invalidate other models' routes.
See the [NEAR routing contract](../providers/near/near_attestation.md#neardirect-backend-selection).
