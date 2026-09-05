# Inference retry contracts

The shared proxy and standalone inference loop permits at most two attempts
(one retry) under one caller deadline. Each attempt obtains valid
authorization and creates a fresh encryption session. Clean up the rejected
attempt before starting the next one. An HTTP error alone does not prove that
the provider did not process inference.

## Retry and invalidation decisions

| Outcome | Retry this request? | Shared authorization action |
| --- | --- | --- |
| Typed DNS error marked temporary or timed out, or a dial error, before any `GotConn` | At most once, if the context remains valid | Retain; acquire valid authorization again |
| Exact supported key rejection before inference | At most once | Conditionally remove the generation used; acquire authorization again |
| TLS WebPKI, CT, or SPKI authentication failure | No | Conditionally remove the generation used |
| Response authentication, decryption, or encryption-policy failure | No | Conditionally remove the generation used |
| Cancellation, deadline, ordinary I/O failure, ambiguous EOF or connection reset, or protocol error after connection assignment | No | Retain; normal expiry still applies |
| Local outbound socket capacity exhausted | No | Retain; return HTTP 503 with `Retry-After: 1` before response headers |
| Redirect, generic service error, or malformed rejection envelope | No | No invalidation solely for this outcome |

Malformed JSON, invalid SSE structure, and response size limits fail the
request without invalidating authorization. Only an authentication,
decryption, or encryption-policy failure uses the decryption-failure
classification. Re-attestation cannot repair an ordinary response schema
error. NEAR non-streaming SSE reassembly decrypts each delta once and uses
that same result for content and tool-call metadata.

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

Collateral retrieval and inference have different retry contracts. Both the
proxy and standalone verifier construct their shared attestation client with
`config.NewAttestationClient`. Intel PCS and AMD KDS getters delegate retries
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

All responses below arrive over attested TLS. NEAR responses require HTTP 400,
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
path. These responses do not authorize replay. The client rejects an empty
nonce.

The parser uses strict validation and a 64 KiB size limit. It rejects duplicate
object members at every depth, including names with equivalent JSON escapes.
An ambiguous envelope must not invalidate authorization or authorize replay.
It returns an error for unknown fields, missing required fields, invalid JSON,
or an invalid content type in a candidate rejection response. It also returns an
error if the body exceeds the size limit or cannot be read. A well-formed response with
another type or message is not a key rejection. Do not search raw body strings
or recursively parse nested error text to expand these contracts.

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

A provider protocol change requires new evidence and tests before changing the
recognizer. Keep the exact accepted response and endpoint set visible here.
See [required regression coverage](testing.md).
