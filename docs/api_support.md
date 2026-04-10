# API Support by Provider

This document describes the OpenAI-compatible API endpoints supported by each provider, their E2EE protocols, and the field-level encryption coverage when E2EE is active.

## Overview

Teep exposes these proxy endpoints to clients:

| Endpoint | Method | Description |
|---|---|---|
| `/v1/chat/completions` | POST | Chat completions (streaming and non-streaming) |
| `/v1/embeddings` | POST | Text embeddings |
| `/v1/audio/transcriptions` | POST | Audio transcription (multipart) |
| `/v1/images/generations` | POST | Image generation |
| `/v1/rerank` | POST | Document reranking |
| `/v1/models` | GET | List available models |

`/v1/models` is a proxy-aggregated endpoint that returns the combined model list from all configured providers. It is not included in the per-provider matrices below because it is handled entirely by the proxy, does not forward requests to individual providers, and is not E2EE-encrypted (GET request, no sensitive data).

Not all providers support all endpoints. If a provider has no path configured for an endpoint, the proxy returns HTTP 400 with an error indicating that the named provider does not support the requested endpoint (for example, `provider "nearcloud" does not support reranking`).

## Endpoint Support Matrix

| Endpoint | NearDirect | NearCloud | Chutes | Venice | Phala Cloud |
|---|---|---|---|---|---|
| Chat completions | Yes | Yes | Yes | Yes | Yes |
| Embeddings | Yes | — | Yes | — | Yes |
| Audio transcriptions | Yes | — | — | — | — |
| Image generation | Yes | Yes | — | — | — |
| Reranking | Yes | — | — | — | — |

**—** = Not wired. Provider returns HTTP 400.

## E2EE Support Matrix

| Endpoint | NearDirect | NearCloud | Chutes | Venice | Phala Cloud |
|---|---|---|---|---|---|
| Chat completions | Encrypted | Encrypted | Encrypted | Encrypted | No E2EE |
| Embeddings | Fail closed | — | Encrypted | — | No E2EE |
| Audio transcriptions | Plaintext (pinned) | — | — | — | — |
| Image generation | Encrypted | Encrypted | — | — | — |
| Reranking | Fail closed | — | — | — | — |

**Encrypted** = E2EE is applied to request and response fields.
**Fail closed** = Proxy rejects the request with an error because E2EE is not supported for this endpoint in the end-to-end path, either because the proxy does not implement E2EE field dispatch for that request type or because the upstream TEE cannot decrypt it.
**Plaintext (pinned)** = Request and response transit in plaintext, but the connection is TLS-pinned to the attested TEE (no E2EE field encryption).
**No E2EE** = Provider does not support E2EE. Requests transit in plaintext over TLS to the attested TEE.
**—** = Endpoint not available for this provider.

## Provider Details

### NearDirect

**Upstream:** Model TEE inference-proxy instances at `*.completions.near.ai`, resolved per-model via the `/endpoints` discovery API.

**E2EE protocol:** Ed25519/X25519 ECDH + XChaCha20-Poly1305 (field-level encryption).

**Connection model:** TLS-pinned. On an SPKI cache miss, attestation is fetched inline and the subsequent inference uses that same TCP connection. On an SPKI cache hit, the proxy may open a fresh TLS connection that is validated against the cached attested SPKI pin rather than re-running attestation inline. In both cases, the TLS certificate is validated with standard CA-based verification, and the connection is additionally bound to the attested TEE with attestation-based SPKI pinning.

| Endpoint | Upstream Path | E2EE | Notes |
|---|---|---|---|
| Chat completions | `/v1/chat/completions` | Yes | Streaming forced when E2EE active |
| Embeddings | `/v1/embeddings` | Fail closed | Inference-proxy supports E2EE for embeddings, but proxy fails closed because the field-level E2EE dispatch does not cover this endpoint |
| Audio transcriptions | `/v1/audio/transcriptions` | No (pinned TLS) | Multipart body; E2EE not applied. Connection is TLS-pinned to attested TEE |
| Image generation | `/v1/images/generations` | Yes | Prompt encrypted; response `b64_json` and `revised_prompt` encrypted |
| Reranking | `/v1/rerank` | Fail closed | Same as embeddings — inference-proxy supports it but proxy fails closed |

**E2EE request fields encrypted:**

| Endpoint | Encrypted fields |
|---|---|
| Chat completions | `messages[].content` (text string or serialized VL content array) |
| Image generation | `prompt` |

**E2EE response fields encrypted (by inference-proxy):**

| Field | Encrypted | Notes |
|---|---|---|
| `choices[].message.content` | Yes | |
| `choices[].delta.content` | Yes | Streaming |
| `choices[].message.reasoning_content` | Yes | |
| `choices[].delta.reasoning_content` | Yes | Streaming |
| `choices[].message.reasoning` | Yes | |
| `choices[].message.audio.data` | Yes | |
| `data[].b64_json` | Yes | Images |
| `data[].revised_prompt` | Yes | Images |

**Chat response fields NOT encrypted (plaintext gaps):**

| Field | Contains sensitive data | Risk |
|---|---|---|
| `tool_calls[].function.arguments` | Yes — model-generated arguments derived from user input | Leaks user data |
| `tool_calls[].function.name` | Yes — reveals query intent | Leaks query intent |
| `refusal` | Yes — reveals what the user asked | Leaks query intent |
| `logprobs.content[].token` | Yes — reveals output text token-by-token | Bypasses content encryption |
| `function_call` (deprecated) | Yes — same as tool_calls | Leaks user data |

These gaps are in the upstream [inference-proxy](https://github.com/nearai/inference-proxy) `encrypt_chat_response_choices` function, not in teep. See [e2ee_plaintext_gaps.md](attestation_gaps/e2ee_plaintext_gaps.md) for details and reproduction steps.

---

### NearCloud

**Upstream:** Two-layer TEE architecture. Gateway TEE at `cloud-api.near.ai` routes requests to per-model inference-proxy instances.

**E2EE protocol:** Same as NearDirect — Ed25519/X25519 ECDH + XChaCha20-Poly1305 (field-level encryption).

**Connection model:** TLS-pinned to gateway TEE. Gateway forwards requests to model TEE internally.

| Endpoint | Upstream Path | E2EE | Notes |
|---|---|---|---|
| Chat completions | `/v1/chat/completions` | Yes | Gateway forwards E2EE headers to model TEE |
| Image generation | `/v1/images/generations` | Yes | Gateway forwards E2EE headers to model TEE |

Embeddings, audio, and reranking are **not wired** in the proxy for NearCloud. The gateway silently drops E2EE headers for these endpoints, so wiring them would send plaintext through a channel the user believes is encrypted.

**E2EE request/response field coverage:** Identical to NearDirect (same inference-proxy). See the NearDirect tables above for encrypted and unencrypted fields.

**Gateway header-forwarding gaps:** The gateway (`cloud-api.near.ai`) only calls `validate_encryption_headers` and forwards E2EE headers for chat completions and image generation. All other endpoints discard E2EE headers silently. The model TEE supports E2EE for embeddings, audio, rerank, and score — headers just never reach it through the gateway. See [e2ee_plaintext_gaps.md](attestation_gaps/e2ee_plaintext_gaps.md) for test evidence comparing gateway vs. direct inference-proxy behavior.

---

### Chutes

**Upstream:** `https://llm.chutes.ai` for inference, `https://api.chutes.ai` for attestation and instance discovery.

**E2EE protocol:** ML-KEM-768 (post-quantum KEM) + ChaCha20-Poly1305 (full-body encryption).

**Connection model:** Standard TLS. E2EE encrypts the entire HTTP body as a single binary blob — no field-level dispatch.

| Endpoint | Upstream Path | E2EE | Notes |
|---|---|---|---|
| Chat completions | `/v1/chat/completions` | Yes | Full-body encryption; streaming via `e2e_init` + `e2e` SSE events |
| Embeddings | `/v1/embeddings` | Yes | Full-body encryption; same protocol as chat |

**E2EE field coverage:** Because Chutes encrypts the entire request and response body as a single AEAD ciphertext, there are **no field-level gaps**. All request fields (messages, tools, parameters) and all response fields (content, tool_calls, logprobs, refusal) are encrypted by construction. Adding new OpenAI API fields requires zero changes to the encryption layer.

**Wire format:**
- Request: `[KEM_CT(1088) || nonce(12) || gzip(JSON) ciphertext || tag(16)]`, sent as `Content-Type: application/octet-stream`
- Response (streaming): `e2e_init` SSE event carries KEM ciphertext for response key derivation; `e2e` SSE events carry per-chunk ChaCha20-Poly1305 ciphertext
- Response (non-streaming): Same full-body AEAD scheme as request

**Not encrypted:** `usage` SSE events (token counts) are plaintext. This is acceptable — usage metadata is not user data.

---

### Venice

**Upstream:** Venice TEE API, typically at `https://api.venice.ai`.

**E2EE protocol:** secp256k1 ECDH + AES-256-GCM (field-level encryption).

**Connection model:** Standard TLS with E2EE field encryption. Streaming is forced when E2EE is active.

| Endpoint | Upstream Path | E2EE | Notes |
|---|---|---|---|
| Chat completions | `/api/v1/chat/completions` | Yes | `stream=true` forced; response decrypted from SSE chunks |

Venice only exposes chat completions. No other endpoints are available.

**E2EE request fields encrypted:**

| Field | Encrypted |
|---|---|
| `messages[].content` | Yes (text string or serialized VL content array) |

**E2EE response field coverage:** Venice uses the same [inference-proxy](https://github.com/nearai/inference-proxy) as NearDirect and NearCloud. The encrypted and unencrypted response fields are identical to NearDirect — see the NearDirect tables above.

**Plaintext gaps:** Same as NearDirect — `tool_calls[].function.arguments`, `tool_calls[].function.name`, `refusal`, `logprobs`, and `function_call` are not encrypted.

---

### Phala Cloud

**Upstream:** Phala Cloud (RedPill) gateway. Multi-backend — routes to different TEE backends depending on the model.

**E2EE protocol:** None. Phala Cloud does not currently support E2EE through teep.

**Connection model:** Standard TLS to the Phala gateway, which forwards to backend model instances.

| Endpoint | Upstream Path | E2EE | Notes |
|---|---|---|---|
| Chat completions | `/chat/completions` | No | Plaintext over TLS |
| Embeddings | `/embeddings` | No | Plaintext over TLS |

**Backend format detection:** Phala Cloud is a multi-backend gateway that serves different attestation formats depending on the backend model:

| Backend | Attestation Format | E2EE |
|---|---|---|
| Chutes | `attestation_type` key present | Not yet wired |
| dstack | `intel_quote` key present | No E2EE |
| Tinfoil | `format` key present | Not yet supported |
| Gateway | `gateway_attestation` key present | Not yet supported |

When a Chutes-format backend is detected, the attestation is parsed using the Chutes protocol, but E2EE is not yet wired through the Phala proxy layer.

## E2EE Protocol Comparison

| Property | NearDirect / NearCloud / Venice | Chutes |
|---|---|---|
| Encryption scope | Per-field | Full-body |
| Key exchange | ECDH (Ed25519→X25519 or secp256k1) | ML-KEM-768 (post-quantum) |
| Symmetric cipher | XChaCha20-Poly1305 or AES-256-GCM | ChaCha20-Poly1305 |
| Request encryption | Selected JSON fields only | Entire body (gzipped) |
| Response encryption | Selected JSON fields in SSE chunks | Entire SSE chunks |
| Field coverage gaps | Yes — tool_calls, refusal, logprobs unencrypted | None — all fields encrypted by construction |
| New field coverage | Requires explicit code change per field | Automatic — new fields covered by construction |
| Streaming | `stream=true` forced; relay decrypts SSE | `e2e_init` + `e2e` SSE events; relay decrypts chunks |
| Post-quantum | No | Yes (ML-KEM-768) |
