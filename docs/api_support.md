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

`/v1/models` is a proxy-aggregated endpoint that returns the combined model list from all configured providers. Each model's `id` field is rewritten to `provider:upstreamID` (e.g. `venice:e2ee-qwen3-5-122b-a10b`, `neardirect:Qwen/Qwen3-VL-30B-A3B-Instruct`) so clients can route requests to the correct provider. It is not included in the per-provider matrices below because it is handled entirely by the proxy, does not forward requests to individual providers, and is not E2EE-encrypted (GET request, no sensitive data).

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

**Teep E2EE Header:** Teep automatically sets `X-Encrypt-All-Fields: true` on all E2EE-enabled requests to NearDirect and NearCloud. This enables full-field encryption of all sensitive request and response fields. The encryption coverage documented below reflects teep's behavior with this header active.

### NearDirect

**Upstream:** Model TEE inference-proxy instances at `*.completions.near.ai`, resolved per-model via the `/endpoints` discovery API.

**E2EE protocol:** Ed25519/X25519 ECDH + XChaCha20-Poly1305 (field-level encryption).

**Connection model:** TLS-pinned. On an SPKI cache miss, attestation is fetched inline and the subsequent inference uses that same TCP connection. On an SPKI cache hit, the proxy may open a fresh TLS connection that is validated against the cached attested SPKI pin rather than re-running attestation inline. In both cases, the TLS certificate is validated with standard CA-based verification, and the connection is additionally bound to the attested TEE with attestation-based SPKI pinning.

| Endpoint | Upstream Path | E2EE | Notes |
|---|---|---|---|
| Chat completions | `/v1/chat/completions` | Yes | Full-field encryption; streaming forced when E2EE active |
| Embeddings | `/v1/embeddings` | Fail closed | Inference-proxy supports E2EE for embeddings, but proxy fails closed because the field-level E2EE dispatch does not cover this endpoint |
| Audio transcriptions | `/v1/audio/transcriptions` | No (pinned TLS) | Multipart body; E2EE not applied. Connection is TLS-pinned to attested TEE |
| Image generation | `/v1/images/generations` | Yes | Full-field encryption; prompt, `b64_json`, and `revised_prompt` encrypted |
| Reranking | `/v1/rerank` | Fail closed | Same as embeddings — inference-proxy supports it but proxy fails closed |

**E2EE request fields encrypted:**

| Endpoint | Encrypted message fields | Encrypted top-level fields |
|---|---|---|
| Chat completions | `messages[].content`, `messages[].reasoning_content`, `messages[].reasoning`, `messages[].refusal`, `messages[].name`, `messages[].audio.data`, `messages[].tool_calls[].function.name`, `messages[].tool_calls[].function.arguments`, `messages[].function_call.name`, `messages[].function_call.arguments` | `tools[].function.name`, `tools[].function.description`, `tools[].function.parameters`, `tool_choice.function.name`, `function_call.name` (object form) |
| Image generation | `prompt` | —

**E2EE response fields encrypted:**

| Field | Encrypted | Notes |
|---|---|---|
| `choices[].message.content` | Yes | |
| `choices[].delta.content` | Yes | Streaming |
| `choices[].message.reasoning_content` | Yes | |
| `choices[].delta.reasoning_content` | Yes | Streaming |
| `choices[].message.reasoning` | Yes | |
| `choices[].message.refusal` | Yes | |
| `choices[].delta.refusal` | Yes | Streaming |
| `choices[].message.name` | Yes | |
| `choices[].message.audio.data` | Yes | |
| `choices[].message.tool_calls[].function.name` | Yes | |
| `choices[].message.tool_calls[].function.arguments` | Yes | |
| `choices[].delta.tool_calls[].function.name` | Yes | Streaming |
| `choices[].delta.tool_calls[].function.arguments` | Yes | Streaming |
| `choices[].message.function_call.name` | Yes | Deprecated format |
| `choices[].message.function_call.arguments` | Yes | Deprecated format |
| `choices[].delta.function_call.name` | Yes | Deprecated format, streaming |
| `choices[].delta.function_call.arguments` | Yes | Deprecated format, streaming |
| `choices[].logprobs.content[].token` | Yes | |
| `choices[].logprobs.content[].bytes` | Yes | |
| `choices[].logprobs.refusal[].token` | Yes | |
| `choices[].logprobs.refusal[].bytes` | Yes | |
| `choices[].logprobs.content[].top_logprobs[*].token` | Yes | Recursive |
| `choices[].logprobs.content[].top_logprobs[*].bytes` | Yes | Recursive |
| `data[].b64_json` | Yes | Images |
| `data[].revised_prompt` | Yes | Images |

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

**E2EE field coverage:** Identical to NearDirect (same inference-proxy backend). See the NearDirect tables above for complete list of encrypted fields.

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

**E2EE field coverage:** Venice uses the same [inference-proxy](https://github.com/nearai/inference-proxy) as NearDirect and NearCloud. All encrypted fields are identical to NearDirect — see the NearDirect tables above for the complete list.

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
| Encryption scope | Per-field (all fields with teep) | Full-body |
| Key exchange | ECDH (Ed25519→X25519 or secp256k1) | ML-KEM-768 (post-quantum) |
| Symmetric cipher | XChaCha20-Poly1305 or AES-256-GCM | ChaCha20-Poly1305 |
| Request encryption | All sensitive JSON fields | Entire body (gzipped) |
| Response encryption | All sensitive JSON fields in SSE chunks | Entire SSE chunks |
| Field coverage | Complete with teep's `X-Encrypt-All-Fields: true` | Complete — all fields encrypted by construction |
| New field coverage | Requires explicit code change per field | Automatic — new fields covered by construction |
| Streaming | `stream=true` forced; relay decrypts SSE | `e2e_init` + `e2e` SSE events; relay decrypts chunks |
| Post-quantum | No | Yes (ML-KEM-768) |
