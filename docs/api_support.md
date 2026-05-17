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
| `/v1/score` | POST | Text similarity scoring |
| `/v1/models` | GET | List available models |

`/v1/models` is a proxy-aggregated endpoint that returns the combined model list from all configured providers. Each model's `id` field is rewritten to `provider:upstreamID` (e.g. `venice:e2ee-qwen3-5-122b-a10b`, `neardirect:Qwen/Qwen3-VL-30B-A3B-Instruct`) so clients can route requests to the correct provider. It is not included in the per-provider matrices below because it is handled entirely by the proxy, does not forward requests to individual providers, and is not E2EE-encrypted (GET request, no sensitive data).

Not all providers support all endpoints. If a provider has no path configured for an endpoint, the proxy returns HTTP 400 with an error indicating that the named provider does not support the requested endpoint (for example, `provider "venice" does not support embeddings`).

## Endpoint Support Matrix

| Endpoint | NearDirect | NearCloud | Chutes | Venice | Phala Cloud |
|---|---|---|---|---|---|
| Chat completions | Yes | Yes | Yes | Yes | Yes |
| Embeddings | Yes | Yes | Yes | — | Yes |
| Audio transcriptions | Yes | — | — | — | — |
| Image generation | Yes | Yes | — | — | — |
| Reranking | Yes | Yes | — | — | — |
| Score | Yes | Yes | — | — | — |

**—** = Not wired. Provider returns HTTP 400.

## E2EE Support Matrix

| Endpoint | NearDirect | NearCloud | Chutes | Venice | Phala Cloud |
|---|---|---|---|---|---|
| Chat completions | Encrypted | Encrypted | Encrypted | Encrypted | No E2EE |
| Embeddings | Encrypted | Encrypted | Encrypted | — | No E2EE |
| Audio transcriptions | Plaintext (pinned) | — | — | — | — |
| Image generation | Encrypted | Encrypted | — | — | — |
| Reranking | Encrypted | Encrypted | — | — | — |
| Score | Request encrypted; response plaintext (pinned) | Request encrypted; response plaintext (pinned) | — | — | — |

**Encrypted** = E2EE is applied to request and response fields.
**Fail closed** = Proxy rejects the request with an error because E2EE is not supported for this endpoint in the end-to-end path, either because the proxy does not implement E2EE field dispatch for that request type or because the upstream TEE cannot decrypt it.
**Plaintext (pinned)** = Request and response transit in plaintext, but the connection is TLS-pinned to the attested TEE (no E2EE field encryption).
**Request encrypted; response plaintext (pinned)** = Request fields are encrypted end-to-end, but upstream currently returns plaintext response fields for this endpoint. This is a known upstream NearAI limitation (inference-proxy/cloud-api score response path), not a teep policy preference. Responses still transit on pinned TLS to attested TEEs.
**No E2EE** = Provider does not support E2EE. Requests transit in plaintext over TLS to the attested TEE.
**—** = Endpoint not available for this provider.

## Provider Details

**Teep E2EE Header:** Teep automatically sets `X-Encrypt-All-Fields: true` on all E2EE-enabled requests to NearDirect and NearCloud. This enables full-field encryption of all sensitive request and response fields. The encryption coverage documented below reflects teep's behavior with this header active.

### NearAI Shared E2EE Behavior

NearDirect and NearCloud both use the NearAI field-encryption protocol: Ed25519/X25519 ECDH + XChaCha20-Poly1305 with `X-Encrypt-All-Fields: true` on supported endpoints. In both providers, teep encrypts the sensitive fields listed below and leaves structural or numeric metadata plaintext.

**Known plaintext request fields (NearDirect and NearCloud):**

| Endpoint | Plaintext request fields |
|---|---|
| Chat completions | Structural request metadata such as `role`, `tool_call_id`, `type`, `id`, and other non-sensitive wrapper fields |
| Embeddings | Request wrapper metadata such as `encoding_format`, `dimensions`, and other non-sensitive wrapper fields |
| Image generation | Request wrapper metadata such as `n`, `size`, `quality`, `style`, and other non-sensitive wrapper fields |
| Reranking | Request wrapper metadata such as non-sensitive top-level parameters |
| Score | Request wrapper metadata; sensitive inputs `text_1` and `text_2` are encrypted |

**Known plaintext response fields (NearDirect and NearCloud):**

| Endpoint | Plaintext response fields |
|---|---|
| Chat completions | Structural metadata including top-level `id`, `object`, `created`, `model`, optional `system_fingerprint`; `choices[].index`, `choices[].finish_reason`, `choices[].message.role`/`choices[].delta.role`, tool-call metadata (`tool_call_id`, `id`, `type`), usage counters (`usage.*`), and other numeric/index metadata |
| Embeddings | Top-level metadata (`id`, `object`, `created`, `model`, `usage.*`) and per-item metadata (`data[].index`, `data[].object`) |
| Image generation | Top-level metadata (for example `created`); if upstream returns URL-form image output, `data[].url` remains plaintext while `b64_json`/`revised_prompt` are encrypted |
| Reranking | Numeric/index metadata (for example `results[].index`, `results[].relevance_score`) |
| Score | `data[].score` plaintext numeric response (known upstream NearAI limitation) |

**E2EE request fields encrypted (NearDirect and NearCloud):**

| Endpoint | Encrypted fields |
|---|---|
| Chat completions | `messages[].content`, `messages[].reasoning_content`, `messages[].reasoning`, `messages[].refusal`, `messages[].name`, `messages[].audio.data`, `messages[].tool_calls[].function.name`, `messages[].tool_calls[].function.arguments`, `messages[].function_call.name`, `messages[].function_call.arguments`; top-level: `tools[].function.name`, `tools[].function.description`, `tools[].function.parameters`, `tool_choice.function.name`, `function_call.name` (object form) |
| Embeddings | `input` (each element if array; string form if single string) |
| Image generation | `prompt` |
| Reranking | `query`, `documents[]` |
| Score | `text_1`, `text_2` |

**E2EE response fields encrypted (NearDirect and NearCloud):**

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
| `data[].embedding` | Yes | Embeddings |
| `results[].document.text` | Yes | Reranking |
| `data[].score` | No | Score response is currently plaintext from upstream (known upstream NearAI limitation) |

### NearDirect

**Upstream:** Model TEE inference-proxy instances at `*.completions.near.ai`, resolved per-model via the `/endpoints` discovery API.

**E2EE protocol:** Ed25519/X25519 ECDH + XChaCha20-Poly1305 (field-level encryption).

**Connection model:** TLS-pinned to the inference machine. On an SPKI cache miss, attestation is fetched inline and the subsequent inference uses that same TCP connection. On an SPKI cache hit, the proxy may open a fresh TLS connection that is validated against the cached attested SPKI pin rather than re-running attestation inline. In both cases, the TLS certificate is validated with standard CA-based verification, and the connection is additionally bound to the attested TEE with attestation-based SPKI pinning.

| Endpoint | Upstream Path | E2EE | Notes |
|---|---|---|---|
| Chat completions | `/v1/chat/completions` | Yes | Sensitive fields encrypted; streaming forced when E2EE active |
| Embeddings | `/v1/embeddings` | Yes | Sensitive fields encrypted; supports string and array input formats |
| Audio transcriptions | `/v1/audio/transcriptions` | No (pinned TLS) | Multipart body; E2EE not applied. Connection is TLS-pinned to attested TEE |
| Image generation | `/v1/images/generations` | Yes | Sensitive fields encrypted; `prompt`, `b64_json`, and `revised_prompt` encrypted |
| Reranking | `/v1/rerank` | Yes | Sensitive fields encrypted; `query` and `documents[]` encrypted |
| Score | `/v1/score` | Request only | Request fields (`text_1`, `text_2`) encrypted; response `data[].score` currently plaintext (known upstream NearAI limitation) |

---

### NearCloud

**Upstream:** Two-layer TEE architecture. Gateway TEE at `cloud-api.near.ai` routes requests to per-model inference-proxy instances.

**E2EE protocol:** Same as NearDirect — Ed25519/X25519 ECDH + XChaCha20-Poly1305 (field-level encryption).

**Connection model:** TLS-pinned to the gateway TEE only. This pinning binds clients to the cloud gateway, not to the underlying per-model inference machine. Gateway forwards requests to model TEE internally.

| Endpoint | Upstream Path | E2EE | Notes |
|---|---|---|---|
| Chat completions | `/v1/chat/completions` | Yes | Gateway forwards E2EE headers to model TEE |
| Embeddings | `/v1/embeddings` | Yes | Gateway forwards E2EE headers to model TEE |
| Audio transcriptions | `/v1/audio/transcriptions` | No (pinned TLS) | Multipart body; E2EE not applied. Gateway pinning only covers the cloud gateway |
| Image generation | `/v1/images/generations` | Yes | Gateway forwards E2EE headers to model TEE |
| Reranking | `/v1/rerank` | Yes | Gateway forwards E2EE headers to model TEE |
| Score | `/v1/score` | Request only | Request fields (`text_1`, `text_2`) encrypted; response `data[].score` currently plaintext (known upstream NearAI limitation) |

NearCloud keeps the same NearAI field-encryption behavior as NearDirect for the supported endpoints, but its TLS binding is to the gateway only rather than to the underlying per-model inference machine. Audio remains unwired because the multipart request body cannot be field-encrypted safely in the current pinned flow.

**E2EE field coverage:** Matches the shared NearAI tables above; score response `data[].score` is currently plaintext due to a known upstream NearAI limitation.

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

**E2EE field coverage:** Venice's E2EE implementation encrypts only `messages[].content`. Other message fields (tool_calls, name, reasoning_content, etc.) and top-level fields are preserved as plaintext. Venice uses X-Venice-TEE-* headers and secp256k1/AES-256-GCM — it does not use the NearDirect/NearCloud XChaCha20-Poly1305 protocol or the `X-Encrypt-All-Fields` header.

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

| Property | NearDirect / NearCloud | Venice | Chutes |
|---|---|---|---|
| Encryption scope | Per-field (requests; most responses) | Per-field (`messages[].content` only) | Full-body |
| Key exchange | ECDH (Ed25519→X25519) | ECDH (secp256k1) | ML-KEM-768 (post-quantum) |
| Symmetric cipher | XChaCha20-Poly1305 | AES-256-GCM | ChaCha20-Poly1305 |
| E2EE headers | `X-Signing-Algo`, `X-Client-Pub-Key`, `X-Encryption-Version`, `X-Encrypt-All-Fields` | `X-Venice-TEE-Client-Pub-Key`, `X-Venice-TEE-Model-Pub-Key`, `X-Venice-TEE-Signing-Algo` | None (body-level AEAD) |
| Request encryption | All sensitive JSON fields | `messages[].content` | Entire body (gzipped) |
| Response encryption | Selected sensitive fields encrypted (chat text/tool-call payloads/logprobs tokens, embeddings vectors, rerank document text, image `b64_json`/`revised_prompt`); structural and numeric metadata plaintext; score `data[].score` currently plaintext (known upstream NearAI limitation) | `choices[].delta.content` in SSE chunks | Entire SSE chunks |
| Field coverage | Broad sensitive-field coverage with `X-Encrypt-All-Fields: true`; metadata fields (IDs, indexes, roles, finish reasons, usage counters, scores) remain plaintext | `messages[].content` only | Complete — all fields encrypted by construction |
| New field coverage | Requires explicit code change per field | Requires explicit code change per field | Automatic — new fields covered by construction |
| Streaming | `stream=true` forced; relay decrypts SSE | `stream=true` forced; relay decrypts SSE | `e2e_init` + `e2e` SSE events; relay decrypts chunks |
| Post-quantum | No | No | Yes (ML-KEM-768) |
