# API Support by Provider

This document describes the OpenAI-compatible API endpoints supported by each provider, their E2EE protocols, and the field-level encryption coverage when E2EE is active.

SSE data fields pass through the same encryption policy checks with or without
one space after `data:`. Streaming relay, reassembly, and standalone verification
share the parser, including LF, CRLF, CR, and an initial UTF-8 byte-order mark.
NEAR and EHBP completion markers use the same parsing rules; trailing data
still fails.

## Endpoint Surface

Teep exposes two endpoint categories:

1. OpenAI-compatible API endpoints for inference and model discovery.
2. Operational endpoints for health checks, dashboard/status streaming, Prometheus metrics, and attestation status.

### OpenAI-Compatible API Endpoints

These are the OpenAI-style endpoints that clients use for inference:

| Endpoint | Method | Description |
|---|---|---|
| `/v1/chat/completions` | POST | Chat completions (streaming and non-streaming) |
| `/v1/responses` | POST | Responses API (streaming and non-streaming) |
| `/v1/embeddings` | POST | Text embeddings |
| `/v1/audio/transcriptions` | POST | Audio transcription (multipart) |
| `/v1/audio/speech` | POST | Text-to-speech |
| `/v1/images/generations` | POST | Image generation |
| `/v1/rerank` | POST | Document reranking |
| `/v1/score` | POST | Text similarity scoring |
| `/v1/models` | GET | List available models |

`/v1/models` is a proxy-aggregated endpoint that returns the combined model list from all configured providers. Each model's `id` field is rewritten to `provider:upstreamID` (e.g. `venice:e2ee-qwen3-5-122b-a10b`, `neardirect:Qwen/Qwen3-VL-30B-A3B-Instruct`) so clients can route requests to the correct provider. It is not included in the per-provider matrices below because it is handled entirely by the proxy, does not forward requests to individual providers, and is not E2EE-encrypted (GET request, no sensitive data).

### Operational Status, Monitoring, and Teep-Specific Endpoints

These are teep runtime/observability endpoints, not OpenAI-compatible inference APIs:

| Endpoint | Method | Type | Description |
|---|---|---|---|
| `/` | GET | Dashboard page | Live HTML status dashboard |
| `/health` | GET | Health API | JSON process health snapshot |
| `/events` | GET | Dashboard status API | Server-Sent Events stream for live dashboard updates |
| `/metrics` | GET | Prometheus API | Prometheus text-format counters |
| `/v1/tee/report` | GET | Teep status API | Cached attestation report for a provider/model (`provider` and `model` query params required) |

Operational endpoints are intended for local monitoring and process supervision. In the current server implementation, these endpoints are unauthenticated and access control relies on binding to loopback by default.

Not all providers support all endpoints. If a provider has no path configured for an endpoint, the proxy returns HTTP 400 with an error indicating that the named provider does not support the requested endpoint (for example, `provider "venice" does not support embeddings`).

### Chat Completions Reasoning Diagnostics and Repairs

For `/v1/chat/completions`, teep inspects OpenAI-compatible `messages[]` metadata for reasoning-field preservation before forwarding the request upstream. This applies across providers. The inspection is limited to structured metadata: roles, message counts, reasoning field presence, reasoning string lengths, tool-call/tool-result shape, and known chat-template control flags. Teep does not log message text, tool arguments, or reasoning text.

Teep recognizes both assistant reasoning field names commonly used by providers and agent frameworks:

| Field | Location | Notes |
|---|---|---|
| `reasoning_content` | `messages[].reasoning_content` | Common OpenAI-compatible reasoning field |
| `reasoning` | `messages[].reasoning` | Used by some providers and compatibility layers |

When debug logging is enabled, teep emits `chat request metadata` with role sequence, reasoning-field indexes, reasoning lengths, tool counts, and relevant `chat_template_kwargs` booleans. Diagnostic INFO/WARN logs are rate-limited to once per hour per category and include `reasoning_diagnostics_issue` plus `reasoning_diagnostics_rate_limit`.

Teep emits the following reasoning diagnostics:

| Case | Level | Meaning |
|---|---|---|
| Prior assistant messages before the latest user message have no reasoning field | INFO | An agent framework may be stripping historical reasoning fields. This is especially risky for coding agents that depend on prior chain-of-thought summaries or hidden reasoning continuity |
| Prior assistant messages preserve reasoning, but a known model family would ignore it without a model-specific chat-template flag | WARN | The API request kept the reasoning fields, but the model template may clear or drop them before inference |
| At least two assistant tool-call messages or at least two visible assistant messages after the latest user message have no reasoning field | WARN | Reasoning may be getting stripped during a multi-step assistant loop. A single direct answer, refusal, or initial tool call without reasoning does not trigger this warning |
| The final message is `user`, the immediately previous message is `tool`, and an assistant tool-call message with no visible answer appears since the previous user | WARN when reasoning is missing, or when preserved reasoning is still at risk | A framework may have appended a reminder/addendum user message after tool output. If the assistant tool-call message has no reasoning, teep warns because the request is malformed in both ways: current-turn reasoning has been stripped and the trailing user shape may cause the model to lose reasoning or tool-result context. If the assistant tool-call message has reasoning, teep warns only when the known model/template preservation flag is not effective, or when teep repaired the request by injecting that flag. When preservation is already effective, the WARN is suppressed; debug `chat request metadata` still shows the trailing-user shape |
| Reasoning metadata cannot be parsed or fully classified | WARN | Teep could not determine the reasoning state reliably enough for one or more diagnostics |

For known model families, teep can repair the two model-template preservation hazards before inference by injecting an explicit `chat_template_kwargs` flag. Detection is intentionally provider-agnostic: teep checks the routed model name and upstream model name for `glm`, `kimi`, or `deepseek`, case-insensitively.

| Model family match | Repair flag injected when needed | Purpose |
|---|---|---|
| `glm` | `chat_template_kwargs.clear_thinking=false` | Preserve prior/current reasoning across turns instead of clearing thinking state |
| `kimi` | `chat_template_kwargs.preserve_thinking=true` | Preserve thinking fields across turns |
| `deepseek` | `chat_template_kwargs.drop_thinking=false` | Prevent DeepSeek templates from dropping prior thinking fields |

Repairs are applied only when the request already contains reasoning fields and teep detects either preserved prior-turn reasoning or the trailing-user-after-tool hazard. Existing explicit boolean settings are honored. Null or incorrectly typed values are treated as ineffective and may be replaced by the repair value. If a repair is applied, the WARN message says that teep repaired the issue by providing the model-specific preserved-thinking flag, and includes `model_reasoning_preservation_family`, `model_reasoning_preservation_flag`, and `reasoning_preservation_repair_reasons`.

These diagnostics and repairs are request-normalization behavior. They do not weaken attestation, routing, E2EE, or fail-closed provider validation. For E2EE providers, the repaired request body is encrypted after normalization, so the injected chat-template flag is protected by the provider's normal E2EE mode.

## Endpoint Support Matrix

This matrix applies to OpenAI-compatible inference endpoints.

| Endpoint | NearDirect | NearCloud | Chutes | Venice | Phala Cloud | Tinfoil Cloud | Tinfoil Direct |
|---|---|---|---|---|---|---|---|
| Chat completions | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Responses | — | — | — | — | — | Yes | Yes |
| Embeddings | Yes | Yes | Yes | — | Yes | Yes | Yes |
| Audio transcriptions | Yes | — | — | — | — | Yes | Yes |
| Text-to-speech | — | — | — | — | — | Yes | Yes |
| Image generation | Yes | Yes | — | — | — | — | — |
| Reranking | Yes | Yes | — | — | — | — | — |
| Score | Yes | Yes | — | — | — | — | — |

**—** = Not implemented. Provider returns HTTP 400.

## E2EE Support Matrix

| Endpoint | NearDirect | NearCloud | Chutes | Venice | Phala Cloud | Tinfoil Cloud | Tinfoil Direct |
|---|---|---|---|---|---|---|---|
| Chat completions | Encrypted | Encrypted | Encrypted | Encrypted | No E2EE | Encrypted | Encrypted |
| Responses | — | — | — | — | — | Encrypted | Encrypted |
| Embeddings | Encrypted | Encrypted | Encrypted | — | No E2EE | Encrypted | Encrypted |
| Audio transcriptions | Plaintext (pinned) | — | — | — | — | Fail closed when E2EE is enabled; plaintext when disabled | Fail closed when E2EE is enabled; plaintext when disabled |
| Text-to-speech | — | — | — | — | — | Encrypted | Encrypted |
| Image generation | Encrypted | Encrypted | — | — | — | — | — |
| Reranking | Encrypted | Encrypted | — | — | — | — | — |
| Score | Request encrypted; response plaintext (pinned) | Request encrypted; response plaintext (pinned) | — | — | — | — | — |

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
| Chat completions | Structural request metadata such as `role`, `tool_call_id`, `type`, `id`, `index`, and other non-sensitive wrapper fields |
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
| Embeddings | `input` when it is a JSON string or a JSON array of strings. Token-ID arrays and other non-string array elements are rejected by teep in E2EE mode because NearAI leaves non-string elements plaintext |
| Image generation | `prompt` |
| Reranking | `query`; `documents[]` when each document is a JSON string; `documents[].text` when documents are JSON objects. Other document object metadata remains plaintext |
| Score | `text_1`, `text_2` |

**E2EE response fields encrypted (NearDirect and NearCloud):**

| Field | Encrypted | Notes |
|---|---|---|
| `choices[].message.content` | Yes | When `content` is a JSON string. This excludes multimodal content-part arrays |
| `choices[].message.content[].text` | Yes | When `content` is a JSON array of content-part objects; only each part's `text` leaf is encrypted |
| `choices[].delta.content` | Yes | Streaming string chunks |
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
| `choices[].logprobs.refusal[].top_logprobs[*].token` | Yes | Recursive |
| `choices[].logprobs.refusal[].top_logprobs[*].bytes` | Yes | Recursive |
| `data[].b64_json` | Yes | Images |
| `data[].revised_prompt` | Yes | Images |
| `data[].embedding` | Yes | Embeddings |
| `results[].document.text` | Yes | Reranking; other object metadata remains plaintext |
| `data[].score` | No | Score response is currently plaintext from upstream (known upstream NearAI limitation) |

### NearDirect

**Upstream:** Model TEE inference-proxy instances at `*.completions.near.ai`.
With `base_url = "https://completions.near.ai"` (the default), or
`https://api.near.ai`, both `serve` and `verify` resolve the model through
`/endpoints`. Set `[providers.neardirect].base_url` to an explicit HTTPS backend
origin to disable endpoint discovery in both commands. That origin is used for
attestation and inference for every requested model; all attestation, TLS, and
E2EE checks still apply. The `/v1/models` catalog remains gateway-provided.

**E2EE protocol:** Ed25519/X25519 ECDH + XChaCha20-Poly1305 (field-level encryption).

**Connection model:** An immutable route selects the model authority once per request. Full attestation authenticates that authority and its TLS SPKI before publishing a complete authorization. Inference uses a pooled transport scoped to the provider, authority, and attested SPKI. Every new connection requires TLS 1.3, WebPKI, Certificate Transparency, and a matching attested key before request bytes are sent. HTTP/2 permits concurrent streams; HTTP/1.1 peers retain sequential reuse. Authorizations expire only at authenticated evidence bounds, or on explicit invalidation, eviction, or trust/key failure.

| Endpoint | Upstream Path | E2EE | Notes |
|---|---|---|---|
| Chat completions | `/v1/chat/completions` | Yes | Sensitive fields encrypted; streaming forced when E2EE active |
| Embeddings | `/v1/embeddings` | Yes | Sensitive fields encrypted; supports string and array input formats |
| Audio transcriptions | `/v1/audio/transcriptions` | Requires E2EE disabled | Multipart requests use attested TLS to the model TEE. The proxy rejects this endpoint when field-level E2EE is enabled |
| Image generation | `/v1/images/generations` | Yes | Sensitive fields encrypted; `prompt`, `b64_json`, and `revised_prompt` encrypted |
| Reranking | `/v1/rerank` | Yes | Sensitive fields encrypted; `query` and `documents[]` encrypted |
| Score | `/v1/score` | Request only | Request fields (`text_1`, `text_2`) encrypted; response `data[].score` currently plaintext (known upstream NearAI limitation) |

---

### NearCloud

**Upstream:** Two-layer TEE architecture. Gateway TEE at `cloud-api.near.ai` routes requests to per-model inference-proxy instances.

**E2EE protocol:** Same as NearDirect — Ed25519/X25519 ECDH + XChaCha20-Poly1305 (field-level encryption).

**Connection model:** Attestation-bound pooled HTTP/2 to the gateway TEE at `cloud-api.near.ai`. The `tls_key_binding` factor and inference transport use the authenticated gateway TLS fingerprint. The model backend fingerprint remains a separately authenticated evidence field; it never selects the gateway transport pin. The same atomic authorization and connection constraints as NearDirect apply. Each encrypted request uses a fresh E2EE session with the currently attested model key.

| Endpoint | Upstream Path | E2EE | Notes |
|---|---|---|---|
| Chat completions | `/v1/chat/completions` | Yes | Gateway forwards E2EE headers to model TEE |
| Embeddings | `/v1/embeddings` | Yes | Gateway forwards E2EE headers to model TEE |
| Audio transcriptions | Not configured | Not supported | The proxy has no NearCloud audio route |
| Image generation | `/v1/images/generations` | Yes | Gateway forwards E2EE headers to model TEE |
| Reranking | `/v1/rerank` | Yes | Gateway forwards E2EE headers to model TEE |
| Score | `/v1/score` | Request only | Request fields (`text_1`, `text_2`) encrypted; response `data[].score` currently plaintext (known upstream NearAI limitation) |

NearCloud keeps the same NearAI field-encryption behavior as NearDirect for the supported endpoints, but its TLS binding is to the gateway only rather than to the underlying per-model inference machine. Audio is not supported because the multipart request body cannot use the current field-encryption protocol. Gateway TLS pinning alone does not protect the multipart body through to the model backend.

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

**E2EE response fields encrypted:**

| Field | Encrypted | Notes |
|---|---|---|
| `choices[].delta.content` | Yes | Streaming string chunks only |

**E2EE field coverage:** Venice's E2EE implementation encrypts `messages[].content` in requests and `choices[].delta.content` in SSE response chunks. On the request side, `messages[].content` can be a plain text string or a serialized multimodal content array. On the response side, Venice only encrypts string `choices[].delta.content` chunks; it does not expose the NearAI-style `content[]` content-part array encryption model. Other message fields (tool_calls, name, reasoning_content, etc.) and top-level fields are preserved as plaintext. Venice uses X-Venice-TEE-* headers and secp256k1/AES-256-GCM — it does not use the NearDirect/NearCloud XChaCha20-Poly1305 protocol or the `X-Encrypt-All-Fields` header.

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
| Chutes | `attestation_type` key present | Not yet implemented |
| dstack | `intel_quote` key present | No E2EE |
| Tinfoil | `format` key present | Not yet implemented |
| Gateway | `gateway_attestation` key present | Not yet supported |

When a Chutes-format backend is detected, the attestation is parsed using the Chutes protocol, but E2EE is not yet implemented through the Phala proxy layer.

### Tinfoil Cloud (`tinfoil_v3_cloud`)

**Upstream:** Tinfoil router at `https://inference.tinfoil.sh`, which routes to per-model inference enclaves.

**E2EE protocol:** EHBP — HPKE X25519 + AES-256-GCM (full-body encryption).

**Connection model:** TLS-bound to the router enclave. Teep fetches `/.well-known/tinfoil-attestation?nonce=<64hex>`, verifies the Tinfoil V3 attestation document, checks the live TLS peer SPKI against `report_data.tls_key_fp`, and then verifies the upstream inference TLS peer against the same attested fingerprint. The EHBP key belongs to the router, not the per-model inference enclave. The router decrypts, forwards to the model enclave internally, and re-encrypts the response.

| Endpoint | Upstream Path | E2EE | Notes |
|---|---|---|---|
| Chat completions | `/v1/chat/completions` | Yes | Full-body EHBP encryption; streaming and non-streaming supported |
| Responses | `/v1/responses` | Yes | Full-body EHBP encryption; streaming and non-streaming supported |
| Embeddings | `/v1/embeddings` | Yes | Full-body EHBP encryption |
| Audio transcriptions | `/v1/audio/transcriptions` | No when E2EE is enabled | Multipart route is implemented, but current proxy guard rejects non-pinned E2EE multipart requests before routing. Plaintext mode can forward after attestation |
| Text-to-speech | `/v1/audio/speech` | Yes | Full-body EHBP encryption |

**E2EE field coverage:** EHBP encrypts the entire HTTP request and response body. There are **no field-level encryption gaps** — all request fields (messages, tools, parameters) and all response fields (content, tool_calls, usage) are encrypted by construction. Adding new OpenAI API fields requires zero changes to the encryption layer.

**Wire format:**
- Request: Chunked EHBP frames (`[4-byte length][AEAD ciphertext]`), sent as `Content-Type: application/json` with `Ehbp-Encapsulated-Key` header carrying the HPKE encapsulated key
- Response: Same chunked EHBP frames; `Ehbp-Response-Nonce` header carries the 32-byte response nonce for key derivation

**Model listing:** `/v1/models` is listed through the router base URL and returned by teep's proxy-aggregated model endpoint with `tinfoil_v3_cloud:` prefixes.

---

### Tinfoil Direct (`tinfoil_v3_direct`)

**Upstream:** Per-model inference enclaves resolved via the router's `/.well-known/tinfoil-proxy` discovery endpoint. The discovery response maps model IDs to actual backend enclave domains such as `gemma4-31b-1.inf10.tinfoil.sh`; teep validates that selected domains end in Tinfoil-owned suffixes before using them.

**E2EE protocol:** Same as Tinfoil Cloud — EHBP (HPKE X25519 + AES-256-GCM full-body encryption).

**Connection model:** TLS-bound directly to the selected per-model inference enclave. Teep fetches the enclave's Tinfoil V3 attestation with a client nonce, verifies the live attestation TLS peer SPKI, then verifies the upstream inference TLS peer against the attested `tls_key_fp`. The EHBP key belongs to the inference enclave itself, providing end-to-end encryption without a router intermediary.

| Endpoint | Upstream Path | E2EE | Notes |
|---|---|---|---|
| Chat completions | `/v1/chat/completions` | Yes | Full-body EHBP encryption; streaming and non-streaming supported |
| Responses | `/v1/responses` | Yes | Full-body EHBP encryption; streaming and non-streaming supported |
| Embeddings | `/v1/embeddings` | Yes | Full-body EHBP encryption |
| Audio transcriptions | `/v1/audio/transcriptions` | No when E2EE is enabled | Multipart route is implemented, but current proxy guard rejects non-pinned E2EE multipart requests before routing. Plaintext mode can forward after attestation |
| Text-to-speech | `/v1/audio/speech` | Yes | Full-body EHBP encryption |

**E2EE field coverage:** Identical to Tinfoil Cloud — full-body EHBP, no field-level gaps.

**Key ownership distinction:** In `tinfoil_v3_direct`, the HPKE public key in the attestation belongs to the inference enclave. In `tinfoil_v3_cloud`, it belongs to the router. Both use the same EHBP wire format.

**Direct routing details:** The direct resolver caches model-to-enclave mappings for 5 minutes. When a request includes `prompt_cache_key`, teep uses deterministic hash-based sticky routing across a model's available enclave domains; otherwise it chooses the lexicographically first domain for deterministic behavior. Attestation and cache keys include the selected backend domain so multiple enclaves for the same model cannot collide.

**Model listing:** Teep's model list for `tinfoil_v3_direct` is still fetched from the router base URL, not from each direct enclave.

---

## E2EE Protocol Comparison

| Property | NearDirect / NearCloud | Venice | Chutes | Tinfoil |
|---|---|---|---|---|
| Encryption scope | Per-field (requests; most responses) | Per-field (`messages[].content` only) | Full-body | Full-body |
| Key exchange | ECDH (Ed25519→X25519) | ECDH (secp256k1) | ML-KEM-768 (post-quantum) | HPKE X25519 (RFC 9180) |
| Symmetric cipher | XChaCha20-Poly1305 | AES-256-GCM | ChaCha20-Poly1305 | AES-256-GCM |
| E2EE headers | `X-Signing-Algo`, `X-Client-Pub-Key`, `X-Encryption-Version`, `X-Encrypt-All-Fields` | `X-Venice-TEE-Client-Pub-Key`, `X-Venice-TEE-Model-Pub-Key`, `X-Venice-TEE-Signing-Algo` | None (body-level AEAD) | `Ehbp-Encapsulated-Key` (request), `Ehbp-Response-Nonce` (response) |
| Request encryption | All sensitive JSON fields | `messages[].content` | Entire body (gzipped) | Entire body (chunked EHBP frames) |
| Response encryption | Selected sensitive fields encrypted (chat text/tool-call payloads/logprobs tokens, embeddings vectors, rerank document text, image `b64_json`/`revised_prompt`); structural and numeric metadata plaintext; score `data[].score` currently plaintext (known upstream NearAI limitation) | `choices[].delta.content` in SSE chunks | Entire SSE chunks | Entire body (chunked EHBP frames) |
| Field coverage | Broad sensitive-field coverage with `X-Encrypt-All-Fields: true`; metadata fields (IDs, indexes, roles, finish reasons, usage counters, scores) remain plaintext | `messages[].content` (request); `choices[].delta.content` (response) | Complete — all fields encrypted by construction | Complete — all fields encrypted by construction |
| New field coverage | Requires explicit code change per field | Requires explicit code change per field | Automatic — new fields covered by construction | Automatic — new fields covered by construction |
| Streaming | `stream=true` forced; relay decrypts SSE | `stream=true` forced; relay decrypts SSE | `e2e_init` + `e2e` SSE events; relay decrypts chunks | EHBP decrypts body to plaintext SSE; relay forwards decrypted stream |
| Post-quantum | No | No | Yes (ML-KEM-768) | No |
