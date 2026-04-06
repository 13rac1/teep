# NearCloud E2EE: Plaintext Gaps in Encryption Coverage

This document describes verified gaps in NearCloud's end-to-end encryption (E2EE) coverage. There are two distinct classes of gaps:

1. **Gateway header-forwarding gaps**: The Gateway TEE silently drops E2EE headers for non-chat endpoints (embeddings, audio, rerank, score), causing those requests to transit in plaintext even though the Model TEE supports E2EE for them.

2. **Chat completions field coverage gaps**: Even for `/v1/chat/completions` where E2EE headers ARE forwarded, the inference-proxy only encrypts a subset of response fields (`content`, `reasoning_content`, `reasoning`, `audio.data`). Other fields containing sensitive user-derived data — `tool_calls[].function.arguments`, `tool_calls[].function.name`, `refusal`, `logprobs`, and `function_call` — transit in **plaintext** through the E2EE layer.

NearCloud uses a two-layer TEE architecture: a **Gateway TEE** (`cloud-api.near.ai`) that routes requests, and **Model TEEs** (inference-proxy instances) that run alongside each model.

## Architecture

```
Client → Gateway TEE (cloud-api) → Model TEE (inference-proxy) → vLLM/Model
          ↑ extracts E2EE           ↑ decrypts request
          ↑ HTTP headers             ↑ encrypts response
          ↑ forwards to model TEE    ↑ per-endpoint field dispatch
```

- **Gateway TEE** ([nearai/cloud-api](https://github.com/nearai/cloud-api)): Receives client HTTP requests, authenticates API keys, validates E2EE headers, resolves models, and forwards requests to model TEEs. E2EE headers must be extracted from the HTTP request and placed into the provider's `extra` map for forwarding.

- **Model TEE** ([nearai/inference-proxy](https://github.com/nearai/inference-proxy)): Runs inside a TEE alongside the model worker (vLLM). Extracts `EncryptionContext` from request headers, decrypts request fields, forwards to the model, and encrypts response fields. All E2EE cryptography happens here.

## Summary of Findings

### Gateway Header-Forwarding Gaps

| Endpoint | Gateway Forwards E2EE? | Model TEE E2EE Support? | Observed Behavior | Response |
|---|---|---|---|---|
| `/v1/chat/completions` | **Yes** | Yes | Decrypts messages, encrypts SSE chunks | **Encrypted** |
| `/v1/chat/completions` (VL serialized) | **Yes** | Yes | Decrypts serialized array, encrypts response | **Encrypted** |
| `/v1/images/generations` | **Yes** | Yes | Decrypts prompt, encrypts b64_json | **Encrypted** |
| `/v1/embeddings` | **No** | Yes | Gateway drops headers → plaintext passthrough | **Plaintext** |
| `/v1/audio/transcriptions` | **No** | Yes | Gateway drops headers → plaintext passthrough | **Plaintext** |
| `/v1/rerank` | **No** | Yes | Gateway drops headers → plaintext passthrough | **Plaintext** |
| `/v1/score` | **No** | Yes | Gateway drops headers → plaintext passthrough | **Plaintext** |
| `/v1/chat/completions` (VL per-field) | **Yes** | No (wrong format) | Encrypted URL not a valid URL → 400 | **Error** |

### Chat Completions Field Coverage Gaps

Even when E2EE is fully active for `/v1/chat/completions`, only a subset of response fields are encrypted. The inference-proxy's `encrypt_chat_response_choices` selectively encrypts content fields but ignores tool calls, refusals, and log probabilities.

| Response Field | Encrypted? | Contains Sensitive Data? | Risk |
|---|---|---|---|
| `choices[].message.content` | **Yes** | Yes | ✅ Protected |
| `choices[].delta.content` | **Yes** | Yes | ✅ Protected |
| `choices[].message.reasoning_content` | **Yes** | Yes | ✅ Protected |
| `choices[].delta.reasoning_content` | **Yes** | Yes | ✅ Protected |
| `choices[].message.reasoning` | **Yes** | Yes | ✅ Protected |
| `choices[].message.audio.data` | **Yes** | Yes | ✅ Protected |
| `choices[].message.tool_calls[].function.arguments` | **No** | **Yes** | ❌ Leaks user data |
| `choices[].message.tool_calls[].function.name` | **No** | Yes (metadata) | ❌ Leaks query intent |
| `choices[].delta.tool_calls[].function.arguments` | **No** | **Yes** | ❌ Leaks user data (streaming) |
| `choices[].delta.tool_calls[].function.name` | **No** | Yes (metadata) | ❌ Leaks query intent (streaming) |
| `choices[].message.refusal` | **No** | Yes | ❌ Leaks query intent |
| `choices[].message.function_call` (deprecated) | **No** | **Yes** | ❌ Leaks user data |
| `choices[].logprobs.content[].token` | **No** | **Yes** | ❌ Leaks output text token-by-token |

#### Request-Side Field Stripping

Teep's `EncryptChatMessagesNearCloud` only preserves `role` and `content` when encrypting request messages. All other fields are stripped:

| Request Message Field | Preserved? | Impact |
|---|---|---|
| `role` | **Yes** | — |
| `content` | **Yes** (encrypted) | ✅ Protected |
| `tool_calls` | **No** (stripped) | ❌ Breaks multi-turn tool calling |
| `tool_call_id` | **No** (stripped) | ❌ Breaks tool result messages |
| `name` | **No** (stripped) | ❌ Drops function/user name |
| `reasoning_content` | **No** (stripped) | ❌ Drops reasoning context |
| `audio` | **No** (stripped) | ❌ Drops audio input |

Additionally, `EncryptChatMessagesNearCloud` **fails entirely** on multi-turn tool calling conversations because assistant tool-call messages have `null` content, which `contentPlaintext` rejects.

## Server Source Code Analysis

### Model TEE: Full E2EE for All Endpoints

The inference-proxy's [`encryption.rs`](https://github.com/nearai/inference-proxy/blob/main/src/encryption.rs) implements per-endpoint field-level encryption and decryption. The `decrypt_request_fields` function (line ~436) dispatches by `Endpoint` enum:

| Endpoint | Request Fields Decrypted | Response Fields Encrypted |
|---|---|---|
| `ChatCompletions` | `messages[].content`, `messages[].reasoning_content`, `messages[].reasoning`, `messages[].audio.data` | `choices[].message.content`, `choices[].delta.content`, `reasoning_content`, `reasoning`, `audio.data` |
| `Completions` | `prompt` (string or array) | `choices[].text` |
| `ImagesGenerations` | `prompt` | `data[].b64_json`, `data[].revised_prompt` |
| `Embeddings` | `input` (string or array of strings) | `data[].embedding` (serialized to JSON string) |
| `AudioTranscriptions` | `prompt` | `text` |
| `Rerank` | `query`, `documents[].text` | `results[].document.text` |
| `Score` | `text_1`, `text_2` | `score` (serialized to JSON string) |

**ChatCompletions fields NOT covered:**

| Field | Direction | Encrypted? | Sensitive? |
|---|---|---|---|
| `tool_calls[].function.arguments` | Response | **No** | **Yes** — model-generated function arguments derived from user input |
| `tool_calls[].function.name` | Response | **No** | Yes — reveals the nature of the user's query |
| `refusal` | Response | **No** | Yes — refusal text can reveal what was asked |
| `function_call.arguments` (deprecated) | Response | **No** | **Yes** — same as tool_calls |
| `function_call.name` (deprecated) | Response | **No** | Yes — same as tool_calls |
| `logprobs.content[].token` | Response | **No** | **Yes** — reveals output text token-by-token |
| `tool_calls[].function.arguments` | Request (assistant msgs) | **No** | Yes — tool call context in multi-turn |
| `name` | Request | **No** | Yes — function or user name |

All passthrough routes in [`routes/passthrough.rs`](https://github.com/nearai/inference-proxy/blob/main/src/routes/passthrough.rs) extract `EncryptionContext` from HTTP headers and call `json_passthrough_encrypted`, which applies both request decryption and response encryption.

**VL content arrays**: The `decrypt_chat_message_fields` function (line ~573) handles vision-language content via a serialize-and-encrypt protocol: when content is a string, it decrypts it, then tries `serde_json::from_str` — if the result is a JSON array, it replaces the string with the parsed array. This allows clients to encrypt an entire `[{"type":"text",...},{"type":"image_url",...}]` array as one string.

### Gateway: Partial Header Forwarding

The gateway's [`routes/completions.rs`](https://github.com/nearai/cloud-api/blob/main/crates/api/src/routes/completions.rs) contains route handlers for each endpoint. Only two call `validate_encryption_headers` and insert them into the `extra` map:

- **`chat_completions`** (line ~343): Calls `validate_encryption_headers(&headers)`, inserts `SIGNING_ALGO`, `CLIENT_PUB_KEY`, `MODEL_PUB_KEY`, `ENCRYPTION_VERSION` into `service_request.extra`.
- **`image_generations`** (line ~860): Same pattern — validates and forwards all four E2EE headers.

The remaining handlers **do not extract E2EE headers**:

- **`embeddings`** (line ~2101): Accepts raw `Bytes` body, does minimal model-name extraction. Calls `try_embeddings` with no E2EE headers.
- **`rerank`** (line ~1811): Deserializes `Json<RerankRequest>`, builds `RerankParams { extra: HashMap::new() }` — E2EE headers discarded.
- **`score`** (line ~2367): Deserializes `Json<ScoreRequest>`, builds `ScoreParams { extra: HashMap::new() }` — E2EE headers discarded.
- **`audio_transcriptions`** (line ~1108): Parses multipart form fields. No encryption header handling.

On the provider side, [`inference_providers/src/vllm/mod.rs`](https://github.com/nearai/cloud-api/blob/main/crates/inference_providers/src/vllm/mod.rs) has `prepare_encryption_headers()` which reads E2EE keys from `params.extra` and sets them as HTTP headers on the outgoing request to the model TEE. This function is called by `chat_completion_stream`, `chat_completion`, and `image_generation`, but **not** by `embeddings_raw`, `rerank`, `audio_transcription`, or `score`.

### Root Cause

The gap is in the gateway, not the model TEE. E2EE headers sent by the client are silently dropped at the gateway layer for embeddings, rerank, score, and audio endpoints. Even though the model TEE would correctly decrypt and encrypt these requests if it received the headers, it never gets the chance.

### Chat Completions: Incomplete Field Encryption in Model TEE

**This is a separate gap from the gateway header-forwarding issue.** Even when E2EE headers are properly forwarded for `/v1/chat/completions`, the inference-proxy's `encrypt_chat_response_choices` function only encrypts a subset of the response fields.

The function in [`encryption.rs`](https://github.com/nearai/inference-proxy/blob/main/src/encryption.rs) (line ~614):

```rust
fn encrypt_chat_response_choices(...) -> Result<(), AppError> {
    for choice in choices {
        let msg = choice.get_mut(msg_key);  // "message" or "delta"
        encrypt_content_field(msg, ...)?;         // content only
        encrypt_field(msg, "reasoning_content")?;  // ✅
        encrypt_field(msg, "reasoning")?;          // ✅
        if let Some(audio) = msg.get_mut("audio") {
            encrypt_field(audio, "data")?;         // ✅
        }
        // NO handling of tool_calls, refusal, function_call, or logprobs
    }
}
```

**Fields encrypted:** `content`, `reasoning_content`, `reasoning`, `audio.data`

**Fields NOT encrypted:**
- `tool_calls[].function.arguments` — Contains user-derived data (e.g., location names, personal information, financial data). When a user sends an encrypted message like "What's the weather at 123 Main Street?", the model generates `get_weather(location="123 Main Street")` which transits in plaintext.
- `tool_calls[].function.name` — Reveals which function the model invokes, leaking the nature of the user's query.
- `refusal` — Contains refusal reasons (e.g., "I cannot help with...") that reveal what the user asked about.
- `function_call` (deprecated OpenAI format) — Same data as tool_calls, also unencrypted.
- `logprobs` — Token-level log probabilities reveal the output text character-by-character, completely bypassing content encryption.

On the request side, `decrypt_chat_message_fields` similarly only decrypts `content`, `reasoning_content`, `reasoning`, and `audio.data` from each message — leaving `tool_calls[].function.arguments` and `name` in plaintext.

## Security Implications

### Gateway Header-Forwarding Gaps

1. **False sense of confidentiality.** A proxy that wires E2EE headers on non-chat endpoints gives the user the impression their data is encrypted end-to-end. It is not — the gateway silently ignores the headers.

2. **Gateway can observe all non-chat traffic.** The NearCloud gateway (and any intermediaries between client and model TEE) can read embeddings inputs, audio recordings, rerank documents, and all corresponding responses.

3. **Embedding vectors leak semantic content.** Plaintext embedding vectors can be used to reconstruct approximate input text or match against known documents.

4. **Audio recordings are highly sensitive.** Voice data contains biometric identifiers and spoken content — plaintext transmission through a gateway is a significant privacy risk.

### Chat Completions Field Coverage Gaps

5. **Tool call arguments leak user data through E2EE.** When a model makes a function call, the arguments are derived from the user's encrypted input. These arguments (locations, names, queries, financial data) transit in plaintext even though the user's message was encrypted. Any intermediary with TLS access (including the gateway) can observe what functions the model calls and with what parameters.

6. **Logprobs completely bypass content encryption.** If a client requests `logprobs: true`, the response includes the literal output tokens and their probabilities. This reveals the model's output character-by-character, rendering content encryption meaningless for that request.

7. **Refusal text reveals user intent.** The `refusal` field contains the model's reason for refusing a request (e.g., "I cannot assist with creating malware"). This plaintext field reveals what the user asked about even when the input was encrypted.

8. **Multi-turn tool calling is incompatible with E2EE.** Teep's `EncryptChatMessagesNearCloud` fails entirely on conversations containing assistant messages with `null` content (standard format for tool call responses). Even if this were fixed, it strips all message fields except `role` and `content`, losing `tool_calls`, `tool_call_id`, and `name` — breaking the conversation context.

## What Works: Chat (Partial), Images, and VL (Serialized)

### Chat completions (text content only)
Standard chat E2EE via `EncryptChatMessagesNearCloud`: encrypts `messages[].content` strings, server decrypts and encrypts `content`, `reasoning_content`, `reasoning`, and `audio.data` in SSE response chunks. **Tool calls, refusals, logprobs, and function_call fields are NOT encrypted** — see "Chat Completions Field Coverage Gaps" above.

### Image generation
The gateway forwards E2EE headers for `/v1/images/generations`. The inference-proxy decrypts the `prompt` field and encrypts `data[].b64_json` and `data[].revised_prompt` in the response. Verified by `TestIntegration_NearCloud_Images_EncryptedInput`: the decrypted `b64_json` is valid base64 image data, and the decrypted `revised_prompt` matches the original prompt.

### VL chat (serialize-and-encrypt)
The inference-proxy supports VL E2EE by accepting the entire content array serialized as a JSON string:

1. Client serializes: `[{"type":"text","text":"..."}, {"type":"image_url","image_url":{"url":"data:..."}}]`
2. Client encrypts the serialized string with `EncryptXChaCha20`
3. Client sends `{"content": "<encrypted_hex>"}` (content is a string, not an array)
4. Server decrypts → detects JSON array → restores original structure

Verified by `TestIntegration_NearCloud_VL_SerializedArray`: server decrypts the serialized array, processes the image, and returns the encrypted response "Red".

**Note:** Encrypting individual fields within the content array (per-field approach) does **not** work — the encrypted image URL is not a valid URL format, causing a 400 error. The serialize-and-encrypt approach is the correct protocol.

## What Does Not Work: Embeddings, Rerank, Audio, Score

These endpoints fail because the gateway does not forward E2EE headers to the model TEE.

### Embeddings
The gateway's `embeddings` handler accepts raw bytes and forwards them without extracting E2EE headers. Even if the client encrypts the `input` field and sends E2EE headers, the model TEE receives no `EncryptionContext` and treats the request as plaintext. The model computes an embedding of the hex-encoded ciphertext.

### Rerank
The gateway's `rerank` handler builds `RerankParams { extra: HashMap::new() }`, discarding any E2EE headers. The model TEE receives no encryption context and reranks the ciphertext strings as plaintext text.

### Audio transcription
The gateway's `audio_transcriptions` handler parses multipart form fields but does not extract E2EE headers. Additionally, the inference-proxy's audio E2EE only encrypts/decrypts the `prompt` field, not the audio file bytes — true audio E2EE would require binary-level encryption of the multipart file content.

### Score
The gateway's `score` handler builds `ScoreParams { extra: HashMap::new() }`, discarding E2EE headers. The model TEE receives no encryption context and scores ciphertext as plaintext.

## Teep's Current Mitigation

Teep blocks E2EE for non-chat NearCloud endpoints where the gateway does not forward E2EE headers. The proxy handler includes an explicit gate:

```
nearcloud non-chat E2EE is NOT verified: EncryptChatMessagesNearCloud
only encrypts the messages array
```

Non-chat endpoints (`/v1/embeddings`, `/v1/audio/transcriptions`) are wired without `RequestEncryptor` for the `nearcloud` provider. This means teep does not falsely advertise E2EE coverage for these endpoints. However, the requests still transit through the NearCloud gateway in plaintext, which means the gateway can observe them.

**Teep should enable E2EE for `/v1/images/generations`**, which is verified to work end-to-end. Teep should also implement the serialize-and-encrypt protocol for VL content arrays to enable E2EE for vision-language chat requests.

### Chat Completions Field Coverage

For `/v1/chat/completions`, teep's `EncryptChatMessagesNearCloud` only encrypts `messages[].content` and only preserves the `role` and `content` fields. This has several consequences:

1. **Tool calling is broken under E2EE.** Multi-turn tool calling conversations fail because assistant messages have null content. Even single-turn tool use results in plaintext `tool_calls` in the response.
2. **Message fields are stripped.** `tool_calls`, `tool_call_id`, `name`, `reasoning_content`, `reasoning`, and `audio` are dropped from request messages passed through E2EE encryption.
3. **Response tool_calls leak data.** The inference-proxy does not encrypt `tool_calls[].function.arguments` or `tool_calls[].function.name`, so user-derived data in function arguments transits in plaintext.
4. **Logprobs bypass encryption.** If a client requests logprobs, the tokens in the response reveal the output text, negating content encryption.

Teep's relay layer (`relay.go`) correctly identifies these as `NonEncryptedFields` and passes them through without attempting decryption, but does not warn users that these fields are plaintext.

## Test Descriptions

All tests are in `internal/e2ee/nearcloud_e2ee_integration_test.go`. They are integration tests that make live API calls to `cloud-api.near.ai` and require a valid `NEARAI_API_KEY`.

### E2EE Header Tests (Plaintext Input)

These tests send normal plaintext requests with E2EE session headers attached. They verify whether the server encrypts the response when it sees E2EE headers on a non-chat endpoint.

- **`TestIntegration_NearCloud_Embeddings_E2EE`**: Sends a plaintext `input` field to `/v1/embeddings` with model `Qwen/Qwen3-Embedding-0.6B`. Establishes a baseline plaintext response, then sends the same request with E2EE headers. Server returns plaintext embeddings in both cases — gateway drops E2EE headers.

- **`TestIntegration_NearCloud_Audio_E2EE`**: Sends a minimal WAV file via multipart to `/v1/audio/transcriptions` with model `openai/whisper-large-v3`. Verifies plaintext baseline, then sends the same multipart body with E2EE headers. Server returns plaintext transcription in both cases — gateway drops E2EE headers.

- **`TestIntegration_NearCloud_Rerank_E2EE`**: Sends a plaintext query and documents to `/v1/rerank` with model `Qwen/Qwen3-Reranker-0.6B`. Verifies plaintext baseline, then sends with E2EE headers. Server returns plaintext ranked results in both cases — gateway drops E2EE headers.

### Encrypted Input Tests

These tests encrypt the actual request data using the NearCloud E2EE protocol (XChaCha20-Poly1305 with the model's X25519 public key derived from its Ed25519 signing key), verifying whether the server decrypts fields before processing.

- **`TestIntegration_NearCloud_Embeddings_EncryptedInput`**: Encrypts the `input` string with `EncryptXChaCha20()` and sends to `/v1/embeddings`. Server returns 200 with an embedding vector — it computed an embedding of the hex-encoded ciphertext, not the original text. Confirms the gateway dropped E2EE headers so the model TEE did not decrypt.

- **`TestIntegration_NearCloud_Rerank_EncryptedInput`**: Encrypts both the `query` and each `documents[]` string individually. Server returns 200 with relevance scores — it ranked the ciphertext strings against each other. All scores cluster near 0.64, consistent with the model scoring random-looking hex strings as equally (ir)relevant. Confirms the gateway dropped E2EE headers.

- **`TestIntegration_NearCloud_Audio_EncryptedInput`**: Encrypts the WAV file bytes and places the hex-encoded ciphertext as the multipart file content. Server returns 502 ("Audio transcription failed") because the ciphertext is not valid WAV data. Confirms no server-side decryption of file content.

- **`TestIntegration_NearCloud_Images_EncryptedInput`**: Encrypts the `prompt` string with `EncryptXChaCha20()` and sends to `/v1/images/generations` with model `black-forest-labs/FLUX.2-klein-4B`. **E2EE works**: the server returns encrypted `b64_json` (hex-encoded ciphertext) which decrypts to valid base64 image data. The `revised_prompt` field also decrypts to the original prompt text. Confirms the gateway forwards E2EE headers for images and the model TEE decrypts/encrypts correctly.

- **`TestIntegration_NearCloud_VL_EncryptedImage`** (negative test): Encrypts individual fields within a VL content array (separate ciphertexts for `text` and `image_url.url`), leaving the array structure visible. Server returns 400 ("The URL must be either a HTTP, data or file URL") because the encrypted image URL is not a valid URL. Demonstrates the **wrong** way to encrypt VL content.

- **`TestIntegration_NearCloud_VL_SerializedArray`**: Serializes the entire VL content array to a JSON string, encrypts that string, and sends it as a scalar `content` field. **E2EE works**: the server decrypts the string, detects a JSON array, restores the `[text, image_url]` structure, processes the image, and returns an encrypted SSE response that decrypts to "Red". Confirms the inference-proxy's serialize-and-encrypt VL protocol works end-to-end.

### Chat Completions Field Coverage Tests

These tests verify which response fields in `/v1/chat/completions` are encrypted when E2EE is active. They send encrypted requests with E2EE headers and examine specific response fields.

- **`TestIntegration_NearCloud_ToolCalls_E2EE`**: Sends a non-streaming chat request with `tools` defined and `tool_choice: "required"` to force tool call output. The encrypted message asks about weather in San Francisco. Verifies whether `tool_calls[].function.arguments` and `tool_calls[].function.name` are encrypted or plaintext in the response. **Expected**: arguments and name are plaintext, revealing the user's location data despite encrypted input.

- **`TestIntegration_NearCloud_ToolCalls_Streaming_E2EE`**: Same as above but with `stream: true`. Accumulates tool_call fragments from SSE delta chunks and checks whether the reassembled `function.name` and `function.arguments` are encrypted. **Expected**: plaintext — `encrypt_streaming_chunk` calls the same `encrypt_chat_response_choices` which skips tool_calls.

- **`TestIntegration_NearCloud_Reasoning_E2EE`**: Sends a math problem with `stream: true` to a model that produces reasoning tokens. Checks whether `reasoning_content` and `reasoning` fields are encrypted alongside `content`. **Expected**: all three fields are encrypted — the inference-proxy handles these correctly.

- **`TestIntegration_NearCloud_Logprobs_E2EE`**: Sends a non-streaming request with `logprobs: true` and `top_logprobs: 3`. Checks whether `choices[].logprobs.content[].token` values reveal the output text. **Expected**: logprobs is plaintext — the inference-proxy does not encrypt logprobs.

- **`TestIntegration_NearCloud_Refusal_E2EE`**: Sends an encrypted request designed to trigger a safety refusal. Checks whether the `refusal` field (if present) is encrypted or plaintext. **Expected**: refusal is plaintext if used, but many models refuse via the `content` field (which IS encrypted).

### Unit Tests

- **`TestEncryptChatMessagesNearCloud_StripsToolCalls`** (in `nearcloud_test.go`): Verifies that `EncryptChatMessagesNearCloud` fails on multi-turn tool calling conversations (assistant messages with null content) and strips all message fields except `role` and `content`.

## Running the Tests

### Prerequisites

- Go 1.24+
- A valid NearCloud API key exported as `NEARAI_API_KEY`

### Run all E2EE integration tests

```sh
source .env  # or export NEARAI_API_KEY=...
go test -v -run 'TestIntegration_NearCloud_' ./internal/e2ee/ -count=1 -timeout 300s
```

### Run only the direct inference-proxy tests

```sh
source .env
go test -v -run 'TestIntegration_NearCloud_Direct_' ./internal/e2ee/ -count=1 -timeout 120s
```

### Run only the chat completions field coverage tests

```sh
source .env
go test -v -run 'TestIntegration_NearCloud_(ToolCalls|Reasoning|Logprobs|Refusal)_E2EE' ./internal/e2ee/ -count=1 -timeout 300s
```

### Run only the encrypted input tests

```sh
source .env
go test -v -run 'TestIntegration_NearCloud_.*Encrypted|TestIntegration_NearCloud_VL_Serialized' ./internal/e2ee/ -count=1 -timeout 120s
```

### Run a specific test

```sh
source .env
go test -v -run 'TestIntegration_NearCloud_VL_SerializedArray' ./internal/e2ee/ -count=1 -timeout 120s
```

## Test Results (April 2026)

All tests pass. Results observed on `cloud-api.near.ai`:

| Test | Status | Key Observation |
|---|---|---|
| Embeddings E2EE | PASS | Plaintext response despite E2EE headers — gateway drops headers |
| Audio E2EE | PASS | Plaintext transcription despite E2EE headers — gateway drops headers |
| Rerank E2EE | PASS | Plaintext ranked results despite E2EE headers — gateway drops headers |
| Embeddings Encrypted | PASS | Server embedded the ciphertext as text — gateway drops headers |
| Rerank Encrypted | PASS | Server reranked ciphertext (scores ~0.64) — gateway drops headers |
| Audio Encrypted | PASS | Server rejected (502: invalid WAV) — gateway drops headers |
| VL EncryptedImage | PASS | Rejected (400: invalid URL) — wrong approach (per-field, not serialized) |
| **Images Encrypted** | **PASS** | **E2EE works** — decrypted b64_json is valid base64, revised_prompt matches |
| **VL SerializedArray** | **PASS** | **E2EE works** — decrypted response is "Red", matching plaintext baseline |

### Direct Inference-Proxy Tests (Bypassing Gateway)

To definitively prove the gateway is the sole point of failure, a second set of tests sends the **exact same E2EE protocol** directly to the model TEE inference-proxy, bypassing the gateway entirely. Direct endpoints are available via `https://completions.near.ai/endpoints`, each model having a dedicated subdomain (e.g., `qwen3-embedding.completions.near.ai`).

The tests share the same `createE2EESession` and `e2eeRequest` helper functions as the gateway tests — the only difference is the base URL. Attestation is fetched directly from the model TEE at `https://{domain}/v1/attestation/report?nonce={hex}&signing_algo=ed25519`.

| Test | Status | Key Observation |
|---|---|---|
| **Direct Embeddings E2EE** | **PASS** | **E2EE works** — embedding value is encrypted hex; decrypts to float array |
| **Direct Rerank E2EE** | **PASS** | **E2EE works** — document text fields encrypted; decrypts to original input. Relevance scores are plaintext (model-generated) |
| **Direct Audio E2EE** | **PASS** | **E2EE works** — transcript `text` field encrypted; decrypts to transcribed text |

**Side-by-side comparison:**

| Endpoint | Through Gateway | Direct to Model TEE | Same Code Path? |
|---|---|---|---|
| `/v1/embeddings` | Plaintext (headers dropped) | **Encrypted** (decryptable) | Yes — same `e2eeRequest` helper |
| `/v1/rerank` | Plaintext (headers dropped) | **Encrypted** (decryptable) | Yes — same `e2eeRequest` helper |
| `/v1/audio/transcriptions` | Plaintext (headers dropped) | **Encrypted** (decryptable) | Yes — same `e2eeRequest` helper |

This confirms the gateway is the only component that prevents E2EE from working for these endpoints. The model TEE correctly decrypts input fields, processes the request, and encrypts response fields — exactly as designed.

### Direct E2EE Test Descriptions

- **`TestIntegration_NearCloud_Direct_Embeddings_E2EE`**: Fetches Ed25519 signing key from `qwen3-embedding.completions.near.ai` attestation. Creates E2EE session and encrypts `"Hello World"` with `EncryptXChaCha20`. Sends to `/v1/embeddings` via `e2eeRequest` (same helper as gateway tests). Response embedding value is an encrypted hex string that decrypts to a JSON float array — the model decrypted the input, computed the embedding, and encrypted the result.

- **`TestIntegration_NearCloud_Direct_Rerank_E2EE`**: Fetches signing key from `qwen3-reranker.completions.near.ai`. Encrypts query and document strings. Sends to `/v1/rerank` via `e2eeRequest`. Response document `text` fields are encrypted: `"9d19c3c6650b..."` decrypts to `"Deep learning is a subset of machine learning"`. Relevance scores are plaintext floats (model output, not user data).

- **`TestIntegration_NearCloud_Direct_Audio_E2EE`**: Fetches signing key from `whisper-large-v3.completions.near.ai`. Sends a minimal WAV file via multipart to `/v1/audio/transcriptions` with E2EE headers. Response `text` field is encrypted: decrypts to the transcribed audio content. The model TEE honors E2EE headers for audio when they arrive — they just never arrive through the gateway.

## Remediation Path

### Gateway fix (NearCloud) — Header Forwarding

The model TEE (inference-proxy) already supports E2EE for all endpoints. The fix is in the gateway only:

1. **Forward E2EE headers for all endpoints.** The `embeddings`, `rerank`, `score`, and `audio_transcriptions` handlers in `completions.rs` need to call `validate_encryption_headers(&headers)` and insert the results into the provider params `extra` map, matching the pattern already used by `chat_completions` and `image_generations`.

2. **Provider methods must call `prepare_encryption_headers`.** The `embeddings_raw`, `rerank`, `score`, and `audio_transcription` methods in `vllm/mod.rs` must call `prepare_encryption_headers()` to set E2EE HTTP headers on the outgoing request to the model TEE.

3. **Audio multipart handling.** The inference-proxy currently only encrypts/decrypts the `prompt` field for audio transcriptions, not the audio file bytes. Full audio E2EE would additionally require binary-level encryption of the multipart file content, which is a fundamentally different wire format from JSON field encryption.

### Inference-proxy fix (NearCloud) — Chat Completions Field Coverage

The inference-proxy's `encrypt_chat_response_choices` must be extended to encrypt all sensitive fields:

1. **Encrypt `tool_calls[].function.arguments`.** This is the highest-priority fix — function arguments contain user-derived data and are the most likely to leak confidential information through E2EE.

2. **Encrypt `tool_calls[].function.name`.** Function names reveal query intent.

3. **Encrypt `refusal`.** Refusal text reveals what the user asked about.

4. **Encrypt or strip `logprobs`.** Token log probabilities reveal the output text character-by-character. Either encrypt the token strings and logprob values, or strip logprobs entirely when E2EE is active.

5. **Encrypt `function_call`** (deprecated). For backward compatibility with older clients.

6. **Decrypt `tool_calls[].function.arguments` in request messages.** For multi-turn tool calling, assistant messages include tool_calls that should be decryptable.

### Teep fixes — Client-Side Encryption

1. **Handle null content in `EncryptChatMessagesNearCloud`.** Assistant tool-call messages have null content. The function should pass null content through as-is (or as an empty encrypted string) rather than failing.

2. **Preserve all message fields.** `EncryptChatMessagesNearCloud` must not strip `tool_calls`, `tool_call_id`, `name`, `reasoning_content`, `reasoning`, or `audio`. These should be preserved in the output, with sensitive fields encrypted.

3. **Warn or block logprobs under E2EE.** If the client requests `logprobs: true` while E2EE is active, teep should either strip the parameter (preventing the leak) or warn that logprobs will be plaintext.

### Teep status

**Implemented:** Image generation E2EE (`/v1/images/generations`) and VL serialize-and-encrypt for vision-language chat are now wired in the nearcloud provider. Unsupported endpoints (embeddings, rerank, score, audio) fail closed — the nearcloud `EncryptRequest` dispatcher rejects them with an explicit error since the gateway does not forward E2EE headers for these endpoints.

**Not yet addressed:** Tool calls, refusal, logprobs, and function_call transit in plaintext through authenticated E2EE sessions. Multi-turn tool calling fails under E2EE due to null content handling and field stripping in `EncryptChatMessagesNearCloud`.
