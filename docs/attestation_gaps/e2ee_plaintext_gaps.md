# NearCloud E2EE: Gateway Header-Forwarding Gaps

This document describes verified gaps in NearCloud's end-to-end encryption (E2EE) coverage for non-chat API endpoints. NearCloud uses a two-layer TEE architecture: a **Gateway TEE** (`cloud-api.near.ai`) that routes requests, and **Model TEEs** (inference-proxy instances) that run alongside each model. Source code analysis of both layers reveals that the Model TEE has full E2EE support for all endpoints, but the Gateway TEE only forwards E2EE headers for `/v1/chat/completions` and `/v1/images/generations`. The remaining endpoints — embeddings, audio transcription, reranking, and scoring — transit in plaintext because the gateway silently drops E2EE headers.

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

## Server Source Code Analysis

### Model TEE: Full E2EE for All Endpoints

The inference-proxy's [`encryption.rs`](https://github.com/nearai/inference-proxy/blob/main/src/encryption.rs) implements per-endpoint field-level encryption and decryption. The `decrypt_request_fields` function (line ~436) dispatches by `Endpoint` enum:

| Endpoint | Request Fields Decrypted | Response Fields Encrypted |
|---|---|---|
| `ChatCompletions` | `messages[].content` (string or JSON-array-as-string) | `choices[].message.content`, `choices[].delta.content` |
| `Completions` | `prompt` (string or array) | `choices[].text` |
| `ImagesGenerations` | `prompt` | `data[].b64_json`, `data[].revised_prompt` |
| `Embeddings` | `input` (string or array of strings) | `data[].embedding` (serialized to JSON string) |
| `AudioTranscriptions` | `prompt` | `text` |
| `Rerank` | `query`, `documents[].text` | `results[].document.text` |
| `Score` | `text_1`, `text_2` | `score` (serialized to JSON string) |

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

## Security Implications

1. **False sense of confidentiality.** A proxy that wires E2EE headers on non-chat endpoints gives the user the impression their data is encrypted end-to-end. It is not — the gateway silently ignores the headers.

2. **Gateway can observe all non-chat traffic.** The NearCloud gateway (and any intermediaries between client and model TEE) can read embeddings inputs, audio recordings, rerank documents, and all corresponding responses.

3. **Embedding vectors leak semantic content.** Plaintext embedding vectors can be used to reconstruct approximate input text or match against known documents.

4. **Audio recordings are highly sensitive.** Voice data contains biometric identifiers and spoken content — plaintext transmission through a gateway is a significant privacy risk.

## What Works: Chat, Images, and VL (Serialized)

Three cases have verified end-to-end encryption:

### Chat completions (text)
Standard chat E2EE via `EncryptChatMessagesNearCloud`: encrypts `messages[].content` strings, server decrypts and encrypts SSE response chunks.

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

### Gateway fix (NearCloud)

The model TEE (inference-proxy) already supports E2EE for all endpoints. The fix is in the gateway only:

1. **Forward E2EE headers for all endpoints.** The `embeddings`, `rerank`, `score`, and `audio_transcriptions` handlers in `completions.rs` need to call `validate_encryption_headers(&headers)` and insert the results into the provider params `extra` map, matching the pattern already used by `chat_completions` and `image_generations`.

2. **Provider methods must call `prepare_encryption_headers`.** The `embeddings_raw`, `rerank`, `score`, and `audio_transcription` methods in `vllm/mod.rs` must call `prepare_encryption_headers()` to set E2EE HTTP headers on the outgoing request to the model TEE.

3. **Audio multipart handling.** The inference-proxy currently only encrypts/decrypts the `prompt` field for audio transcriptions, not the audio file bytes. Full audio E2EE would additionally require binary-level encryption of the multipart file content, which is a fundamentally different wire format from JSON field encryption.

### Teep status

**Implemented:** Image generation E2EE (`/v1/images/generations`) and VL serialize-and-encrypt for vision-language chat are now wired in the nearcloud provider. Unsupported endpoints (embeddings, rerank, score, audio) fail closed — the nearcloud `EncryptRequest` dispatcher rejects them with an explicit error since the gateway does not forward E2EE headers for these endpoints.
