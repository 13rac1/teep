# NearCloud E2EE: Non-Chat Endpoints Return Plaintext

This document describes verified gaps in NearCloud's end-to-end encryption (E2EE) coverage for non-chat API endpoints. The NearCloud gateway advertises E2EE via Ed25519/X25519 key exchange with XChaCha20-Poly1305 authenticated encryption, but this encryption only applies to `/v1/chat/completions` message content. All other endpoints — embeddings, audio transcription, reranking, image generation, and vision-language (VL) — transmit and receive data in plaintext, even when E2EE headers are present.

## Summary of Findings

| Endpoint | E2EE Headers | Encrypted Input | Server Behavior | Response |
|---|---|---|---|---|
| `/v1/chat/completions` | Yes | Yes (messages) | Decrypts messages, encrypts SSE chunks | **Encrypted** |
| `/v1/embeddings` | Yes | Plaintext | Computes embedding normally | **Plaintext** |
| `/v1/embeddings` | Yes | Encrypted | Embeds the ciphertext as text | **Plaintext** |
| `/v1/audio/transcriptions` | Yes | Plaintext | Transcribes audio normally | **Plaintext** |
| `/v1/audio/transcriptions` | Yes | Encrypted WAV | Rejects (502: invalid audio) | **Error** |
| `/v1/rerank` | Yes | Plaintext | Reranks normally | **Plaintext** |
| `/v1/rerank` | Yes | Encrypted | Reranks ciphertext as text | **Plaintext** |
| `/v1/images/generations` | Yes | Plaintext | Generates image normally | **Plaintext** |
| `/v1/images/generations` | Yes | Encrypted | Generates image from ciphertext prompt | **Plaintext** |
| `/v1/chat/completions` (VL) | Yes | Encrypted content array | Rejects (400: invalid image URL) | **Error** |

Every non-chat endpoint either processes ciphertext as if it were plaintext or rejects the malformed input entirely. None decrypt request fields server-side.

## The Problem

NearCloud's `EncryptChatMessagesNearCloud` function encrypts only the `messages[].content` string fields in chat completion requests. It does not handle:

- **Embeddings**: The `input` field (string or array of strings)
- **Audio**: Multipart `file` field (binary data in `multipart/form-data`)
- **Rerank**: The `query` and `documents` fields
- **Images**: The `prompt` field
- **VL chat**: Structured `content` arrays containing `image_url` objects (the function only encrypts flat string content, not structured content arrays)

When the proxy sends E2EE headers (`X-Client-Pub-Key`, `X-Signing-Algo`, `X-Encryption-Version`) with a non-chat request, the NearCloud gateway accepts the request but does not encrypt the response. Both the request payload and the response travel as plaintext through the gateway, despite the client's E2EE session being active.

This means a client that believes E2EE is active — because it negotiated keys and sent E2EE headers — will transmit sensitive embeddings, audio recordings, documents, image prompts, and generated images in plaintext.

## Security Implications

1. **False sense of confidentiality.** A proxy that wires E2EE headers on non-chat endpoints gives the user the impression their data is encrypted end-to-end. It is not.

2. **Gateway can observe all non-chat traffic.** The NearCloud gateway (and any intermediaries between client and TEE) can read embeddings inputs, audio recordings, rerank documents, image prompts, and all corresponding responses.

3. **Embedding vectors leak semantic content.** Plaintext embedding vectors can be used to reconstruct approximate input text or match against known documents.

4. **Audio recordings are highly sensitive.** Voice data contains biometric identifiers and spoken content — plaintext transmission through a gateway is a significant privacy risk.

5. **VL content arrays are structurally incompatible.** Even if a client encrypts the text and image URL fields individually, the server rejects the request because the encrypted image URL is not a valid `data:`, `http:`, or `file:` URL. True E2EE for VL would require the server to decrypt structured content arrays before dispatching to the model.

## Teep's Current Mitigation

Teep blocks E2EE for non-chat NearCloud endpoints. The proxy handler includes an explicit gate:

```
nearcloud non-chat E2EE is NOT verified: EncryptChatMessagesNearCloud
only encrypts the messages array
```

Non-chat endpoints (`/v1/embeddings`, `/v1/audio/transcriptions`, `/v1/images/generations`) are wired without `RequestEncryptor` for the `nearcloud` provider. This means teep does not falsely advertise E2EE coverage for these endpoints. However, the requests still transit through the NearCloud gateway in plaintext, which means the gateway can observe them.

## Test Descriptions

All tests are in `internal/e2ee/nearcloud_e2ee_integration_test.go`. They are integration tests that make live API calls to `cloud-api.near.ai` and require a valid `NEARAI_API_KEY`.

### E2EE Header Tests (Plaintext Input)

These tests send normal plaintext requests with E2EE session headers attached. They verify whether the server encrypts the response when it sees E2EE headers on a non-chat endpoint.

- **`TestIntegration_NearCloud_Embeddings_E2EE`**: Sends a plaintext `input` field to `/v1/embeddings` with model `Qwen/Qwen3-Embedding-0.6B`. Establishes a baseline plaintext response, then sends the same request with E2EE headers. Server returns plaintext embeddings in both cases.

- **`TestIntegration_NearCloud_Audio_E2EE`**: Sends a minimal WAV file via multipart to `/v1/audio/transcriptions` with model `openai/whisper-large-v3`. Verifies plaintext baseline, then sends the same multipart body with E2EE headers. Server returns plaintext transcription in both cases.

- **`TestIntegration_NearCloud_Rerank_E2EE`**: Sends a plaintext query and documents to `/v1/rerank` with model `Qwen/Qwen3-Reranker-0.6B`. Verifies plaintext baseline, then sends with E2EE headers. Server returns plaintext ranked results in both cases.

### Encrypted Input Tests

These tests encrypt the actual request data using the NearCloud E2EE protocol (XChaCha20-Poly1305 with the model's X25519 public key derived from its Ed25519 signing key), verifying whether the server decrypts fields before processing.

- **`TestIntegration_NearCloud_Embeddings_EncryptedInput`**: Encrypts the `input` string with `EncryptXChaCha20()` and sends to `/v1/embeddings`. Server returns 200 with an embedding vector — it computed an embedding of the hex-encoded ciphertext, not the original text. Confirms no server-side decryption.

- **`TestIntegration_NearCloud_Rerank_EncryptedInput`**: Encrypts both the `query` and each `documents[]` string individually. Server returns 200 with relevance scores — it ranked the ciphertext strings against each other. All scores cluster near 0.76, consistent with the model scoring random-looking hex strings as equally (ir)relevant. Confirms no server-side decryption.

- **`TestIntegration_NearCloud_Audio_EncryptedInput`**: Encrypts the WAV file bytes and places the hex-encoded ciphertext as the multipart file content. Server returns 502 ("Audio transcription failed") because the ciphertext is not valid WAV data. Confirms no server-side decryption of file content.

- **`TestIntegration_NearCloud_Images_EncryptedInput`**: Encrypts the `prompt` string with `EncryptXChaCha20()` and sends to `/v1/images/generations` with model `black-forest-labs/FLUX.2-klein-4B`. Server returns 200 with a generated image — it used the hex-encoded ciphertext as the image generation prompt. Confirms no server-side decryption.

- **`TestIntegration_NearCloud_VL_EncryptedImage`**: Encrypts both the text prompt and the `data:image/png;base64,...` URL in a VL chat message content array. Sends to `/v1/chat/completions` with model `Qwen/Qwen3-VL-30B-A3B-Instruct`. Includes a plaintext baseline that confirms the model correctly identifies a solid red 8x8 PNG as "Red". With encrypted content, the server returns 400 ("The URL must be either a HTTP, data or file URL") because the encrypted image URL is not a recognizable URL format. Confirms the E2EE protocol cannot handle structured VL content arrays.

## Running the Tests

### Prerequisites

- Go 1.24+
- A valid NearCloud API key exported as `NEARAI_API_KEY`

### Run all E2EE integration tests

```sh
source .env  # or export NEARAI_API_KEY=...
go test -v -run 'TestIntegration_NearCloud_.*E2EE' ./internal/e2ee/ -count=1 -timeout 120s
```

### Run only the encrypted input tests

```sh
source .env
go test -v -run 'TestIntegration_NearCloud_.*Encrypted' ./internal/e2ee/ -count=1 -timeout 120s
```

### Run a specific test

```sh
source .env
go test -v -run 'TestIntegration_NearCloud_Images_EncryptedInput' ./internal/e2ee/ -count=1 -timeout 120s
```

### Run all tests (header + encrypted input)

```sh
source .env
go test -v -run 'TestIntegration_NearCloud_' ./internal/e2ee/ -count=1 -timeout 120s
```

## Test Results (April 2026)

All tests pass. Results observed on `cloud-api.near.ai`:

| Test | Status | Key Observation |
|---|---|---|
| Embeddings E2EE | PASS | Plaintext response despite E2EE headers (dimensions=1024) |
| Audio E2EE | PASS | Plaintext transcription despite E2EE headers |
| Rerank E2EE | PASS | Plaintext ranked results despite E2EE headers |
| Embeddings Encrypted | PASS | Server embedded the ciphertext as text |
| Rerank Encrypted | PASS | Server reranked ciphertext (scores ~0.76 for all docs) |
| Audio Encrypted | PASS | Server rejected (502: invalid WAV) |
| Images Encrypted | PASS | Server generated image from ciphertext prompt |
| VL Encrypted | PASS | Server rejected (400: invalid image URL); plaintext baseline returned "Red" |

## Remediation Path

For NearCloud to support true E2EE on non-chat endpoints, the gateway TEE would need to:

1. **Decrypt request fields by endpoint type.** The TEE must recognize which JSON fields contain user data for each endpoint (`input` for embeddings, `prompt` for images, `query`/`documents` for rerank) and decrypt them before forwarding to the model.

2. **Encrypt response fields by endpoint type.** The TEE must encrypt the relevant response fields (`data[].embedding` for embeddings, `data[].b64_json` or `data[].url` for images, `results[].document.text` for rerank, `text` for audio).

3. **Handle multipart for audio.** Audio transcription uses `multipart/form-data`, which requires decrypting the file part within the multipart body — a fundamentally different wire format from JSON.

4. **Handle structured VL content arrays.** Vision-language messages use structured `content` arrays with mixed `text` and `image_url` objects. The encryption layer must traverse these arrays, encrypting/decrypting each part individually while preserving the array structure.

Until these capabilities exist, teep correctly blocks E2EE for non-chat NearCloud endpoints and documents the gap.
