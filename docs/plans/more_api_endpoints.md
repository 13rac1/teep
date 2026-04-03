# Plan: Multi-Endpoint Support (Embeddings, VL, Audio, Image Gen)

**TL;DR** — Add five new proxy endpoints (`/v1/embeddings`, `/v1/rerank`, `/v1/audio/transcriptions`, `/v1/images/generations`, and VL via existing `/v1/chat/completions`) across neardirect, nearcloud, chutes, and phalacloud. All endpoints require TEE attestation + body E2EE per policy; providers that can't meet this will fail-closed, which is intentional.

---

## Target Models

| Model | Provider | Endpoint |
|---|---|---|
| Qwen/Qwen3-Embedding-0.6B | near.ai (neardirect/nearcloud) | POST /v1/embeddings |
| Qwen/Qwen3-Reranker-0.6B | near.ai (neardirect/nearcloud) | POST /v1/rerank (TBD) |
| qwen/qwen3-embedding-8b | phalacloud | POST /embeddings |
| chutes fd636cb1 (Qwen3-Embedding-8B) | chutes | POST /v1/embeddings |
| openai/whisper-large-v3 | near.ai (neardirect/nearcloud) | POST /v1/audio/transcriptions |
| Qwen/Qwen3-VL-30B-A3B-Instruct | near.ai (neardirect/nearcloud) | POST /v1/chat/completions (existing) |
| chutes 51a4284a (Qwen3.5-397B-A17B-TEE) | chutes | POST /v1/chat/completions (existing) |
| black-forest-labs/FLUX.2-klein-4B | near.ai (neardirect/nearcloud) | POST /v1/images/generations |

---

## E2EE Status by Provider

All endpoints require TEE attestation + body E2EE per policy. Providers that cannot meet this requirement must fail-closed — this is correct behavior, not a bug.

| Provider | E2EE mechanism | New endpoint viability |
|---|---|---|
| **neardirect** | TLS-level (SPKI pinned to model TEE cert) | ✓ all types |
| **nearcloud** | XChaCha20-Poly1305 app-layer (chat only today) | ⚠️ investigate non-chat paths |
| **chutes** | ML-KEM-768 via `/e2e/invoke` + `X-E2E-Path` | ✓ all types |
| **phalacloud** | None | ✗ fail-closed per policy (expected) |

neardirect TLS E2EE: SPKI cert is generated inside the model TEE and verified by attestation; TLS terminates at the model TEE, so the TLS channel provides end-to-end encryption to the TEE directly. No additional application-layer E2EE is needed.

---

## Phase 1 — Provider & Proxy Infrastructure

No dependencies. All other phases depend on this.

1. Add `EmbeddingsPath`, `AudioPath`, `ImagesPath` string fields to `Provider` in `internal/provider/provider.go`. Follow the same pattern as `ChatPath`.

2. Register new routes in `fromConfig` / `NewServer` in `internal/proxy/proxy.go`:
   - `POST /v1/embeddings` → `handleEmbeddings`
   - `POST /v1/audio/transcriptions` → `handleAudioTranscriptions`
   - `POST /v1/images/generations` → `handleImagesGenerations`

3. In `fromConfig`, assign new paths per provider:
   - **neardirect** + **nearcloud**: `EmbeddingsPath = "/v1/embeddings"`, `AudioPath = "/v1/audio/transcriptions"`, `ImagesPath = "/v1/images/generations"`
   - **phalacloud**: `EmbeddingsPath = "/embeddings"` (no `/v1/` prefix, consistent with `ChatPath = "/chat/completions"`)
   - **chutes**: `EmbeddingsPath = "/v1/embeddings"` (for `X-E2E-Path` threading)

4. Raise the `handleChatCompletions` body limit from 10 MiB → **100 MiB** to accommodate base64-encoded VL images. Per-endpoint limits for new handlers:
   - Embeddings: 10 MiB
   - Audio: 25 MiB
   - Images: 10 MiB

5. Add unit tests for new route dispatch and 404 for unregistered paths.

---

## Phase 2 — Chutes E2EE Multi-Path Support

Depends on Phase 1.

The Chutes `/e2e/invoke` tunnel requires an `X-E2E-Path` header naming the TEE-internal endpoint. Today it is hardcoded to `/v1/chat/completions` in `chutesProvider.NewPreparer`.

6. Add `TargetPath string` to the `e2ee.ChutesE2EE` struct (in `internal/e2ee/chutes.go` or wherever `ChutesE2EE` is defined).

7. In every Chutes relay handler, set `meta.TargetPath` unconditionally before calling `prov.Preparer.PrepareRequest`:
   - chat completions: `meta.TargetPath = prov.ChatPath`
   - embeddings: `meta.TargetPath = prov.EmbeddingsPath`
   - audio transcriptions: `meta.TargetPath = prov.AudioPath`
   - image generations: `meta.TargetPath = prov.ImagesPath`

8. In `internal/provider/chutes/chutes.go` `PrepareRequest`: require `meta.TargetPath` to be non-empty, use it for `X-E2E-Path`, and return an error if it is missing. Do not fall back to configured `chatPath`; missing routing metadata must fail-closed.

9. Unit tests for the chutes preparer must cover both explicit `TargetPath` routing and rejection when `TargetPath` is empty, so non-chat requests cannot be silently misrouted to the chat endpoint.

---

## Phase 3 — Embeddings

Depends on Phases 1–2.

10. Implement `handleEmbeddings` in `internal/proxy/proxy.go`:
    - Parse JSON body; require `model` field (`{"model": "...", "input": ...}`).
    - `resolveModel` → check `prov.EmbeddingsPath != ""`, else 400.
    - Same attestation path as chat: `attestAndCache` for standard providers; `handlePinnedEmbeddings` (parallel to `handlePinnedChat`) for pinned providers — passes `Path: prov.EmbeddingsPath` to `PinnedHandler.HandlePinned`.
    - Non-streaming relay only (embeddings have no SSE stream).
    - E2EE required: for chutes, sets `meta.TargetPath = prov.EmbeddingsPath`; for neardirect, TLS-level; for nearcloud/phalacloud, the `e2ee_usable` factor gates the request.

11. Integration tests:
    - `internal/integration/embeddings_neardirect_test.go` — `Qwen/Qwen3-Embedding-0.6B`
    - `internal/integration/embeddings_chutes_test.go` — `Qwen/Qwen3-Embedding-8B` (chute `fd636cb1-ed88-5c76-b5af-8cc69be91bf3`)
    - `internal/integration/embeddings_phalacloud_test.go` — `qwen/qwen3-embedding-8b` (expected fail-closed; documents current state)

---

## Phase 4 — VL / Vision-Language

Depends on Phase 1 body limit only.

VL models use `/v1/chat/completions` verbatim — no new handler needed.

12. Both neardirect `Qwen/Qwen3-VL-30B-A3B-Instruct` and chutes `51a4284a-a5a0-5e44-a9cc-6af5a2abfbcf` route through the existing handler. The chutes UUID passes through `looksLikeUUID` in `internal/provider/chutes/resolve.go` unchanged. Verify the chutes Preparer does not mis-classify a VL (chat) request as requiring a non-chat path.

13. Integration tests:
    - `internal/integration/vl_neardirect_test.go` — `Qwen/Qwen3-VL-30B-A3B-Instruct`
    - `internal/integration/vl_chutes_test.go` — chute `51a4284a`
    - Use a small inline base64 PNG test image (< 1 MiB) in the test body.

---

## Phase 5 — Audio / ASR (Whisper)

Depends on Phase 1.

14. Implement `handleAudioTranscriptions` in `internal/proxy/proxy.go`:
    - Body is `multipart/form-data` (audio file + `model` field). Extract `model` from the form; do NOT parse as JSON.
    - 25 MiB body limit.
    - Pinned handler path for neardirect/nearcloud: `Path: prov.AudioPath`.
    - No chutes audio in scope (Whisper not listed on chutes).
    - E2EE: neardirect provides TLS-level. nearcloud E2EE over multipart requires investigation (flag as ⚠️ further research — encrypting raw multipart form data at app layer is non-trivial; may require a near.ai Audio-specific E2EE protocol or base64 JSON wrapping).

15. Integration test: `internal/integration/audio_neardirect_test.go` — `openai/whisper-large-v3`.

---

## Phase 6 — Image Generation (FLUX)

Depends on Phase 1.

16. Implement `handleImagesGenerations` in `internal/proxy/proxy.go`:
    - JSON body: `{"model": "...", "prompt": "...", "n": 1, ...}`.
    - Non-streaming JSON relay.
    - Pinned handler path: `Path: prov.ImagesPath`.

17. Integration test: `internal/integration/images_neardirect_test.go` — `black-forest-labs/FLUX.2-klein-4B`.

---

## Phase 7 — Reranking

Depends on Phase 1; research required first.

18. **Research step**: Determine what HTTP path near.ai uses for `Qwen/Qwen3-Reranker-0.6B` (likely `/v1/rerank` Cohere-style, or may route through `/v1/embeddings`). Check live API or near.ai docs.

19. If `/v1/rerank`: add `RerankPath` to Provider, register `POST /v1/rerank`, implement `handleRerank` following the same pattern as `handleEmbeddings`.

20. If near.ai routes reranking through `/v1/embeddings`: no new proxy endpoint; configure `EmbeddingsPath` and route through `handleEmbeddings`.

21. Integration test: neardirect `Qwen/Qwen3-Reranker-0.6B`.

---

## Relevant Files

- `internal/provider/provider.go` — add `EmbeddingsPath`, `AudioPath`, `ImagesPath` to `Provider`
- `internal/proxy/proxy.go` — new handlers, routes, `fromConfig` path wiring, body limit
- `internal/e2ee/chutes.go` — add `TargetPath` to `ChutesE2EE` struct
- `internal/provider/chutes/chutes.go` — Preparer uses `meta.TargetPath`
- `internal/provider/chutes/resolve.go` — verify UUID pass-through handles VL chute
- `internal/provider/neardirect/pinned.go` — verify `PinnedRequest.Path` is already forwarded unchanged (no change expected)
- `internal/provider/nearcloud/pinned.go` — same
- `internal/integration/*` — new integration test files per phase

---

## Verification

1. `make check` passes after each phase (fmt + vet + lint + unit tests).
2. `make integration` at plan completion.
3. `make reports` to verify attestation factors still pass for existing chat models after refactors.
4. Phalacloud embeddings test should produce a **blocked** result (fail-closed on `e2ee_usable`) — expected correct behavior.

---

## Open Questions

1. **nearcloud non-chat E2EE**: Does near.ai's `X-Client-Pub-Key` / `X-Encryption-Version` protocol extend to `/v1/embeddings`, `/v1/audio/transcriptions`, `/v1/images/generations`? If yes, nearcloud becomes viable for those endpoints and should be wired in Phases 3/5/6. If no, only neardirect is in scope for new endpoint types from near.ai.

2. **Audio over Chutes / NearCloud**: Encrypting `multipart/form-data` at app layer is non-trivial. Needs resolution once nearcloud non-chat E2EE status is known.

3. **Chutes embeddings base URL**: Chutes uses `llm.chutes.ai` for LLM models and `api.chutes.ai` for E2EE invoke. Verify whether the embeddings base URL differs (e.g. `embedding.chutes.ai`). Check the `/v1/models` response for embedding chute type metadata.
