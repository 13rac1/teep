# Plan: Multi-Endpoint Support (Embeddings, VL, Audio, Image Gen)

**TL;DR** — Phase 1 adds three new proxy endpoint families: embeddings (`POST /v1/embeddings`), audio transcriptions (`POST /v1/audio/transcriptions`), and image generations (`POST /v1/images/generations`). VL support continues via the existing `POST /v1/chat/completions` route. Rerank support is follow-on/conditional work rather than a guaranteed new endpoint. All endpoints require TEE attestation + body E2EE per policy; providers that can't meet this will fail-closed, which is intentional.

---

## Design Principle: Standard OpenAI Endpoints Only

The teep proxy exposes **only standard OpenAI-compatible endpoints** to clients. Provider-specific upstream path formats (e.g., phalacloud's `/embeddings` without `/v1/` prefix, or phalacloud's `/chat/completions`) are internal routing details — the proxy always accepts `/v1/embeddings`, `/v1/chat/completions`, etc. from the client.

The per-provider `EmbeddingsPath`, `AudioPath`, `ImagesPath` fields (like the existing `ChatPath`) specify the **upstream** path sent to the provider backend, not the client-facing route. For example, phalacloud's `ChatPath = "/chat/completions"` is already an upstream path; the proxy route is always `/v1/chat/completions`.

Each new endpoint's integration tests must verify that the upstream provider response schema matches the OpenAI spec (correct fields, types, status codes). If a provider returns a non-standard response, that is a provider compliance issue, not something the proxy should silently transform.

---

## Target Models

Integration tests and reports should always use **model names** (not chute UUIDs) to exercise the full model name → chute ID → instance ID resolution path via `llm.chutes.ai`. This resolution code is shared across all endpoint types (chat, embeddings, vision, images) and must be tested end-to-end.

| Model | Provider | Endpoint |
|---|---|---|
| Qwen/Qwen3-Embedding-0.6B | near.ai (neardirect/nearcloud) | POST /v1/embeddings |
| Qwen/Qwen3-Reranker-0.6B | near.ai (neardirect/nearcloud) | POST /v1/rerank (TBD) |
| qwen/qwen3-embedding-8b | phalacloud | POST /v1/embeddings (upstream: `/embeddings`) |
| Qwen/Qwen3-Embedding-8B | chutes (chute `fd636cb1`) | POST /v1/embeddings |
| openai/whisper-large-v3 | near.ai (neardirect/nearcloud) | POST /v1/audio/transcriptions |
| Qwen/Qwen3-VL-30B-A3B-Instruct | near.ai (neardirect/nearcloud) | POST /v1/chat/completions (existing) |
| Qwen/Qwen3.5-397B-A17B-TEE | chutes (chute `51a4284a`) | POST /v1/chat/completions (existing) |
| black-forest-labs/FLUX.2-klein-4B | near.ai (neardirect/nearcloud) | POST /v1/images/generations |

---

## E2EE Status by Provider

All endpoints require TEE attestation + body E2EE per policy. Providers that cannot meet this requirement must fail-closed — this is correct behavior, not a bug.

| Provider | E2EE mechanism | New endpoint viability |
|---|---|---|
| **neardirect** | TLS-level (SPKI pinned to model TEE cert) | ✓ all types |
| **nearcloud** | XChaCha20-Poly1305 app-layer (chat + images) | ⚠️ chat/images only; embeddings/audio/rerank blocked (gateway drops E2EE headers) |
| **chutes** | ML-KEM-768 via `/e2e/invoke` + `X-E2E-Path` | ✓ all types |
| **phalacloud** | None | ✗ fail-closed per policy (expected) |

neardirect TLS E2EE: SPKI cert is generated inside the model TEE and verified by attestation; TLS terminates at the model TEE, so the TLS channel provides end-to-end encryption to the TEE directly. No additional application-layer E2EE is needed.

**GATE: nearcloud non-chat E2EE** — nearcloud E2EE dispatch now covers chat (`messages[].content`, including VL serialize-and-encrypt) and image generation (`prompt`). The gateway forwards E2EE headers for these two endpoints only. **nearcloud MUST NOT be wired for embeddings, audio, rerank, or score endpoints** — the gateway silently drops E2EE headers for these, so encrypting fields would leave the model TEE unable to decrypt. See `docs/attestation_gaps/e2ee_plaintext_gaps.md` for the full analysis. Until the gateway fix lands, only neardirect handles non-chat/non-image endpoint types from near.ai.

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

4. Raise the default body limit from 10 MiB to **50 MiB** for all endpoints (chat/VL, embeddings, images, audio). The primary use case for teep is trusted local inference; if teep is exposed to untrusted input, operators can enforce their own limits on their use of the local API proxy. A future streaming refactor (neardirect `io.Copy` via pinned `tls.Conn`, and eventually chunked encryption for Chutes/nearcloud) can further reduce memory pressure, but should not block usability now.

5. Parameterize `doUpstreamRoundtrip` to accept the endpoint path via a struct instead of reading `prov.ChatPath`. Today `proxy.go:1468` hardcodes `prov.BaseURL + prov.ChatPath` as the upstream URL. Replace the loose parameters with an `upstreamRequest` struct:

   ```go
   type upstreamRequest struct {
       Body          []byte
       UpstreamModel string
       EndpointPath  string                       // e.g. "/v1/chat/completions", "/v1/embeddings"
       E2EEActive    bool
       Raw           *attestation.RawAttestation
       Stream        bool
   }
   ```

   URL construction becomes `prov.BaseURL + ureq.EndpointPath`. Named fields at the call site make adding `EndpointPath` self-documenting. `relayWithRetry` forwards `EndpointPath` down to `doUpstreamRoundtrip`. Same for `PinnedRequest` construction — all `handlePinned*` functions pass the correct path field rather than hardcoding `prov.ChatPath`.

6. **Handler factory.** The flow from `resolveModel` through `attestAndCache` and `relayWithRetry` is identical for all endpoint types (~130 lines). Rather than duplicating this core across separate `handleEmbeddings`, `handleAudioTranscriptions`, `handleImagesGenerations` handlers, extract a common `handleEndpoint` factory:

   ```go
   type endpointConfig struct {
       path       func(*provider.Provider) string // e.g. func(p) { return p.EmbeddingsPath }
       bodyLimit  int64
       parseModel func(*http.Request, []byte) (model string, stream bool, err error)
   }

   func (s *Server) handleEndpoint(ep endpointConfig) http.HandlerFunc { ... }
   ```

   Registration:
   ```go
   s.mux.HandleFunc("POST /v1/chat/completions", s.handleEndpoint(chatConfig))
   s.mux.HandleFunc("POST /v1/embeddings", s.handleEndpoint(embeddingsConfig))
   s.mux.HandleFunc("POST /v1/audio/transcriptions", s.handleEndpoint(audioConfig))
   s.mux.HandleFunc("POST /v1/images/generations", s.handleEndpoint(imagesConfig))
   ```

   The `parseModel` function varies per endpoint: JSON endpoints extract `model` from the body; audio extracts `model` from `r.FormValue`. Per-endpoint guards (e.g., multipart E2EE rejection for audio) go in `parseModel` or as a guard function on the config. The existing `handleChatCompletions` should be migrated to this factory to avoid drift.

7. Add unit tests for new route dispatch and 404 for unregistered paths.

---

## Phase 2 — Chutes E2EE Multi-Path Support

Depends on Phase 1.

The Chutes `/e2e/invoke` tunnel requires an `X-E2E-Path` header naming the TEE-internal endpoint. Today the Chutes Preparer at `chutes.go` uses `p.chatPath` (a struct field set once at construction time), which does not vary per-request. This must be made dynamic.

8. **Add `path string` to the `RequestPreparer.PrepareRequest` interface.** The endpoint path is a property of the request being made, not the provider configuration. Current interface:

   ```go
   PrepareRequest(req *http.Request, e2eeHeaders http.Header, meta *e2ee.ChutesE2EE, stream bool) error
   ```

   Proposed:
   ```go
   PrepareRequest(req *http.Request, e2eeHeaders http.Header, meta *e2ee.ChutesE2EE, stream bool, path string) error
   ```

   The handler factory (Phase 1 step 6) passes the resolved endpoint path to `PrepareRequest` on every call. The Chutes Preparer uses `path` for its `X-E2E-Path` header instead of the stored `chatPath` field — remove `chatPath` from Chutes Preparer construction entirely. Non-Chutes preparers (Venice, NearCloud, Phalacloud) ignore the parameter.

   This is cleaner than stuffing routing info into the `ChutesE2EE` metadata struct: the data flow is explicit (handler knows the path, passes it through to the preparer), and there is no `TargetPath` field to forget to set.

9. In `internal/provider/chutes/chutes.go` `PrepareRequest`: **require** `path` to be non-empty. Return an error if it is missing. Do **not** fall back to any default — missing routing metadata must fail-closed so non-chat requests cannot be silently misrouted to the chat endpoint.

10. Unit tests for the chutes preparer must cover both explicit path routing for each endpoint type AND rejection when path is empty.

---

## Phase 3 — Embeddings

Depends on Phases 1–2.

11. Implement `handleEmbeddings` in `internal/proxy/proxy.go`:
    - Parse JSON body; require `model` field (`{"model": "...", "input": ...}`).
    - `resolveModel` → check `prov.EmbeddingsPath != ""`, else 400.
    - Same attestation path as chat: `attestAndCache` for standard providers; `handlePinnedEmbeddings` (parallel to `handlePinnedChat`) for pinned providers — passes `Path: prov.EmbeddingsPath` to `PinnedHandler.HandlePinned`.
    - Non-streaming relay only (embeddings have no SSE stream).
    - Pass `prov.EmbeddingsPath` to `doUpstreamRoundtrip` (not `prov.ChatPath`).
    - E2EE required: for chutes, endpoint path is passed through `PrepareRequest` per Phase 2 step 8; for neardirect, TLS-level; nearcloud is gated per the nearcloud non-chat E2EE gate (not wired until verified).
    - Verify upstream response matches OpenAI embeddings spec: `{"object": "list", "data": [{"object": "embedding", "embedding": [...], "index": 0}], "model": "...", "usage": {...}}`.

12. Integration tests (use **model names**, not chute UUIDs, to exercise full resolution path):
    - `internal/integration/embeddings_neardirect_test.go` — `Qwen/Qwen3-Embedding-0.6B`
    - `internal/integration/embeddings_chutes_test.go` — `Qwen/Qwen3-Embedding-8B` (exercises model name → chute ID resolution via `llm.chutes.ai`)
    - `internal/integration/embeddings_phalacloud_test.go` — `qwen/qwen3-embedding-8b` (expected fail-closed; documents current state)
    - Each test validates response schema against OpenAI embeddings spec.

---

## Phase 4 — VL / Vision-Language

Depends on Phase 1 body limit only.

VL models use `/v1/chat/completions` verbatim — no new handler needed.

13. Both neardirect `Qwen/Qwen3-VL-30B-A3B-Instruct` and chutes `Qwen/Qwen3.5-397B-A17B-TEE` route through the existing handler. The chutes model name is resolved via `llm.chutes.ai` like any other model. Verify the chutes Preparer does not mis-classify a VL (chat) request as requiring a non-chat path.

14. Integration tests (use **model names** to exercise full resolution):
    - `internal/integration/vl_neardirect_test.go` — `Qwen/Qwen3-VL-30B-A3B-Instruct`
    - `internal/integration/vl_chutes_test.go` — `Qwen/Qwen3.5-397B-A17B-TEE` (exercises model name → chute ID resolution)
    - Use a small inline base64 PNG test image (< 1 MiB) in the test body.

---

## Phase 5 — Audio / ASR (Whisper)

Depends on Phase 1.

15. Implement `handleAudioTranscriptions` in `internal/proxy/proxy.go`:
    - Body is `multipart/form-data` (audio file + `model` field). Extract `model` from the form; do NOT parse as JSON.
    - 50 MiB body limit.
    - Pinned handler path for neardirect: `Path: prov.AudioPath`.
    - No chutes audio in scope (Whisper not listed on chutes).
    - **Multipart E2EE guard (fail-closed):** Non-pinned E2EE providers (Chutes, nearcloud) require body encryption, which does not support multipart. The handler must explicitly reject these with an error:
      ```go
      // Non-pinned E2EE providers (Chutes, nearcloud) require body encryption,
      // which doesn't support multipart. Fail closed.
      if prov.E2EE && prov.PinnedHandler == nil {
          http.Error(w, "audio transcription requires TLS-level E2EE (pinned provider)", 400)
          return
      }
      ```
      Without this, adding Chutes audio later would silently try to JSON-unmarshal multipart data.
    - E2EE: neardirect provides TLS-level. nearcloud E2EE over multipart requires investigation (flag as ⚠️ further research — encrypting raw multipart form data at app layer is non-trivial).

16. Integration test: `internal/integration/audio_neardirect_test.go` — `openai/whisper-large-v3`.

---

## Phase 6 — Image Generation (FLUX)

Depends on Phase 1.

17. Implement `handleImagesGenerations` in `internal/proxy/proxy.go`:
    - JSON body: `{"model": "...", "prompt": "...", "n": 1, ...}`.
    - Non-streaming JSON relay.
    - Pass `prov.ImagesPath` to `doUpstreamRoundtrip` and `PinnedRequest`.
    - Verify upstream response matches OpenAI images spec.

18. Integration test: `internal/integration/images_neardirect_test.go` — `black-forest-labs/FLUX.2-klein-4B`.

---

## Phase 7 — Reranking

Depends on Phase 1; research required first.

19. **Research step**: Determine what HTTP path near.ai uses for `Qwen/Qwen3-Reranker-0.6B` (likely `/v1/rerank` Cohere-style, or may route through `/v1/embeddings`). Check live API or near.ai docs.

20. If `/v1/rerank`: add `RerankPath` to Provider, register `POST /v1/rerank`, implement `handleRerank` following the same pattern as `handleEmbeddings`.

21. If near.ai routes reranking through `/v1/embeddings`: no new proxy endpoint; configure `EmbeddingsPath` and route through `handleEmbeddings`.

22. Integration test: neardirect `Qwen/Qwen3-Reranker-0.6B`.

---

## Relevant Files

- `internal/provider/provider.go` — add `EmbeddingsPath`, `AudioPath`, `ImagesPath` to `Provider`; add `path string` to `RequestPreparer.PrepareRequest` interface
- `internal/proxy/proxy.go` — handler factory, `upstreamRequest` struct, routes, `fromConfig` path wiring, body limit
- `internal/provider/chutes/chutes.go` — Preparer uses `path` parameter for `X-E2E-Path`; remove stored `chatPath` field
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

1. **nearcloud non-chat E2EE** *(partially resolved)*: The gateway forwards E2EE headers for `/v1/chat/completions` and `/v1/images/generations` only. Teep now wires `RequestEncryptor` for both. The gateway does **not** forward E2EE headers for `/v1/embeddings`, `/v1/audio/transcriptions`, `/v1/rerank`, or `/v1/score` — these endpoints remain blocked for nearcloud. If the gateway fix lands (see `e2ee_plaintext_gaps.md` remediation path), teep can wire nearcloud for these additional endpoints.

2. **Audio over Chutes / NearCloud**: Encrypting `multipart/form-data` at app layer is non-trivial. Needs resolution once nearcloud non-chat E2EE status is known. Phase 5 includes a fail-closed guard that blocks multipart requests for non-pinned E2EE providers.

3. **Chutes embeddings base URL**: Chutes uses `llm.chutes.ai` for LLM models and `api.chutes.ai` for E2EE invoke. Verify whether the embeddings base URL differs (e.g. `embedding.chutes.ai`). Check the `/v1/models` response for embedding chute type metadata.

4. **Streaming body relay (future)**: neardirect's pinned handler can `io.Copy` directly to the model TEE's `tls.Conn`, eliminating full-body buffering entirely. Chutes/nearcloud require protocol-level chunked encryption for the same benefit. Both are follow-on work, not blocking this plan.
