# Plan: Multi-Provider Serve Mode

## 1. Goal

Update teep so that `teep serve` runs a single proxy instance that serves all providers whose API keys are currently configured via TOML or environment variables, without requiring a provider positional argument on the command line.

This new serve mode must:

1. Activate every provider whose resolved API key is non-empty.
2. Expose `/v1/models` as an aggregated catalog across all active providers.
3. Prefix every returned model ID with the provider name.
4. Route every supported inference request by parsing that provider prefix from the request `model` field, without requiring the client to query `/v1/models` first.
5. Support all current teep API endpoints:
   - `POST /v1/chat/completions`
   - `POST /v1/embeddings`
   - `POST /v1/audio/transcriptions`
   - `POST /v1/images/generations`
   - `POST /v1/rerank`
   - `GET /v1/models`
6. Preserve teep's fail-closed behavior and concurrency safety rules.

Backward compatibility is not required. Unprefixed model names may be rejected in serve mode.

---

## 2. Recommended External Contract

### 2.1 Serve command

Recommended new contract:

```text
teep serve [--offline] [--log-level LEVEL]
```

Debug builds also support `--force`, which bypasses enforced verification factors. Keep that flag out of the release-build/public contract, but note its existence explicitly so help text and README updates do not accidentally drop it.
No provider positional argument.

The proxy starts with every provider whose resolved API key is non-empty after config plus env processing.

### 2.2 Client model namespace

Recommended public model ID format:

```text
provider:model
```

Examples:

```text
venice:e2ee-qwen3-5-122b-a10b
neardirect:Qwen/Qwen3-VL-30B-A3B-Instruct
nearcloud:black-forest-labs/FLUX.2-klein-4B
chutes:deepseek-ai/DeepSeek-V3-0324-TEE
```

This is the preferred format because:

1. It is explicit and deterministic.
2. It avoids ambiguity across providers that may expose the same upstream model ID.
3. Many upstream model names already contain `/`, so prefixing with `provider:` is cleaner than trying to encode provider into a path or relying on implicit defaults.

### 2.3 Request routing rule

For all inference endpoints, the proxy must:

1. Parse the `model` field.
2. Split it into `provider` and `upstreamModel` using the first `:`.
3. Look up the provider by exact provider name.
4. Rewrite the request body so the upstream receives only `upstreamModel`.
5. Perform attestation, E2EE, and forwarding against that provider.

If the prefix is missing, malformed, or unknown, the proxy should fail closed with HTTP 400.

---

## 3. Current State of the Codebase

### 3.1 CLI and config

Current serve mode is single-provider by construction.

Relevant code paths:

- `cmd/teep/main.go`
- `cmd/teep/help.go`
- `cmd/teep/main_test.go`
- `internal/config/config.go`

Current behavior:

1. `teep serve PROVIDER [flags]` requires a positional provider argument.
2. `extractProvider()` removes the first non-flag arg before flag parsing.
3. `filterProviders(cfg, providerName)` narrows `cfg.Providers` to exactly one provider.
4. `config.Load()` already loads all configured providers from TOML and env vars.
5. `applyEnvOverrides()` already resolves or injects providers based on env vars such as:
   - `VENICE_API_KEY`
   - `NEARAI_API_KEY`
   - `NANOGPT_API_KEY`
   - `PHALA_API_KEY`
   - `CHUTES_API_KEY`

Important implication: the config layer already supports multiple providers simultaneously. The single-provider constraint is imposed by the CLI flow, not by the config loader.

### 3.2 Proxy server

Relevant code paths:

- `internal/proxy/proxy.go`
- `internal/proxy/proxy_test.go`
- `internal/proxy/integration_multiendpoint_test.go`
- `internal/proxy/relay_internal_test.go`

Current behavior:

1. `proxy.New(cfg)` already wires all providers from `cfg.Providers` into `Server.providers`.
2. `Server.providers` is a `map[string]*provider.Provider`.
3. The HTTP mux already exposes all OpenAI-compatible routes centrally in one server.
4. `handleModels()` already aggregates models from all configured providers.
5. `resolveModel(clientModel)` currently returns the first provider from the map and passes the model through unchanged.

That means the internal server structure already has multi-provider shape, but request routing is still effectively single-provider.

### 3.3 Provider-local model discovery and translation

Relevant code paths:

- `internal/provider/provider.go`
- `internal/provider/models.go`
- `internal/provider/chutes/resolve.go`
- `internal/provider/neardirect/endpoints.go`
- `internal/provider/neardirect/nearai.go`

Important provider-local behavior already exists:

1. Generic model listers fetch raw `/v1/models` catalogs.
2. Filtered model listers intersect upstream catalogs with provider-local discovery filters.
3. Chutes has a thread-safe model resolver that maps human-readable model IDs to chute UUIDs.
4. NearDirect has a thread-safe endpoint resolver that maps models to backend domains.

The multi-provider implementation must preserve these provider-local resolution steps after the global provider prefix has been stripped.

### 3.4 Concurrency synchronization state

The proxy server is already heavily protected by thread-safe synchronization:

1. **Immutable maps**: `Server.providers` is written once at init time (`proxy.New()`) and accessed lock-free thereafter.
2. **Keyed Locks**: Attestation, SPKI, validation caches (`Cache`, `NegativeCache`, `SigningKeyCache`), and stats use key combinations of `{provider, model}` protected by `sync.RWMutex` or `sync.Map`, preventing key collision.
3. **Double-Checked Locking**: Stats maps use standard double-checked locking for allocation safety.
4. **Atomics**: Base operational stats counters utilize `atomic.Int64`.
5. **Constant-time Compares**: Timing-safe checks (`subtle.ConstantTimeCompare`) are used where appropriate (e.g. `SPKICache`).

### 3.5 CLI help text vs actual implementation

`teep serve`'s help text currently claims: "Parses the model name to determine the upstream provider." In reality, `resolveModel()` simply picks the first map entry generated by random map iteration, heavily assuming `filterProviders()` has already trimmed `s.providers` to precisely 1.

---

## 4. Existing Multi-Provider Capability and Current Gaps

### 4.1 Already working

The following is already present:

1. Config can load multiple provider sections.
2. `proxy.New()` can initialize multiple providers.
3. `/v1/models` can already collect models from multiple providers.
4. Current caches are keyed by provider plus model, not just model.
5. The codebase is already designed to support concurrent provider access.
6. There is already a multi-provider unit test for `/v1/models` aggregation.

### 4.2 Currently broken or incomplete

The following must change:

1. Serve mode still requires a provider argument.
2. `filterProviders()` collapses the provider set to one entry.
3. `resolveModel()` is non-deterministic and does not inspect model names.
4. `/v1/models` does not prefix returned model IDs.
5. Inference request bodies are forwarded with the client model name unchanged.
6. Help text claims provider parsing by model name, but the implementation does not do that yet.
7. Map iteration in `handleModels()` produces a non-deterministic order of models per request.

### 4.3 Roadmap already documented in TODO

The intended direction is already reflected in `TODO`:

1. Remove the need to specify a provider on `teep serve`.
2. Aggregate `/v1/models` across providers with provider-prefixed model names.
3. Route requests using the model prefix.

This plan formalizes that work into a full implementation and test plan.

### 4.4 Concurrency Test Coverage Gaps

While the current tests leverage Go's `-race` detector, the existing tests verify multi-provider model compilation but do not explicitly assert correct resource mapping under parallel multi-provider loads.

Missing coverage:

1. Concurrent requests to completely different providers.
2. Concurrent attestation fetches targeting the same provider under varied model names.
3. E2EE decryption failure tracing explicitly segregated between providers concurrently.
4. Determinism checks on parallel model mapping with and without invalid structural prefixes.

---

## 5. Design Overview

### 5.1 High-level request flow in the new mode

For every inference request:

1. Read and size-bound the body.
2. Parse the request model.
3. Split `provider:model`.
4. Resolve the provider from `Server.providers`.
5. Rewrite the request body so the upstream sees only the provider-local model ID.
6. Run existing per-endpoint support checks.
7. Run existing attestation and E2EE logic.
8. Forward to the selected provider.
9. Keep all cache keys and stats keyed by the selected provider plus the stripped upstream model.

### 5.2 Why the prefix belongs in the proxy layer

The provider prefix should be handled in the proxy, not in provider packages, because:

1. It is a client-facing namespace concern.
2. Providers should continue operating on provider-local upstream model IDs.
3. Provider-local discovery, translation, and attestation logic should remain unchanged wherever possible.
4. This avoids forcing each provider package to understand global multi-provider semantics.

### 5.3 Behavior for unsupported endpoints

Existing endpoint support checks already use provider-specific path configuration.

The new flow should preserve that behavior exactly:

1. First resolve provider from the model prefix.
2. Then check whether that provider supports the requested endpoint.
3. If not, return the existing provider-specific 400 error.

Example:

- Request to `/v1/embeddings` with model `venice:some-model`
- Routing resolves to Venice
- Venice has no embeddings path
- Proxy returns the existing unsupported-provider-style error

### 5.4 Body rewriting requirement

The current proxy flow parses the model but largely forwards the original request body through attestation and relay paths.

That is not sufficient for multi-provider serve, because if the client sends `venice:foo`, the upstream provider must receive `foo`, not `venice:foo`.

This requires a request normalization layer that rewrites the request body before forwarding.

This must cover:

1. JSON bodies for chat, embeddings, images, rerank
2. Multipart bodies for audio transcription

---

## 6. Concurrency and Shared-State Analysis

### 6.1 Executive summary

Teep's architecture is already well-designed for concurrent multi-provider operation. After initialization, the proxy is effectively immutable for provider selection state. All mutable shared structures already use the correct synchronization primitives.

Moving from single-provider to multi-provider routing requires no new locking. The main correctness change is deterministic model parsing and provider lookup.

### 6.2 Shared state that is already safe

### Immutable-after-init state

`Server.providers` is written once during `proxy.New()` and then read-only during request handling.

Implications:

1. No locking is needed for request-time provider lookup.
2. Concurrent map reads are safe because the map is never mutated after initialization.
3. Multi-provider routing should use direct lookup by parsed provider name, not map iteration.

### Attestation and E2EE caches

The major shared caches are already protected and keyed correctly.

Relevant code:

- `internal/attestation/attestation.go`
- `internal/attestation/spki.go`

Current shared caches:

1. `Cache` for verification reports
   - Lock: `sync.RWMutex`
   - Key: `cacheKey{provider, model}`
2. `NegativeCache` for recent failures
   - Lock: `sync.RWMutex`
   - Key: `cacheKey{provider, model}`
3. `SigningKeyCache` for E2EE signing keys
   - Lock: `sync.RWMutex`
   - Key: `cacheKey{provider, model}`
4. `SPKICache` for TLS certificate SPKI pins
   - Lock: `sync.RWMutex`
   - Keyed per domain
   - Uses constant-time compare for SPKI membership checks

This means different providers can safely serve the same model name without cache collisions, because the provider name is already part of the cache key.

### Stats and E2EE failure tracking

Relevant code:

- `internal/proxy/proxy.go`

Current synchronization strategy:

1. Global stats counters use `atomic.Int64`
2. The per-model stats map uses `sync.RWMutex` with a double-check locking pattern in `getModelStats()`
3. E2EE failure tracking uses `sync.Map` keyed by `providerModelKey{provider, model}`

This is already the correct concurrency model for multi-provider traffic.

### Provider-local discovery caches

Relevant code:

- `internal/provider/chutes/resolve.go`
- `internal/provider/neardirect/endpoints.go`

These components are already thread-safe:

1. Chutes model resolver uses a mutex-protected cached mapping.
2. NEAR endpoint resolver uses `sync.RWMutex` plus `singleflight.Group`.

The global provider prefix must be removed before these resolvers are invoked. Once that happens, they continue to operate on provider-local model names exactly as they do today.

## 6.3 What is unsafe today

### `resolveModel()` is non-deterministic

The current implementation returns the first provider from a Go map.

Problems:

1. Go map iteration order is randomized.
2. With multiple providers enabled, request routing would be arbitrary.
3. This is not a data race, but it is a determinism and correctness defect.

Required fix:

1. Parse `provider:model`
2. Use exact provider-name lookup in `s.providers`
3. Fail closed on malformed or unknown prefixes

### `/v1/models` aggregation order is non-deterministic

`handleModels()` currently iterates `s.providers` directly.

Problems:

1. Response ordering can vary across runs.
2. This is not a race, but it makes behavior less reproducible.

Required fix:

1. Collect provider names
2. Sort them
3. Iterate in sorted order

## 6.4 Required concurrency stance for implementation

The implementation should explicitly preserve the existing concurrency model.

That means:

1. Do not add new mutexes for `Server.providers`.
2. Do not introduce mutable package-level state for routing.
3. Do not replace existing provider+model cache keys with model-only keys.
4. Do not add provider-global mutable state without synchronization.
5. Prefer immutable initialization plus existing request-time keyed caches.

## 6.5 Required concurrency tests

The repository rules require concurrent test coverage when manipulating shared state.

Add tests that use `sync.WaitGroup` and parallel goroutines for:

1. Concurrent requests to different providers
   - Verify correct provider routing
   - Verify no cache collisions
2. Concurrent requests to the same provider with different models
   - Verify keyed cache isolation
3. Concurrent model resolution with valid and invalid prefixes
   - Verify deterministic behavior under load
4. Concurrent E2EE failure tracking across providers
   - Verify failures on one provider do not contaminate another
5. Concurrent stats creation and updates
   - Verify `getModelStats()` remains race-free

All of these should run under the repository's race-enabled workflow.

---

## 7. Implementation Plan

### 7.1 Phase 1: Remove the single-provider serve contract

### Objective

Make `teep serve` start without a provider argument and activate all configured providers with resolved API keys. This directly resolves the issues that serve mode still requires an argument and `filterProviders()` collapses the set to a single entry.

### Files

- `cmd/teep/main.go`
- `cmd/teep/help.go`
- `cmd/teep/main_test.go`

### Changes

1. Remove the requirement that `runServe()` receive a positional provider argument.
2. Stop using `filterProviders()` in serve mode.
3. Add a serve-only pruning step after config load that keeps only providers whose resolved API key is non-empty.
4. Fail closed at startup if no providers remain after pruning.
5. Keep `teep verify` provider-scoped.

### Notes

The config loader already resolves keys from TOML and environment variables. The serve path should rely on that existing merged result.

### Recommended behavior

A provider is active in serve mode if and only if its resolved `APIKey` is non-empty after config plus env processing.

---

## Phase 2: Define deterministic aggregated `/v1/models`

### Objective

Return a single model catalog across all active providers, with provider-prefixed model IDs. This resolves the lack of prefixing on returned model IDs and enforces deterministic model aggregation ordering.

### Files

- `internal/proxy/proxy.go`
- `internal/proxy/proxy_test.go`
- possibly helper code near model aggregation

### Changes

1. Collect active provider names.
2. Sort them.
3. For each provider:
   - Call `ModelLister.ListModels(ctx)`
   - Preserve partial-success behavior if one provider fails
4. Rewrite each returned model object's `id` to `provider:upstreamID`
5. Preserve all other upstream model metadata fields unchanged

### Important constraint

Implement the ID rewrite in the proxy layer, not by mutating provider-specific listers.

Reason:

1. Provider listers should continue working with upstream IDs.
2. Filtered listers and provider-local discovery should remain unchanged.
3. The provider prefix is part of the proxy's external API contract, not the provider packages' internal contracts.

---

## Phase 3: Replace `resolveModel()` with strict prefix parsing

### Objective

Make routing deterministic and fail closed. This completely replaces the non-deterministic `resolveModel()` functionality that ignores `clientModel` namespaces.

### Files

- `internal/proxy/proxy.go`
- `internal/proxy/proxy_test.go`

### Changes

Replace current behavior with strict parsing of the form:

```text
provider:model
```

### Required validation

Reject all of the following with HTTP 400:

1. Missing `model`
2. No `:` separator
3. Empty provider segment
4. Empty model segment
5. Unknown provider name

### Output of resolver

The resolver should return:

1. `*provider.Provider`
2. `upstreamModel` without the prefix
3. success boolean or error path

### Important note

This is not a locking change. It is a deterministic lookup over immutable state.

---

## Phase 4: Add request normalization and body rewriting

### Objective

Ensure upstream providers receive provider-local model IDs, not client-facing prefixed IDs. This explicitly resolves the issue where inference request bodies were forwarded carrying the user's `provider:model` string unmodified instead of just the `model` portion.

### Files

- `internal/proxy/proxy.go`
- possibly a new helper file in `internal/proxy/`
- `internal/proxy/relay_internal_test.go`
- `internal/proxy/proxy_test.go`

### Changes

Refactor the endpoint handling contract so each endpoint can:

1. Extract the client model from the request body
2. Return or build a normalized upstream body with the stripped model

### JSON endpoints

Cover:

- chat completions
- embeddings
- images
- rerank

Strategy:

1. Parse just enough to find and replace the `model` field.
2. Preserve the rest of the body shape and semantics.
3. Avoid changing unrelated fields.

### Multipart audio endpoint

Cover:

- audio transcriptions

Strategy:

1. Rebuild multipart form data with the `model` field rewritten
2. Preserve other form parts and payload contents
3. Maintain existing body bounds and validation guarantees

### Important sequencing

Body normalization must happen before:

1. provider-specific attestation fetches that depend on upstream model
2. E2EE request encryption
3. upstream request construction

---

## Phase 5: Preserve endpoint-specific behavior

### Objective

Integrate multi-provider routing without weakening existing endpoint safety checks.

### Files

- `internal/proxy/proxy.go`

### Requirements

1. Run provider resolution first.
2. Then use the chosen provider's configured endpoint path.
3. Preserve current unsupported-endpoint errors.
4. Preserve the existing audio fail-closed E2EE guard for providers that cannot safely handle multipart encryption.
5. Preserve provider-specific downstream model translation after the global prefix is stripped.

Examples:

1. Chutes still maps names to chute UUIDs.
2. NearDirect still maps models to resolved backend domains.
3. Venice still receives its expected upstream model names unchanged except for prefix stripping.

---

## Phase 6: Concurrency and shared-state validation in implementation

### Objective

Ensure the implementation remains compliant with repository concurrency rules.

### Files

- `internal/proxy/proxy.go`
- `internal/attestation/attestation.go`
- `internal/attestation/spki.go`
- `internal/provider/chutes/resolve.go`
- `internal/provider/neardirect/endpoints.go`

### Requirements

1. Keep `Server.providers` immutable after startup.
2. Keep all report, failure, and signing-key caches keyed by provider plus upstream model.
3. Keep SPKI cache behavior unchanged unless there is a separate reason to modify it.
4. Do not add routing globals or mutable package-level variables.
5. If any new shared map or cache is introduced, it must be synchronized explicitly and tested under concurrency.

### Explicit conclusion

No new synchronization primitives are required for the currently scoped design.

That is an intentional design conclusion, not an omission.

---

## Phase 7: Unit test plan

### CLI tests

Files:

- `cmd/teep/main_test.go`
- `cmd/teep/help_test.go`

Add coverage for:

1. Serve mode with no provider argument
2. Provider activation by resolved API key
3. Failure when zero providers are active
4. Updated serve help text

### Model list tests

Files:

- `internal/proxy/proxy_test.go`

Add coverage for:

1. Prefixed model IDs in `/v1/models`
2. Deterministic provider ordering
3. Preservation of raw upstream metadata
4. Partial-success behavior when one provider fails listing

### Resolver tests

Files:

- `internal/proxy/proxy_test.go`

Add coverage for:

1. valid `provider:model`
2. unknown provider
3. missing separator
4. empty provider
5. empty model
6. unprefixed model rejection

### Endpoint body rewrite tests

Files:

- `internal/proxy/proxy_test.go`
- `internal/proxy/relay_internal_test.go`

Add coverage for:

1. JSON request normalization for each supported JSON endpoint
2. multipart model rewrite for audio transcription
3. stripped upstream model reaching the chosen provider
4. unchanged handling of unrelated request fields

### Provider support tests

Files:

- `internal/proxy/proxy_test.go`

Add coverage for:

1. correct provider routing before endpoint support evaluation
2. expected 400 responses when a routed provider does not support the endpoint

### Concurrency tests

Files:

- `internal/proxy/proxy_test.go`
- possibly dedicated new proxy concurrency test file

To directly address the test coverage gaps identified in Section 4.4, add tests using `sync.WaitGroup` and parallel goroutines specifically for:

1. Simultaneous requests to completely different providers (verifies safe parallel mapping and routing).
2. Simultaneous requests (including attestation fetches) targeting the same provider under varied model names (verifies cache isolation per provider+model).
3. Concurrent resolver usage under mixed valid and invalid input, asserting deterministic behavior on parallel model mapping with and without invalid structural prefixes.
4. Stats creation and update under load to assert double-checked locking mechanisms.
5. E2EE decryption failure tracing explicitly segregated between providers concurrently (ensures `sync.Map` failure isolation across providers).

These tests should verify:

1. no race detector warnings
2. no cross-provider cache contamination
3. no incorrect routing under contention
4. no shared-state corruption

---

## Phase 8: Live integration test plan

### Files

- `internal/proxy/integration_multiendpoint_test.go`
- possibly a new multi-provider integration test file

### Goals

Start one proxy with multiple real providers enabled and prove that it can serve them concurrently.

### Required live coverage

1. `/v1/models` returns aggregated prefixed IDs
2. chat works on at least two providers
3. embeddings works on a provider that supports it
4. images works on NearDirect or NearCloud
5. audio works on NearDirect
6. rerank works on NearDirect
7. concurrent requests across different providers succeed in one proxy instance
8. at least one cross-provider identical-model-name case is disambiguated correctly by prefix

### Test gating

Keep live tests behind the existing environment-based integration conventions so the normal offline suite remains safe.

---

## Phase 9: Documentation updates

### Files

- `cmd/teep/help.go`
- `README.md`
- `docs/api_support.md`
- `teep.toml.example`
- `docs/plans/multi_provider.md`

### Required updates

1. Change serve usage examples to one proxy process for all configured providers.
2. Document the `provider:model` requirement.
3. Update client examples to use prefixed models.
4. Document that `/v1/models` is an aggregated provider-prefixed catalog.
5. Document that routing is based solely on model prefix in serve mode.
6. Explain that active providers are selected automatically based on resolved API keys.

### Help text mismatch to fix

Current help text claims the proxy parses the model name to determine the upstream provider. This is only partially true today. After this change, it will become true and must be documented precisely, explicitly replacing the broken behavior with the promised deterministic parsing scheme.

---

## 8. Relevant Source Files and Why They Matter

### CLI and config

- `cmd/teep/main.go`
  - current serve flow
  - provider extraction
  - provider filtering
- `cmd/teep/help.go`
  - current serve usage text
- `cmd/teep/main_test.go`
  - single-provider assumptions in tests
- `internal/config/config.go`
  - multi-provider config loading
  - env-based API key injection

### Proxy routing and endpoint handling

- `internal/proxy/proxy.go`
  - route registration
  - current `resolveModel()`
  - endpoint parsing
  - request forwarding
  - `/v1/models` aggregation
  - stats and shared proxy state
- `internal/proxy/proxy_test.go`
  - unit tests for routing and model listing
- `internal/proxy/integration_multiendpoint_test.go`
  - current integration test patterns
- `internal/proxy/relay_internal_test.go`
  - multipart helpers and request-body utility tests

### Caches and concurrency-critical structures

- `internal/attestation/attestation.go`
  - verification report cache
  - negative cache
  - signing-key cache
- `internal/attestation/spki.go`
  - SPKI cache for pinned providers

### Provider-local model handling

- `internal/provider/provider.go`
  - provider interfaces and endpoint-path fields
- `internal/provider/models.go`
  - generic and filtered model listers
- `internal/provider/chutes/resolve.go`
  - Chutes model resolution cache
- `internal/provider/neardirect/endpoints.go`
  - NEAR endpoint discovery cache
- `internal/provider/neardirect/nearai.go`
  - NEAR attestation fetch path that uses the resolver

### Documentation and project context

- `README.md`
- `docs/api_support.md`
- `teep.toml.example`
- `TODO`
- `AGENTS.md`

---

## 9. Verification Checklist

1. `go test ./cmd/teep ./internal/proxy ./internal/provider/...`
2. `make check`
3. Unit tests proving body rewrite correctness for JSON and multipart endpoints
4. Race-focused tests proving there are no cross-provider cache collisions or stats races
5. Live integration tests proving one proxy instance can serve multiple providers concurrently
6. Manual local verification:
   - start `teep serve`
   - call `/v1/models`
   - verify prefixed IDs
   - send prefixed requests to each supported endpoint
   - confirm provider and stripped upstream model in logs

---

## 10. Final Decisions and Non-Goals

### Decisions

1. Public model namespace: `provider:model`
2. Active serve providers: all providers with non-empty resolved API keys
3. Unprefixed model IDs: rejected in serve mode
4. Prefix handling: implemented in proxy layer
5. Provider-local translation: preserved after prefix stripping
6. `/v1/models` ordering: deterministic by sorted provider name
7. No new synchronization primitives required for current scope

### Non-goals

1. Preserve old unprefixed serve behavior
2. Change `teep verify` into a multi-provider command
3. Redesign provider-local attestation or E2EE flows
4. Introduce mutable package-level routing state

---

## 11. Summary

This change is mostly an orchestration and request-normalization project, not a deep architectural rewrite.

The codebase already has the important foundation pieces:

1. multi-provider config loading
2. multi-provider server construction
3. provider-keyed caches
4. synchronized shared state
5. provider-local discovery and translation layers

The work is to complete the missing serve-mode contract:

1. activate all configured providers
2. define a client-facing provider-prefixed model namespace
3. make routing deterministic
4. rewrite request bodies before upstream forwarding
5. expand tests and docs to match the new behavior

If implemented this way, teep will support one serve process for all configured providers while remaining fail-closed, deterministic, and compliant with the repository's concurrency rules.
