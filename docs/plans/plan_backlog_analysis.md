# Plan Backlog: Ordering Analysis

This document analyzes implementation ordering for three planned changes:

1. **E2EE Enforcement Redesign** (`e2ee_usable_refactoring.md`) — Generalize
   the hard-coded `e2ee_usable` Skip→Fail promotion exemption into a `Deferred`
   factor property; add `MarkE2EEFailed` for report consistency.

2. **Multi-Endpoint Support** (`more_api_endpoints.md`) — Add embeddings,
   audio, and image generation proxy endpoints; refactor proxy handler into a
   generic factory; parameterize `PrepareRequest` interface with endpoint path.

3. **Attestation Cache** (`supply_chain_caching.md`) — New `teep cache` command
   and cache file; remove `--update-config`/`--config-out`/config policy fields;
   cache consultation in `teep serve` and `teep verify`.

---

## 1. Overlapping Code Areas

### 1a. `internal/proxy/proxy.go` — All Three Plans

This is the highest-contention file. Each plan modifies it differently:

| Plan | proxy.go Changes | Scope |
|------|-----------------|-------|
| **E2EE Redesign** | `handleE2EEDecryptionFailure` adds `MarkE2EEFailed` before cache deletion; minor touch to post-relay `MarkE2EEUsable` flow | ~20 lines changed |
| **Multi-Endpoint** | **Major refactor**: `handleChatCompletions` → `handleEndpoint` factory; `doUpstreamRoundtrip` takes `upstreamRequest` struct; `relayWithRetry` parameterized with `EndpointPath`; 3 new route registrations; `fromConfig` wires new path fields | ~300–500 lines restructured |
| **Caching** | `attestAndCache` consults cache for online factors; `Server` struct gets memory-only cache; cache write-back after successful authentication; `fromConfig` reads `--cache-file` | ~100–200 lines added |

**Conflict severity: HIGH.** Multi-Endpoint restructures the handler flow that
both E2EE and Caching modify. Whichever lands first defines the code shape the
others must integrate into.

### 1b. `internal/attestation/report.go` — E2EE Redesign + Caching

| Plan | report.go Changes |
|------|-------------------|
| **E2EE Redesign** | Adds `Deferred bool` to `FactorResult`; changes Skip→Fail promotion from name check to `!factors[i].Deferred`; adds `MarkE2EEFailed` method |
| **Caching** | Factor evaluation consults cached data (Intel PCS, NVIDIA NRAS, Sigstore, PoC); cached TDX measurements compared against live values |

**Conflict severity: LOW-MODERATE.** These touch different parts of
`report.go` — E2EE modifies factor lifecycle mechanics, Caching modifies factor
evaluation inputs. No direct code overlap, but both change how `BuildReport`
operates.

### 1c. `internal/provider/provider.go` — Multi-Endpoint Only

Multi-Endpoint adds `EmbeddingsPath`, `AudioPath`, `ImagesPath` fields and
changes the `PrepareRequest` interface signature (adds `path string`). Neither
E2EE Redesign nor Caching touches this file.

**Conflict severity: NONE** with other plans.

### 1d. `internal/config/` — Caching Only

Caching removes `Policy`/`MeasurementPolicy` fields from config, deletes
`update.go` entirely, and removes `MergedMeasurementPolicy()` /
`MergedGatewayMeasurementPolicy()`. Neither other plan touches config.

**Conflict severity: NONE** with other plans.

### 1e. `cmd/teep/main.go` — Caching Only

Caching removes `--update-config`/`--config-out` flags, `extractObserved()`,
and adds the `teep cache` subcommand and `--cache-file` flag. Neither other
plan modifies the CLI.

**Conflict severity: NONE** with other plans.

### 1f. `internal/provider/chutes/chutes.go` — Multi-Endpoint Only

Multi-Endpoint changes `PrepareRequest` to accept a dynamic `path` parameter
instead of using the stored `chatPath` field for `X-E2E-Path`. All provider
preparers must update their signatures.

**Conflict severity: NONE** with other plans.

---

## 2. Behavioral Interactions

### 2a. `e2ee_usable` × Caching

The caching plan explicitly declares `e2ee_usable` non-cacheable (Section 8a,
factor 5). The cache stores `e2ee_tested`/`e2ee_passed` as informational-only
fields. The E2EE Redesign's `Deferred` mechanism defines how this factor
behaves when no live test has occurred (deferred Skip, not promoted to Fail).

**Interaction**: The Deferred mechanism must be in place before Caching
implements its `e2ee_usable` handling. If Caching implements cache-based factor
evaluation without the Deferred concept, it must independently handle the
e2ee_usable special case — duplicating the problem the E2EE Redesign solves.

**Recommendation**: E2EE Redesign should land before Caching.

### 2b. Multi-Endpoint E2EE Enforcement × E2EE Redesign

Multi-Endpoint's new handlers (embeddings, audio, images) all follow the same
E2EE flow as chat: `attestAndCache` → `relayWithRetry` → `MarkE2EEUsable`
promotion. The `handleEndpoint` factory centralizes this.

If Multi-Endpoint lands before E2EE Redesign:
- The factory uses the existing hard-coded `e2ee_usable` name check.
- E2EE Redesign then replaces the name check with `Deferred` in the (already
  factored) code. One change point instead of four (the factory, not per-
  handler).

If E2EE Redesign lands before Multi-Endpoint:
- The `Deferred` mechanism is already in place.
- The factory inherits it naturally.

**Either order works.** The E2EE Redesign changes are in `report.go`
(BuildReport, FactorResult), not in the handler code itself. The proxy.go
changes (MarkE2EEFailed in `handleE2EEDecryptionFailure`) are small and
localized.

### 2c. Multi-Endpoint Cache Consultation × Caching

Multi-Endpoint's handler factory centralizes the attestation flow. Caching adds
cache consultation to this flow. If Multi-Endpoint lands first, Caching
integrates cache logic into the factory once. If Caching lands first, it adds
logic to `handleChatCompletions`, then Multi-Endpoint must extract that logic
into the factory.

**Recommendation**: Multi-Endpoint first produces a cleaner integration point
for Caching. But the reverse is also viable — the factory is designed to
generalize whatever `handleChatCompletions` already does.

### 2d. Caching TDX Measurements × Current Config Policy

Caching removes the config `Policy` fields (`mrtd_allow`, `mrseam_allow`,
etc.) and the `--update-config` flow. This is a breaking change — operators
must switch to `teep cache`. Neither E2EE Redesign nor Multi-Endpoint depends
on config policy fields, so this migration has no interaction with either plan.

---

## 3. Size and Risk Assessment

| Plan | Estimated Size | Files Modified | Risk Profile |
|------|---------------|----------------|-------------|
| **E2EE Redesign** | Small (~200 LOC) | 2 files (`report.go`, `proxy.go`) + tests | Low — additive change, no structural refactoring |
| **Multi-Endpoint** | Large (~800 LOC) | 5+ files (`proxy.go`, `provider.go`, `chutes.go`, all preparers) + new integration tests | High — interface change, major proxy refactor |
| **Caching** | Very Large (~1500+ LOC) | 8+ files (new cache package, `config.go`, `update.go` deleted, `main.go`, `proxy.go`, `report.go`) | High — new subsystem, breaking migration, CLI changes |

---

## 4. Ordering Alternatives

### Option A: E2EE → Multi-Endpoint → Caching

```
Phase 1: E2EE Enforcement Redesign
  ├─ Deferred field on FactorResult
  ├─ MarkE2EEFailed method
  └─ handleE2EEDecryptionFailure report consistency

Phase 2: Multi-Endpoint Support
  ├─ Handler factory (handleEndpoint) — inherits Deferred semantics
  ├─ upstreamRequest struct, parameterized doUpstreamRoundtrip
  ├─ PrepareRequest interface change (path parameter)
  └─ New endpoints: embeddings, audio, images

Phase 3: Attestation Cache
  ├─ Cache data structures (YAML, per-model, global images)
  ├─ teep cache command
  ├─ Cache consultation integrated into handler factory
  ├─ Remove --update-config, config policy fields
  └─ Memory-only cache in teep serve
```

**Pros**:
- Smallest change first — establishes correct factor semantics early.
- Multi-Endpoint factory is the final proxy.go shape before Caching integrates.
  Caching adds cache consultation to the factory's single code path rather than
  duplicating across multiple handlers.
- Each step is independently testable and shippable.
- E2EE test coverage (Deferred, MarkE2EEFailed) validates assumptions both
  other plans rely on.

**Cons**:
- Caching (the most complex change) goes last. If there's urgency for offline
  verification, this delays it.
- Multi-Endpoint's factory refactor is a large diff that restructures proxy.go
  before Caching adds its logic — Caching must understand the final factory
  shape rather than the simpler current code.

**Best when**: Feature delivery order is E2EE correctness → new API endpoints → 
offline/caching capability. Proxy refactoring stability is prioritized.

### Option B: E2EE → Caching → Multi-Endpoint

```
Phase 1: E2EE Enforcement Redesign (same as Option A)

Phase 2: Attestation Cache
  ├─ Cache consultation added to handleChatCompletions (pre-factory)
  ├─ teep cache command, cache data structures
  ├─ Remove --update-config, config policy fields
  └─ Memory-only cache in teep serve

Phase 3: Multi-Endpoint Support
  ├─ Handler factory extracts handleChatCompletions (now including cache logic)
  ├─ Factory inherits both Deferred semantics and cache consultation
  ├─ PrepareRequest interface change
  └─ New endpoints: embeddings, audio, images
```

**Pros**:
- E2EE first (same foundational benefit).
- Caching lands earlier — offline verification available before multi-endpoint.
- When Multi-Endpoint refactors proxy.go into a factory, the cache consultation
  code is already part of `handleChatCompletions` and gets extracted naturally
  into the factory. The factory becomes the canonical integration of
  attestation + caching + E2EE + relay — built once, used by all endpoints.
- Multi-Endpoint goes last, so the factory is written once against the final
  codebase state. The factory author has full knowledge of both E2EE and
  caching patterns to incorporate.

**Cons**:
- Caching adds logic to the pre-factory `handleChatCompletions`. If the
  Multi-Endpoint refactor into a factory changes the control flow significantly,
  the cache integration code may require non-trivial adaptation during
  extraction.
- Cache consultation in `teep serve` is initially chat-only. When Multi-
  Endpoint adds new endpoints, each endpoint needs cache consultation — but
  the factory handles this automatically.

**Best when**: Offline verification / caching is the highest priority feature.
Accepts that the factory refactor will be slightly more complex because it must
incorporate cache awareness.

### Option C: Multi-Endpoint → E2EE → Caching

```
Phase 1: Multi-Endpoint Support
  ├─ Handler factory (uses existing hard-coded e2ee_usable exemption)
  ├─ upstreamRequest struct, PrepareRequest interface change
  └─ New endpoints

Phase 2: E2EE Enforcement Redesign
  ├─ Deferred field, MarkE2EEFailed
  ├─ Applied once in report.go (same regardless of factory)
  └─ handleE2EEDecryptionFailure already in final proxy.go shape

Phase 3: Attestation Cache
  ├─ Cache consultation into handler factory
  └─ Everything else same as Option A Phase 3
```

**Pros**:
- The largest proxy.go refactor goes first, establishing the final code
  structure. All subsequent changes modify stable code.
- E2EE and Caching both modify proxy.go that's already in its final factored
  shape — no adapting to pre-factory or mid-factory states.
- New endpoints are available earliest.

**Cons**:
- The hard-coded `e2ee_usable` name check persists through the factory refactor.
  The factory initially includes a known architectural wart (the special-case
  exemption) that E2EE Redesign later cleans up. This is cosmetic — it doesn't
  affect correctness — but means the factory tests must be updated twice.
- Multi-Endpoint's integration tests for new endpoints initially test E2EE
  with the un-redesigned factor system. When E2EE Redesign lands, those tests
  should still pass (the behavior is identical), but the test assertions may
  reference the old exemption pattern if they check factor details.

**Best when**: New API endpoints are the highest priority. Accepts that the
factory is built with a known wart and cleaned up in the next phase.

---

## 5. Recommendation

**Option A (E2EE → Multi-Endpoint → Caching)** is the recommended default
ordering for these reasons:

1. **Foundation first**: The `Deferred` mechanism in E2EE Redesign is a
   semantic foundation that both other plans benefit from. Multi-Endpoint's
   factory inherits correct factor semantics. Caching's non-cacheable
   `e2ee_usable` handling aligns with the Deferred lifecycle.

2. **Structural stability**: Multi-Endpoint's factory establishes the final
   proxy.go shape. Caching integrates into a stable factory rather than into
   pre-factory code that will be refactored.

3. **Risk isolation**: E2EE Redesign is low-risk and independently verifiable.
   Multi-Endpoint is high-risk but confined to proxy/provider layers. Caching
   is the highest-risk (new subsystem + breaking migration) and benefits from
   going last when the rest of the codebase is stable.

4. **Test coverage builds progressively**: E2EE tests validate factor
   lifecycle. Multi-Endpoint tests validate the factory and new endpoint
   routing. Caching tests can rely on both being correct.

**Switch to Option B** if offline verification has higher priority than new
endpoints. The cost is that the Multi-Endpoint factory must incorporate cache
consultation during extraction, but this is manageable — the factory is
designed to generalize `handleChatCompletions`.

**Switch to Option C** if new endpoints are urgently needed and E2EE Redesign
can wait. The cost is carrying the hard-coded `e2ee_usable` exemption through
the factory refactor and touching the factory tests twice.

---

## 6. Cross-Plan Test Strategy

Regardless of ordering, each plan should follow this testing discipline:

| Phase | Required | Rationale |
|-------|----------|-----------|
| After E2EE Redesign | `make check` | Factor system changes affect all report generation |
| After Multi-Endpoint (each internal phase) | `make check` | Interface changes may break compilation across packages |
| After Multi-Endpoint (completion) | `make check` + `make integration` + `make reports` | Validate existing chat still works after proxy refactor |
| After Caching (migration) | `make check` | Config field removal may break compilation |
| After Caching (completion) | `make check` + `make integration` + `make reports` | Full validation of cache integration and migration |

Per AGENTS.md: one commit per phase, `make check` before each commit, stage
only specific modified files.

---

## 7. Shared Preconditions

All three plans assume the current codebase state (no partial implementations
detected):

- `FactorResult` has no `Deferred` field.
- `PrepareRequest` signature is `(req, headers, meta, stream) error` — no
  `path` parameter.
- `handleChatCompletions` is a single monolithic handler — no factory.
- `--update-config` and config `Policy` fields are present and functional.
- `e2ee_usable` uses a hard-coded name check in the Skip→Fail promotion loop.

If any other work modifies these assumptions before implementation begins,
revisit this analysis.
