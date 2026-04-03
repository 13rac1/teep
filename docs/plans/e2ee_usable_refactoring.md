# Plan: E2EE Enforcement Redesign

## Goals

Redesign E2EE enforcement by cleanly separating two concerns the current
architecture conflates:

1. **Attestation Validation** — immutable cryptographic verification of the
   TEE environment (TDX quote, GPU attestation, container measurements,
   Sigstore/Rekor transparency, data binding). Evaluated once at attestation
   time. Gates request forwarding via `Blocked()`.

2. **Provider Functionality** — live verification that provider features
   work as expected (E2EE roundtrip, future tool call tests). Requires an
   actual inference roundtrip and cannot be evaluated at attestation time.
   In the proxy, enforced at the relay layer. In `teep verify`, evaluated
   via probe requests and displayed separately.

Remove `e2ee_usable` from the attestation factor system entirely. Replace
it with an E2EE state machine in the proxy and a separate "Provider
Functionality" tier in `teep verify`.

---

## Problems

### P1: Chicken-and-egg blocking (critical)

When `e2ee_usable` is enforced (not in a provider's `allow_fail` list),
`BuildReport` promotes the initial `Skip` → `Fail (enforced)`, which causes
`Blocked()` to return `true`. The proxy then refuses the request with HTTP
502. But `e2ee_usable` can only pass after a successful live E2EE
roundtrip — which requires a request to go through first.

**Code path** (proxy non-pinned):
1. `handleChatCompletions` calls `attestAndCache` on cache miss
2. `attestAndCache` → `fetchAndVerify` → `BuildReport` with
   `E2EEConfigured: prov.E2EE` and `E2EETest: nil`
3. `evalE2EEUsable` returns `Skip "E2EE configured; pending live test"`
4. `BuildReport` promotes enforced `Skip` → `Fail (enforced)`
5. `enforceReport` checks `report.Blocked()` → request rejected
6. `MarkE2EEUsable` is never reached

**Code path** (proxy pinned, NearCloud):
Same issue: the report is built with `E2EEConfigured=true` and
`E2EETest=nil` inside the pinned handler's attestation path.
`enforceReport` fires before the E2EE relay.

### P2: Cache mutation race

`MarkE2EEUsable()` mutates the `*VerificationReport` pointer stored in the
cache in-place. The cache's `Get()` returns the same pointer to all
concurrent callers. This means:

- Two concurrent requests for the same provider/model can race on
  `MarkE2EEUsable`, observing a half-mutated `Factors` slice.
- The `/v1/tee/report` endpoint can read the report mid-mutation.
- `report.Passed++` and `report.Skipped--` are non-atomic int mutations.

**Locations**: non-pinned and pinned paths in `internal/proxy/proxy.go`.

### P3: Counter desync risk

`MarkE2EEUsable()` manually adjusts `Passed` and `Skipped` counters. If the
factor was promoted from `Skip` to `Fail (enforced)` by `BuildReport` (as
happens when `e2ee_usable` is enforced per P1), the guard `Status == Skip`
prevents the transition — but the factor remains `Fail` and is never
corrected. If the guard were removed without also adjusting the `Failed`
counter, counters would desync.

### P4: Divergent verify vs proxy paths

`teep verify` and `teep serve` use fundamentally different lifecycles for
`e2ee_usable`:

| Aspect | `teep verify` | `teep serve` (proxy) |
|--------|--------------|---------------------|
| When E2EE is tested | During report-build via `testE2EE()` | After first successful relay |
| `E2EETest` | Populated in `ReportInput` | Always `nil` |
| `E2EEConfigured` | Not used (irrelevant) | Set from `prov.E2EE` |
| Factor result | Clean `Pass`/`Fail`/`Skip` from `evalE2EEUsable` | Initially `Skip`, retroactively patched via `MarkE2EEUsable` |
| Report mutation | None | Yes (cache in-place mutation) |

### P5: Inconsistent enforcement across providers

`e2ee_usable` enforcement varies across providers' default `allow_fail`
lists, with no clear rationale for the differences:

| Provider | `allow_fail` list | `e2ee_usable` in list? | Enforced? |
|----------|------------------|----------------------|-----------|
| Venice | `DefaultAllowFail` | Yes | No |
| NearDirect | `NeardirectDefaultAllowFail` | Yes | No |
| NearCloud | `NearcloudDefaultAllowFail` | **No** | **Yes** |
| Chutes | `ChutesDefaultAllowFail` | **No** | **Yes** |

NearCloud and Chutes both support E2EE and have it enabled by default.
Having `e2ee_usable` enforced for them triggers P1.

---

## Code Context

### E2EE Relay Error Handling

When E2EE is active and decryption fails in the relay functions, the
current behavior is:

- **Streaming** (`RelayStream`/`relaySSELine` in `internal/e2ee/relay.go`):
  Writes an SSE error event `{"error":{"message":"stream decryption failed",
  "type":"decryption_error"}}` and ends the stream. The HTTP 200 status has
  already been sent, so no status code change is possible. Returns
  `StreamStats`.

- **Non-streaming** (`RelayReassembledNonStream` in
  `internal/e2ee/relay.go`): Returns HTTP 502 "response decryption failed".
  Returns `StreamStats`. `ReassembleNonStream` returns
  `([]byte, StreamStats, error)`.

- **Chutes streaming** (`RelayStreamChutes` in
  `internal/e2ee/relay_chutes.go`): Uses `writeStreamError` helper: returns
  HTTP 502 if failure occurs before first chunk; writes SSE error event via
  `WriteSSEError` if after headers. Unparseable SSE events abort the stream.
  Logs `data_len` instead of raw event data. Init and chunk processing are
  in `handleChutesInit` and `handleChutesChunk` helpers. Returns
  `StreamStats`.

- **Chutes non-streaming** (`RelayNonStreamChutes`): Returns HTTP 502
  "response decryption failed".

**Key observation**: None of these paths currently invalidate the cached
report or prevent future requests. A decryption failure is treated as a
transient error for the current request only.

Relay functions currently return `StreamStats` but not `error`. `StreamStats`
has `Chunks`, `Tokens`, and `Duration` fields. Changing the return to
`(StreamStats, error)` is the structural change needed for post-relay
enforcement.

### Chutes Instance Retry Loop

Chutes runs a dynamic fleet of GPU instances behind a routing layer.
Individual instances are unreliable — they may fail E2EE handshakes, crash
mid-inference, or go offline without notice. This is an expected operational
characteristic, not a security failure. Retrying a request on a *different*
instance with a *fresh* E2EE handshake (new key encapsulation, new nonces)
is not a fallback or a weakening of E2EE — it is the normal path for
maintaining request reliability across an unreliable fleet.

The Chutes-specific retry loop (`chutesMaxAttempts = 3`) lives in
`doUpstreamRoundtrip`. It wraps the body-build → upstream-request cycle and
handles **transport-level** and **per-instance E2EE** failures (connection
errors, HTTP 429/500-504, handshake failures) by:

1. Marking the failed instance via `NoncePool.MarkFailed(chuteID,
   instanceID)` — fail-closed for that specific instance.
2. Zeroing crypto material from the failed attempt via `zeroE2EESessions`.
3. Selecting a different instance from the nonce pool and performing a
   complete fresh E2EE handshake (new key pair, new nonces).

Each retry attempt is a full cryptographic session from scratch, not a
resumption of the failed session.

`doUpstreamRoundtrip` returns `(*upstreamResult, error)`. The
`upstreamResult` struct carries `Resp`, `Session`, `Meta`, `Cancel`,
`E2EEDur`, and `UpstreamDur`. On error it returns an `httpError` with a
`status` field that distinguishes E2EE preparation errors (`"e2ee_failed"`,
HTTP 500) from transport errors (`"upstream_failed"`, HTTP 502). The caller
(`handleChatCompletions`) maps these to different client messages.

`buildUpstreamBody` returns an `upstreamBody` struct that carries `Body`,
`Session`, `Meta`, `ChuteID`, and `InstanceID`. The `ChuteID`/`InstanceID`
fields are populated from the raw attestation (or nonce pool) and are
independent of `meta.Session` being populated — this decoupling allows the
retry loop to track instances for `MarkFailed` even when the encryptor
returns `meta == nil`.

**Two failure tiers**:

| Failure scope | Trigger | Action | Retryable? |
|---------------|---------|--------|------------|
| Per-instance | Transport error, handshake failure, HTTP 429/5xx | `MarkFailed(instanceID)`, zero session, retry on fresh instance | Yes — fresh handshake on new instance |
| Provider+model | Post-relay decryption failure (response data cannot be decrypted) | `E2EETracker.MarkFailed`, invalidate all caches | No — fail-closed for all requests |

The retry loop handles the first tier (pre-relay, per-instance). Post-relay
enforcement handles the second tier (post-relay, provider-wide). A
post-relay decryption failure is qualitatively different from a
pre-relay transport error: it means a seemingly-healthy instance returned
data that could not be authenticated, indicating possible MITM or
server-side E2EE breakage.

**Hazard — retry + decryption failure interaction**: If the retry loop
succeeds on the last attempt (transport OK) but the relay then detects a
decryption failure, post-relay enforcement must fire using the *last
successful attempt's* instance info for both per-instance `MarkFailed` and
provider-level `MarkFailed`. Instance info is available via
`attemptChuteID` / `attemptInstanceID` (from `upstreamBody`), not from
`meta`.

### Existing Safeguards

**Pre-relay session guard**: A fail-closed check
(`meta != nil && meta.Session == nil`) runs in `handleChatCompletions`
*before* the relay dispatch. If Chutes E2EE metadata was populated but
key encapsulation failed to produce a session, the guard returns HTTP 500
instead of forwarding ciphertext as plaintext. Error counters and
`slog.ErrorContext` are incremented. This catches pre-relay invariant
violations; post-relay enforcement catches cryptographic failures.

**Pinned E2EE nil report block**: The pinned (NearCloud) path blocks when
`prov.E2EE && report == nil`. Without a report, the signing key cannot be
verified as bound to the TDX quote, so E2EE would degrade to plaintext.
Records a negative cache entry and returns HTTP 502.

---

## Design

### Architecture Overview

```
teep serve (proxy)                    teep verify (CLI)
──────────────────                    ─────────────────

Attestation factors                   Attestation factors
  → BuildReport()                       → BuildReport()
  → immutable VerificationReport        → immutable VerificationReport
  → Blocked() gates requests            → displayed in Attestation Tier

E2EE state machine                    E2EE probe
  → per-provider/model tracker          → testE2EE() probe request
  → Pending → Active → Failed          → result displayed in Functionality Tier
  → enforced at relay layer             → NOT passed to BuildReport
  → exposed in report metadata          → separate section in formatReport()
```

The proxy never runs an E2EE probe. It tracks E2EE state via the actual
relay lifecycle. `teep verify` runs an explicit probe and displays the
result. In both cases, `e2ee_usable` is **not** an attestation factor —
it does not participate in `BuildReport`, `Blocked()`, or the `allow_fail`
system.

### E2EE State Machine (proxy only)

The state machine operates at the **provider+model** level, not the
instance level. Individual instance failures (common in Chutes fleet
dynamics) are handled by the retry loop's per-instance `MarkFailed` and do
not affect the provider+model E2EE state. Only a post-relay cryptographic
failure — where a response from a seemingly-healthy instance cannot be
decrypted — escalates to provider+model failure.

Per provider+model pair:

```
                     ┌─────────┐
                     │ Pending │  (E2EE configured, not yet tested)
                     └────┬────┘
                          │ first successful encrypted roundtrip
                          ▼
                     ┌─────────┐
                     │ Active  │  (E2EE verified working)
                     └────┬────┘
                          │ post-relay decryption failure
                          ▼
                     ┌─────────┐
                     │ Failed  │  (block all subsequent requests)
                     └─────────┘
```

- **Pending**: Provider has `E2EE=true` in config. The proxy encrypts
  outgoing requests when `ReportDataBindingPassed()`. If the roundtrip
  succeeds, transition to `Active`. Per-instance failures during the retry
  loop do not prevent the transition — only the final attempt's outcome
  matters.
- **Active**: E2EE has been verified working. Continue encrypting.
  Per-instance transport failures and handshake failures are retried
  transparently via the retry loop without affecting this state.
- **Failed**: A relay received data it could not decrypt. This indicates
  a key mismatch (possible MITM) or server-side E2EE breakage — not a
  transient instance failure. **Block all subsequent requests** for this
  provider+model (fail-closed). Invalidate report cache, signing key cache,
  and nonce pool. Require full re-attestation to recover.

**What does NOT trigger provider+model `Failed`**:
- Instance going offline mid-request (transport error → retry)
- E2EE handshake failure on a specific instance (prep error → retry)
- HTTP 429/500-504 from a specific instance (transport error → retry)
- All retry attempts exhausted for a single request (returns error to
  client, but next request may succeed on newly-available instances)

### `teep verify` E2EE Probe

`teep verify` continues to run provider-specific E2EE test functions
(`testE2EEVenice`, `testE2EENearCloud`, `testE2EEChutes`) as it does today.
The difference is that the result is no longer fed into `BuildReport` as
`E2EETest`. Instead, it is displayed in a separate "Provider Functionality"
section of the report output, visually distinct from the attestation factor
table.

Example `teep verify` output:

```
Attestation Validation
──────────────────────
  ✓ tdx_quote          TDX quote signature valid
  ✓ gpu_attestation    NVIDIA EAT token verified
  ✓ container_hash     Matches allowed measurement
  ✓ data_binding       Signing key bound to TDX report
  ✓ sigstore           Rekor log entry verified
  ...

  12 passed, 0 failed, 0 skipped

Provider Functionality
──────────────────────
  ✓ e2ee_usable        E2EE roundtrip succeeded (streaming + non-streaming)
```

Attestation factors determine whether the provider's TEE environment is
trustworthy. Provider functionality tests verify that features work correctly
through the attested environment.

### Key Design Decisions

- **`e2ee_usable` is NOT an attestation factor.** It does not participate in
  `BuildReport`, `Blocked()`, or `allow_fail`. This permanently eliminates
  P1 (chicken-and-egg), P2 (cache mutation race), P3 (counter desync), and
  P5 (inconsistent enforcement). P4 (divergent paths) is resolved by giving
  each path its own appropriate mechanism.

- **Enforcement moves to the relay layer.** The proxy always encrypts when
  `prov.E2EE && ReportDataBindingPassed()`. If decryption fails on the
  response, the E2EE state machine blocks future requests (fail-closed).

- **Forward-looking enforcement.** For streaming responses, the HTTP 200
  status has already been sent with the first chunk. The first decryption
  failure is relayed to the client as an SSE error event. Enforcement is
  forward-looking: the *next* request is blocked. This is unavoidable without
  buffering the entire response.

- **Three caches must be invalidated together.** On E2EE failure: the
  report cache, signing key cache, and nonce pool
  (`E2EEMaterialFetcher`) must all be invalidated to prevent serving cached
  material from a compromised or broken instance.

- **Crypto material must be zeroed on failure.** Use `zeroE2EESessions` to
  zero ephemeral key material from the current session after any E2EE
  failure, per cryptographic safety requirements.

- **Instance failover is not a fallback.** For fleet-based providers like
  Chutes, retrying a request on a different instance with a fresh E2EE
  handshake (new key encapsulation, new nonces) is the normal reliability
  mechanism, not a security degradation. Each retry performs a complete
  cryptographic session from scratch. Per-instance failures are fail-closed
  at the instance level (the failed instance is marked unusable) while
  allowing the request to succeed on a healthy instance. Only post-relay
  decryption failures — where a seemingly-healthy instance returns data
  that cannot be authenticated — escalate to provider+model fail-closed.

---

## Implementation

### Phase 1: Foundation

**Goal**: Build the E2EE state machine and cache deletion infrastructure.

1. **`internal/proxy/e2ee_state.go`** (new file)
   - Define `E2EEState` type with `Pending`/`Active`/`Failed` constants.
   - Define `E2EETracker` struct: concurrent-safe map of
     `cacheKey{provider, model}` → `E2EEState`.
   - Methods: `Get`, `MarkActive`, `MarkFailed`, `Delete`.
   - `MarkFailed` must be idempotent (multiple concurrent relay failures
     should not panic or desync).

2. **`internal/proxy/e2ee_state_test.go`** (new file)
   - Test state transitions: Pending → Active, Active → Failed.
   - Test concurrent access safety.
   - Test fail-closed: once `Failed`, `Get` always returns `Failed` even
     after `Delete` is called (until re-added as `Pending`).

3. **Cache `Delete` methods**: `internal/attestation/attestation.go`
   - Add `Delete(provider, model)` to the report cache and signing key
     cache if they don't already exist.

### Phase 2: Relay Error Propagation

**Goal**: Relay functions signal decryption failures to callers.

1. **`internal/e2ee/relay.go`**
   - Change `RelayStream` return from `StreamStats` to `(StreamStats, error)`.
   - Change `RelayReassembledNonStream` return from `StreamStats` to
     `(StreamStats, error)`.
   - Return a sentinel or typed error on decryption failure (e.g.
     `ErrDecryptionFailed`). Return `nil` on success.

2. **`internal/e2ee/relay_chutes.go`**
   - Change `RelayStreamChutes` return from `StreamStats` to
     `(StreamStats, error)`.
   - `RelayNonStreamChutes` already returns `error` — ensure decryption
     failures use the same sentinel/typed error.

3. **`internal/proxy/proxy.go`** `relayResponse` helper
   - Update `relayResponse` to propagate the new `error` return from all
     relay dispatch paths back to `handleChatCompletions`.

4. **Update relay tests** to check the new error return.

### Phase 3: Factor System Cleanup & Proxy Integration

**Goal**: Remove `e2ee_usable` from the factor system. Integrate the E2EE
state machine into the proxy. Wire up post-relay enforcement.

#### Factor system removal (`internal/attestation/report.go`)

1. Remove `evalE2EEUsable` from the evaluator list in `buildEvaluators()`.
2. Remove `"e2ee_usable"` from `KnownFactors`, `DefaultAllowFail`,
   `NearcloudDefaultAllowFail`, `NeardirectDefaultAllowFail`,
   `ChutesDefaultAllowFail`, and `OnlineFactors`.
3. Delete the `MarkE2EEUsable` method.
4. Delete the `E2EEConfigured` field from `ReportInput`.
5. Delete the `E2EETest` field from `ReportInput`. Keep `E2EETestResult` as
   a standalone type (used by the verify path).
6. Update `internal/attestation/report_test.go`: remove
   `TestMarkE2EEUsable` tests and `e2ee_usable` references from factor
   evaluation tests.

#### Proxy integration (`internal/proxy/proxy.go`)

7. Add `E2EETracker` field to the `Server` struct. Initialize in
   `NewServer` or equivalent.

8. **E2EE state gate** — In `handleChatCompletions`, after `enforceReport`:
   if `prov.E2EE && e2eeTracker.Get(prov.Name, model) == Failed`, return
   HTTP 502 "E2EE previously failed; re-attestation required".

9. **Post-relay enforcement** — In `handleChatCompletions`, after the
   `relayResponse` call, if the relay returned a decryption error AND
   `e2eeActive` was true:
   ```go
   // Mark the specific instance as failed (Chutes fleet dynamics).
   // attemptChuteID/attemptInstanceID come from upstreamBody struct.
   if prov.E2EEMaterialFetcher != nil {
       prov.E2EEMaterialFetcher.MarkFailed(attemptChuteID, attemptInstanceID)
   }
   // Post-relay decryption failure is provider+model level: fail-closed.
   // Unlike pre-relay transport errors (handled by retry loop), this
   // means a seemingly-healthy instance returned unauthenticated data.
   s.e2eeTracker.MarkFailed(prov.Name, upstreamModel)
   s.cache.Delete(prov.Name, upstreamModel)
   s.signingKeyCache.Delete(prov.Name, upstreamModel)
   // Nonce pool: discard ALL cached instances/nonces (not just the
   // failed instance) — the trust model for this provider is broken.
   if prov.E2EEMaterialFetcher != nil {
       prov.E2EEMaterialFetcher.Invalidate(attemptChuteID)
   }
   // Zero crypto material from current session.
   zeroE2EESessions(session, meta)
   // Increment error counters for monitoring.
   s.stats.errors.Add(1)
   if ms != nil {
       ms.errors.Add(1)
   }
   ```
   Note: post-relay decryption failure is categorically different from
   pre-relay instance failures. The retry loop handles instance-level
   unreliability (transport errors, handshake failures) by failing over
   to fresh instances. Post-relay enforcement fires when a
   seemingly-successful HTTP response cannot be decrypted, which
   indicates a systemic problem (MITM, server-side E2EE breakage) that
   instance failover cannot recover from.

10. **Post-relay success** — After successful relay, if `e2eeActive`:
    call `e2eeTracker.MarkActive(prov.Name, model)`.

11. Remove all `MarkE2EEUsable` calls (non-pinned and pinned paths).

12. Remove `E2EEConfigured` and `E2EETest` from `ReportInput` construction
    in `fetchAndVerify`.

#### Report endpoint (`internal/proxy/proxy.go`)

13. Include E2EE state in the JSON report as metadata, e.g.
    `"e2ee_status": "active"`. Clone the report before adding metadata
    (do not mutate the cached report).

#### Config validation (`internal/config/config.go`)

14. Remove `"e2ee_usable"` from valid `allow_fail` entries. Unknown factor
    names must be rejected at config load time (no backwards-compatible
    no-ops).

### Phase 4: Verify Path & Two-Tier Report

**Goal**: Update `teep verify` to display E2EE results in a separate
"Provider Functionality" tier.

1. **`cmd/teep/main.go`**
   - Keep `testE2EE()` and all provider-specific E2EE test functions.
   - Remove `E2EETest` from the `ReportInput` passed to `BuildReport`.
   - Display the E2EE test result in a separate "Provider Functionality"
     section of `formatReport()`, after the attestation factor table.
   - Use the same pass/fail/skip iconography as the factor table but
     clearly label as a distinct tier.

2. **(Optional) Shared E2EE probe functions**: `internal/e2ee/probe.go`
   - Factor out core E2EE test logic from `cmd/teep/main.go` into a
     shared package. Not strictly required since only `teep verify` runs
     probes:
     - `ProbeVenice(ctx, signingKey, apiKey, baseURL, model) error`
     - `ProbeNearCloud(ctx, signingKey, apiKey, baseURL, model) error`
     - `ProbeChutes(ctx, raw, apiKey, baseURL, model) error`
   - The stream validation logic (`doE2EEStreamTest`,
     `doE2EEChutesStreamTest`) tests both streaming and non-streaming
     paths. This thoroughness is appropriate for `teep verify` (runs once
     per invocation).

3. **Update integration tests**: `internal/proxy/integration_*_test.go`
   - Remove assertions that `e2ee_usable` factor is `Pass`.
   - Check `Metadata["e2ee_status"]` is `"active"` after a successful
     E2EE roundtrip.

4. **Update verify output tests**: `cmd/teep/`
   - Expect the two-tier report format (attestation tier + functionality
     tier).

---

## Tradeoffs

- **Pro**: Cleanest separation of concerns. Attestation factors are
  immutable after `BuildReport` — no report mutation, no counter desync,
  no cache race. Eliminates P1, P2, P3, P5 by design.
- **Pro**: E2EE failure triggers fail-closed at the right layer — after
  observing actual decryption failure, not at report-build time.
- **Pro**: Unified behavior across all providers. No per-provider
  `allow_fail` exceptions for `e2ee_usable`.
- **Pro**: `teep verify` retains full E2EE visibility via probes,
  displayed in a dedicated tier.
- **Pro**: Two-tier format scales to future live-test checks (e.g. tool
  call tests) that face the same chicken-and-egg problem.
- **Con**: Touches relay function signatures, report format, config
  validation, and `teep verify` output formatting.
- **Con**: External tools parsing `e2ee_usable` from the report's
  `Factors` JSON array will need to look in `Metadata["e2ee_status"]`
  (proxy) or the functionality tier (verify).
- **Con**: E2EE state machine is another concurrent data structure
  alongside the report cache and signing key cache.

---

## Success Criteria

1. **P1 eliminated**: No request is ever blocked due to `e2ee_usable` being
   evaluated at report-build time. `BuildReport` does not include
   `e2ee_usable` as a factor.

2. **P2, P3 eliminated**: `MarkE2EEUsable` is deleted. No report mutation
   after `BuildReport`.

3. **Fail-closed on decryption failure**: After a post-relay decryption
   failure with `e2eeActive`, the E2EE state machine transitions to
   `Failed` and all subsequent requests for that provider+model are
   blocked with HTTP 502.

4. **Cache invalidation complete**: Post-relay decryption failure
   invalidates all three caches (report, signing key, nonce pool) and
   zeroes crypto material.

5. **Instance failover preserves reliability**: For Chutes, per-instance
   failures (transport errors, handshake failures, instance going offline)
   are retried on fresh instances with new E2EE handshakes without
   affecting the provider+model E2EE state. Only post-relay decryption
   failures escalate to provider+model fail-closed.

6. **`teep verify` shows E2EE status**: The verify output displays a
   separate "Provider Functionality" section with E2EE probe results.

7. **Config rejects `e2ee_usable` in `allow_fail`**: Unknown factor names
   are rejected at startup.

8. **All existing tests pass**: `make check` and `make integration` pass.
   Integration tests assert `Metadata["e2ee_status"]` instead of factor
   status.

9. **Report endpoint includes E2EE status**: The `/v1/tee/report` JSON
   includes `"e2ee_status"` in the metadata map.

---

## Future Considerations

- **Tool call test factor**: A forthcoming check that tests whether tool
  calls work through the E2EE path. It will face the same chicken-and-egg
  problem as `e2ee_usable`. It belongs in the Provider Functionality tier,
  not the attestation factor system.
- **E2EE key rotation**: When a signing key rotates (VM restart), the E2EE
  state machine should reset to `Pending`, requiring re-verification of the
  E2EE path with the new key.
- **Report cache TTL vs E2EE state**: The report cache has a 5-minute TTL.
  E2EE state is tracked independently and persists across report cache
  misses. A cache miss triggers re-attestation but does not reset E2EE
  state.
- **Client-facing E2EE status**: Consider adding an `X-Teep-E2EE` response
  header so clients can verify E2EE was used for each request without
  fetching the full report.
- **Nonce pool exhaustion**: When all instances in the nonce pool are
  marked failed (across multiple requests), `Take` currently returns an
  error only when no nonces remain, not when all instances are unhealthy.
  Consider whether the pool should signal "no healthy instances" as a
  distinct condition. This is an operational exhaustion (all instances
  individually failed), not a cryptographic failure, so it should NOT
  escalate to `E2EETracker.MarkFailed`. The correct recovery is
  re-attestation to refresh the instance pool.
- **Crypto material lifecycle in retry**: `zeroE2EESessions` is the
  canonical helper for zeroing E2EE crypto material. Post-relay enforcement
  should use the same pattern when invalidating material after decryption
  failure.
