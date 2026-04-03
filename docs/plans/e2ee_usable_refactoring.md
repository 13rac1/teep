# Plan: E2EE Enforcement Redesign

## Goals

1. Keep `e2ee_usable` as a standard attestation factor that can be
   enforced or listed in `allow_fail`, configurable per-provider via config
   — consistent behavior across `teep verify`, `teep serve`, and
   integration tests.

2. No chicken-and-egg blocking: the proxy must be able to forward a
   first request through E2EE *before* the factor transitions to Pass, even
   when the factor is enforced.

3. Post-relay fail-closed enforcement: decryption failures block future
   requests and invalidate caches. This is the primary E2EE safety
   mechanism.

4. Instance-level failover for fleet-based providers (Chutes) must not
   impact overall request reliability. Per-instance failures are fail-closed
   at the instance level; the request retries on a fresh instance with a
   new E2EE handshake.

---

## Current State

The short-term plan has been fully implemented. The following mechanisms
are now in place:

### Factor System

- `e2ee_usable` remains in `KnownFactors`, `OnlineFactors`, and is
  evaluated by `evalE2EEUsable` in `BuildReport`.
- `e2ee_usable` is **exempt from Skip→Fail promotion** in `BuildReport`:
  even when enforced (not in `allow_fail`), a `Skip` status stays `Skip`
  rather than being promoted to `Fail`. This solves the chicken-and-egg
  problem — the initial `Skip "E2EE configured; pending live test"` does
  not cause `Blocked()` to return `true`.
- `e2ee_usable` is enforced by default for NearCloud and Chutes (absent
  from `NearcloudDefaultAllowFail` and `ChutesDefaultAllowFail`), and
  allowed-to-fail for Venice/NearDirect (present in `DefaultAllowFail`
  and `NeardirectDefaultAllowFail`).
- Users can add or remove `e2ee_usable` from their `allow_fail` config.
  Config validation accepts it as a valid factor name.

### Proxy Post-Relay Enforcement

- `VerificationReport.Clone()` deep-copies Factors and Metadata before
  mutation. `MarkE2EEUsable` uses `recomputeCounters()` instead of manual
  counter adjustment. Both non-pinned and pinned paths clone before
  calling `MarkE2EEUsable`.
- Relay functions (`RelayStream`, `RelayNonStream`,
  `RelayReassembledNonStream`, `RelayStreamChutes`,
  `RelayNonStreamChutes`) return `(StreamStats, error)` with
  `ErrDecryptionFailed` and `ErrRelayFailed` sentinel errors.
- `relayWithRetry` performs the upstream roundtrip and E2EE relay. For
  Chutes, it retries on `ErrDecryptionFailed` before response headers are
  sent — marking the specific instance failed and selecting a fresh
  instance with a new E2EE handshake. Non-Chutes providers execute exactly
  once.
- `classifyRelayOutcome` dispatches post-loop relay errors.
  `handleE2EEDecryptionFailure` handles unretriable decryption failures:
  for Chutes it invalidates the nonce pool; for non-Chutes it stores to
  `e2eeFailed`. Both paths delete from report cache and signing key cache.
- `e2eeFailed sync.Map` (keyed by `providerModelKey{provider, model}`)
  tracks provider+model pairs with prior E2EE decryption failures.
  Checked after `attestAndCache` — recovery requires a confirmed fresh
  attestation (`ar.Raw != nil` for non-pinned, `pinnedResp.Report != nil`
  for pinned). Cached attestation with a stale marker fails closed and
  invalidates caches to force re-attestation.
- `responseInterceptor` tracks whether HTTP headers have been written
  (`headerSent`), enabling the retry loop to attempt new instances before
  the client receives any data.
- `Cache.Delete` and `SigningKeyCache.Delete` methods support targeted
  cache invalidation.

### Chutes Instance Failover

Chutes runs a dynamic fleet of GPU instances behind a routing layer.
Individual instances are unreliable — they may fail E2EE handshakes, crash
mid-inference, or go offline without notice. This is an expected operational
characteristic, not a security failure. Retrying a request on a *different*
instance with a *fresh* E2EE handshake (new key encapsulation, new nonces)
is not a fallback or a weakening of E2EE — it is the normal path for
maintaining request reliability across an unreliable fleet.

Instance failover operates at two levels:

1. **Pre-relay** (`doUpstreamRoundtrip`, `chutesMaxAttempts = 3`):
   Transport-level failures (connection errors, HTTP 429/500-504,
   handshake failures). Each retry marks the failed instance via
   `NoncePool.MarkFailed(chuteID, instanceID)`, zeros crypto material,
   and selects a different instance for a complete fresh E2EE handshake.

2. **Post-relay** (`relayWithRetry`, `chutesMaxAttempts`): Decryption
   failures detected during relay (before response headers are sent to
   client). The specific instance is marked failed and the loop retries
   with a new instance and new E2EE handshake.

**Two failure tiers**:

| Failure scope | Trigger | Action | Retryable? |
|---------------|---------|--------|------------|
| Per-instance | Transport error, handshake failure, HTTP 429/5xx, pre-header decryption error | `MarkFailed(instanceID)`, zero session, retry on fresh instance | Yes — fresh handshake on new instance |
| Provider+model | Post-relay decryption failure after headers sent (non-Chutes), or all Chutes retries exhausted | `e2eeFailed.Store`, invalidate all caches | No — fail-closed until re-attestation |

**What does NOT trigger provider+model failure**:
- Instance going offline mid-request (transport error → retry)
- E2EE handshake failure on a specific instance (prep error → retry)
- HTTP 429/500-504 from a specific instance (transport error → retry)
- Pre-header decryption failure on a Chutes instance (retry on new instance)
- All retry attempts exhausted for a single request (returns error to
  client, but next request may succeed on newly-available instances)

### Existing Safeguards

**Pre-relay session guard**: A fail-closed check
(`meta != nil && meta.Session == nil`) runs in `relayWithRetry` before the
relay dispatch. If Chutes E2EE metadata was populated but key encapsulation
failed to produce a session, the guard retries on a new instance (if
attempts remain) or returns an error. This catches pre-relay invariant
violations.

**Pinned E2EE nil report block**: The pinned (NearCloud) path blocks when
`prov.E2EE && report == nil`. Without a report, the signing key cannot be
verified as bound to the TDX quote, so E2EE would degrade to plaintext.
Records a negative cache entry and returns HTTP 502.

**e2eeFailed recovery guards**: The `e2eeFailed` marker is only cleared
after a confirmed fresh attestation (cache miss with `ar.Raw != nil`
non-pinned, or `pinnedResp.Report != nil` pinned). A concurrent request
that hits a cached attestation while `e2eeFailed` is set fails closed and
invalidates caches to force re-attestation on the next attempt.

---

## Remaining Problems

### R1: Skip→Fail promotion exemption is a special case

The `e2ee_usable` exemption in `BuildReport` (`factors[i].Name !=
"e2ee_usable"`) is a hard-coded special case in the factor promotion loop.
If future factors have similar lifecycle requirements (e.g. tool call
tests), each would need its own exemption. A cleaner approach would be a
general mechanism for factors that require post-report-build evaluation.

### R2: Report mutation via Clone + MarkE2EEUsable

The proxy still mutates a cloned report after `BuildReport` via
`MarkE2EEUsable` to transition the factor from `Skip` to `Pass`. While
`Clone()` and `recomputeCounters()` prevent the original P2/P3 cache
mutation race and counter desync issues, the pattern of post-build report
mutation remains architecturally unusual — no other factor is modified
after `BuildReport`.

### R3: Divergent evaluation paths

`teep verify` evaluates `e2ee_usable` cleanly inside `BuildReport` via
`E2EETest` in `ReportInput`. The proxy evaluates it via a two-step
process: `BuildReport` produces `Skip`, then `MarkE2EEUsable` promotes to
`Pass` after a successful relay. Both paths produce the same end result
(Pass/Fail/Skip), but via different mechanisms.

### R4: `e2eeFailed` is a parallel enforcement mechanism

The `e2eeFailed sync.Map` duplicates some responsibility that would
otherwise belong to the factor system. A decryption failure blocks future
requests via `e2eeFailed`, but `e2ee_usable` in the cached report is not
demoted back to `Fail` — the factor and the blocking map can be
inconsistent (factor says `Pass`, but requests are blocked). This is
correct from a security perspective (fail-closed) but confusing from a
report-reading perspective.

---

## Design

### Approach: Deferred Factor Evaluation

Rather than removing `e2ee_usable` from the factor system, introduce a
general mechanism for **deferred factors** — factors whose evaluation
requires a live roundtrip and cannot complete at attestation time. This
preserves `e2ee_usable` as a standard factor with consistent `allow_fail`
behavior while eliminating the special-case exemption.

### Factor Lifecycle

```
BuildReport time          Post-relay (proxy)           teep verify
──────────────            ──────────────────           ───────────
evalE2EEUsable:           MarkE2EEUsable:              evalE2EEUsable:
  E2EETest=nil →            relay succeeded →           E2EETest populated →
  Skip (deferred)           Clone + promote               Pass/Fail/Skip
                            to Pass                       (clean, no mutation)

                          handleE2EEDecryptionFailure:
                            relay failed →
                            e2eeFailed.Store +
                            cache invalidation
```

**Key property**: A deferred factor in `Skip` status never triggers
`Blocked()`, even when enforced. The Skip→Fail promotion exemption is
generalized from a name check to a factor property.

### Generalized Deferred Factor Mechanism

Replace the hard-coded `factors[i].Name != "e2ee_usable"` check with a
`Deferred` property on `FactorResult`:

```go
type FactorResult struct {
    Name     string
    Status   FactorStatus
    Detail   string
    Enforced bool
    Tier     FactorTier
    Deferred bool // true = post-report-build evaluation; Skip not promoted
}
```

The Skip→Fail promotion loop becomes:

```go
for i := range factors {
    if factors[i].Status == Skip && factors[i].Enforced && !factors[i].Deferred {
        factors[i].Status = Fail
        factors[i].Detail += " (enforced)"
    }
}
```

`evalE2EEUsable` sets `Deferred: true` when returning `Skip` with
`E2EEConfigured: true` and `E2EETest: nil` (the proxy path). The existing
`teep verify` path (where `E2EETest` is populated) returns `Pass`/`Fail`
with `Deferred: false` — no behavior change.

### e2eeFailed → Report Consistency

When `handleE2EEDecryptionFailure` fires, in addition to storing to
`e2eeFailed` and invalidating caches, the factor should be demoted to
`Fail` in the cached report so that `e2ee_usable` accurately reflects the
failure state. This keeps the report and the blocking map consistent:

```go
func (s *Server) handleE2EEDecryptionFailure(...) string {
    // ... existing invalidation logic ...

    // Demote e2ee_usable in the cached report so the report endpoint
    // reflects the failure. The cache entry is about to be deleted, but
    // a concurrent reader may still see it briefly.
    if cachedReport := s.cache.Get(prov.Name, upstreamModel); cachedReport != nil {
        cloned := cachedReport.Clone()
        cloned.MarkE2EEFailed("E2EE decryption failed: " + relayErr.Error())
        s.cache.Put(prov.Name, upstreamModel, cloned)
    }

    s.cache.Delete(prov.Name, upstreamModel)
    // ...
}
```

This requires a new `MarkE2EEFailed` method (counterpart to
`MarkE2EEUsable`) that transitions the factor from `Pass`/`Skip` to `Fail`
and recomputes counters. In practice, the cache entry is deleted
immediately after, so this is a belt-and-suspenders measure for the brief
window between Put and Delete.

### Key Design Decisions

- **`e2ee_usable` remains a standard factor.** It participates in
  `BuildReport`, `KnownFactors`, `allow_fail`, and `OnlineFactors`.
  Users can enforce or allow-fail it via config. This is consistent with
  all other factors.

- **Deferred factors are exempt from Skip→Fail promotion.** A general
  `Deferred` property replaces the hard-coded name check. Future factors
  with similar lifecycle requirements (e.g. tool call tests) use the same
  mechanism.

- **Post-relay enforcement is the primary E2EE safety mechanism.** The
  proxy always encrypts when `prov.E2EE && ReportDataBindingPassed()`.
  Decryption failures trigger `e2eeFailed` (fail-closed for future
  requests), cache invalidation, and report demotion.

- **Forward-looking enforcement.** For streaming responses, the HTTP 200
  status has already been sent with the first chunk. The first decryption
  failure is relayed to the client as an SSE error event. Enforcement is
  forward-looking: the *next* request is blocked. This is unavoidable
  without buffering the entire response.

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

### Phase 1: Generalize Deferred Factor Mechanism

**Goal**: Replace the hard-coded `e2ee_usable` exemption with a general
`Deferred` property on `FactorResult`.

1. **`internal/attestation/report.go`**
   - Add `Deferred bool` field to `FactorResult`.
   - In `evalE2EEUsable`: set `Deferred: true` when returning `Skip`
     with `E2EEConfigured: true` and `E2EETest: nil` (proxy path). All
     other return paths set `Deferred: false` (or leave as zero value).
   - In `BuildReport` Skip→Fail promotion: change
     `factors[i].Name != "e2ee_usable"` to `!factors[i].Deferred`.
   - Update JSON serialization if `FactorResult` is exposed via the
     report endpoint (include `Deferred` field with `omitempty`).

2. **`internal/attestation/report_test.go`**
   - Update `TestEvalE2EEUsable` cases to verify `Deferred` is set
     correctly for each evaluation path.
   - Add test: deferred factor with `Skip` and `Enforced` stays `Skip`
     (not promoted to `Fail`).
   - Add test: non-deferred factor with `Skip` and `Enforced` is
     promoted to `Fail` (existing behavior preserved).

### Phase 2: Report Consistency on Failure

**Goal**: Keep `e2ee_usable` factor status consistent with `e2eeFailed`
blocking state.

1. **`internal/attestation/report.go`**
   - Add `MarkE2EEFailed(detail string)` method: transitions
     `e2ee_usable` from `Pass` or `Skip` to `Fail`, sets detail,
     calls `recomputeCounters()`.

2. **`internal/proxy/proxy.go`** `handleE2EEDecryptionFailure`
   - Before `s.cache.Delete(...)`, clone the cached report and call
     `MarkE2EEFailed` so any concurrent reader sees the failure state.
   - Apply the same pattern to the pinned path's post-relay E2EE
     failure handling.

3. **`internal/attestation/report_test.go`**
   - Add `TestMarkE2EEFailed` tests: transition from Pass→Fail,
     Skip→Fail; verify counters are correct after recomputation.

### Phase 3: Cleanup

**Goal**: Remove deprecated workarounds and ensure consistency.

1. **Remove Skip→Fail exemption by name**: Verify no code still
   references `factors[i].Name != "e2ee_usable"` — the `Deferred`
   property should be the sole mechanism.

2. **Verify allow_fail consistency**: Write a test that:
   - With `e2ee_usable` in `allow_fail` (Venice/NearDirect): factor
     starts `Skip` (not enforced, not deferred-relevant since not
     enforced), report is not blocked, proxy serves requests, factor
     transitions to `Pass` after successful relay.
   - With `e2ee_usable` NOT in `allow_fail` (NearCloud/Chutes): factor
     starts `Skip` (enforced + deferred, not promoted to Fail), report
     is not blocked, proxy serves requests, factor transitions to `Pass`
     after successful relay.
   - Both cases: decryption failure triggers `e2eeFailed`, caches
     invalidated, factor demoted to `Fail`, subsequent requests blocked
     until re-attestation.

3. **Integration test verification**: Run `make integration` to confirm
   that enforced `e2ee_usable` works end-to-end for NearCloud and Chutes.

---

## Tradeoffs

- **Pro**: `e2ee_usable` is a standard factor — consistent with user
  expectations and the existing factor system. No special-case behavior
  visible to users.
- **Pro**: `allow_fail` configuration works as expected: users can
  enforce or relax `e2ee_usable` like any other factor.
- **Pro**: The `Deferred` mechanism is general — future live-test factors
  (tool call tests) use the same pattern without new exemptions.
- **Pro**: Post-relay enforcement catches real cryptographic failures at
  the right layer.
- **Pro**: Chutes instance failover preserves request reliability without
  weakening E2EE guarantees.
- **Pro**: Report consistency — `e2ee_usable` factor status and
  `e2eeFailed` blocking state stay in sync.
- **Con**: Proxy still mutates reports via `Clone` + `MarkE2EEUsable` /
  `MarkE2EEFailed`. This is safe (clone prevents races) but
  architecturally unusual.
- **Con**: Two enforcement mechanisms coexist: `e2ee_usable` factor
  status (informational after relay) and `e2eeFailed` map (blocking).
  The blocking map is the primary safety mechanism; the factor status
  is for reporting/observability.
- **Con**: `Deferred` adds a new concept to the factor system that
  requires documentation.

---

## Success Criteria

1. **No chicken-and-egg blocking**: With `e2ee_usable` enforced (not in
   `allow_fail`), the proxy serves the first E2EE request without
   blocking. The factor starts as `Skip` (deferred), not `Fail`.

2. **Consistent factor behavior**: `e2ee_usable` in `allow_fail` or not
   produces consistent results across `teep verify`, `teep serve`, and
   integration tests. No unspecified fail-open behavior.

3. **Fail-closed on decryption failure**: After a post-relay decryption
   failure, `e2eeFailed` is set, caches are invalidated, and all
   subsequent requests for that provider+model are blocked until
   successful re-attestation.

4. **Report consistency**: After a decryption failure, the `e2ee_usable`
   factor shows `Fail` in the report (not stale `Pass`). After a
   successful relay, it shows `Pass`.

5. **Instance failover preserves reliability**: For Chutes, per-instance
   failures (transport errors, handshake failures, pre-header decryption
   errors) are retried on fresh instances with new E2EE handshakes
   without triggering provider+model failure.

6. **Deferred mechanism is general**: The `Deferred` property on
   `FactorResult` replaces the hard-coded name check. No
   `e2ee_usable`-specific logic in the Skip→Fail promotion loop.

7. **All tests pass**: `make check` and `make integration` pass.

---

## Future Considerations

- **Tool call test factor**: A forthcoming check that tests whether tool
  calls work through the E2EE path. It will face the same lifecycle as
  `e2ee_usable` and should use `Deferred: true` to avoid Skip→Fail
  promotion.
- **E2EE key rotation**: When a signing key rotates (VM restart), the
  `e2eeFailed` marker should be cleared (the new key requires fresh
  attestation anyway, which gates recovery).
- **Report cache TTL vs e2eeFailed**: The report cache has a 5-minute
  TTL. `e2eeFailed` persists independently and is only cleared on fresh
  attestation, not on cache expiry. This is correct — cache expiry
  triggers re-attestation, which is the recovery path.
- **Client-facing E2EE status**: Consider adding an `X-Teep-E2EE`
  response header so clients can verify E2EE was used for each request
  without fetching the full report.
- **Nonce pool exhaustion**: When all instances in the nonce pool are
  marked failed (across multiple requests), `Take` currently returns an
  error only when no nonces remain, not when all instances are unhealthy.
  Consider whether the pool should signal "no healthy instances" as a
  distinct condition. This is an operational exhaustion (all instances
  individually failed), not a cryptographic failure, so it should NOT
  trigger `e2eeFailed`. The correct recovery is re-attestation to refresh
  the instance pool.
- **Crypto material lifecycle in retry**: `zeroE2EESessions` is the
  canonical helper for zeroing E2EE crypto material. Post-relay
  enforcement uses the same pattern when invalidating material after
  decryption failure.
