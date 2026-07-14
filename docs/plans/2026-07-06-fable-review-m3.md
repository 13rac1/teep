# Plan: Fable review M3 — SPKI re-pinning silently skipped on attestation cache hits

Source: `docs/2026-07-02-fable-review.md`, finding M3. Verified still present
on main @ 4152307. **Highest-priority medium** — on every cache hit the TLS
binding that justifies the 1-hour attestation cache is simply not checked.

## Current state

- `verifyUpstreamTLSBinding` (`internal/proxy/proxy.go:2736-2765`) compares
  the live upstream leaf SPKI against the attested `TinfoilTLSKeyFP`.
- Its call is guarded by `raw != nil && raw.TinfoilTLSKeyFP != ""`
  (`proxy.go:2875-2882`).
- `attestAndCache` (`proxy.go:2278-2332`) assigns `raw` only in the
  cache-miss branch (:2292); on a hit `attestResult.Raw` is nil (:2328).
- `setUpstreamConnectionHeaders` (`proxy.go:2717-2725`) sets
  `Connection: close` only when `prov.UsesTLSBinding && raw != nil` — also
  cache-miss only.
- The comment at `proxy.go:2710-2716` claims per-response SPKI verification
  keeps reused connections bound to the attested enclave — false on the
  cache-hit path, which is the *common* path for up to
  `AttestationCacheTTL` (1 hour).

Failure scenario: after the first request caches attestation, all
subsequent requests within the TTL reach the enclave domain over
pooled/reusable TLS whose leaf SPKI is never compared to the attested
fingerprint. A mis-issued CA-valid cert for the domain goes undetected
between attestations. Affects `tinfoil_v3_cloud`/`tinfoil_v3_direct`
(`UsesTLSBinding = true`).

## Design

Cache the attested fingerprint with the attestation and verify it on
**every** upstream response, hit or miss:

1. **Store the fingerprint in the cache entry.** Extend the attestation
   cache value (the struct behind `attestAndCache`) with
   `TLSKeyFP string`, populated on the miss path from
   `raw.TinfoilTLSKeyFP`. Cache entries are already provider+model scoped;
   no key change.
2. **Return it on hits.** `attestResult` gains a `TLSKeyFP` field set on
   both paths (from `raw` on miss, from the cache entry on hit). Callers
   stop reaching into `raw` for it.
3. **Unconditional verification.** Change the call-site guard
   (:2875-2882) to `prov.UsesTLSBinding && attestResult.TLSKeyFP != ""`.
   For a TLS-binding provider, an **empty** fingerprint (cache entry
   predating the field, or attestation that failed to produce one) must
   fail closed — error the request, do not skip the check.
4. **`Connection: close` semantics.** With per-response SPKI verification
   genuinely running on every response, connection reuse within the TTL is
   acceptable (that is the design the misleading comment described). Update
   `setUpstreamConnectionHeaders` to drop the `raw != nil` condition:
   `Connection: close` is set whenever attestation is (re-)performed
   (attestation boundary rule, AGENTS.md), while cache-hit requests rely on
   the now-real per-response SPKI check. If maintainers prefer belt and
   braces, setting `Connection: close` unconditionally for TLS-binding
   providers is the simpler, slightly slower alternative — decide in
   review; the plan implements the first.
5. **Fix the comment** (:2710-2716) to describe the actual mechanism.

## Files

- `internal/proxy/proxy.go` — cache entry struct, `attestAndCache`,
  `attestResult`, call-site guard, `setUpstreamConnectionHeaders`, comment.

## Tests

- Unit (httptest.NewTLSServer per AGENTS.md):
  - Cache miss → SPKI verified (existing behavior preserved).
  - **Cache hit → SPKI still verified**: prime the cache, swap the upstream
    server cert (new SPKI), next request through the hit path must be
    rejected with the binding error. This is the regression test for the
    finding.
  - Cache hit with matching SPKI → request proceeds.
  - TLS-binding provider with empty cached fingerprint → fail closed.
  - Concurrent: parallel requests across hit/miss transitions
    (`sync.WaitGroup`, `-race`) — the cache is shared state.
- Integration: tinfoil replay fixtures exercise the hit path on the second
  request of a capture; assert the binding check ran (add a counter or rely
  on the swap-cert unit test for the negative case).

## Verification

- `make check`; `go test -race ./internal/proxy/...`; `make integration`.

## Constraints (AGENTS.md)

- Cache eviction/misses must never allow unattested connections — the
  empty-fingerprint fail-closed rule in step 3 preserves this.
- `Connection: close` across attestation boundaries retained (step 4).
- Constant-time comparison for the SPKI fingerprint (verify
  `verifyUpstreamTLSBinding` already uses `subtle.ConstantTimeCompare`;
  fix if not).
- Concurrent tests required (shared cache).
