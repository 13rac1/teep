---
applyTo: "**"
excludeAgent: "coding-agent"
---

# Teep Code Review Instructions

Teep is a TEE attestation proxy for private LLM inference. It is **critical
infrastructure security software** — protecting confidential traffic is more
important than providing service. Failing closed is a feature, not a bug.

## Data Flow

The Teep proxy receives an OpenAI-compatible chat request → resolves model to provider →
fetches and validates TEE attestation per policy → forwards (or blocks) the request.

The proxy receives concurrent API inference requests to multiple providers and models from multiple client API consumers simultaneously. All code paths from the HTTP handler inward must be safe for concurrent use. All attestation caches, key pinning, connection pinning, supply chain validation, and supply chain caches must also be safe for concurrent use via multiple clients performing simultaneous access of multiple providers and models.

## Fail-Closed Policy (highest priority)

Every validation check MUST block the request on failure, unless the check has been explicitly whitelisted in an allow_fail list or disabled by command line argument.

Flag any code that:

- Returns a nil error, default value, or falls through on a validation failure.
- Catches an error and continues instead of aborting (error fallback).
- Uses a fallback, default, or degraded mode when a security check fails.
- Introduces a "best-effort", "soft-fail", or "skip-on-error" code path.
- Adds backwards-compatible shims that weaken validation.
- Silently drops malformed elements instead of rejecting the whole input.
- Allows an unattested or partially-attested request to be forwarded.
- Serves stale or cached data when re-validation fails, without blocking.

If an error path does anything other than return/propagate an error, it is a
defect. There are NO acceptable workarounds, fallbacks, or error recoveries for
security validation.

## Cryptographic Safety

- All comparisons of secrets, keys, fingerprints, nonces, or hashes MUST use
  `subtle.ConstantTimeCompare`. Flag any use of `==`, `!=`, `bytes.Equal`,
  or `strings.EqualFold` on security-sensitive values.
- Encryption keys MUST be bound to TEE attestation.
- Encryption MUST be used when requested; plaintext fallback is unacceptable!
- Nonce generation MUST use `crypto/rand`. If randomness fails, the code MUST
  panic or return an error — never use a weak source.

## Sensitive Data Handling

- NEVER log or print API keys, inference request bodies, or response bodies.
- API keys in logs must be redacted (first few characters only).
- Ephemeral key material should be zeroed after use.
- Config files containing secrets should have permission checks.

## Attestation Integrity

- Attestation MUST be verified before any inference request is forwarded.
- The nonce MUST originate from the client, not the server response.
- No provider-asserted "verified" field may be trusted without independent
  cryptographic verification.
- Cache misses MUST trigger full re-attestation, never pass-through.
- Cache eviction under memory pressure MUST NOT allow unattested connections.

## Error Handling Style

- Error returns block the request — no silent swallowing.
- Unknown or misspelled config values MUST be rejected at startup.
- JSON unmarshalling MUST use strict mode (warn on unknown fields, and reject failures).
- Malformed attestation data MUST fail the entire response, not skip elements.
- **Do not request nil checks for internal objects and arguments** that are
  expected to be always non-nil by normal program construction. A nil dereference panic is
  preferable to a nil guard that returns a default value or skips validation,
  which would introduce fail-open behavior. Nil checks are acceptable when they fail
  closed by returning/propagating a clear error that blocks the request; they must not
  introduce fail-open behavior.

## Concurrency Safety

Teep serves concurrent inference requests to multiple providers and models
from multiple consumers. Flag any code that:

- Introduces or writes to a **mutable package-level variable**. State that
  varies per-request or per-provider must live on a struct or be passed as a
  parameter. A global written during request handling will race under load.
- Uses a package-level variable with `save/restore` cleanup (e.g.
  `orig := pkg.Global; defer func() { pkg.Global = orig }()`) — this pattern
  is inherently racy when callers run concurrently.
- Shares mutable state (maps, slices, pointers) between goroutines without
  synchronization (`sync.Mutex`, `sync.Map`, channels, or atomics).
- Mutates a struct field that is read by concurrent request handlers without
  holding a lock.

Preferred patterns:
- **Dependency injection** — pass per-call or per-handler dependencies via
  constructor parameters, struct fields, or function arguments.
- **Immutable-after-init** — state set once during `New()`/`init()` and never
  written again is safe. Document the invariant.
- Concurrent test coverage (`sync.WaitGroup` + parallel goroutines + `-race`)
  should accompany any new shared state.

## Go Conventions

- Ensure Effective Go idioms and best practices are followed.
- All new code and bug fixes require unit test coverage.
- New providers or major features require integration test coverage.
- Bound all reads from untrusted sources (HTTP bodies, JSON arrays).
- Use `Connection: close` or equivalent to prevent TLS connection reuse
  across attestation boundaries.

## Plan Compliance Review

If the requested review contains a removed plan file along with code changes, then the code changes are meant to implement the removed plan.

In addition to ensuring that the code meets the above review requirements, verify:

- All behaviors and features of the plan are implemented, with test coverage.
- All phases of the plan have been executed with clean design.
- Security and reliability of the surrounding code and related components have not been impacted.
- Any problems or requirements that the plan enumerates are addressed and verified with tests.
- Appropriate documentation has been updated.

## Review Style

- Be specific: cite the code location and explain the risk.
- Prioritize fail-open and fallback defects above all other issues.
- Flag any weakening of existing validation, even if "temporary".
