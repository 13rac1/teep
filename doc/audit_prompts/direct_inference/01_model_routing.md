# Section 01 — Model Routing & Endpoint Discovery

## Scope

Audit model-to-domain discovery and routing safety for direct inference providers.

## Primary Files

- [`internal/provider/nearai/endpoints.go`](../../../internal/provider/nearai/endpoints.go)
- [`internal/provider/nearai/pinned.go`](../../../internal/provider/nearai/pinned.go)
- [`internal/tlsct/checker.go`](../../../internal/tlsct/checker.go)

## Secondary Context Files

- [`internal/provider/nearai/nearai.go`](../../../internal/provider/nearai/nearai.go)

## Required Checks

Verify and report:
- model-to-domain mapping cache TTL and refresh behavior,
- rejection of malformed endpoint domains (scheme/path/whitespace injection),
- rejection of domains without a dot (non-qualified hostnames),
- rejection of domains outside expected API subdomain suffix,
- model selection behavior when multiple endpoint entries exist (first/last/conflict),
- duplicate model entries mapping to different domains (including operator-visible warning behavior),
- refresh concurrency behavior (singleflight or equivalent anti-stampede),
- behavior when discovery endpoint is unreachable (stale-on-error vs hard failure),
- first-use behavior when no stale mapping exists (must identify fail-closed vs not),
- IDN/punycode normalization or as-is acceptance, plus homograph residual risk,
- CT check behavior for routing endpoint certificate,
- CT cache keying and TTL behavior,
- maximum response size limits for discovery payload.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. per-check classification (`enforced fail-closed` / `computed but non-blocking` / `skipped/advisory`),
3. explicit residual risk statement for hostname-authenticity gap,
4. include at least one concrete positive control and one concrete negative/residual-risk observation,
5. source citations for every substantive claim.
