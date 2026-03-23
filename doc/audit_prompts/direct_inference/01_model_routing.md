# Section 01 — Model Routing & Endpoint Discovery

## Scope

Audit model-to-domain discovery and routing safety for direct inference providers.

In this direct inference model, the attestation covers a single model server. There is a model mapping routing API that the teep proxy consults to determine the destination host for a particular model identity string.

Certificate Transparency MUST be consulted for the TLS certificate of this model router endpoint. This CT log report SHOULD be cached.

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

> NOTE: Even with all of these checks, ultimately nothing strongly authenticates this list of hostnames as belonging to the inference provider. This is a gap that can only be mitigated by ensuring that the docker images are those expected to be used by the inference provider (see CVM Image Component Verification in Section 08).

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. per-check classification (`enforced fail-closed` / `computed but non-blocking` / `skipped/advisory`),
3. explicit residual risk statement for hostname-authenticity gap,
4. include at least one concrete positive control and one concrete negative/residual-risk observation,
5. source citations for every substantive claim.
