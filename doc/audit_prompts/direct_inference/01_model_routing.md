# Section 01 — Model Routing & Endpoint Discovery

## Scope

Audit model-to-domain discovery and routing safety for direct inference providers.

In this direct inference model, the attestation covers a single model server. There is a model mapping routing API that the teep proxy consults to determine the destination host for a particular model identity string.

Certificate Transparency MUST be consulted for the TLS certificate of this model router endpoint. This CT log report SHOULD be cached.

## Primary Files

- [`internal/provider/neardirect/endpoints.go`](../../../internal/provider/neardirect/endpoints.go)
- [`internal/provider/neardirect/pinned.go`](../../../internal/provider/neardirect/pinned.go)
- [`internal/tlsct/checker.go`](../../../internal/tlsct/checker.go)

## Secondary Context Files

- [`internal/provider/neardirect/nearai.go`](../../../internal/provider/neardirect/nearai.go)
- [`internal/provider/neardirect/endpoints_test.go`](../../../internal/provider/neardirect/endpoints_test.go)
- [`internal/provider/neardirect/pinned_test.go`](../../../internal/provider/neardirect/pinned_test.go)

## Required Checks

### Endpoint Discovery and Domain Validation

Verify and report:
- model-to-domain mapping cache TTL and refresh behavior,
- rejection of malformed endpoint domains (scheme/path/whitespace injection),
- rejection of domains without a dot (non-qualified hostnames),
- rejection of domains that do not end in the same subdomain as the API endpoint (e.g., `completions.near.ai`),
- exact model selection behavior when multiple endpoint entries map different models to different domains (last-wins, first-wins, or explicit conflict handling),
- duplicate model entries mapping to different domains in a single refresh (and whether this emits an operator-visible warning),
- refresh concurrency behavior (singleflight or equivalent anti-stampede),
- behavior when discovery endpoint is unreachable (stale-on-error vs hard failure),
- first-use behavior when no stale mapping exists (must identify fail-closed vs not),
- IDN/punycode normalization or as-is acceptance, plus homograph residual risk,
- CT check behavior for routing endpoint certificate,
- CT cache keying and TTL behavior,
- maximum response size limits for discovery payload (recommended: ≤1 MiB to prevent memory exhaustion from a malicious discovery response).

### HTTP Request and Response Safety for Discovery Calls

Verify:
- that the discovery endpoint URL is constructed from trusted constants and not from user-supplied input,
- that response body reads use `io.LimitReader` or equivalent to enforce the size bound,
- that HTTP client timeouts (connect, read, overall) are configured and reasonable,
- that the HTTP response status code is checked before parsing the body,
- that the response `Content-Type` is validated before JSON parsing.

### Certificate Transparency for Routing Endpoint

Verify:
- that CT log checks are performed for the TLS certificate of the discovery/routing endpoint,
- the CT cache keying strategy (e.g., keyed by domain, certificate fingerprint, or both),
- CT cache TTL and maximum entry bounds,
- behavior when CT log servers are unreachable (fail-open vs fail-closed, and the residual risk of each).

> NOTE: Even with all of these checks, ultimately nothing strongly authenticates this list of hostnames as belonging to the inference provider. This is a gap that can only be mitigated by ensuring that the docker images are those expected to be used by the inference provider (see CVM Image Component Verification in Section 08).

## Go Best-Practice Audit Points

- **Error handling in HTTP calls**: Verify that all HTTP client errors (DNS failure, connection refused, timeouts, non-2xx status) are handled distinctly and wrapped with context via `fmt.Errorf("...: %w", err)`. Verify no panics on network errors.
- **URL construction safety**: Verify that domain strings from the discovery response are validated using `net/url` parsing or equivalent, not string concatenation. Confirm that scheme injection (e.g., `evil.com/path?scheme=https://`) is blocked.
- **Concurrency safety of endpoint cache**: Verify the endpoint cache is protected by `sync.RWMutex` or `singleflight` to prevent data races during concurrent refreshes. Check with `-race` flag considerations.
- **Context propagation**: Verify that `context.Context` is threaded through the discovery call chain so that upstream cancellation (e.g., client disconnect) terminates in-flight discovery requests.
- **Struct field validation**: Verify that the parsed endpoint response struct uses strict JSON unmarshalling and that unexpected fields trigger warnings or errors.

## Security Audit Points

- **SSRF prevention**: Verify that resolved domains are not private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, ::1, fc00::/7) to prevent server-side request forgery through the model routing layer.
- **DNS rebinding**: Consider whether an attacker could register a domain that initially resolves to a valid IP for the discovery check but later resolves to a malicious IP for the inference connection. Document any mitigations or residual risk.
- **Trust boundary**: The discovery endpoint itself is only weakly authenticated (TLS + CT). An attacker who compromises the discovery API could redirect models to rogue servers. Document this trust boundary clearly and note that attestation of the destination server is the compensating control.
- **Cache poisoning**: Verify that a malicious discovery response cannot persistently poison the endpoint cache beyond the TTL. Verify that cache entries are keyed to prevent cross-provider contamination.
- **Input validation depth**: The model identity string from the user request flows into the discovery lookup. Verify that this string is validated/sanitized before use as a cache key or in any string interpolation.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. per-check classification (`enforced fail-closed` / `computed but non-blocking` / `skipped/advisory`),
3. explicit residual risk statement for hostname-authenticity gap,
4. include at least one concrete positive control and one concrete negative/residual-risk observation,
5. source citations for every substantive claim.
