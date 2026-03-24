# Section 01 — Gateway Architecture & Endpoint Validation

## Scope

Audit gateway host resolution, endpoint validation, and verification that no routing indirection or alternate host code paths exist.

In the gateway inference model, the proxy connects to a single hardcoded gateway host. Unlike direct inference providers, there is no model-to-domain routing API — all models are served through the same gateway endpoint. The audit MUST verify that this architectural constraint is correctly enforced and that no code path allows connecting to an unattested alternate host.

Certificate Transparency MUST be consulted for the TLS certificate of the gateway endpoint. This CT log report SHOULD be cached.

## Primary Files

- [`internal/provider/nearcloud/nearcloud.go`](../../../internal/provider/nearcloud/nearcloud.go)
- [`internal/provider/nearcloud/pinned.go`](../../../internal/provider/nearcloud/pinned.go)
- [`internal/tlsct/checker.go`](../../../internal/tlsct/checker.go)

## Secondary Context Files

- [`internal/provider/nearcloud/nearcloud_test.go`](../../../internal/provider/nearcloud/nearcloud_test.go)
- [`internal/provider/nearcloud/pinned_test.go`](../../../internal/provider/nearcloud/pinned_test.go)

## Required Checks

### Gateway Host Validation

Verify and report:
- that the gateway host (`cloud-api.near.ai`) is a hardcoded constant in the source code (not configurable via environment variable, config file, or API response),
- that there is no model routing or endpoint discovery API call (unlike `neardirect`),
- that the model identity string from the user request does NOT influence the destination host — it is only used for model selection within the combined attestation response,
- that no code path constructs or overrides the destination host from external input,
- that there is no DNS-based routing indirection or load balancer discovery mechanism.

### Absence of Model Routing

Unlike direct inference providers (which resolve model → domain via a routing API), the gateway provider:
- does NOT call any endpoint discovery API,
- does NOT maintain a model-to-domain mapping cache,
- uses the model identity string only to select the correct attestation entry from the combined gateway+model response.

Verify that:
- no routing API call exists in the nearcloud provider implementation,
- the model string is used purely as a selection key within the attestation response, not as a network destination,
- there is no fallback to routing-based discovery if model selection fails within the combined response.

### Combined Attestation Endpoint

The gateway attestation endpoint returns both gateway and model attestation in a single response. Verify:
- that the attestation URL is constructed from the hardcoded host and a fixed attestation path,
- that the attestation path includes the model identity for model-specific attestation retrieval,
- that the URL construction does not allow path traversal or injection from the model string,
- that no separate connection is opened to the model backend (the proxy only connects to the gateway),
- that the combined response format is expected and parsed correctly (gateway_attestation + model_attestations in a single JSON object).

### Certificate Transparency for Gateway Endpoint

Verify:
- that CT log checks are performed for the TLS certificate of the gateway endpoint,
- the CT cache keying strategy (e.g., keyed by domain, certificate fingerprint, or both),
- CT cache TTL and maximum entry bounds,
- behavior when CT log servers are unreachable (fail-open vs fail-closed, and the residual risk of each).

## Go Best-Practice Audit Points

- **URL construction safety**: Verify that the attestation endpoint URL is built from trusted constants. Confirm that the model string is safely embedded (URL-encoded if necessary, no scheme/host/path injection).
- **Constant strings vs configurable**: Verify that `gatewayHost` and the attestation path are `const` declarations or effectively immutable package-level variables, not settable via test hooks that could leak to production.
- **Context propagation**: Verify that `context.Context` is threaded through so that upstream cancellation terminates in-flight attestation requests.

## Security Audit Points

- **No SSRF via model string**: Verify that the model identity string cannot redirect the proxy to a different host, path, or scheme. Even though the host is hardcoded, a crafted model string could potentially escape the URL path if not properly encoded.
- **Trust boundary**: The gateway host is authenticated solely by its TLS certificate + attestation. The hardcoded host constant ensures DNS resolution is the only variability — and attestation-bound SPKI pinning is the compensating control.
- **No alternate host fallback**: Verify that no error-handling code path falls back to a different host (e.g., a non-gateway direct connection to the model backend) when the gateway is unreachable.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. per-check classification (`enforced fail-closed` / `computed but non-blocking` / `skipped/advisory`),
3. explicit confirmation that no model routing exists (or finding if routing is present),
4. CT check assessment for gateway endpoint,
5. include at least one concrete positive control and one concrete negative/residual-risk observation,
6. source citations for every substantive claim.
