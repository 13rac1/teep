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

### Known Architectural Divergence

Venice is a gateway provider with a fundamentally weaker security model:
- Venice does NOT have a `PinnedHandler` — there is no attestation-bound TLS pinning to the Venice gateway,
- Venice does NOT produce a gateway TDX quote — there are no Tier 4 gateway factors,
- Venice's `ServerVerification` field is an untrusted gateway-side claim that is parsed but NOT independently verified by teep,
- Venice forwards model backend attestation (which may be produced by NearAI infrastructure), but the gateway itself is not hardware-attested,
- The audit SHOULD document Venice's weaker gateway model as a contrast to nearcloud's full dual-tier attestation, but as these issues are server-side, they are not findings to fix in teep.
### Known Architectural Divergence: Chutes/Sek8s

Chutes uses a gateway architecture where all traffic routes through the Chutes gateway (`api.chutes.ai`/`llm.chutes.ai`) to specific sek8s TEE instances by instance ID. However, unlike nearcloud, the Chutes gateway is **not a TEE-attested CVM** — it produces no TDX quote and has no `gateway_*` attestation factors:
- There is no `PinnedHandler`, no gateway TDX quote, no gateway compose binding, and no gateway REPORTDATA.
- The attestation flow uses the Chutes gateway to reach backend instances via a **two-step** protocol: an instances endpoint (`GET /e2e/instances/{chute}`) returns available TEE instances with ML-KEM-768 public keys, then an evidence endpoint (`GET /chutes/{chute}/evidence?nonce={hex}`) returns TDX quotes per instance.
- Instance-to-evidence matching is by instance ID, with bounds checking (max 256 instances, max 256 evidence entries, max 64 GPU evidence per instance).
- Model resolution uses a separate cache (`resolve.go`) that maps human-readable model names to chute UUIDs with a 5-minute TTL.

**Primary files for chutes architecture audit:**
- [`internal/provider/chutes/chutes.go`](../../../internal/provider/chutes/chutes.go) \u2014 two-step attestation flow
- [`internal/provider/chutes/models.go`](../../../internal/provider/chutes/models.go) \u2014 TEE model discovery
- [`internal/provider/chutes/resolve.go`](../../../internal/provider/chutes/resolve.go) \u2014 model name resolution
- [`internal/provider/chutes/noncepool.go`](../../../internal/provider/chutes/noncepool.go) \u2014 nonce/instance caching
- [`internal/provider/chutes_format.go`](../../../internal/provider/chutes_format.go) \u2014 gateway-wrapped format parsing

When chutes evidence appears in a gateway-wrapped format, the audit MUST verify that the gateway-wrapped parsing extracts the inner chutes evidence correctly and applies all chutes-specific verification (TDX quote, REPORTDATA binding, measurement policy).
## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. per-check classification (`enforced fail-closed` / `computed but non-blocking` / `skipped/advisory`),
3. explicit confirmation that no model routing exists (or finding if routing is present),
4. CT check assessment for gateway endpoint,
5. include at least one concrete positive control and one concrete negative/residual-risk observation,
6. source citations for every substantive claim.
