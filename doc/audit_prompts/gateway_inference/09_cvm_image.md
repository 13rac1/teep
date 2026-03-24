# Section 09 — CVM Image Binding & Component Provenance (Gateway and Model)

## Scope

Audit CVM image binding to TDX evidence and verification of compose-listed component images using Sigstore/Rekor trust signals, for BOTH the gateway CVM and the model backend CVM.

Both the gateway and the model backend provide `app_compose` content that is bound to their respective TDX `MRConfigID` fields. The compose files list docker images that must be checked against provider allowlists and verified for supply-chain provenance via Sigstore/Rekor.

## Primary Files

- [`internal/attestation/compose.go`](../../../internal/attestation/compose.go)
- [`internal/attestation/sigstore.go`](../../../internal/attestation/sigstore.go)
- [`internal/attestation/rekor.go`](../../../internal/attestation/rekor.go)

## Secondary Context Files

- [`internal/attestation/report.go`](../../../internal/attestation/report.go)
- [`internal/provider/nearcloud/nearcloud.go`](../../../internal/provider/nearcloud/nearcloud.go)
- [`internal/attestation/compose_test.go`](../../../internal/attestation/compose_test.go)
- [`internal/attestation/sigstore_test.go`](../../../internal/attestation/sigstore_test.go)
- [`internal/attestation/rekor_test.go`](../../../internal/attestation/rekor_test.go)

## Background: Dual Compose Binding in the Gateway Model

In the gateway inference model, there are TWO compose binding checks:
1. **Model backend compose binding**: `SHA-256(model app_compose)` → model TDX `MRConfigID` — enforcement factor: `compose_binding`
2. **Gateway compose binding**: `SHA-256(gateway app_compose)` → gateway TDX `MRConfigID` — enforcement factor: `gateway_compose_binding`

Both are hardware-attested via their respective TDX quotes. The compose binding is the primary supply-chain control — it proves the compose configuration measured by the TEE matches the expected software configuration.

## Required Checks

### Compose Binding to MRConfigID (Model Backend)

Verify and report:
- exact compose-hash-to-`MRConfigID` binding format: the code expects `MRConfigID` to start with byte `0x01` followed by the `SHA-256(app_compose)` hash (33 bytes total prefix within the 48-byte `MRConfigID` field),
- that `VerifyComposeBinding()` uses `subtle.ConstantTimeCompare` for the prefix comparison,
- that `MRConfigID` length is validated (must be at least 33 bytes),
- that an empty `MRConfigID` is explicitly rejected,
- `app_compose` extraction path from the model attestation response,
- that the hash input is the raw extracted compose content (not re-serialized).

### Compose Binding to MRConfigID (Gateway)

The gateway's compose binding works the same way but with the gateway's own `app_compose` and `MRConfigID`. Verify and report:
- that the gateway's `app_compose` extraction path correctly handles double-encoded JSON (the gateway's `tcb_info` may be a JSON string containing escaped JSON),
- that the gateway compose binding uses the **same** `VerifyComposeBinding()` function as the model compose binding,
- that the gateway compose binding check is a **separate** enforced factor (`gateway_compose_binding`) from the model compose binding (`compose_binding`),
- that both factors are in the default enforced set.

### CVM Image Component Verification

The docker compose files for BOTH the gateway and model backend list sub-images. Verify and report:
- digest extraction logic from compose content: regex `@sha256:([0-9a-f]{64})` or equivalent — verify anchoring to exactly 64 lowercase hex characters,
- handling/rejection of non-`sha256` digest formats (e.g., `sha512:` digests),
- deduplication behavior for extracted digests,
- image repository extraction and normalization logic (tag stripping, registry port preservation),
- provider allowlist enforcement: every extracted repository MUST be checked against the provider's allowlist, with unknown repositories causing a hard failure,
- whether the allowlist matching is case-sensitive or case-insensitive.

### Gateway Compose Image Verification Gap

> NOTE: The current implementation may perform Sigstore/Rekor checks only on the model backend's compose images.

The audit MUST verify:
- whether gateway compose images are also subject to Sigstore/Rekor provenance checks,
- whether gateway compose images are checked against the provider's image repository allowlist,
- if gateway compose images are NOT checked, flag this as a gap and document the residual risk (a compromised gateway image that is nonetheless compose-bound would pass attestation).

### Sigstore Verification

Verify and report:
- Sigstore query behavior: HTTP HEAD to `search.sigstore.dev` with GET fallback,
- a digest is considered "OK" if HTTP status < 400 — verify this threshold,
- Sigstore query failure semantics (hard fail vs advisory skip),
- response body handling (`resp.Body.Close()` on all paths),
- the Sigstore search base URL mutability and whether it can be manipulated at runtime in production.

### Rekor Provenance Extraction

Verify and report:
- Rekor API interaction: UUID search via POST, then entry fetch via POST,
- response body size limits (recommended: 1 MiB limit),
- DSSE envelope parsing: extraction of verifier from `spec.signatures[0]`,
- PEM block type classification: `CERTIFICATE` → Fulcio provenance, `PUBLIC KEY` → raw key (no provenance),
- Fulcio certificate provenance extraction via X.509 extension OIDs (1.3.6.1.4.1.57264.1.*),
- accepted signer identity model (OIDC issuer, identity patterns, exact-match vs glob),
- behavior when a Rekor entry has a raw public key (no Fulcio cert): document whether this is treated as passing provenance,
- when multiple Rekor UUIDs are returned, only the first is fetched — document risk.

### Outage Behavior and Enforcement Classification

Explicitly state:
- whether Sigstore/Rekor checks are soft-fail in default policy,
- what traffic is still allowed during Sigstore/Rekor outage conditions,
- whether the current enforcement policy includes `sigstore_verification` or `build_transparency_log` as enforced factors,
- the residual risk when these checks are advisory-only.

### Relationship to TDX Measurements

Compose binding (`MRConfigID`) provides application-layer assurance. Document:
- compose binding covers: docker images listed in the compose file,
- compose binding does NOT cover: the host OS, kernel, initrd, firmware, TDX module,
- the combined assurance level when compose binding is enforced but `MRTD`/`RTMR0-2` golden values are absent.

## Go Best-Practice Audit Points

- **Regex compilation**: Verify image digest regex is compiled at package init time.
- **JSON unmarshalling safety**: Verify strict unmarshalling for compose extraction.
- **Error wrapping with `%w`**: Verify consistent error wrapping.
- **Nil/empty slice handling**: Verify graceful handling of empty compose content.
- **HTTP client context propagation**: Verify Sigstore/Rekor calls respect context cancellation.
- **Resource cleanup**: Verify all HTTP response bodies are closed on every path.

## Cryptography Best-Practice Audit Points

- **SHA-256 for compose binding**: Confirm `crypto/sha256.Sum256` is used.
- **Constant-time comparison**: `VerifyComposeBinding` uses `subtle.ConstantTimeCompare` for MRConfigID prefix.
- **X.509 certificate parsing**: Fulcio certificate parsing errors are hard failures.
- **No cosign bundle verification**: If the code relies on HTTP status rather than full cosign bundle signature verification, document this gap.

## General Security Audit Points

- **Trust boundary**: Sigstore and Rekor are external services. Evaluate what happens if they are compromised.
- **Supply chain depth**: Verify the granularity of the OIDC identity check for Fulcio provenance.
- **Defense in depth**: Compose binding (enforced, hardware-attested) is primary. Sigstore/Rekor is secondary. Classify each.
- **Input validation**: Regex-based extraction cannot be confused by crafted compose content.
- **Denial-of-service**: Thousands of image references could trigger thousands of API calls. Verify bounds.
- **Fail-secure defaults**: A new image not in the allowlist MUST be a hard failure.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. `MRConfigID` binding verification for BOTH gateway and model,
3. gateway compose image verification gap assessment (Sigstore/Rekor coverage),
4. Sigstore/Rekor outage behavior and soft-fail residual risk,
5. image allowlist enforcement completeness (both gateway and model),
6. include at least one concrete positive control and one concrete negative/residual-risk observation,
7. source citations for all claims.
