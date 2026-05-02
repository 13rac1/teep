# Teep Supply Chain & Compose Binding Attestation

## Provider Supply Chain Policies

### Dstack-Based Providers (Venice, Neardirect, Nearcloud, NanoGPT)

All dstack-backed providers build their measurement defaults from `DstackBaseMeasurementPolicy()` in [internal/attestation/dstack_defaults.go](../../internal/attestation/dstack_defaults.go). That base policy includes:
- **MRSEAM**: 4 Intel TDX module measurements covering TDX module versions 1.5.08, 1.5.16, 2.0.08, and 2.0.02
- **MRTD**: 2 dstack virtual firmware measurements covering `dstack-nvidia-0.5.4.1` and `dstack-nvidia-0.5.5`
- **RTMR**: provider-specific allowlists layered on top by each provider package

Nearcloud also carries a separate gateway CVM measurement policy in [internal/provider/nearcloud/policy.go](../../internal/provider/nearcloud/policy.go). NanoGPT widens the RTMR allowlists beyond a single deployment class, but still inherits the shared MRSEAM and MRTD baselines.

### Venice ([internal/provider/venice/policy.go](../../internal/provider/venice/policy.go))
- `SupplyChainPolicy()` delegates directly to neardirect because Venice and neardirect use the same model-tier container set.
- The policy contains 3 model-tier repositories:
  1. `datadog/agent` with `SigstorePresent` plus a pinned signing-key fingerprint
  2. `certbot/dns-cloudflare` with `ComposeBindingOnly`
  3. `nearaidev/compose-manager` with `FulcioSigned`, GitHub Actions OIDC identity checks, expected source repositories, and `NoDSSE=true`

### Neardirect ([internal/provider/neardirect/policy.go](../../internal/provider/neardirect/policy.go))
- `SupplyChainPolicy()` defines the shared Venice/neardirect model-tier policy.
- `datadog/agent` is accepted as `SigstorePresent` with an exact key fingerprint check.
- `certbot/dns-cloudflare` is `ComposeBindingOnly`, so integrity comes from the attested compose manifest rather than Rekor/Fulcio identity checks.
- `nearaidev/compose-manager` is `FulcioSigned` and must match the GitHub Actions issuer, workflow identity, and source repository allowlist.

### Nearcloud ([internal/provider/nearcloud/policy.go](../../internal/provider/nearcloud/policy.go))
- `SupplyChainPolicy()` starts from the neardirect model-tier policy and adds gateway-tier images.
- `datadog/agent` is marked as both model-tier and gateway-tier.
- Additional gateway-tier repositories are:
  - `nearaidev/dstack-vpc-client` (`FulcioSigned`, `NoDSSE=true`)
  - `nearaidev/dstack-vpc` (`FulcioSigned`, `NoDSSE=true`)
  - `alpine` (`SigstorePresent` only)
  - `nearaidev/cloud-api` (`FulcioSigned`, `NoDSSE=true`)
  - `nearaidev/cvm-ingress` (`FulcioSigned`, `NoDSSE=true`)
- All Fulcio-enforced nearcloud gateway images require the GitHub Actions OIDC issuer and a workflow-specific subject URI plus matching source repository metadata.

### NanoGPT ([internal/provider/nanogpt/policy.go](../../internal/provider/nanogpt/policy.go))
- `SupplyChainPolicy()` declares 10 model-tier repositories, all with `ComposeBindingOnly` provenance.
- The current NanoGPT manifests use tag-based image references rather than `@sha256:` pins, so the policy depends on `compose_binding` rather than Sigstore/Rekor provenance for image identity.
- The repositories are `alpine`, `dstacktee/dstack-ingress`, `dstacktee/vllm-proxy`, `haproxy`, `lmsysorg/sglang`, `mondaylord/vllm-openai`, `phalanetwork/vllm-proxy`, `python`, `redis`, and `vllm/vllm-openai`.

### Chutes ([internal/provider/chutes/policy.go](../../internal/provider/chutes/policy.go))
- Chutes has no `SupplyChainPolicy`; both verify and proxy paths pass `nil`.
- Chutes uses sek8s-specific measurement allowlists for MRTD/RTMR, while still inheriting and expanding the shared `DstackBaseMeasurementPolicy()` MRSEAM baseline.
- `compose_binding`, `sigstore_verification`, and `build_transparency_log` are not the primary enforcement mechanism for Chutes because container admission and runtime integrity are validator-side (`cosign` + IMA) rather than client-visible compose metadata.

## Compose Binding Verification

### Core Helpers ([internal/attestation/compose.go](../../internal/attestation/compose.go))

1. **`VerifyComposeBinding(appCompose, mrConfigID)`**
   - Computes `sha256(appCompose)` over the raw `app_compose` string.
   - Expects MRConfigID to begin with `0x01 || sha256(appCompose)`.
   - Uses `subtle.ConstantTimeCompare` over the 33-byte prefix.
   - Fails on empty or short MRConfigID values and on any prefix mismatch.

2. **`ExtractDockerCompose(appCompose)`**
   - Parses the `app_compose` JSON payload.
   - Returns the `docker_compose_file` string when present.
   - Returns `""` with no error when the field is absent.

3. **`ExtractImageDigests(text)`**
   - Extracts `@sha256:<64 hex>` digests.
   - Deduplicates digests.
   - Caps the result set at `maxImageDigests = 64`.

4. **`ExtractImageRepositories(text)`**
   - Extracts repository names from `@sha256:`-pinned references.
   - Lowercases and trims whitespace.
   - Removes trailing tags while preserving registry ports.

5. **`ExtractImageDigestToRepoMap(text)`**
   - Builds a digest-to-repository map from pinned image references.
   - Keeps the first repository seen for a digest and logs conflicts.

6. **`ExtractComposeDigests(appCompose)`**
   - Prefers `docker_compose_file` when it is present in the JSON payload.
   - Falls back to the raw `app_compose` text when no extracted compose file is available.
   - Returns repositories, digest-to-repository mappings, and digests together as `ComposeDigests`.

7. **`MergeComposeDigests(model, gateway)`**
   - Merges model-tier and gateway-tier digest sets.
   - Uses model digests first, then appends new gateway digests.
   - Preserves first-writer-wins semantics for digest-to-repository conflicts.

## Attestation Report Evaluation

### Verification Factor Layout ([internal/attestation/report.go](../../internal/attestation/report.go))

**Tier 3: Supply Chain & Channel Integrity** includes:
- `evalTLSKeyBinding`
- `evalCPUGPUChain`
- `evalMeasuredModelWeights`
- `evalBuildTransparencyLog`
- `evalCPUIDRegistry`
- `evalComposeBinding`
- `evalSigstoreVerification`
- `evalEventLogIntegrity`

**Tier 4: Gateway Attestation** is appended only when `ReportInput.GatewayTDX != nil` and includes:
- `evalGatewayNonceMatch`
- `evalGatewayTDXQuotePresent`
- `evalGatewayTDXParseDependent`
- `evalGatewayTDXMrseamMrtd`
- `evalGatewayTDXHardwareConfig`
- `evalGatewayTDXBootConfig`
- `evalGatewayTDXReportDataBinding`
- `evalGatewayComposeBinding`
- `evalGatewayCPUIDRegistry`
- `evalGatewayEventLogIntegrity`

### Supply Chain Policy Types

The policy types live in [internal/attestation/report.go](../../internal/attestation/report.go):

```go
type SupplyChainPolicy struct {
	Images []ImageProvenance
}

type ImageProvenance struct {
	Repo           string
	ModelTier      bool
	GatewayTier    bool
	Provenance     ProvenanceType
	KeyFingerprint string
	OIDCIssuer     string
	OIDCIdentity   string
	SourceRepos    []string
	NoDSSE         bool
}

type ProvenanceType int
// FulcioSigned: require Fulcio cert + OIDC issuer/identity + source repo match
// SigstorePresent: require transparency-log presence, optionally fingerprint match
// ComposeBindingOnly: do not require Sigstore presence; trust compose binding
```

The helper methods on `SupplyChainPolicy` (`Lookup`, `AllowedInModel`, `AllowedInGateway`, `HasGatewayImages`, `ModelRepoNames`, `GatewayRepoNames`) drive repo-level policy checks before Rekor provenance is evaluated.

### Build Transparency Log Evaluation

`evalBuildTransparencyLog` runs three stages:

1. **`checkImageRepoPolicy`**
   - Validates every extracted model repository against `AllowedInModel`.
   - Validates every extracted gateway repository against `AllowedInGateway` when the policy has gateway images.
   - Fails if no model repositories were extracted under a configured policy.
   - Fails if gateway repositories are present but the policy does not permit any gateway images.

2. **`buildTransparencyNoRekor`**
   - Fails immediately when a `SupplyChainPolicy` exists but no Rekor provenance was fetched.
   - Skips when no policy exists but a compose hash is present.
   - Skips for Chutes because the attestation payload does not expose container image metadata to the client.
   - Fails otherwise with `no build transparency log`.

3. **`rekorProvenanceResult`**
   - Maps each Rekor record back to an extracted repository using `DigestToRepo`.
   - Uses `classifyRekorEntry` to split entries into Fulcio-verified, Sigstore-present, or failed.
   - For `FulcioSigned` policy entries, `verifyFulcioEntry` enforces DSSE-signature presence unless `NoDSSE=true`, requires a Fulcio certificate, matches OIDC issuer and subject URI in constant time, and checks the source repository against the allowlist.
   - For `SigstorePresent` entries with a configured fingerprint, performs a constant-time fingerprint comparison.
   - Requires verified Rekor SET and inclusion proofs for both Fulcio and Sigstore-only paths.
   - Produces a pass summary with Fulcio count, Sigstore count, and log-integrity counters; otherwise fails on the first policy or verification violation.

When no policy exists, a Fulcio-backed Rekor entry still requires the GitHub Actions OIDC issuer if a certificate is present. Raw-key entries are treated as Sigstore-presence-only.

### Enforce-by-Default vs Allow-Fail

Factors are enforced unless their names appear in the effective `allow_fail` list. `BuildReport()` also promotes `Skip` to `Fail` for enforced factors unless the factor is marked `Deferred`.

**Global `DefaultAllowFail`** includes:
- `tdx_quote_present`
- `tdx_quote_structure`
- `tdx_hardware_config`
- `tdx_boot_config`
- `intel_pcs_collateral`
- `tdx_tcb_current`
- `nvidia_payload_present`
- `nvidia_claims`
- `nvidia_nras_verified`
- `e2ee_capable`
- `e2ee_usable`
- `tls_key_binding`
- `cpu_gpu_chain`
- `measured_model_weights`
- `cpu_id_registry`
- `gateway_tdx_quote_present`
- `gateway_tdx_quote_structure`
- `gateway_tdx_hardware_config`
- `gateway_tdx_boot_config`
- `gateway_tdx_reportdata_binding`
- `gateway_cpu_id_registry`

Because they are absent from `DefaultAllowFail`, the following remain enforced globally unless a provider-specific or config override relaxes them:
- `build_transparency_log`
- `compose_binding`
- `sigstore_verification`
- `event_log_integrity`
- all gateway factors not listed above, including `gateway_nonce_match`, `gateway_tdx_cert_chain`, `gateway_tdx_quote_signature`, `gateway_tdx_debug_disabled`, `gateway_tdx_mrseam_mrtd`, `gateway_compose_binding`, and `gateway_event_log_integrity`

**Provider-specific defaults**:
- `NearcloudDefaultAllowFail` allows only `tdx_hardware_config`, `tdx_boot_config`, `cpu_gpu_chain`, `measured_model_weights`, `cpu_id_registry`, `gateway_tdx_hardware_config`, `gateway_tdx_boot_config`, `gateway_tdx_reportdata_binding`, and `gateway_cpu_id_registry`.
- `NeardirectDefaultAllowFail` allows only `tdx_hardware_config`, `tdx_boot_config`, `cpu_gpu_chain`, `measured_model_weights`, and `cpu_id_registry`.
- `ChutesDefaultAllowFail` allows `tdx_hardware_config`, `tdx_boot_config`, `nvidia_signature`, `nvidia_nras_verified`, `tls_key_binding`, `cpu_gpu_chain`, `measured_model_weights`, `build_transparency_log`, `cpu_id_registry`, `compose_binding`, `sigstore_verification`, and `event_log_integrity`.

**Offline mode** adds `OnlineFactors` to the effective allow-fail list:
- `intel_pcs_collateral`
- `tdx_tcb_current`
- `tdx_tcb_not_revoked`
- `nvidia_nras_verified`
- `e2ee_usable`
- `build_transparency_log`
- `cpu_id_registry`
- `sigstore_verification`
- `gateway_cpu_id_registry`

## Key Security Properties

1. **Cryptographic Safety**
   - `subtle.ConstantTimeCompare` is used for nonce checks, compose-binding prefix checks, Sigstore fingerprint checks, and Fulcio OIDC issuer/identity checks.

2. **Fail-Closed Evaluation**
   - Repository allowlist violations and signer-identity violations fail immediately.
   - Missing `SupplyChainPolicy` disables only policy-driven allowlists and signer requirements; it does not suppress all supply-chain checks.
   - Enforced skipped factors are promoted to failures unless the factor is explicitly deferred.

3. **Gateway-Aware Evidence Handling**
   - The verify path can evaluate model-tier and nearcloud gateway-tier compose bindings separately and merge their digest sets before Sigstore/Rekor checks.
   - Gateway factors are emitted only when the caller populates gateway verification inputs.

4. **Digest Extraction Bounds**
   - `maxImageDigests = 64` limits the number of digests that can trigger Sigstore and Rekor lookups from a single attested compose payload.

5. **Defense in Depth**
   - Measurement policies constrain TDX measurements.
   - Compose binding constrains the attested deployment manifest.
   - Rekor and Fulcio constrain build provenance.
   - Sigstore presence and Rekor log verification constrain transparency-log integrity.
   - Event-log replay constrains RTMR consistency.

## SupplyChainPolicy Flow & Wiring

### Verify / Reverify Path

The CLI entry point in [cmd/teep/main.go](../../cmd/teep/main.go) delegates verification to [internal/verify](../../internal/verify/):
- `runVerification()` calls `verify.Run(...)`.
- `--reverify` calls `verify.Replay(...)` through `runReverify()`.
- `--capture` records attestation HTTP traffic for later replay, but it is mutually exclusive with `--offline`.

Within the verify package:
- [internal/verify/factory.go](../../internal/verify/factory.go) selects the provider-specific `SupplyChainPolicy()` by provider name.
- [internal/verify/verify.go](../../internal/verify/verify.go) verifies model compose binding when `raw.AppCompose` is present and the model TDX quote parsed successfully.
- [internal/verify/attest.go](../../internal/verify/attest.go) verifies nearcloud gateway TDX, gateway REPORTDATA binding, gateway compose binding, and gateway Proof of Cloud when `raw.GatewayIntelQuote` is present.
- [internal/verify/verify.go](../../internal/verify/verify.go) extracts model and gateway compose digests separately, merges them with `MergeComposeDigests`, then checks Sigstore and Rekor across the merged digest set.
- `verify.Run()` populates `ReportInput` with `SupplyChainPolicy`, `ImageRepos`, `GatewayImageRepos`, `DigestToRepo`, `Compose`, `GatewayCompose`, `GatewayTDX`, `GatewayPoC`, `GatewayNonceHex`, and `GatewayEventLog` before calling `BuildReport()`.

### Proxy Path

The proxy path wires the policy through [internal/proxy/proxy.go](../../internal/proxy/proxy.go):
- `teep serve` startup in [cmd/teep/main.go](../../cmd/teep/main.go)
   activates all providers with non-empty resolved API keys before calling
   `proxy.New(...)`.
- `proxy.New(...)` initializes one server instance with the resulting provider
   set, not a single selected provider.
- Inference routing resolves the client model as `provider:model`, selects the
   provider by exact prefix match, and rewrites request bodies so upstreams
   receive only the provider-local upstream model.
- `fromConfig()` populates `Provider.SupplyChainPolicy` with provider-specific hardcoded policies for Venice, neardirect, nearcloud, and NanoGPT.
- `fromConfig()` sets `nil` for phalacloud and chutes.
- `fetchAndVerify()` passes `prov.SupplyChainPolicy` into `attestation.BuildReport()`.
- `verifySupplyChain()` verifies model-side compose binding, extracts model-side compose digests, and performs Sigstore/Rekor checks for those model digests.

Under concurrent multi-provider traffic, provider/model keyed report caches
and report inputs stay isolated after prefix stripping, preventing
cross-provider collisions when two providers offer the same upstream model ID.

Gateway field population in proxy traffic is path-dependent:
- Generic proxy `fetchAndVerify()` in [internal/proxy/proxy.go](../../internal/proxy/proxy.go)
   does not populate gateway fields.
- Nearcloud pinned attestation in
   [internal/provider/nearcloud/pinned.go](../../internal/provider/nearcloud/pinned.go)
   does populate `GatewayTDX`, `GatewayCompose`, `GatewayImageRepos`,
   `GatewayPoC`, and `GatewayEventLog` before `BuildReport()`.
- Neardirect pinned attestation in
   [internal/provider/neardirect/pinned.go](../../internal/provider/neardirect/pinned.go)
   remains model-tier only.

Therefore, gateway-specific supply-chain factors are emitted in verify/reverify
and in nearcloud pinned-proxy flows, but not in the generic proxy
`fetchAndVerify()` path.

### Provider Wiring Sources

The provider-specific policy constructors live in:
- [internal/provider/venice/policy.go](../../internal/provider/venice/policy.go)
- [internal/provider/neardirect/policy.go](../../internal/provider/neardirect/policy.go)
- [internal/provider/nearcloud/policy.go](../../internal/provider/nearcloud/policy.go)
- [internal/provider/nanogpt/policy.go](../../internal/provider/nanogpt/policy.go)

The two `nil` policy cases are hardcoded in both [internal/verify/factory.go](../../internal/verify/factory.go) and [internal/proxy/proxy.go](../../internal/proxy/proxy.go):
- `phalacloud`
- `chutes`

### ReportInput Surface

[internal/attestation/report.go](../../internal/attestation/report.go) accepts the supply-chain inputs through `ReportInput`:

```go
SupplyChainPolicy *SupplyChainPolicy
ImageRepos        []string
GatewayImageRepos []string
DigestToRepo      map[string]string
Compose           *ComposeBindingResult
Sigstore          []SigstoreResult
Rekor             []RekorProvenance
GatewayTDX        *TDXVerifyResult
GatewayPoC        *PoCResult
GatewayNonceHex   string
GatewayNonce      Nonce
GatewayCompose    *ComposeBindingResult
GatewayEventLog   []EventLogEntry
GatewayPolicy     MeasurementPolicy
```

Gateway evaluators are included only when `GatewayTDX` is non-nil.

In serve mode, `ReportInput.Provider` is always the resolved provider prefix
and `ReportInput.Model` is the provider-local upstream model (without the
`provider:` prefix).

### Config Integration Status

Supply-chain policy selection remains hardcoded in Go:
- [internal/config](../../internal/config/) does not define any `SupplyChainPolicy` fields or TOML schema.
- There is no `MergedSupplyChainPolicy()` helper analogous to `MergedMeasurementPolicy()` or `MergedGatewayMeasurementPolicy()`.
- Configuration integrates `allow_fail` lists and measurement policies, but not repository allowlists or Sigstore/Fulcio identity policy.