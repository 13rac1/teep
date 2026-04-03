# Plan: Supply Chain Policy Caching and Configuration

## Background

Today, `SupplyChainPolicy` (the allowed container image list for each dstack
provider) is 100% hardcoded in Go — one `policy.go` file per provider package.
There is no config file support, no caching of validated results, and no way to
pin observed supply chain values the way `--update-config` already pins TDX
measurement registers.

This plan adds:

1. User-configurable image allowlists in `teep.toml`.
2. Compose-hash-based caching (skip re-evaluation when the compose manifest
   hasn't changed).
3. Global image-digest caching (skip Sigstore/Rekor re-verification for images
   pinned by `@sha256:` digest).
4. `--update-config` expansion to capture supply chain observations.
5. A new `--merge-config` flag that unions hardcoded, configured, and observed
   values.
6. `--offline` mode awareness of pinned vs. absent hash values.

**Scope**: dstack providers only (venice, neardirect, nearcloud, nanogpt).
Chutes (cosign/IMA) and phalacloud are out of scope; they use different supply
chain models that don't involve docker-compose attestation.

---

## 1. Caching Layers

### 1a. In-Memory Caches (Runtime, No Config Impact)

Two new caches, both process-lifetime (no TTL/expiration), used during `serve`
and `verify` to reduce network traffic:

| Cache | Key | Value | Scope |
|-------|-----|-------|-------|
| Compose policy cache | `sha256(app_compose)` | policy evaluation result (pass/fail + image list) | Per-provider |
| Image Sigstore cache | `sha256:<digest>` | Sigstore/Rekor verification result (pass/fail) | Global (cross-provider) |

**Compose policy cache**: When a new attestation arrives, compute
`sha256(app_compose)`. If a matching entry exists, skip image-allowlist
evaluation and Sigstore/Rekor checks entirely — the compose manifest is
identical, so the exact same images are attested. If the hash is new
(cache miss), perform full image extraction, allowlist checks, and
Sigstore/Rekor verification, then cache the result.

**Image Sigstore cache**: After a successful Sigstore/Rekor verification of
an image digest, cache the result globally. This cache is only consulted for
images that are pinned by `@sha256:` in their docker-compose (i.e., the image
reference includes an immutable digest). Tag-based references (e.g.,
`image:latest`) bypass this cache because the same tag can point to different
digests over time. This cache is global because a given `sha256:<digest>` is
the same image regardless of which provider uses it.

**Eviction**: No TTL. Entries live for the process lifetime. Both caches are
bounded by max entry count (e.g., 1000) with LRU eviction, matching existing
cache patterns in the codebase (`proxy.go` report cache, SPKI cache).

**Fail-closed**: A cache miss always triggers full online verification.
A previous failure result is cached (negative cache) to avoid retrying known
failures within the same process. Cache eviction never results in silent
pass-through.

### 1b. Config-File Cache (Persistent Across Runs)

Verified values written to `teep.toml` by `--update-config` or `--merge-config`:

| Config field | Scope | Purpose |
|-------|-------|-------|
| `compose_hashes` | Per-provider | Pinned compose manifest hashes |
| `pinned_digests` | Per-provider supply chain section | Image digests observed in compose, verified via Sigstore |
| Image allowlist | Per-provider supply chain section | Image repo allowlist (overrides/extends hardcoded policy) |

**Compose hashes**: A list of `sha256:...` strings. When the compose hash from
a new attestation matches a pinned value, the images within that compose do not
need to be re-evaluated against the allowlist. If the compose hash is new/different,
full image extraction and verification proceeds.

**Pinned digests**: Per-provider list of `sha256:...` digests that have been observed
and verified via Sigstore/Rekor. When a known digest appears in a new (unrecognized)
compose manifest, its Sigstore verification can be skipped. Only applies to images
pinned by `@sha256:` in the docker-compose YAML.

---

## 2. Config File Format — Two Options

Both options share the same semantics. The difference is TOML surface syntax.

### Option A: Array of Tables (mirrors Go struct)

```toml
[providers.neardirect.supply_chain]
# Pinned compose manifest hashes. A matching hash means the compose file
# does not need to be re-evaluated against the image allowlist.
compose_hashes = [
  "sha256:a1b2c3d4e5f6...",
]

# Image digests that have been verified via Sigstore/Rekor.
# Only used for images pinned by @sha256: in docker-compose.
pinned_digests = [
  "sha256:1234567890ab...",
  "sha256:fedcba098765...",
]

# Image allowlist. Each [[images]] entry defines one allowed image repo.
[[providers.neardirect.supply_chain.images]]
repo = "datadog/agent"
model_tier = true
provenance = "sigstore_present"
key_fingerprint = "25bcab4ec8eede1e3091a14692126798c23986832ae6e5948d6f7eb0a928ab0b"

[[providers.neardirect.supply_chain.images]]
repo = "certbot/dns-cloudflare"
model_tier = true
provenance = "compose_binding_only"

[[providers.neardirect.supply_chain.images]]
repo = "nearaidev/compose-manager"
model_tier = true
provenance = "fulcio_signed"
no_dsse = true
oidc_issuer = "https://token.actions.githubusercontent.com"
oidc_identity = "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master"
source_repos = ["nearai/compose-manager", "https://github.com/nearai/compose-manager"]

# NearCloud extends neardirect with gateway images:
[[providers.nearcloud.supply_chain.images]]
repo = "nearaidev/dstack-vpc"
gateway_tier = true
provenance = "fulcio_signed"
no_dsse = true
oidc_issuer = "https://token.actions.githubusercontent.com"
oidc_identity = "https://github.com/nearai/dstack-vpc/.github/workflows/build.yml@refs/heads/main"
source_repos = ["nearai/dstack-vpc", "https://github.com/nearai/dstack-vpc"]

# NanoGPT: all compose-binding-only (no Sigstore)
[[providers.nanogpt.supply_chain.images]]
repo = "alpine"
model_tier = true
provenance = "compose_binding_only"

[[providers.nanogpt.supply_chain.images]]
repo = "vllm/vllm-openai"
model_tier = true
provenance = "compose_binding_only"
# ... (remaining nanogpt images follow same pattern)
```

**Pros**: Direct 1:1 mapping to Go `ImageProvenance` struct. Familiar TOML
array-of-tables idiom. Each image is a clearly delineated block.

**Cons**: Verbose for providers with many images (nanogpt has 10). TOML
array-of-tables syntax (`[[...]]`) can feel heavy.

### Option B: Map-Based (repo name as key)

```toml
[providers.neardirect.supply_chain]
compose_hashes = [
  "sha256:a1b2c3d4e5f6...",
]
pinned_digests = [
  "sha256:1234567890ab...",
  "sha256:fedcba098765...",
]

[providers.neardirect.supply_chain.images."datadog/agent"]
model_tier = true
provenance = "sigstore_present"
key_fingerprint = "25bcab4ec8eede1e3091a14692126798c23986832ae6e5948d6f7eb0a928ab0b"

[providers.neardirect.supply_chain.images."certbot/dns-cloudflare"]
model_tier = true
provenance = "compose_binding_only"

[providers.neardirect.supply_chain.images."nearaidev/compose-manager"]
model_tier = true
provenance = "fulcio_signed"
no_dsse = true
oidc_issuer = "https://token.actions.githubusercontent.com"
oidc_identity = "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master"
source_repos = ["nearai/compose-manager", "https://github.com/nearai/compose-manager"]

# NanoGPT: concise for compose-binding-only images
[providers.nanogpt.supply_chain.images."alpine"]
model_tier = true
provenance = "compose_binding_only"

[providers.nanogpt.supply_chain.images."vllm/vllm-openai"]
model_tier = true
provenance = "compose_binding_only"
```

**Pros**: More concise. Repo name is a natural key. Easier to visually scan.
`BurntSushi/toml` supports `map[string]ImageProvenanceConfig` natively.

**Cons**: Quoted keys for repos with `/` (e.g., `"datadog/agent"`). Map
ordering not guaranteed in TOML (minor — sort on write). Less obvious 1:1
mapping to the Go struct.

### Recommendation

Option B is recommended. It is more concise, particularly for providers like
nanogpt that have many compose-binding-only images. The quoted key is a minor
visual cost that buys significant readability. The `BurntSushi/toml` library
handles quoted table keys without issue.

---

## 3. Config Merge Semantics

Three-layer merge matching the existing `MergedMeasurementPolicy()` pattern:

| Priority | Source | Description |
|----------|--------|-------------|
| 1 (highest) | Per-provider TOML | `[providers.X.supply_chain]` |
| 2 | Global TOML | `[supply_chain]` (future: cross-provider image defaults) |
| 3 (lowest) | Go hardcoded | `provider.SupplyChainPolicy()` |

**Per-field merge rules**:

- **`images`**: If the config defines *any* images for a provider, the config
  list **replaces** the hardcoded list entirely (same as measurement policy:
  "most specific non-empty layer wins"). This prevents accidental merging of
  stale hardcoded entries with user-customized lists.
- **`compose_hashes`**: Config-only. No hardcoded defaults (hashes are
  inherently instance-specific).
- **`pinned_digests`**: Config-only. No hardcoded defaults (observed values).

**Rationale for replace-not-merge on images**: If a user pins a specific image
list, they likely want exactly that list. Silently merging in hardcoded images
that the user deliberately removed would violate least surprise. However,
`--merge-config` (see Section 5) explicitly unions all three sources.

---

## 4. `--update-config` Expansion

Extends the existing `UpdateConfig()` flow in `internal/config/update.go`.

**Currently captures**: TDX measurements (MRSEAM, MRTD, RTMR0-2, gateway
variants).

**New captures** (added to `ObservedMeasurements` or a new `ObservedSupplyChain`
struct):

| Field | Source | When captured |
|-------|--------|---------------|
| Compose hash | `sha256(raw.AppCompose)` | Always (from attestation response) |
| Image repos | `ExtractImageRepositories(dockerCompose)` | Always |
| Image digests | `ExtractImageDigests(dockerCompose)` | Only for `@sha256:`-pinned images |
| Provenance type | From Rekor/Sigstore results | After successful verification |

**Behavior**:
- Only writes observed values to config if attestation is not blocked (existing
  guard — prevents pinning untrustworthy values).
- Adds new compose hash to `compose_hashes` (deduplicating).
- Adds new verified digests to `pinned_digests` (deduplicating).
- Does **not** modify the image allowlist (images section). Image allowlists
  are structural policy, not observed values.

**Full --update-config example output** (extending current behavior):

```toml
[providers.neardirect]
base_url = "https://completions.near.ai"
api_key_env = "NEARAI_API_KEY"

[providers.neardirect.policy]
mrseam_allow = ["49b66faa451d19ebb..."]
mrtd_allow = ["b24d3b24e9e3c160..."]
rtmr0_allow = ["bc122d143ab76856..."]
rtmr1_allow = ["c0445b704e4c4813..."]
rtmr2_allow = ["564622c7ddc55a53..."]

[providers.neardirect.supply_chain]
compose_hashes = [
  "sha256:e3b0c44298fc1c14...",
]
pinned_digests = [
  "sha256:1234567890abcdef...",
  "sha256:fedcba0987654321...",
]
```

---

## 5. `--merge-config` (New Flag)

`teep verify PROVIDER --model MODEL --merge-config`

**Purpose**: Produce a config file that is the union of all three sources:
hardcoded Go defaults, existing config file values, and freshly observed
attestation values.

**Difference from `--update-config`**:

| Behavior | `--update-config` | `--merge-config` |
|----------|-------------------|-------------------|
| Image allowlist | Not written (policy, not observation) | Written: union of hardcoded + config + observed |
| Compose hashes | Adds observed to existing | Adds observed to existing |
| Pinned digests | Adds observed to existing | Adds observed to existing |
| Measurement policy | Adds observed to existing | Writes merged (hardcoded + config + observed) |
| Use case | Pin observations incrementally | Export full effective config |

**Key behavior**: `--merge-config` writes the image allowlist because it is
meant to produce a self-contained config that does not depend on hardcoded
defaults. This is useful for:
- Auditing the effective policy.
- Forking/customizing the policy (e.g., removing an image the user doesn't
  expect, or adding a new one).
- Offline deployments where hardcoded defaults may change across teep versions.

**Merge-config output example** (full self-contained config):

```toml
[providers.neardirect]
base_url = "https://completions.near.ai"
api_key_env = "NEARAI_API_KEY"

[providers.neardirect.policy]
mrseam_allow = [
  "49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6",
  "7bf063280e94fb051f5dd7b1fc59ce9aac42bb961df8d44b709c9b0ff87a7b4df648657ba6d1189589feab1d5a3c9a9d",
]
mrtd_allow = ["b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217"]
rtmr0_allow = ["bc122d143ab768565ba5c3774ff5f03a63c89a4df7c1f5ea38d3bd173409d14f8cbdcc36d40e703cccb996a9d9687590"]
rtmr1_allow = ["c0445b704e4c48139496ae337423ddb1dcee3a673fd5fb60a53d562f127d235f11de471a7b4ee12c9027c829786757dc"]
rtmr2_allow = ["564622c7ddc55a53272cc9f0956d29b3f7e0dd18ede432720b71fd89e5b5d76cb0b99be7b7ff2a6a92b89b6b01643135"]

[providers.neardirect.supply_chain]
compose_hashes = [
  "sha256:e3b0c44298fc1c14...",
]
pinned_digests = [
  "sha256:1234567890abcdef...",
  "sha256:fedcba0987654321...",
]

[providers.neardirect.supply_chain.images."datadog/agent"]
model_tier = true
provenance = "sigstore_present"
key_fingerprint = "25bcab4ec8eede1e3091a14692126798c23986832ae6e5948d6f7eb0a928ab0b"

[providers.neardirect.supply_chain.images."certbot/dns-cloudflare"]
model_tier = true
provenance = "compose_binding_only"

[providers.neardirect.supply_chain.images."nearaidev/compose-manager"]
model_tier = true
provenance = "fulcio_signed"
no_dsse = true
oidc_issuer = "https://token.actions.githubusercontent.com"
oidc_identity = "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master"
source_repos = ["nearai/compose-manager", "https://github.com/nearai/compose-manager"]
```

---

## 6. `--offline` Behavior

### With pinned hashes in config

When `--offline` is set and the config file contains `compose_hashes` and/or
`pinned_digests`:

- **Compose hash match**: Compose hash found in `compose_hashes` →
  compose policy evaluation passes. No Sigstore/Rekor checks needed (images
  already validated when the hash was pinned).
- **Compose hash mismatch**: Compose hash NOT in `compose_hashes` →
  extract images from compose. For each image:
  - If image digest is in `pinned_digests` → Sigstore verification passes
    (treated as pinned, not skipped).
  - If image digest is NOT pinned → Sigstore verification is skipped
    (offline), but image repo must still match the configured image allowlist.
    Factor result: `Skip` (allowed to fail in offline mode per existing
    `OnlineFactors` mechanism).

### Without pinned hashes in config

When `--offline` is set and no `compose_hashes` or `pinned_digests` exist:

- **No online validation** is performed (Sigstore/Rekor calls are skipped).
- **Image names** extracted from the compose file are still verified against
  the image allowlist (hardcoded or configured). This is a local-only check
  that requires no network access.
- Supply chain factors that require online access (`build_transparency_log`,
  `sigstore_verification`) are added to `allow_fail` via the existing
  `OnlineFactors` mechanism, so they degrade to `Skip (allowed)` instead of
  `Fail (enforced)`.

### Summary table

| Condition | Compose hash | Image digest | Image repo |
|-----------|-------------|-------------|------------|
| Online, cache hit | Cached → skip re-eval | Cached → skip Sigstore | N/A (compose validated) |
| Online, cache miss | Full eval | Full Sigstore/Rekor | Checked against allowlist |
| Offline, pinned hash | Pinned → pass | Pinned → pass | N/A (compose validated) |
| Offline, unpinned hash | Skip (allow-fail) | Skip (allow-fail) | Checked against allowlist |
| Offline, no config | Skip (allow-fail) | Skip (allow-fail) | Checked against allowlist |

---

## 7. Implementation Phases

### Phase 1: Config Structure and Parsing

Add supply chain policy types to config and wire up TOML deserialization.

**Files to modify**:
- `internal/config/config.go` — Add `SupplyChainConfig` struct with TOML tags,
  add `SupplyChain` field to provider config, add parsing/validation, reject
  unknown `provenance` values.
- `internal/config/config_test.go` — Test parsing of new fields, unknown-key
  rejection, validation of provenance enum.
- `teep.toml.example` — Add commented supply chain examples.

**New types** (in config package):
```
SupplyChainConfig {
    ComposeHashes  []string
    PinnedDigests  []string
    Images         map[string]ImageConfig  // Option B: repo name as key
}
ImageConfig {
    ModelTier      bool
    GatewayTier    bool
    Provenance     string  // "fulcio_signed" | "sigstore_present" | "compose_binding_only"
    KeyFingerprint string
    OIDCIssuer     string
    OIDCIdentity   string
    SourceRepos    []string
    NoDSSE         bool
}
```

**New function**: `MergedSupplyChainPolicy(providerName, cfg)` — three-layer
merge following existing `MergedMeasurementPolicy()` pattern. Returns
`*attestation.SupplyChainPolicy`.

*Depends on*: nothing. Can start immediately.

### Phase 2: In-Memory Caching

Add compose-hash and image-digest caches to the proxy and verify paths.

**Files to modify**:
- `internal/attestation/report.go` — Accept optional cache in `ReportInput`;
  consult cache before compose policy evaluation and Sigstore checks; populate
  cache after successful verification.
- `internal/proxy/proxy.go` — Instantiate caches at server startup; pass to
  `ReportInput`.
- `cmd/teep/main.go` — Instantiate caches for `verify` command; pass to
  `ReportInput`.

**New types** (in attestation or a new `internal/cache` package):
```
ComposePolicyCache  — key: sha256 hex string, value: policy result
ImageSigstoreCache  — key: sha256 hex string, value: Sigstore/Rekor result
```

Both should follow the existing LRU+bounded pattern used by the SPKI cache.

**Cache consultation points**:
- `evalBuildTransparencyLog()` — check image Sigstore cache before calling
  `FetchRekorProvenance`/`CheckSigstoreDigests`.
- `evalComposeBinding()` — after compose binding passes, record compose hash
  in cache. Before evaluating image policy, check compose cache.

*Depends on*: Phase 1 (to know which digests are in `pinned_digests`).
*Parallel with*: Phase 3 (update.go changes are independent).

### Phase 3: --update-config Supply Chain Capture

Extend `UpdateConfig()` to capture observed compose hashes and image digests.

**Files to modify**:
- `internal/config/update.go` — Add `ObservedSupplyChain` struct; extend
  `UpdateConfig()` to merge compose hashes and pinned digests into
  `[providers.X.supply_chain]`. Add `updateSupplyChain` type with TOML tags.
- `internal/config/update_test.go` — Test merge/dedup logic for compose hashes
  and pinned digests.
- `cmd/teep/main.go` — Extract compose hash and verified digests from report
  metadata and Sigstore results; pass to `UpdateConfig()`.

*Depends on*: Phase 1 (config types).

### Phase 4: --merge-config Flag

Add the new CLI flag and merge-all-sources logic.

**Files to modify**:
- `cmd/teep/main.go` — Add `--merge-config` flag to `verify` command. When
  set, call new `MergeConfig()` function instead of `UpdateConfig()`.
- `internal/config/update.go` — Add `MergeConfig()` that:
  1. Loads config file.
  2. Loads hardcoded defaults (`SupplyChainPolicy()`, `DefaultMeasurementPolicy()`).
  3. Merges observed values.
  4. Unions all image allowlists (hardcoded + config + observed).
  5. Writes merged result.
- `internal/config/update_test.go` — Test three-way merge for images.

*Depends on*: Phase 1, Phase 3.

### Phase 5: --offline Pinned Hash Support

Wire up offline mode to consult config-file pinned hashes.

**Files to modify**:
- `internal/attestation/report.go` — In `evalBuildTransparencyLog()` and
  `evalSigstoreVerification()`, check `ReportInput` for pinned compose hashes
  and digests before skipping. If pinned hash matches, return `Pass` with
  detail "pinned in config" instead of `Skip`.
- `internal/attestation/report_test.go` — Test offline+pinned pass, offline
  +unpinned skip, offline+missing-config skip.

*Depends on*: Phase 1 (config types available in ReportInput), Phase 2 helpful
but not required.

### Phase 6: Integration and Documentation

- `internal/integration/` — Integration tests for --update-config and
  --merge-config with supply chain fields.
- `teep.toml.example` — Full supply chain section documentation.
- `docs/measurement_allowlists.md` — Update to cover supply chain caching.
- `README.md` / `README_ADVANCED.md` — Document new flags and config sections.

*Depends on*: All previous phases.

---

## 8. Verification

1. `make check` passes after each phase.
2. **Unit tests** for each phase:
   - Config parsing: valid TOML round-trips, unknown keys rejected, bad
     provenance values rejected, missing required fields rejected.
   - Cache: hit/miss/eviction/negative-cache behavior.
   - UpdateConfig: compose hashes and pinned digests merge correctly,
     deduplication works, backup created.
   - MergeConfig: three-way union produces expected output.
   - Offline pinning: compose hash match → Pass, digest match → Pass,
     no match → Skip (allowed).
3. `make integration` with live providers (after Phase 6).
4. `make reports` to verify no regressions in provider verification.
5. Manual: run `teep verify neardirect --model ... --update-config`, inspect
   output config for supply_chain section. Run again with `--merge-config`,
   verify image allowlist is written.

---

## 9. Decisions

- **Image allowlist merge**: Config replaces hardcoded (not union) for normal
  operation. `--merge-config` explicitly unions all sources.
- **Compose hash cache**: Per-provider (different providers may have different
  compose files with the same images).
- **Image digest cache**: Global (same digest = same image regardless of
  provider).
- **Pinned digests scope**: Per-provider in config (user controls which
  providers trust which digests). Global in-memory cache (same image is same
  image).
- **provenance enum**: String in TOML (`"fulcio_signed"`, `"sigstore_present"`,
  `"compose_binding_only"`), validated at config load time. Unknown values
  rejected at startup (fail-closed).
- **Chutes/phalacloud**: Excluded from this plan. Chutes uses cosign/IMA (no
  docker-compose). PhalaCloud has no supply chain policy yet.

---

## 10. Further Considerations

1. **Global supply chain section**: A `[supply_chain]` top-level section could
   define default images shared across all providers (e.g., `datadog/agent`
   appears in both neardirect and nearcloud). This is a natural extension but
   adds merge complexity. Recommend deferring to a follow-up.

2. **Config-file digest scope**: Pinned digests are per-provider in the config
   file but cached globally in memory. If a user wants to restrict which
   providers trust a specific digest, the per-provider config is the control
   point. However, the same digest verified by provider A could be silently
   reused in provider B's in-memory cache. Acceptable because a sha256 digest
   is an immutable identifier — if it passes Sigstore for one provider, it
   passes for all.

3. **Sigstore re-verification for tag-based images**: Images referenced by tag
   (not `@sha256:`) cannot use the global digest cache because the tag may
   resolve to a different digest. These images must be re-verified via Sigstore
   on every new compose hash. This is the correct security behavior but means
   providers like nanogpt (all ComposeBindingOnly, tag-based) see no benefit
   from the Sigstore cache — which is fine because they don't use Sigstore
   anyway.
