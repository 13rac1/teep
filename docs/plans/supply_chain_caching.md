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
4. `--update-config` expansion to capture supply chain observations and write
   the full merged policy (hardcoded + configured + observed).
5. `--offline` mode awareness of pinned vs. absent hash values.

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
bounded by max entry count (e.g., 1000). When a cache is full, evict the
oldest inserted entry. This is closer to the current codebase cache patterns
than LRU: the existing report/SPKI caches use TTL-based retention plus
oldest-entry-style eviction at capacity, not recency tracking.

**Fail-closed**: A cache miss always triggers full online verification.
A previous failure result is cached (negative cache) to avoid retrying known
failures within the same process. Cache eviction never results in silent
pass-through.

**Config-change invalidation**: The compose policy cache does not monitor for
config file changes. If the user edits the image allowlist or other config
fields, a process restart is required for the change to take effect. This is
consistent with the existing config-load-once-at-startup pattern.

### 1b. Config-File Cache (Persistent Across Runs)

Verified values written to `teep.toml` by `--update-config`:

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
that the user deliberately removed would violate least surprise.

---

## 4. `--update-config` Expansion

Extends the existing `UpdateConfig()` flow in `internal/config/update.go`.
`--update-config` now writes the **full merged policy** (hardcoded defaults +
existing config + observed values), not just observations. This makes the
output a self-contained config that does not depend on hardcoded defaults,
which is useful for auditing, forking, and offline deployments.

**Currently captures**: TDX measurements (MRSEAM, MRTD, RTMR0-2, gateway
variants).

**New captures** (added to `ObservedMeasurements` or a new `ObservedSupplyChain`
struct):

| Field | Source | When captured |
|-------|--------|---------------|
| Compose hash | `sha256(raw.AppCompose)` | Always (from attestation response) |
| Image repos | `ExtractImageRepositories(dockerCompose)` | Only for `@sha256:`-pinned images under the current implementation |
| Image digests | `ExtractImageDigests(dockerCompose)` | Only for `@sha256:`-pinned images |
| Provenance type | From Rekor/Sigstore results | After successful verification |

**Note**: Under the current implementation, `ExtractImageRepositories` does
not extract repositories from tag-based Compose `image:` entries. That means
tag-based manifests do not produce repository observations here, and any repo
allowlist enforcement described in this plan applies only to digest-pinned
images unless a separate tag-based extractor is added.

**Behavior**:
- Only writes observed values to config if attestation is not blocked (existing
  guard — prevents pinning untrustworthy values).
- Adds new compose hash to `compose_hashes` (deduplicating).
- Adds new verified digests to `pinned_digests` (deduplicating).
- **Writes the effective image allowlist**: union of hardcoded Go defaults,
  existing config values, and any newly observed images. This makes the
  resulting config self-contained.
- **Writes the full merged measurement policy**: union of hardcoded + config +
  observed values (extending the current behavior that only adds observed).

**Full --update-config example output** (extending current behavior):

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

## 5. `--offline` Behavior

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
  - If image digest is NOT pinned → Sigstore verification is not performed
    (offline), but image repo must still match the configured image allowlist.
    The factor becomes non-enforced (allowed to fail) via the existing
    `OnlineFactors` / `WithOfflineAllowFail` mechanism. The factor may still
    evaluate as `Fail`, but it will not block the request.

### Without pinned hashes in config

When `--offline` is set and no `compose_hashes` or `pinned_digests` exist:

- **No online validation** is performed (Sigstore/Rekor calls are skipped).
- **Image names** are only verified against the image allowlist when the
  repository can be extracted from the compose file using the current
  extractor. Today that extractor only handles digest-pinned image references
  such as `image: repo@sha256:...`; tag-based references such as
  `image: repo:tag` do not currently yield an extracted repository, so this
  local-only allowlist check cannot be relied on for them in offline mode
  until extractor support is added (see Section 5a below).
- Supply chain factors that require online access (`build_transparency_log`,
  `sigstore_verification`) are added to `allow_fail` via the existing
  `OnlineFactors` / `WithOfflineAllowFail` mechanism. This makes them
  non-enforced (allowed to fail) — the factor may still evaluate as `Fail` or
  `Skip`, but it will not block the request.

**Note**: `WithOfflineAllowFail` adds factor names to the `allow_fail` list;
it does not change the factor evaluation result itself. A factor that evaluates
as `Fail` remains `Fail` — it just becomes non-enforced, so it does not block.
A factor that evaluates as `Skip` stays `Skip` and is not promoted to `Fail`
because it is non-enforced.

### Startup warnings for insufficient offline config

When `--offline` is set, teep should inspect the effective config at startup
and emit log warnings if there are insufficient configured hashes or images to
enforce all supply chain factors. Specifically:

- If `compose_hashes` is empty or absent for the provider, warn that
  `compose_binding` will be non-enforced (allowed to fail) in offline mode.
- If `pinned_digests` is empty or absent, warn that `sigstore_verification`
  and `build_transparency_log` will be non-enforced.
- If the image allowlist is empty or absent, warn that image repo allowlist
  checks will be skipped.
- Each warning should name the specific factor(s) being demoted to allow_fail
  as a result (e.g., `"--offline: no pinned_digests configured for provider
  'neardirect'; factors [sigstore_verification, build_transparency_log]
  demoted to allow_fail"`).

This ensures operators understand the security posture difference without
making `--offline` always fail when the config lacks pinned values.

### Summary table

| Condition | Compose hash | Image digest | Image repo |
|-----------|-------------|-------------|------------|
| Online, cache hit | Cached → skip re-eval | Cached → skip Sigstore | N/A (compose validated) |
| Online, cache miss | Full eval | Full Sigstore/Rekor | Checked against allowlist |
| Offline, pinned hash | Pinned → pass | Pinned → pass | N/A (compose validated) |
| Offline, unpinned hash | Fail (non-enforced) | Fail (non-enforced) | Checked against allowlist |
| Offline, no config | Fail (non-enforced) | Fail (non-enforced) | Checked against allowlist |

### 5a. Tag-Based Image Caching and `allow_any_version`

The current `ExtractImageRepositories` only handles `@sha256:`-pinned image
references. To support tag-based images (common in NanoGPT and other dstack
providers), the plan adds tag-aware caching:

**Specific release tags**: If a specific release tag for an image is
authenticated via Sigstore/Rekor verification, the implementation must resolve
and persist the corresponding immutable image digest and treat that digest as
the cache key / trust anchor. The original **full canonical `image:tag`**
(e.g., `vllm/vllm-openai:v0.4.2`) may be stored only as metadata for operator
readability, but it must not by itself be treated like a hash pin for offline
authentication because tags are mutable in many registries. Offline reuse is
allowed only when the previously verified digest is present and matches the
cached policy entry, or when a registry-side tag immutability guarantee is an
explicit prerequisite and is verified by policy.

**Generic / branch tags**: For image references that use non-specific tags
such as `latest`, `head`, `main`, or similar branch-tracking tags, the version
cannot be pinned because the same tag may resolve to different images over
time. For these, `--update-config` emits an explicit `allow_any_version = true`
field in the image config entry. This means the image is considered
authenticated by its presence in the allowlist without requiring further online
update verification. This option is **on by default** for images where a
specific release cannot be determined, but is always **explicitly present in
the config** so operators can see what is happening just from reading the
cached config.

**Config example** (Option B format):

```toml
# Specific release tag — cached like a hash, no allow_any_version needed
[providers.nanogpt.supply_chain.images."vllm/vllm-openai"]
model_tier = true
provenance = "sigstore_present"
pinned_tag = "v0.4.2"  # full canonical tag, authenticated via sigstore

# Generic tag — allow_any_version is explicit
[providers.nanogpt.supply_chain.images."alpine"]
model_tier = true
provenance = "compose_binding_only"
allow_any_version = true  # tag is 'latest' or similar; no specific release to pin

# Digest-pinned — standard behavior, no special fields needed
[providers.neardirect.supply_chain.images."datadog/agent"]
model_tier = true
provenance = "sigstore_present"
key_fingerprint = "25bcab4ec8eede1e3091a14692126798c23986832ae6e5948d6f7eb0a928ab0b"
```

**Behavior summary**:
- `pinned_tag` present → image at that exact tag is treated as authenticated
  (cacheable across restarts, no online re-verification required)
- `allow_any_version = true` → any version of this image is accepted based on
  allowlist membership alone (no digest or tag pinning)
- Neither present → standard behavior (digest-based verification via Sigstore)

---

## 6. Implementation Phases

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
    ModelTier        bool
    GatewayTier      bool
    Provenance       string    // "fulcio_signed" | "sigstore_present" | "compose_binding_only"
    KeyFingerprint   string
    OIDCIssuer       string
    OIDCIdentity     string
    SourceRepos      []string
    NoDSSE           bool
    PinnedTag        string    // full canonical tag authenticated via sigstore (e.g., "v0.4.2")
    AllowAnyVersion  bool      // true → any version accepted (for generic/branch tags)
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

Both should follow the existing bounded cache pattern: oldest-entry eviction
at capacity, matching the report/SPKI cache designs.

**Cache consultation points**:
- `evalBuildTransparencyLog()` — check image Sigstore cache before calling
  `FetchRekorProvenance`/`CheckSigstoreDigests`.
- `evalComposeBinding()` — after compose binding passes, record compose hash
  in cache. Before evaluating image policy, check compose cache.

*Depends on*: Phase 1 (to know which digests are in `pinned_digests`).
*Parallel with*: Phase 3 (update.go changes are independent).

### Phase 3: --update-config Full Merged Output

Extend `UpdateConfig()` to capture observed supply chain values **and** write
the full merged policy (hardcoded + config + observed).

**Files to modify**:
- `internal/config/update.go` — Add `ObservedSupplyChain` struct; extend
  `UpdateConfig()` to merge compose hashes, pinned digests, and the full
  image allowlist into `[providers.X.supply_chain]`. Add `updateSupplyChain`
  type with TOML tags.
- `internal/config/update_test.go` — Test merge/dedup logic for compose hashes,
  pinned digests, and three-way image allowlist union.
- `cmd/teep/main.go` — Extract compose hash and verified digests from report
  metadata and Sigstore results; load hardcoded defaults; pass all to
  `UpdateConfig()`.

*Depends on*: Phase 1 (config types).

### Phase 4: --offline Pinned Hash Support

Wire up offline mode to consult config-file pinned hashes.

**Files to modify**:
- `internal/attestation/report.go` — In `evalBuildTransparencyLog()` and
  `evalSigstoreVerification()`, check `ReportInput` for pinned compose hashes
  and digests before skipping. If pinned hash matches, return `Pass` with
  detail "pinned in config" instead of `Skip`.
- `internal/attestation/report_test.go` — Test offline+pinned pass, offline
  +unpinned non-enforced fail, offline+missing-config non-enforced fail.

*Depends on*: Phase 1 (config types available in ReportInput), Phase 2 helpful
but not required.

### Phase 5: Integration and Documentation

- `internal/integration/` — Integration tests for --update-config with supply
  chain fields.
- `teep.toml.example` — Full supply chain section documentation.
- `docs/measurement_allowlists.md` — Update to cover supply chain caching.
- `README.md` / `README_ADVANCED.md` — Document new config sections.

*Depends on*: All previous phases.

---

## 7. Verification

1. `make check` passes after each phase.
2. **Unit tests** for each phase:
   - Config parsing: valid TOML round-trips, unknown keys rejected, bad
     provenance values rejected, missing required fields rejected.
   - Cache: hit/miss/eviction/negative-cache behavior.
   - UpdateConfig: compose hashes, pinned digests, and image allowlist merge
     correctly; deduplication works; backup created; three-way union produces
     expected output.
   - Offline pinning: compose hash match → Pass, digest match → Pass,
     no match → Fail (non-enforced).
3. `make integration` with live providers (after Phase 5).
4. `make reports` to verify no regressions in provider verification.
5. Manual: run `teep verify neardirect --model ... --update-config`, inspect
   output config for supply_chain section including image allowlist and
   pinned hashes.

---

## 8. Decisions

- **No separate `--merge-config` flag**: `--update-config` always writes the
  full merged policy (hardcoded + config + observed). This produces a
  self-contained config without requiring a second flag. The original
  incremental-only behavior is not preserved as a separate mode.
- **Image allowlist merge**: Config replaces hardcoded (not union) for normal
  runtime operation. `--update-config` output is the union of all sources.
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
- **Compose hash as trust anchor**: A pinned compose hash causes policy
  evaluation to pass without re-evaluating the image allowlist, even if the
  allowlist has changed since the hash was pinned (e.g., across teep versions
  or after user config edits). This is intentional: the compose was fully
  validated against the effective policy at pinning time. To invalidate a
  pinned hash after an allowlist change, remove it from the config file.

---

## 9. Further Considerations

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

3. **Tag-based image versioning**: Images referenced by tag (not `@sha256:`)
   are handled by two new config fields: `pinned_tag` (for specific release
   tags authenticated via Sigstore) and `allow_any_version` (for generic/branch
   tags where a specific release cannot be determined). See Section 5a for
   details. This replaces the earlier approach of always re-verifying tag-based
   images, and gives operators explicit visibility into which images are
   version-locked vs. version-flexible.
