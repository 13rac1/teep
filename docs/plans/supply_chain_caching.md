# Plan: Attestation Cache (`teep cache`)

## 1. Goal

All data currently exempted by `--offline` should be cached post-authentication,
and all data currently obtained by `--update-config` should instead be obtained
by a dedicated `teep cache` command, such that the full attestation report can
be rebuilt and verified with zero online activity so long as the cached data is
fresh.

This replaces the current `--update-config` / `--config-out` flags on
`teep verify` with a standalone `teep cache` command and a dedicated cache file
separate from the user config (`teep.toml`). TDX register pinning data formerly stored in the config will now be stored in this cache file. Do not preserve backwards compatibility or old code. Remove all support for config file TDX pinning fields.

---

## 2. Command Design

### 2a. `teep cache`

```
teep cache <provider> --model <model>     # cache one model
teep cache <provider> --all-models        # cache all known models for provider
teep cache <provider> --model <m1>,<m2>   # cache specific models
```

**Behavior**:
1. For each requested (provider, model) pair, fetch attestation, run full
   online verification (TDX, NVIDIA NRAS, Intel PCS, Sigstore/Rekor, Proof
   of Cloud, E2EE test).
2. Write all authenticated verification results to the cache file.
3. **Merge semantics**: replace entries for the specified provider + model(s)
   but preserve unrelated providers and models already in the cache file.
4. The cache file location defaults to `$TEEP_CACHE_FILE` or
   `~/.config/teep/cache.yaml`. Overridable with `--cache-file <path>`
   or with `attestation_cache_file` field in the teep toml config.
5. If attestation is blocked (report would be blocked), refuse to write cache
   for that model — same safety guard as the current `--update-config`.

**Flags**:
- `--model <name>` / `--all-models` (required, mutually exclusive)
- `--cache-file <path>` (optional override)
- `--offline` is NOT supported on `teep cache` — caching requires online access

### 2b. Changes to `teep verify`

- Remove `--update-config` and `--config-out` flags.
- Add `--cache-file <path>` flag (optional; defaults to `$TEEP_CACHE_FILE` or
  `~/.config/teep/cache.yaml`).
- `teep verify` reads the cache file if present and uses cached data for any
  online factors. If a cache entry is stale or invalidated (e.g., compose hash
  changed), it re-fetches live unless `--offline` is set. If `--offline` is
  set, the affected factor is evaluated using the normal offline behavior
  (for example, `Skip` if the factor cannot be refreshed), and enforcement
  still depends on the configured `allow_fail` set and offline handling for
  online-only factors.
- When stale entries are encountered, emit `slog.Info` (notice-level) logs
  explaining what was stale, whether it was re-fetched, and if offline, what
  factor result was returned and whether that result is blocking under the
  normal enforcement rules.

### 2c. Changes to `teep serve`

- Add `--cache-file <path>` flag (same default).
- Same cache consultation logic as `teep verify`: use cached data, re-fetch
  stale entries live, emit notice logs on staleness.
- **Memory-only cache**: Even without a cache file, `teep serve` creates an
  in-memory cache at startup (using the same cache data structures and code
  paths as `teep cache`). Subsequent re-attestations of the same (provider,
  model) benefit from cached Sigstore/Rekor, Intel PCS, NVIDIA NRAS, and
  Proof of Cloud results without re-fetching. The memory-only cache is
  initialized empty and populated as attestations are performed.
- **Authenticated write-back**: When `teep serve` (or `teep verify` with a
  cache file) encounters changes it can fully authenticate, it updates the
  cache file:
  - New compose hash where all images pass Sigstore/Rekor verification.
  - Refreshed Intel PCS or NVIDIA NRAS results.
  - New Proof of Cloud positive registrations.
  - New or updated global image entries with full Sigstore/Rekor provenance.
- **Unauthenticated values are NOT written back**: Changes to TDX measurement
  registers (MRSEAM, MRTD, RTMR0–2) are not updated by `teep serve` or
  `teep verify`. These values can only be updated by `teep cache`, which
  performs the explicit operator-initiated trust-on-first-use flow. If `teep
  serve` observes a TDX measurement mismatch against the cache, it reports
  a factor failure (or warning if in `allow_fail`) but does not overwrite
  the cached values.

---

## 3. Cache File Design

### 3a. Principles

1. **Separate from config**: The cache file is machine-generated output, not
   user-edited configuration. The config file (`teep.toml`) retains policy
   settings (allow_fail, base_url, api_key_env, etc.). The cache file stores
   authenticated observations.

2. **Global image table**: Container images are cached at the top level, keyed
   by a unique identifier (the image digest or a generated ID for tag-based
   images). This avoids duplicating Sigstore/Rekor results when the same image
   appears across multiple providers or models.

3. **Per-provider, per-model sections**: Each (provider, model) pair has its
   own section containing the TDX measurements, compose hash, NVIDIA results,
   Intel PCS results, Proof of Cloud results, and references into the global
   image table.

4. **Per-provider gateway section**: For providers with gateway attestation
   (e.g., nearcloud), a `gateway` section sits alongside model sections with
   its own TDX measurements, compose hash, and image references.

5. **Deterministic merge**: `teep cache provider --model X` replaces only
   the `providers.<provider>.models.<X>` section (and the gateway section
   if the provider has one). All other providers, models, and global images
   are preserved. Orphaned global images (no longer referenced by any
   provider/model in the merged config file) should be pruned.

### 3b. Data Stored Per Scope

#### Global Images (top-level `images` map)

Each entry is keyed by a stable identifier. For digest-pinned images
(`repo@sha256:...`), the key is `sha256:<hex>` (matching OCI notation). For
tag-based images, the key is the `<repo>:<tag>` string as it appeared in the
compose manifest — this allows direct cache lookup without resolving the tag
to a digest first (see Section 5b rationale). For `allow_any_version` images,
the key is also `<repo>:<tag>`.

| Field | Type | Description |
|-------|------|-------------|
| `repo` | string | Image repository (e.g., `datadog/agent`) |
| `digest` | string | `sha256:<hex>` (immutable content address); empty for `allow_any_version` |
| `tag` | string | Tag observed in compose (e.g., `v0.4.2`, `latest`); empty for digest-pinned |
| `provenance` | string | `fulcio_signed` / `sigstore_present` / `compose_binding_only` |
| `allow_any_version` | bool | `true` → any version accepted by allowlist membership alone |
| `key_fingerprint` | string | SHA-256 hex of PKIX public key (for `sigstore_present`) |
| `oidc_issuer` | string | Fulcio OIDC issuer (for `fulcio_signed`) |
| `oidc_identity` | string | SAN URI / workflow identity (for `fulcio_signed`) |
| `source_repos` | []string | Git repos (for `fulcio_signed`) |
| `source_commit` | string | Git commit SHA (for `fulcio_signed`) |
| `no_dsse` | bool | DSSE envelope lacks signatures |
| `signature_verified` | bool | DSSE signature check passed |
| `set_verified` | bool | Rekor SET check passed |
| `inclusion_verified` | bool | Merkle inclusion proof passed |
| `verified_at` | timestamp | When Sigstore/Rekor verification was performed |

**Staleness**: Rekor entries are append-only and immutable. Digest-pinned
entries never go stale. Tag-based entries with resolved digests are fresh as
long as the same digest appears in the compose. `allow_any_version` entries
are valid as long as the repo is in the allowlist.

#### Per-Provider Model Section

Each model section under `providers.<name>.models.<model>`:

| Field | Type | Description |
|-------|------|-------------|
| `cached_at` | timestamp | When this model was cached |
| **TDX Measurements** | | |
| `mrseam` | string | 48-byte hex |
| `mrtd` | string | 48-byte hex |
| `rtmr0` | string | 48-byte hex |
| `rtmr1` | string | 48-byte hex |
| `rtmr2` | string | 48-byte hex |
| **Compose** | | |
| `compose_hash` | string | `sha256:<hex>` of the docker-compose YAML |
| `image_refs` | []string | References into the global `images` map |
| **Intel PCS** | | |
| `fmspc` | string | 12-char hex |
| `tee_tcb_svn` | string | hex |
| `tcb_status` | string | `UpToDate` / `SWHardeningNeeded` / etc. |
| `advisory_ids` | []string | Intel-SA-XXXXX IDs |
| `intel_pcs_verified_at` | timestamp | When PCS was queried |
| **NVIDIA NRAS** | | |
| `eat_hash` | string | Content hash of GPU evidence |
| `nras_overall_result` | bool | `x-nvidia-overall-att-result` |
| `nras_gpu_count` | int | Number of GPUs verified |
| `nras_verified_at` | timestamp | When NRAS was queried |
| **Proof of Cloud** | | |
| `ppid` | string | 32-char hex PPID |
| `poc_registered` | bool | Machine in registry |
| `poc_machine_id` | string | Machine ID from JWT |
| `poc_label` | string | Machine label |
| `poc_verified_at` | timestamp | When PoC was queried |
| **E2EE** | | |
| `e2ee_tested` | bool | Whether E2EE roundtrip was attempted |
| `e2ee_passed` | bool | Whether it succeeded |
| `e2ee_tested_at` | timestamp | When test was performed |

#### Per-Provider Gateway Section

For providers with gateway attestation (nearcloud), a `gateway` section
at `providers.<name>.gateway` with the same structure as a model section:
TDX measurements (gateway MRSEAM, MRTD, RTMR0–2), compose hash, image refs,
Intel PCS, NVIDIA (if applicable), Proof of Cloud, etc.

### 3c. Cache Key and Invalidation Summary

| Cached Data | Cache Key | Valid When | Staleness Behavior |
|-------------|-----------|-----------|-------------------|
| TDX measurements | (provider, model) | Compose hash matches | Invalidated if compose hash changes |
| Compose hash | `sha256(app_compose)` | Content-addressed (immutable per-content) | New hash → re-extract images, re-validate |
| Image (digest-pinned) | `sha256:<hex>` | Immutable | Never stale |
| Image (release tag) | `<repo>:<tag>` | Resolved digest matches cached digest | Stale if tag resolves to different digest |
| Image (allow_any_version) | `<repo>:<tag>` | Repo in allowlist | Never stale (presence-only) |
| Intel PCS | `(FMSPC, TeeTCBSVN)` | Within max-age (default 24h) | Re-fetch; offline → `Skip` |
| NVIDIA NRAS | EAT evidence hash | Within max-age (default 24h) | Re-fetch; offline → `Skip` |
| Proof of Cloud | PPID | Positive → infinite; negative → short TTL | Positive never stale; negative re-fetched |
| E2EE test | — | **Not cacheable** (live test) | Always re-run if online; offline → `Skip` |

---

## 4. Staleness and Re-fetch Behavior

When `teep serve` or `teep verify` encounters a stale or invalidated cache
entry during online operation (i.e., `--offline` is NOT set):

### 4a. Compose Hash Changes

If the compose hash from a fresh attestation differs from the cached
`compose_hash`, the entire compose-dependent cache for that model is
invalidated. Re-validation proceeds as:

1. Extract images from the new compose manifest.
2. For each image, check the global image cache:
   - **Digest-pinned image in cache**: Cache hit — use cached Sigstore data.
   - **Tag-based image with matching resolved digest**: Cache hit.
   - **Tag-based image with different digest**: Cache miss — re-verify via
     Sigstore/Rekor.
   - **Image not in cache at all**: Cache miss — full Sigstore/Rekor fetch.
3. After successful re-validation, update `compose_hash` and `image_refs` in
   the model section; add any new images to the global table.
4. Emit `slog.Info("compose hash changed, re-validated supply chain",
   "provider", p, "model", m, "old_hash", old, "new_hash", new)`.

### 4b. Mutable-Authority Staleness (Intel PCS, NVIDIA NRAS)

If `intel_pcs_verified_at` or `nras_verified_at` is older than max-age:
- **Online**: Re-fetch from the authority. Update cache. Log:
  `slog.Info("refreshing stale cache entry", "factor", f, "age", age)`.
- **Offline**: Factor evaluates as `Skip`. Whether this blocks depends on the
  configured `allow_fail` list and normal offline factor handling. Log:
  `slog.Warn("stale cache entry in offline mode", "factor", f, "age", age)`.

### 4c. Offline Mode

When `--offline` is set, no re-fetching occurs. Cache data is used as-is with
these rules:
- **Fresh cache entry**: Factor evaluates using cached data (Pass/Fail as
  originally determined).
- **Stale mutable-authority entry**: Factor evaluates as `Skip`. Log emitted.
- **Missing cache entry**: Factor evaluates as `Skip`. Same behavior as
  current `--offline` without cache.
- **Immutable entries** (Rekor, PoC positive): Never stale; used directly.
- **E2EE usable**: Always `Skip` in offline mode (non-cacheable).
- **Compose hash mismatch (no matching images)**: Supply chain factors
  evaluate as `Skip`. Without online access, unknown images cannot be
  verified.

---

## 5. Image Reference Types

Images in docker-compose manifests fall into three categories, each with
different caching and offline authentication behavior:

### 5a. Digest-Pinned (`repo@sha256:...`)

The strongest form. The digest is an immutable content address. Sigstore/Rekor
verification is bound to this exact digest. Cache entries keyed by digest never
go stale. Offline authentication: cached digest match → Pass.

### 5b. Specific Release Tag (`repo:v1.2.3`)

When authenticated via Sigstore/Rekor, the resolved immutable digest is
persisted as the trust anchor. The tag is stored as readable metadata. Offline
authentication requires the resolved digest to match what's in the current
compose manifest. If the compose now resolves the same tag to a different
digest, the cache entry is stale and must be re-verified online.

**Cache key is `<repo>:<tag>`, not the resolved digest.** The compose manifest
specifies images by tag, and we cannot know which digest the provider resolved
a given tag to on their side. Keying by tag allows direct cache lookup when the
same tag appears in a compose manifest without requiring a digest resolution
step. The resolved digest is stored inside the cache entry as the authenticated
trust anchor, not as the key.

### 5c. Generic / Branch Tag (`repo:latest`, `repo:main`, no tag)

The version cannot be pinned because the same tag may resolve to different
images over time. These are cached with `allow_any_version: true`, meaning the
image is authenticated by its presence in the supply chain allowlist alone — no
digest or tag pinning. This is the weakest authentication level but is explicit
in the cache for operator visibility.

### Security Ordering

Digest-pinned > specific release tag > allow_any_version.

| Image Reference | Global Image Key | Offline Auth | Staleness |
|----------------|-----------------|-------------|-----------|
| `repo@sha256:abc` | `sha256:abc` | Digest match → Pass | Never stale |
| `repo:v1.2.3` | `repo:v1.2.3` | Cached resolved digest match → Pass | Stale if tag resolves to new digest |
| `repo:latest` | `repo:latest` | Allowlist membership → Pass | Never stale (presence-only) |

---

## 6. Cache File Format (YAML)

The cache file uses YAML for human readability and comment support.
Operators may inspect and occasionally hand-edit cache entries (e.g., remove
a stale provider). Strict unmarshalling (`KnownFields(true)`) rejects unknown
fields on read (fail-closed).

```yaml
# teep attestation cache — machine-generated, do not edit
# regenerate with: teep cache <provider> --model <model>
version: 1

images:
  "sha256:a1b2c3d4e5f67890fedcba0987654321a1b2c3d4e5f67890fedcba0987654321":
    repo: "datadog/agent"
    digest: "sha256:a1b2c3d4e5f67890fedcba0987654321a1b2c3d4e5f67890fedcba0987654321"
    provenance: sigstore_present
    key_fingerprint: "25bcab4ec8eede1e3091a14692126798c23986832ae6e5948d6f7eb0a928ab0b"
    signature_verified: true
    set_verified: true
    inclusion_verified: true
    verified_at: "2026-04-05T14:30:00Z"

  "sha256:fedcba0987654321a1b2c3d4e5f67890fedcba0987654321a1b2c3d4e5f67890":
    repo: "nearaidev/compose-manager"
    digest: "sha256:fedcba0987654321a1b2c3d4e5f67890fedcba0987654321a1b2c3d4e5f67890"
    provenance: fulcio_signed
    oidc_issuer: "https://token.actions.githubusercontent.com"
    oidc_identity: "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master"
    source_repos:
      - "nearai/compose-manager"
      - "https://github.com/nearai/compose-manager"
    source_commit: "abc123def456"
    no_dsse: true
    signature_verified: true
    set_verified: true
    inclusion_verified: true
    verified_at: "2026-04-05T14:30:00Z"

  "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef":
    repo: "certbot/dns-cloudflare"
    digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    provenance: compose_binding_only
    verified_at: "2026-04-05T14:30:00Z"

  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":
    repo: "nearaidev/dstack-vpc"
    digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    provenance: fulcio_signed
    oidc_issuer: "https://token.actions.githubusercontent.com"
    oidc_identity: "https://github.com/nearai/dstack-vpc/.github/workflows/build.yml@refs/heads/main"
    source_repos:
      - "nearai/dstack-vpc"
    no_dsse: true
    signature_verified: true
    set_verified: true
    inclusion_verified: true
    verified_at: "2026-04-05T14:30:00Z"

  "vllm/vllm-openai:v0.6.6.post1":
    repo: "vllm/vllm-openai"
    digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    tag: "v0.6.6.post1"
    provenance: sigstore_present
    key_fingerprint: "aabbccdd..."
    signature_verified: true
    set_verified: true
    inclusion_verified: true
    verified_at: "2026-04-05T14:30:00Z"

  "alpine:latest":
    repo: "alpine"
    tag: "latest"
    provenance: compose_binding_only
    allow_any_version: true
    verified_at: "2026-04-05T14:30:00Z"

providers:
  neardirect:
    models:
      "meta-llama/Llama-3.3-70B-Instruct":
        cached_at: "2026-04-05T14:30:00Z"

        # TDX measurements (pinned)
        mrseam: "49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6"
        mrtd: "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217"
        rtmr0: "bc122d143ab768565ba5c3774ff5f03a63c89a4df7c1f5ea38d3bd173409d14f8cbdcc36d40e703cccb996a9d9687590"
        rtmr1: "c0445b704e4c48139496ae337423ddb1dcee3a673fd5fb60a53d562f127d235f11de471a7b4ee12c9027c829786757dc"
        rtmr2: "564622c7ddc55a53272cc9f0956d29b3f7e0dd18ede432720b71fd89e5b5d76cb0b99be7b7ff2a6a92b89b6b01643135"

        # Compose binding
        compose_hash: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        image_refs:
          - "sha256:a1b2c3d4e5f67890fedcba0987654321a1b2c3d4e5f67890fedcba0987654321"
          - "sha256:fedcba0987654321a1b2c3d4e5f67890fedcba0987654321a1b2c3d4e5f67890"
          - "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

        # Intel PCS
        fmspc: "00906ED50000"
        tee_tcb_svn: "04040303ffff01000000000000000000"
        tcb_status: "UpToDate"
        advisory_ids:
          - "INTEL-SA-00615"
        intel_pcs_verified_at: "2026-04-05T14:30:00Z"

        # NVIDIA NRAS
        eat_hash: "sha256:1234abcd..."
        nras_overall_result: true
        nras_gpu_count: 8
        nras_verified_at: "2026-04-05T14:30:00Z"

        # Proof of Cloud
        ppid: "0a1b2c3d4e5f67890a1b2c3d4e5f6789"
        poc_registered: true
        poc_machine_id: "machine-xyz-123"
        poc_label: "Azure DC-series v5"
        poc_verified_at: "2026-04-05T14:30:00Z"

        # E2EE (informational only — not used for offline)
        e2ee_tested: false

  nearcloud:
    gateway:
      cached_at: "2026-04-05T14:30:00Z"
      mrseam: "49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6"
      mrtd: "aabbccdd..."
      rtmr0: "11223344..."
      rtmr1: "55667788..."
      rtmr2: "99aabbcc..."
      compose_hash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
      image_refs:
        - "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      ppid: "ff00ee11dd22cc33ff00ee11dd22cc33"
      poc_registered: true
      poc_machine_id: "gateway-001"
      poc_label: "Gateway node"
      poc_verified_at: "2026-04-05T14:30:00Z"

    models:
      "meta-llama/Llama-3.3-70B-Instruct":
        cached_at: "2026-04-05T14:30:00Z"
        mrseam: "49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6"
        mrtd: "b24d3b24..."
        rtmr0: "bc122d14..."
        rtmr1: "c0445b70..."
        rtmr2: "564622c7..."
        compose_hash: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        image_refs:
          - "sha256:a1b2c3d4e5f67890fedcba0987654321a1b2c3d4e5f67890fedcba0987654321"
          - "sha256:fedcba0987654321a1b2c3d4e5f67890fedcba0987654321a1b2c3d4e5f67890"
          - "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        fmspc: "00906ED50000"
        tee_tcb_svn: "04040303ffff01000000000000000000"
        tcb_status: "UpToDate"
        advisory_ids: []
        intel_pcs_verified_at: "2026-04-05T14:30:00Z"
        eat_hash: "sha256:5678efgh..."
        nras_overall_result: true
        nras_gpu_count: 8
        nras_verified_at: "2026-04-05T14:30:00Z"
        ppid: "0a1b2c3d4e5f67890a1b2c3d4e5f6789"
        poc_registered: true
        poc_machine_id: "machine-xyz-123"
        poc_label: "Azure DC-series v5"
        poc_verified_at: "2026-04-05T14:30:00Z"
        e2ee_tested: true
        e2ee_passed: true
        e2ee_tested_at: "2026-04-05T14:30:00Z"

  nanogpt:
    models:
      "meta-llama/Llama-3.3-70B-Instruct":
        cached_at: "2026-04-05T14:30:00Z"
        mrseam: "..."
        mrtd: "..."
        rtmr0: "..."
        rtmr1: "..."
        rtmr2: "..."
        compose_hash: "sha256:eeeeeeee..."
        image_refs:
          - "vllm/vllm-openai:v0.6.6.post1"
          - "alpine:latest"
        fmspc: "00906ED50000"
        tee_tcb_svn: "04040303ffff01000000000000000000"
        tcb_status: "SWHardeningNeeded"
        advisory_ids:
          - "INTEL-SA-00615"
          - "INTEL-SA-00657"
        intel_pcs_verified_at: "2026-04-05T14:30:00Z"
        eat_hash: "sha256:9999..."
        nras_overall_result: true
        nras_gpu_count: 1
        nras_verified_at: "2026-04-05T14:30:00Z"
        ppid: "aabb..."
        poc_registered: true
        poc_machine_id: "nano-001"
        poc_label: "NanoGPT node"
        poc_verified_at: "2026-04-05T14:30:00Z"
        e2ee_tested: false
```

---

## 7. Format Decision

**YAML only.** Operators may want to examine and modify cache entries (e.g.,
remove a stale provider, inspect image provenance). YAML supports comments,
is compact, and is human-readable. The cache file header comment
(`# teep attestation cache — machine-generated`) signals its origin.

Strict unmarshalling will be enforced during cache reads: unknown fields are
rejected (fail-closed), preventing version skew or corruption from going
unnoticed. The Go `gopkg.in/yaml.v3` decoder's `KnownFields(true)` option
provides this guarantee.

---

## 8. Cacheability Analysis Per Factor

For reference, here is the full analysis of which online factors can be served
from cache:

### 8a. Current `--offline` Exemptions

`OnlineFactors` lists 9 factors automatically added to `allow_fail` in offline
mode:

| # | Factor | Online Service | Cacheable? | Staleness |
|---|--------|---------------|-----------|-----------|
| 1 | `intel_pcs_collateral` | Intel PCS | **Yes** | Max-age 24h |
| 2 | `tdx_tcb_current` | (derived from #1) | **Yes** | Max-age 24h |
| 3 | `tdx_tcb_not_revoked` | (derived from #1) | **Yes** | Max-age 24h |
| 4 | `nvidia_nras_verified` | NVIDIA NRAS | **Yes** | Max-age 24h |
| 5 | `e2ee_usable` | Provider inference API | **No** | Non-cacheable |
| 6 | `build_transparency_log` | Rekor | **Yes** | Immutable (infinite) |
| 7 | `sigstore_verification` | Rekor | **Yes** | Immutable (infinite) |
| 8 | `cpu_id_registry` | Proof of Cloud | **Yes** (positive) | Append-only (infinite) |
| 9 | `gateway_cpu_id_registry` | Proof of Cloud | **Yes** (positive) | Append-only (infinite) |

**8 of 9 factors are cacheable. Only `e2ee_usable` is non-cacheable.**

### 8b. Per-Factor Details

**Intel PCS (factors 1–3)**: TCB info for `(FMSPC, TeeTCBSVN)` is
deterministic for a given platform firmware. Cached `tcb_status` and
`advisory_ids` are valid until Intel publishes new advisories (typically
monthly). Max-age 24h default; stale → `Skip` in offline mode (enforcement
depends on `allow_fail` configuration).

**NVIDIA NRAS (factor 4)**: GPU measurement verification for a given EAT
payload is deterministic for a given hardware+firmware. Cached
`nras_overall_result` is valid until NVIDIA publishes firmware revocations.
Same max-age and staleness policy as Intel PCS.

**E2EE (factor 5)**: Requires live encrypted roundtrip. Non-cacheable. Always
`Skip` in offline mode. The `e2ee_tested` / `e2ee_passed` fields in the cache
are informational only (recorded for operator reference, not used for factor
evaluation).

**Rekor/Sigstore (factors 6–7)**: Rekor entries are append-only and immutable.
Digest-pinned results never go stale. This is the ideal caching candidate. The
global `images` table in the cache stores full Rekor provenance data.

**Proof of Cloud (factors 8–9)**: Hardware registry is append-only. Positive
registrations never expire. Negative results are not cached (machine may be
registered tomorrow). Cached positive `poc_registered: true` is valid
indefinitely.

### 8c. Non-Online Cacheable Data

Beyond the 9 online factors, the cache also stores data that is not online-
dependent but was previously obtained via `--update-config`:

| Data | Previously | Now |
|------|-----------|-----|
| TDX measurements (MRSEAM, MRTD, RTMR0–2) | `--update-config` → `teep.toml` policy allowlists | `teep cache` → cache file (config fields removed) |
| Gateway TDX measurements | `--update-config` → `teep.toml` policy allowlists | `teep cache` → cache file (config fields removed) |
| Compose hash | Not captured | `teep cache` → cache file |
| Image list per compose | Not captured | `teep cache` → cache file |

---

## 9. Merge Semantics

When `teep cache neardirect --model meta-llama/Llama-3.3-70B-Instruct` runs:

1. Read existing cache file (if present).
2. Replace `providers.neardirect.models["meta-llama/Llama-3.3-70B-Instruct"]`.
3. If neardirect has gateway attestation, also replace
   `providers.neardirect.gateway`.
4. For each image in the new model's compose + gateway compose:
   - If the image (by digest or tag-key) already exists in global `images`
     and is still valid, keep it.
   - If the image is new or has a different resolved digest, add/update it.
5. Preserve all other providers and models untouched.
6. **Optional orphan pruning**: After merge, scan global `images` for entries
   not referenced by any provider/model. These can be pruned to keep the file
   compact, or left for potential future reuse (configurable, default: prune).
7. Write the merged cache file atomically (write → rename).

For `--all-models`, repeat step 2 for each model, then do one gateway update
and one orphan prune pass at the end.

---

## 10. Migration

### 10a. Removing `--update-config`, `--config-out`, and Config Policy Fields

**CLI flags removed from `teep verify`**:
- `--update-config`
- `--config-out`

**Config code removed entirely**:
- `config.UpdateConfig()` and all supporting types (`ObservedMeasurements`,
  `updateFile`, `updateProvider`, `updatePolicy`, `mergeObserved`, `addUnique`,
  `knownProviderDefaults`, `writeConfig`) from `internal/config/update.go`.
- `internal/config/update_test.go`.
- The `Policy` field (type `policyConfig`) from the provider config struct,
  including all measurement allowlist fields: `mrtd_allow`, `mrseam_allow`,
  `rtmr0_allow` through `rtmr3_allow`, and all `gateway_*` equivalents.
- `MeasurementPolicy`, `GatewayMeasurementPolicy`, `ProviderPolicies`,
  `ProviderGatewayPolicies` from the `Config` struct.
- `MergedMeasurementPolicy()` and `MergedGatewayMeasurementPolicy()`.
- The `extractObserved()` function from `cmd/teep/main.go`.

**No backwards compatibility**: If an existing `teep.toml` contains
`[providers.X.policy]` sections with measurement allowlists, those fields
will be rejected at startup as unknown keys (consistent with the existing
strict TOML parsing). Operators must remove these sections from their config
and run `teep cache` to populate the cache file instead.

### 10b. How the Cache Replaces Config Policy

The cache file's per-model TDX register values (`mrseam`, `mrtd`, `rtmr0`–
`rtmr2`, and gateway equivalents) serve the role formerly filled by the config
measurement allowlists. At verification time:

1. Teep fetches a live attestation from the provider (as before).
2. The live TDX quote is parsed and verified locally (signature, cert chain,
   nonce binding — all offline-capable factors).
3. The live TDX measurement values are compared against the cached values for
   that (provider, model) pair.

**Enforcement follows the configured `allow_fail` list**:

- **Factor NOT in `allow_fail`** (enforced): If a cached TDX register value
  does not match the live value, the factor **fails**. In `teep serve`, the
  request is **blocked**. In `teep verify`, the report shows the factor as
  **Fail** and the overall result is blocked.

- **Factor in `allow_fail`** (non-enforced): If a cached TDX register value
  does not match the live value, a **warning** is emitted
  (`slog.Warn("cached TDX register mismatch", "register", name,
  "cached", cached, "live", live, "factor", factor)`), but the request is
  not blocked and the report is not failed.

- **No cache entry for the (provider, model)**: The comparison is skipped —
  there is nothing to compare against. This is equivalent to the former
  behavior when no measurement allowlists were configured. Factors that depend
  on external verification (Intel PCS, NVIDIA NRAS, etc.) proceed with their
  normal online/offline logic.

**All other cached data** (Intel PCS, NVIDIA NRAS, Proof of Cloud, Sigstore/
Rekor results) follows the staleness and re-fetch behavior described in
Section 4. The `allow_fail` list governs whether a factor's failure blocks or
warns regardless of whether the failure came from cache comparison, live
verification, or staleness degradation.

### 10c. Config vs. Cache After Migration

| Concern | Config (`teep.toml`) | Cache (cache file) |
|---------|---------------------|-------------------|
| Purpose | User policy / preferences | Machine-observed authenticated data |
| Edited by | Human | `teep cache` command |
| Content | `allow_fail`, `base_url`, `api_key_env`, provider settings | TDX register values, compose hashes, image provenance, PCS/NRAS/PoC results |
| TDX register handling | **Removed** (no allowlists) | Cached values compared against live attestation |
| Enforcement | `allow_fail` controls which factors block | Cached data compared; `allow_fail` controls block/warn |
| Merge on update | N/A (user-managed) | Provider+model replacement with merge |
| Format | TOML | YAML |

---

## 11. Implementation Phases

### Phase 1: Cache File Format and I/O

- Define Go types for the cache file structure.
- Implement read/write/merge operations with atomic file writes.
- Implement orphan pruning.
- Unit tests for merge semantics, format round-tripping, concurrent access.

### Phase 2: `teep cache` Command

- Add `teep cache` subcommand to `cmd/teep/main.go`.
- Wire up attestation fetch → full verification → cache extraction → file write.
- Support `--model`, `--all-models`, `--cache-file`.
- Unit and integration tests.

### Phase 3: Cache Consumption in `teep verify` and Config Removal

- Load cache file in `teep verify`.
- For each online factor, check cache before making network calls.
- Compare live TDX register values against cached values; enforce via
  `allow_fail` (see Section 10b).
- Implement staleness detection and re-fetch logic.
- Implement notice logging for stale/invalidated entries.
- Remove `--update-config`, `--config-out`, and all config measurement
  allowlist fields (see Section 10a).

### Phase 4: Cache Consumption in `teep serve`

- Create in-memory cache at `teep serve` startup (same data structures as the
  cache file). If a cache file is configured, load it into memory; otherwise
  start with an empty memory-only cache.
- Same staleness/re-fetch/logging logic as `teep verify`.
- Populate the in-memory cache after each successful attestation, using the
  same code paths as `teep cache` for extracting authenticated results.
- **Authenticated write-back**: When live re-attestation produces changes that
  are fully authenticated (new compose hash with all images passing
  Sigstore/Rekor, refreshed Intel PCS / NVIDIA NRAS, new PoC positive
  registrations), write these back to both the in-memory cache and the cache
  file (if configured). Use atomic write (write → rename) and a file lock to
  handle concurrent proxy requests.
- **TDX measurement registers are read-only**: `teep serve` never overwrites
  cached MRSEAM, MRTD, or RTMR values. Only `teep cache` can update these
  (explicit operator trust-on-first-use).

### Phase 5: Testing and Documentation

- Integration tests with live providers.
- `make reports` regression check.
- Update `README.md`, `README_ADVANCED.md`, help text.
- `teep.toml.example` — remove update-config examples, add cache-file
  documentation.
- Rewrite `docs/measurement_allowlists.md` to describe how to use
  `teep cache` combined with `allow_fail` configuration to pin cached
  values with and without strict enforcement.
