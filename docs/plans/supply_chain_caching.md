# Plan: Attestation Cache (`teep cache`)

## 1. Goal

All data currently exempted by `--offline` should be cached post-authentication,
and all data currently obtained by `--update-config` should instead be obtained
by a dedicated `teep cache` command, such that the attestation report can be
rebuilt and verified with zero online activity for all cacheable factors so
long as the cached data is fresh. Live-only checks that are not cacheable,
such as the E2EE usability roundtrip (`e2ee_usable`), are not included in
that offline guarantee and retain their normal offline result (e.g., `Skip`
under `--offline`).

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
   or with `cache_file` field in the teep toml config.
5. If attestation is blocked (report would be blocked), refuse to write cache
   for that model — same safety guard as the current `--update-config`.
6. **Partial failure for `--all-models`**: If some models fail attestation and
   others succeed, write cache entries for successful models, skip failed
   models, collect per-model errors, and exit non-zero with a summary of
   which models succeeded and which failed (and why).

**Flags**:
- `--model <name>` (required unless `--all-models` is set; supports one or more models, either as a comma-separated list such as `--model <m1>,<m2>` and/or by repeating the flag) / `--all-models` (required unless `--model` is set; mutually exclusive with `--model`)
- `--cache-file <path>` (optional override)
- `--offline` is NOT supported on `teep cache` — caching requires online access

### 2b. Changes to `teep verify`

- Remove `--update-config` and `--config-out` flags.
- `teep verify` does NOT read or write the cache file. It always performs live
  network requests for all factors. This avoids surprising cache mutations
  during what operators expect to be a read-only inspection command, and
  avoids contention with the `--capture` and `--reverify` options.

### 2c. Changes to `teep serve`

- Add `--cache-file <path>` flag (defaults to `$TEEP_CACHE_FILE` or
  `~/.config/teep/cache.yaml`; overridable with `cache_file` in config).
- `teep serve` now runs one proxy for all active providers (all providers
  with non-empty resolved API keys) and routes inference requests by
  `provider:model` prefix. Supply-chain cache lookups and writes are keyed by
  `(provider, upstream model)`, where `upstream model` is the model after the
  provider prefix is stripped.
- Use cached data for online factors, re-fetch stale entries live, emit
  notice logs on staleness.
- **Handler factory integration**: The proxy uses a `handleEndpoint` factory
  (`internal/proxy/proxy.go`) that produces handlers for all endpoint types
  (chat, embeddings, audio, images, rerank). The `attestAndCache` function
  within this flow is the natural integration point for supply chain cache
  consultation — cache lookup happens once per attestation, automatically
  covering all endpoint types. The supply chain cache is distinct from the
  existing short-lived proxy caches (`attestation.Cache` for reports,
  `SigningKeyCache`, `SPKICache`, `NegativeCache`); it stores long-lived
  authenticated verification data (Sigstore/Rekor results, Intel PCS
  collateral, NVIDIA NRAS results, Proof of Cloud registrations).
- **Memory-only cache**: Even without a cache file, `teep serve` creates an
  in-memory cache at startup (using the same cache data structures and code
  paths as `teep cache`). Subsequent re-attestations of the same (provider,
  upstream model) benefit from cached Sigstore/Rekor, Intel PCS, NVIDIA NRAS, and
  Proof of Cloud results without re-fetching. The memory-only cache is
  initialized empty and populated as attestations are performed.
- **Authenticated write-back**: When `teep serve` encounters changes it can
  fully authenticate, it updates the in-memory cache and, if a cache file is
  configured, writes back to the file:
  - New compose hash where all images pass Sigstore/Rekor verification.
  - Refreshed Intel PCS or NVIDIA NRAS results.
  - New Proof of Cloud positive registrations.
  - New or updated image entries with full Sigstore/Rekor provenance.
- **Write-back failure handling**: If a cache file write-back fails (I/O
  error, permission denied, etc.), `teep serve` logs the error at
  `slog.Error` level and continues serving requests. Cache write-back failures
  MUST NOT cause request failures or block proxy operation.
- **Unauthenticated values are NOT written back**: Changes to TDX measurement
  registers (MRSEAM, MRTD, RTMR0–2) are not updated by `teep serve`. These
  values can only be updated by `teep cache`, which performs the explicit
  operator-initiated trust-on-first-use flow. If `teep serve` observes a TDX
  measurement mismatch against the cache, it reports a factor failure (or
  warning if in `allow_fail`) but does not overwrite the cached values.

---

## 3. Cache File Design

### 3a. Principles

1. **Separate from config**: The cache file is machine-generated output, not
   user-edited configuration. The config file (`teep.toml`) retains policy
   settings (allow_fail, base_url, api_key_env, etc.). The cache file stores
   authenticated observations.

2. **Per-provider, per-model sections**: Each (provider, model) pair has its
   own self-contained section with TDX measurements, compose hash, inline
   image provenance data, NVIDIA results, Intel PCS results, Proof of Cloud
   results, and E2EE test results. Sigstore/Rekor data is immutable — the
   simplicity of inline storage outweighs the duplication cost when the same
   image appears across multiple providers or models.

  In multi-provider serve mode, this `model` key is the provider-local
  upstream model (the `provider:` prefix has already been removed by routing).

3. **Per-provider gateway section**: For providers with gateway attestation
   (e.g., nearcloud), a `gateway` section sits alongside model sections with
   its own TDX measurements, compose hash, and inline image provenance.

4. **Deterministic merge**: `teep cache provider --model X` replaces only
   the `providers.<provider>.models.<X>` section (and the gateway section
   if the provider has one). All other providers and models are preserved.

### 3b. Data Stored Per Scope

#### Per-Provider Model Section

Each model section under `providers.<name>.models.<model>`:

| Field | Type | Description |
|-------|------|-------------|
| `cached_at` | timestamp | When this model was cached (informational; per-factor timestamps are authoritative) |
| **TDX Measurements** | | |
| `mrseam` | []string | 48-byte hex allowlist |
| `mrtd` | []string | 48-byte hex allowlist |
| `rtmr0` | []string | 48-byte hex allowlist |
| `rtmr1` | []string | 48-byte hex allowlist |
| `rtmr2` | []string | 48-byte hex allowlist |
| **Compose** | | |
| `compose_hash` | string | `sha256:<hex>` of the docker-compose YAML |
| `images` | []image | Inline image provenance entries (see below) |
| **Intel PCS** | | |
| `fmspc` | string | 12-char hex |
| `tee_tcb_svn` | string | hex |
| `tcb_status` | string | `UpToDate` / `SWHardeningNeeded` / etc. |
| `advisory_ids` | []string | Intel-SA-XXXXX IDs |
| `intel_pcs_verified_at` | timestamp | When PCS was queried |
| **NVIDIA NRAS** | | |
| `nvidia_evidence_hash` | string | Content hash of GPU evidence |
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

#### Per-Model Image Entry

Each image in the `images` list within a model section:

| Field | Type | Description |
|-------|------|-------------|
| `reference` | string | **Identity key**: verbatim image reference from the docker-compose file (e.g., `repo@sha256:...`, `repo:tag`, or bare `repo`). This is the sole key used for cache lookup. |
| `version_unpinned` | bool | `true` if reference uses a generic/branch tag or bare name (e.g., `latest`, `main`, no tag) |
| `provenance` | string | `fulcio_signed` / `sigstore_present` / `no_sigstore_entry` |
| `key_fingerprint` | string | SHA-256 hex of PKIX public key (for `sigstore_present`) |
| `oidc_issuer` | string | Fulcio OIDC issuer (for `fulcio_signed`) |
| `oidc_identity` | string | SAN URI / workflow identity (for `fulcio_signed`) |
| `source_repos` | []string | Git repos (for `fulcio_signed`) |
| `source_commit` | string | Git commit SHA (for `fulcio_signed`) |
| `dsse_unsigned` | bool | DSSE envelope lacks signatures |
| `signature_verified` | bool | DSSE signature check passed |
| `set_verified` | bool | Rekor SET check passed |
| `inclusion_verified` | bool | Merkle inclusion proof passed |
| `verified_at` | timestamp | When Sigstore/Rekor verification was performed |

**Cache lookup semantics**: For each image reference in the docker-compose
file, cache lookup compares the verbatim reference string against the
`reference` field in the cached image list. If a matching entry exists, it is
a cache hit — no further Sigstore/Rekor verification is needed, because
entries are only stored in the cache after successful authentication. If no
match exists, it is a cache miss. This comparison is identical in online and
offline modes.

The `version_unpinned` classification is derived from the compose manifest
reference type, not operator-settable. `teep cache` MUST emit a warning when
encountering `version_unpinned` images, recommending that the provider pin
images by digest. The `version_unpinned` field is the weakest authentication
level — the image is authenticated only by its presence in the supply-chain
policy allowlist defined by the provider policy code (for example, provider
`policy.go` files) and enforced via `attestation.SupplyChainPolicy`
evaluation in `internal/attestation/report.go`; that allowlist membership is
not a freshness signal.

**Staleness**: Image cache entries are keyed by the verbatim compose reference
(`reference` field). If the compose hash has not changed, all image references
are identical and all cache entries remain valid. If the compose hash changes,
each image in the new compose is looked up by its reference identity — matches
are cache hits, new references are cache misses (see Section 4a). Because
cache lookup is reference-identity-only, tag re-push (where the same tag now
points to a different image) is not detectable via the cache; the
`image_binding` factor (see Section 5d) captures this weakness.
Digest-pinned entries (`repo@sha256:...`) are immutable by definition.
`version_unpinned` entries are authenticated by allowlist membership only.

#### Per-Provider Gateway Section

For providers with gateway attestation (nearcloud), a `gateway` section
at `providers.<name>.gateway` with the same structure as a model section:
TDX measurements (gateway MRSEAM, MRTD, RTMR0–2), compose hash, inline
images, Intel PCS, NVIDIA (if applicable), Proof of Cloud, etc.

### 3c. Cache Key and Invalidation Summary

| Cached Data | Cache Key | Valid When | Staleness Behavior |
|-------------|-----------|-----------|-------------------|
| TDX measurements | (provider, upstream model) | Compose hash matches | Invalidated if compose hash changes |
| Compose hash | `sha256(app_compose)` | Content-addressed (immutable per-content) | New hash → re-extract images, re-validate |
| Image (digest-pinned) | compose reference (`repo@sha256:...`) | Reference matches compose | Immutable by definition |
| Image (release tag) | compose reference (`repo:tag`) | Reference matches compose | Tag re-push not detectable; `image_binding` factor captures risk |
| Image (version_unpinned) | compose reference (bare `repo` or generic tag) | Reference matches compose and repo in allowlist | Allowlist membership only |
| Intel PCS | `(FMSPC, TeeTCBSVN)` | Within max-age (default 24h) | Re-fetch; offline → `Skip` |
| NVIDIA NRAS | NVIDIA evidence hash | Within max-age (default 24h) | Re-fetch; offline → `Skip` |
| Proof of Cloud | PPID | Positive → infinite; authenticated negative → `max_cache_age` | Positive never stale; authenticated negative re-fetched after `max_cache_age`; connectivity errors not cached |
| E2EE test | — | **Not cacheable** (live test) | Always re-run if online; offline → `Skip` |

---

## 4. Staleness and Re-fetch Behavior

When `teep serve` encounters a stale or invalidated cache entry during online
operation:

### 4a. Compose Hash Changes

If the compose hash from a fresh attestation differs from the cached
`compose_hash`, the entire compose-dependent cache for that model is
invalidated. Re-validation proceeds as:

1. Extract images from the new compose manifest.
2. For each image, check the model's cached image list by compose reference
   identity (the `reference` field — the verbatim image string from the
   docker-compose file):
   - **Cache hit** (reference matches a cached entry): Use cached
     Sigstore/Rekor data. No further verification needed — entries are only
     stored in the cache after successful Sigstore authentication.
   - **Cache miss** (reference not in cache):
     - **Online**: Perform full Sigstore/Rekor query and authenticate per
       the existing `sigstore_verification` code. Update the cache with
       the fully authenticated result.
     - **Offline**: Factor evaluates as `Skip` for this image.
3. After successful re-validation, update `compose_hash` and `images` in
   the model section.
4. Emit `slog.Info("compose hash changed, re-validated supply chain",
   "provider", p, "model", m, "old_hash", old, "new_hash", new)`.

### 4b. Mutable-Authority Staleness (Intel PCS, NVIDIA NRAS)

If `intel_pcs_verified_at` or `nras_verified_at` is older than max-age, the
cached authority result is stale and MUST NOT be used to satisfy the factor
until a fresh authority check succeeds.

- **Online**: Re-fetch from the authority. Log:
  `slog.Info("refreshing stale cache entry", "factor", f, "age", age)`.
  - On successful re-fetch and verification, update the cache and continue.
  - On refresh failure (including timeout, DNS, TLS, HTTP, or malformed
    response), the factor evaluates as `Fail` in normal online mode. `teep
    serve` MUST return the error and MUST NOT fall back to the stale cached
    result.
- **Offline**: Factor evaluates as `Skip`. Whether this blocks depends on the
  configured `allow_fail` list and normal offline factor handling. The stale
  cached result MUST NOT be used as a substitute for a fresh authority check.
  Log:
  `slog.Warn("stale cache entry in offline mode", "factor", f, "age", age)`.

### 4c. Proof of Cloud Negative Caching

PoC results fall into three categories with different caching behavior:

- **Positive results** (`poc_registered: true`): Cached indefinitely. The
  hardware registry is append-only; positive registrations never expire.
- **Authenticated negative results** (`poc_registered: false` with a valid,
  authenticated response from the registry): Cached up to `max_cache_age`
  (default 7 days, see Section 4d). This avoids hammering the registry for
  machines that are genuinely not registered. PoC is currently `allow_fail`
  for all providers.
- **Connectivity and response errors** (network timeout, DNS failure, HTTP
  error, malformed response, TLS error): NOT cached. Errors are transient
  and must not persist as false negatives. The factor evaluates using its
  normal error-handling path (typically `Skip` or `Fail` depending on the
  error type and `allow_fail` configuration).

The distinction between an authenticated negative and a connectivity error
is made at the PoC client level: only a well-formed, successfully
authenticated response indicating "not registered" is treated as a cacheable
negative. Any other failure mode is treated as an error and not written to
the cache.

### 4d. Maximum Cache Age

A `max_cache_age` configuration option (default 7 days) controls the maximum
age of any cache entry for `teep serve`. If all per-factor timestamps in a
model's cache entry are older than `max_cache_age`, `teep serve` refuses to
use the cache and requires a fresh attestation. This prevents indefinite
operation on stale cache data when network access to Intel PCS or NVIDIA NRAS
is blocked (which could mask a platform TCB revocation). The `max_cache_age`
value is configured in `teep.toml` (e.g., `max_cache_age = "168h"`) and
overridable with `--max-cache-age` on the CLI.

### 4e. Offline Mode

When `--offline` is set on `teep serve`, no re-fetching occurs. Cache data
is used as-is with these rules:
- **Fresh cache entry**: Factor evaluates using cached data (Pass/Fail as
  originally determined).
- **Stale mutable-authority entry**: Factor evaluates as `Skip`. Log emitted.
- **Missing cache entry**: Factor evaluates as `Skip`. Same behavior as
  current `--offline` without cache.
- **Immutable entries** (Sigstore/Rekor provenance, PoC positive): Never
  stale; used directly. Cache lookup by compose reference identity (see
  Section 3b).
- **E2EE usable**: Always `Skip` in offline mode (non-cacheable).
- **Compose hash mismatch (cache miss by reference)**: Image provenance
  factors for images whose compose reference has no matching cache entry
  evaluate as `Skip` — those images cannot be verified without online
  access. This is logged at notice level.

---

## 5. Image Reference Types

Images in docker-compose manifests fall into three categories, each with
different caching and offline authentication behavior:

### 5a. Digest-Pinned (`repo@sha256:...`)

The strongest form. The digest is an immutable content address. Sigstore/Rekor
verification is bound to this exact digest. Cache entries whose `reference`
contains a digest are immutable and never go stale. Offline authentication:
cached reference match → Pass.

### 5b. Specific Release Tag (`repo:v1.2.3`)

When authenticated via Sigstore/Rekor, the provenance data is stored in the
cache entry.

**Cache key is the compose reference** (e.g., `vllm/vllm-openai:v0.6.6.post1`).
Cache lookup compares the verbatim image reference from the docker-compose file
against the `reference` field in the cached image list. If they match, it is a
cache hit and no further Sigstore/Rekor verification is needed — the entry was
authenticated when it was stored. There is no digest comparison for cache
matching; the compose reference is the sole identity key.

**Online and offline behavior**: Cache lookup by compose reference identity is
identical in both modes. On cache hit, the cached Sigstore/Rekor provenance is
used. On cache miss, online mode performs a full Sigstore/Rekor query and
stores the authenticated result; offline mode evaluates as `Skip`.

**Security limitation — tag re-push**: Because we are the client and have no
visibility into which digest the provider actually pulled for a given tag, a
tag re-push (where the same tag now points to a different image) is not
detectable by teep in either online or offline mode. The compose YAML text is
unchanged, so the compose hash does not change, and the cache is not
invalidated. This is an inherent limitation of tag-based image references.
`teep cache` and `teep serve` MUST emit `slog.Info` notices when encountering
images referenced by tag rather than digest, recommending that providers pin
images by digest for stronger supply chain guarantees.

### 5c. Generic / Branch Tag (`repo:latest`, `repo:main`, no tag)

The version cannot be pinned because the same tag may resolve to different
images over time. These are cached with `version_unpinned: true`, meaning the
image is authenticated by its presence in the authoritative supply-chain
allowlist/policy used by attestation verification — no digest or tag pinning.
This is the weakest authentication level but is explicit in the cache for
operator visibility. Do not implement or reference this policy in
`internal/attestation/compose.go`; that module is only for compose handling.
`version_unpinned` MUST be evaluated by the existing supply-chain policy
definition/evaluation path, and `teep cache` MUST warn prominently when
encountering `version_unpinned` images.

### 5d. `image_binding` Report Factor

A new report factor, `image_binding`, evaluates whether **all** images in the
docker-compose manifest are pinned by digest (`repo@sha256:...`). This factor
provides a clear signal about the strength of the supply chain binding:

- **Pass**: Every image in the compose is referenced by digest. This is the
  strongest supply chain guarantee — each image is immutably content-addressed
  and Sigstore/Rekor verification is bound to the exact content.
- **Fail**: One or more images are referenced by tag (specific release tag or
  generic/branch tag) rather than digest. Tag-based references are vulnerable
  to tag re-push attacks that are not detectable by teep (see 5b).

`image_binding` MUST be included in the **default `allow_fail` list** for all
providers, since no providers currently pin all images by digest. This means
the factor is evaluated and reported but does not block requests unless an
operator explicitly removes it from `allow_fail` to enforce digest pinning.

When `image_binding` fails, the report MUST list which images are not
digest-pinned, along with their reference type (specific tag or
`version_unpinned`), so operators can see exactly which images weaken the
supply chain binding.

The `image_binding` factor is **not an online factor** — it is derived from
the compose manifest content, not from an external service. It is evaluated
during both `teep verify` and `teep serve` attestation, and does not require
cache consultation.

### Security Ordering

Digest-pinned > specific release tag > version_unpinned.

| Image Reference | Offline Auth | Staleness | `image_binding` |
|----------------|-------------|-----------|----------------|
| `repo@sha256:abc` | Digest match → Pass | Never stale | Pass |
| `repo:v1.2.3` | Previously authenticated tag → Pass | Not detectable if tag re-pushed (see 5b) | Fail |
| `repo:latest` | Allowlist membership → Pass | Never stale (presence-only) | Fail |

---

## 6. Cache File Format (YAML)

The cache file uses YAML for human readability, comment support, and a more
ergonomic representation of the nested provider/model/image data used here.
TOML can encode nested structures, but YAML is the preferred format for this
cache file's operator-facing layout. Note that `teep cache` rewrites the file
using struct-based encoding, so operator-added comments will not be preserved
across refreshes; only the generated header comment persists.

It is normally generated and refreshed by `teep cache`, but operators may
inspect it and hand-edit it when needed. Any manual change to cached entries,
including pinned TDX register values, is an explicit local policy change and
must be treated as operator-authored trust data rather than re-verified cached
evidence.

**File permissions and safety**: Because the cache contains trust anchors (for
example pinned TDX measurements and verified image provenance), cache file
access must be protected with the same strict local file safety policy used
for sensitive config. On every read, enforce owner-only style permissions (for
example `0600`-style permissions) and reject the cache file if it is
readable/writable by other users or groups. Do not silently warn and continue:
insecure permissions MUST fail closed and the cache MUST NOT be loaded.
Implementation detail: the current `internal/config/config.go`
`checkFilePermissions` helper uses `os.Stat`, so it is not symlink-safe as-is.
Either update that helper or add a cache-specific helper that uses `os.Lstat`
(not `os.Stat`) before accepting the path, to prevent symlink attacks where a
symlink to an attacker-controlled file with correct target permissions would
pass validation. On write, create or replace the cache file with restrictive
permissions explicitly set (do not rely on umask).

**Strict unmarshalling**: `KnownFields(true)` rejects unknown fields on read
(fail-closed). Post-unmarshal validation MUST verify that all hex-encoded
fields decode to expected lengths (e.g., 48 bytes for TDX measurements, 32
bytes for SHA-256 digests). This catches YAML type coercion issues (unquoted
hex strings parsed as integers) and data corruption.

**Version compatibility**: The `version: 1` field combined with
`KnownFields(true)` means an older binary will reject a cache file written by
a newer binary that adds fields. This is acceptable — the project has no
backwards compatibility guarantees, and the correct action is to upgrade the
binary and re-run `teep cache`.

```yaml
# teep attestation cache — generated by `teep cache`
# manual edits are allowed but are treated as operator policy changes
version: 1

providers:
  neardirect:
    models:
      "meta-llama/Llama-3.3-70B-Instruct":
        cached_at: "2026-04-05T14:30:00Z"

        # TDX measurements (pinned allowlists)
        mrseam:
          - "49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6"
        mrtd:
          - "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217"
        rtmr0:
          - "bc122d143ab768565ba5c3774ff5f03a63c89a4df7c1f5ea38d3bd173409d14f8cbdcc36d40e703cccb996a9d9687590"
        rtmr1:
          - "c0445b704e4c48139496ae337423ddb1dcee3a673fd5fb60a53d562f127d235f11de471a7b4ee12c9027c829786757dc"
        rtmr2:
          - "564622c7ddc55a53272cc9f0956d29b3f7e0dd18ede432720b71fd89e5b5d76cb0b99be7b7ff2a6a92b89b6b01643135"

        # Compose binding
        compose_hash: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        images:
          - reference: "datadog/agent@sha256:a1b2c3d4e5f67890fedcba0987654321a1b2c3d4e5f67890fedcba0987654321"
            provenance: sigstore_present
            key_fingerprint: "25bcab4ec8eede1e3091a14692126798c23986832ae6e5948d6f7eb0a928ab0b"
            signature_verified: true
            set_verified: true
            inclusion_verified: true
            verified_at: "2026-04-05T14:30:00Z"
          - reference: "nearaidev/compose-manager@sha256:fedcba0987654321a1b2c3d4e5f67890fedcba0987654321a1b2c3d4e5f67890"
            provenance: fulcio_signed
            oidc_issuer: "https://token.actions.githubusercontent.com"
            oidc_identity: "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master"
            source_repos:
              - "nearai/compose-manager"
              - "https://github.com/nearai/compose-manager"
            source_commit: "abc123def456"
            dsse_unsigned: true
            signature_verified: true
            set_verified: true
            inclusion_verified: true
            verified_at: "2026-04-05T14:30:00Z"
          - reference: "certbot/dns-cloudflare@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            provenance: no_sigstore_entry
            verified_at: "2026-04-05T14:30:00Z"

        # Intel PCS
        fmspc: "00906ED50000"
        tee_tcb_svn: "04040303ffff01000000000000000000"
        tcb_status: "UpToDate"
        advisory_ids:
          - "INTEL-SA-00615"
        intel_pcs_verified_at: "2026-04-05T14:30:00Z"

        # NVIDIA NRAS
        nvidia_evidence_hash: "sha256:1234abcd..."
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
      mrseam:
        - "49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6"
      mrtd:
        - "aabbccdd..."
      rtmr0:
        - "11223344..."
      rtmr1:
        - "55667788..."
      rtmr2:
        - "99aabbcc..."
      compose_hash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
      images:
        - reference: "nearaidev/dstack-vpc@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          provenance: fulcio_signed
          oidc_issuer: "https://token.actions.githubusercontent.com"
          oidc_identity: "https://github.com/nearai/dstack-vpc/.github/workflows/build.yml@refs/heads/main"
          source_repos:
            - "nearai/dstack-vpc"
          dsse_unsigned: true
          signature_verified: true
          set_verified: true
          inclusion_verified: true
          verified_at: "2026-04-05T14:30:00Z"
      ppid: "ff00ee11dd22cc33ff00ee11dd22cc33"
      poc_registered: true
      poc_machine_id: "gateway-001"
      poc_label: "Gateway node"
      poc_verified_at: "2026-04-05T14:30:00Z"

    models:
      "meta-llama/Llama-3.3-70B-Instruct":
        cached_at: "2026-04-05T14:30:00Z"
        mrseam:
          - "49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6"
        mrtd:
          - "b24d3b24..."
        rtmr0:
          - "bc122d14..."
        rtmr1:
          - "c0445b70..."
        rtmr2:
          - "564622c7..."
        compose_hash: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        images:
          - reference: "datadog/agent@sha256:a1b2c3d4e5f67890fedcba0987654321a1b2c3d4e5f67890fedcba0987654321"
            provenance: sigstore_present
            key_fingerprint: "25bcab4ec8eede1e3091a14692126798c23986832ae6e5948d6f7eb0a928ab0b"
            signature_verified: true
            set_verified: true
            inclusion_verified: true
            verified_at: "2026-04-05T14:30:00Z"
          - reference: "nearaidev/compose-manager@sha256:fedcba0987654321a1b2c3d4e5f67890fedcba0987654321a1b2c3d4e5f67890"
            provenance: fulcio_signed
            oidc_issuer: "https://token.actions.githubusercontent.com"
            oidc_identity: "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master"
            source_repos:
              - "nearai/compose-manager"
            dsse_unsigned: true
            signature_verified: true
            set_verified: true
            inclusion_verified: true
            verified_at: "2026-04-05T14:30:00Z"
          - reference: "certbot/dns-cloudflare@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            provenance: no_sigstore_entry
            verified_at: "2026-04-05T14:30:00Z"
        fmspc: "00906ED50000"
        tee_tcb_svn: "04040303ffff01000000000000000000"
        tcb_status: "UpToDate"
        advisory_ids: []
        intel_pcs_verified_at: "2026-04-05T14:30:00Z"
        nvidia_evidence_hash: "sha256:5678efgh..."
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
        mrseam:
          - "..."
        mrtd:
          - "..."
        rtmr0:
          - "..."
        rtmr1:
          - "..."
        rtmr2:
          - "..."
        compose_hash: "sha256:eeeeeeee..."
        images:
          - reference: "vllm/vllm-openai:v0.6.6.post1"
            provenance: sigstore_present
            key_fingerprint: "aabbccdd..."
            signature_verified: true
            set_verified: true
            inclusion_verified: true
            verified_at: "2026-04-05T14:30:00Z"
          - reference: "alpine"
            provenance: no_sigstore_entry
            version_unpinned: true
            verified_at: "2026-04-05T14:30:00Z"
        fmspc: "00906ED50000"
        tee_tcb_svn: "04040303ffff01000000000000000000"
        tcb_status: "SWHardeningNeeded"
        advisory_ids:
          - "INTEL-SA-00615"
          - "INTEL-SA-00657"
        intel_pcs_verified_at: "2026-04-05T14:30:00Z"
        nvidia_evidence_hash: "sha256:9999..."
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

**Why YAML over TOML**: The codebase uses TOML (`BurntSushi/toml`) for config,
but TOML lacks the nested hierarchical structure needed for
`providers.<name>.models.<model>.images[].source_repos[]`. YAML's native
support for deeply nested maps and sequences makes the cache file
significantly more readable than equivalent TOML. This introduces a new
`gopkg.in/yaml.v3` dependency. The TOML dependency could be dropped in the
future if the config format is also migrated to YAML.

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
| 6 | `build_transparency_log` | Rekor | **Yes**, when image identified by immutable compose reference | Immutable for digest-pinned; tag-based entries use reference-identity caching (see Section 3b) |
| 7 | `sigstore_verification` | Rekor | **Yes**, when image identified by immutable compose reference | Immutable for digest-pinned; tag-based entries use reference-identity caching (see Section 3b) |
| 8 | `cpu_id_registry` | Proof of Cloud | **Yes** (positive) | Append-only (infinite) |
| 9 | `gateway_cpu_id_registry` | Proof of Cloud | **Yes** (positive) | Append-only (infinite) |

**8 of 9 factors are cacheable. Only `e2ee_usable` is non-cacheable.** For
`build_transparency_log` and `sigstore_verification`, cache entries are keyed
by compose reference identity. Digest-pinned references (`repo@sha256:...`)
provide the strongest offline guarantee because the reference itself is
immutable. Tag-based references are cached by their compose reference string;
tag re-push is not detectable via the cache, which is why the `image_binding`
factor (Section 5d) exists as a separate signal.

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
`Skip` in offline mode. The `Deferred` property on `FactorResult` cleanly handles this: `e2ee_usable` starts as
`Skip` with `Deferred: true` in `BuildReport`, so it is exempt from Skip→Fail
promotion even when enforced. The proxy's `MarkE2EEUsable` promotes it to
`Pass` after a successful relay; `MarkE2EEFailed` demotes it on decryption
failure. No special-case caching logic is needed for `e2ee_usable` — the
`Deferred` mechanism ensures correct behavior regardless of cache state.
The `e2ee_tested` / `e2ee_passed` fields in the cache are informational only
(recorded for operator reference, not used for factor evaluation).

**Rekor/Sigstore (factors 6–7)**: Rekor entries are append-only and immutable.
Cache entries are keyed by compose reference identity (the `reference` field).
Digest-pinned references are the ideal caching candidate — the reference
itself is immutable. Tag-based references are cached by their compose reference
string; tag re-push is not detectable (see `image_binding`, Section 5d). The
per-model `images` list in the cache stores full Rekor provenance data.

**Proof of Cloud (factors 8–9)**: Hardware registry is append-only. Positive
registrations never expire. Authenticated negative results (`poc_registered:
false` with a valid registry response) are cached up to `max_cache_age`
(default 7 days) to avoid hammering the registry — PoC is currently
`allow_fail` for all providers. Connectivity and response errors are NOT
cached (see Section 4c). Cached positive `poc_registered: true` is valid
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

### 8d. Non-Online, Non-Cacheable Factor

The `image_binding` factor (Section 5d) is derived from the compose manifest
content and is not an online factor. It evaluates whether all images are
digest-pinned and is computed at attestation time from the live compose data.
It is included in the default `allow_fail` list for all providers (no
providers currently pin all images by digest). It does not depend on cache
data and is evaluated during both `teep verify` and `teep serve`.

---

## 9. Merge Semantics

When `teep cache neardirect --model meta-llama/Llama-3.3-70B-Instruct` runs:

1. Read existing cache file (if present).
2. Replace `providers.neardirect.models["meta-llama/Llama-3.3-70B-Instruct"]`
   with the newly fetched and verified data (including inline images).
3. If neardirect has gateway attestation, also replace
   `providers.neardirect.gateway`.
4. Preserve all other providers and models untouched.
5. Write the merged cache file atomically (write to temp file → rename).

For `--all-models`, repeat step 2 for each model, then do one gateway update
at the end.

### 9a. File Locking and Concurrency

**In-process coordination (`teep serve`)**: The in-memory cache uses a `sync.RWMutex` to protect its shared data structures, ensuring safe concurrent access via multiple clients performing simultaneous access of multiple providers and models.

Request routing and cache/report keying remain provider-isolated under
concurrency because requests are first resolved from `provider:model` to
`(provider, upstream model)` and then all cache operations use that tuple.
This prevents cross-provider collisions when providers expose identical
upstream model IDs.

**Cross-process coordination**: Multiple `teep serve` processes (or a `teep
serve` and a `teep cache`) may share the same cache file. Cross-process disk
writes are performed by first acquiring a file lock and then proceeding with
the read-merge-write file cycle. All cache file writes use `flock(2)`
(advisory file locking) to serialize cross-process access:

1. Acquire an exclusive `flock` on a lock file (`<cache-file>.lock`).
2. Read the current cache file contents.
3. Merge the new data into the loaded cache.
4. Write to a temp file and `rename` atomically.
5. Release the `flock`.

The lock file is separate from the cache file itself so that the atomic
rename does not invalidate the lock. The `flock` is held across the full
read-merge-write-rename cycle to prevent lost updates.

`teep cache` uses the same `flock`-based write path, so concurrent `teep
cache` and `teep serve` invocations are safely serialized. Concurrent `teep
cache` invocations for different providers are safe (each replaces only its
own provider section). Concurrent invocations for the same provider are
serialized by the lock — the second invocation reads the first's output and
merges on top of it.

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

The cache file's per-model TDX register value lists (`mrseam`, `mrtd`,
`rtmr0`–`rtmr2`, and gateway equivalents) serve the role formerly filled by
the config measurement allowlists. At verification time in `teep serve`:

1. Teep fetches a live attestation from the provider (as before).
2. The live TDX quote is parsed and verified locally (signature, cert chain,
   nonce binding — all offline-capable factors).
3. The live TDX measurement values are compared against the cached allowlists
  for that (provider, upstream model) pair.

**Enforcement follows the configured `allow_fail` list**:

- **Factor NOT in `allow_fail`** (enforced): If a live TDX register value
  does not match any entry in the cached allowlist, the factor **fails**. In
  `teep serve`, the request is **blocked**. In `teep verify`, TDX register
  comparison is not performed (teep verify does not use the cache).

- **Factor in `allow_fail`** (non-enforced): If a live TDX register value
  does not match any entry in the cached allowlist, a **warning** is emitted
  (`slog.Warn("cached TDX register mismatch", "register", name,
  "cached", cached, "live", live, "factor", factor)`), but the request is
  not blocked.

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
| Content | `allow_fail`, `base_url`, `api_key_env`, `cache_file`, `max_cache_age`, provider settings | TDX register allowlists, compose hashes, image provenance, PCS/NRAS/PoC results |
| TDX register handling | **Removed** (no allowlists) | Cached allowlists compared against live attestation |
| Enforcement | `allow_fail` controls which factors block | Cached data compared; `allow_fail` controls block/warn |
| Used by | `teep verify`, `teep serve`, `teep cache` | `teep serve`, `teep cache` (NOT `teep verify`) |
| Merge on update | N/A (user-managed) | Provider+model replacement with merge |
| Format | TOML | YAML |

---

## 11. Implementation Phases

### Phase 1: Cache File Format and I/O

- Define Go types for the cache file structure in `internal/cache/`.
- Per-model inline image entries (no global image table).
- TDX register fields as `[]string` allowlists.
- Implement read/write/merge operations with atomic file writes.
- Permission checks using `os.Lstat` (symlink-safe).
- Post-unmarshal validation of hex field lengths.
- Unit tests for merge semantics, format round-tripping, and safe concurrent access involving multiple providers over `sync.WaitGroup` and parallel goroutines.

### Phase 2: `teep cache` Command

- Add `teep cache` subcommand to `cmd/teep/main.go`.
- Call `verify.Run()` to fetch attestation and run full verification, then extract authenticated fields from the returned `VerificationReport` to populate the cache file.
- Support `--model`, `--all-models`, `--cache-file`.
- Emit warnings for tag-based and `version_unpinned` images.
- Partial failure handling for `--all-models`: continue all models, collect
  per-model errors, write cache for successes, exit non-zero with summary.
- Unit and integration tests.

### Phase 3: Config Removal

- Remove `--update-config`, `--config-out`, and all config measurement
  allowlist fields (see Section 10a).
- `teep verify` does NOT use the cache — no `--cache-file` flag, no cache
  reads, no cache writes. It always performs live network requests.
- Note: `e2ee_usable` needs no special handling. The `Deferred` property
  already prevents Skip→Fail promotion in `BuildReport`. Cache consultation
  code can treat it uniformly as a non-cacheable factor that evaluates via
  its normal live-test path.

### Phase 4: Cache Consumption in `teep serve`

- Add a `supplyChainCache` field to the existing `Server` struct in
  `internal/proxy/proxy.go`. This is distinct from the existing short-lived
  proxy caches (`cache` for attestation reports at 5m TTL, `negCache` at 30s,
  `signingKeyCache` at 1h, `spkiCache` at 1h). The supply chain cache stores
  long-lived authenticated verification data.
- Create the supply chain cache at `teep serve` startup (same data structures
  as the cache file). If a cache file is configured, load it into memory;
  otherwise start with an empty memory-only cache.
- Implement staleness detection, re-fetch logic, and `max_cache_age` threshold.
- Implement notice logging for stale/invalidated entries.
- Compare live TDX register values against cached allowlists; enforce via
  `allow_fail` (see Section 10b).
- **Integration point**: The `handleEndpoint` factory dispatches all endpoint
  types (chat, embeddings, audio, images, rerank) through `attestAndCache`.
  Supply chain cache consultation integrates into this flow — either within
  `attestAndCache` itself or in the `fetchAndVerify` / `BuildReport` path it
  calls. This single integration point automatically covers all endpoint types
  without per-endpoint cache code.
- Populate the in-memory cache after each successful attestation, using the
  same code paths as `teep cache` for extracting authenticated results.
- **Authenticated write-back**: When live re-attestation produces changes that
  are fully authenticated (new compose hash with all images passing
  Sigstore/Rekor, refreshed Intel PCS / NVIDIA NRAS, new PoC positive
  registrations), write these back to both the in-memory cache and the cache
  file (if configured). Use atomic write (write → rename) with `flock(2)` for
  cross-process safety and `sync.RWMutex` for in-process memory
  coordination (see Section 9a).
- **Write-back failure handling**: Cache file write failures are logged at
  `slog.Error` level and do not fail requests or block proxy operation.
- **TDX measurement registers are read-only**: `teep serve` never overwrites
  cached MRSEAM, MRTD, or RTMR values. Only `teep cache` can update these
  (explicit operator trust-on-first-use).

### Phase 5: Testing and Documentation

- Integration tests with live providers.
- `make reports` regression check.
- Update `README.md`, `README_ADVANCED.md`, help text.
- `teep.toml.example` — remove update-config examples, add `cache_file`
  and `max_cache_age` documentation.
- Rewrite `docs/measurement_allowlists.md` to describe how to use
  `teep cache` combined with `allow_fail` configuration to pin cached
  values with and without strict enforcement.
