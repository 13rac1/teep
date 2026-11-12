# NEAR DeepSeek Image Provenance: Platform Digest Discovery Gap

NEAR's DeepSeek-V4.1-Flash-1017 deployments do not provide a reliable way to
find NEAR's signed build records for a deployed Docker image. Clients must
either block requests when those records cannot be found or accept the image
without verifying that NEAR's approved build process produced it. Accepting an
unverified image can expose customer data to unapproved container code.

## The Problem

A malicious operator or an attacker who controls Docker deployments can choose
the container code that runs inside a confidential machine. That code can read
or change the customer data and credentials available to the container. Machine
authentication and encrypted connections can protect the connection to that
code without establishing that NEAR's approved GitHub Actions workflow built it.

NEAR publishes signed build records for its launcher image in Sigstore, but
these DeepSeek deployments identify the launcher using a different Docker
digest from the one that NEAR signed and logged. A client cannot find the
signed record by looking up the digest in the deployed Docker Compose file.
It must first find a Docker image index that contains the deployed image and
then authenticate that index using NEAR's signed build record.

Docker registry tags provide candidates for that search, but do not guarantee
that the client can find the required index. Normal image publishing can move
a tag to another build or copy a tag as a platform-specific image, leaving no
searchable tag for the signed index. Registry outages and rate limits add
further failure conditions. The client must then block requests even if the
launcher was built by NEAR, or continue without authenticating its origin.
This choice applies to any client verifying a deployment that uses this
image reference; it is not caused by a particular client's configuration.

## Impact

### Security: accepting a Docker image without authenticating its build

- **Who:** A malicious operator or an attacker who can replace a deployed Docker image.
- **What they do:** Run a launcher image without verifiable evidence that NEAR's approved GitHub Actions workflow built it, when the customer accepts images whose signed build records cannot be found.
- **What they get:** The ability to run container code with access to the customer data and credentials available to that container.
- **What stops it today:** Blocking requests until the image's signed build record is found and its signature is verified would prevent this case. Machine authentication and encrypted connections do not establish who built the image.

The missing build record leaves the client unable to distinguish a legitimate
NEAR image from an unapproved image solely from the deployed image digest.

### Availability: preventing clients from finding NEAR's signed build record

- **Who:** An attacker who can disrupt Docker registry access or control its tags.
- **What they do:** Prevent a client from finding the signed image index that contains an otherwise legitimate deployed launcher image.
- **What they get:** The ability to block requests from clients that require authentication of the Docker image's build.
- **What stops it today:** Previously acquired and verified index and build records can avoid repeated discovery, but cannot supply records that a client has never obtained.

Ordinary publishing changes, registry outages and rate limits can cause the
same interruption without an attacker, even while NEAR's signed build record
remains available in Sigstore.

---

## Technical Background

### Digests, manifests, and indexes

Every image reference examined here ends in a SHA-256 content hash, or digest,
for example `nearaidev/compose-manager-launcher@sha256:91fdff3c…`. A digest
identifies the exact bytes of one registry object, so a compose pin fixes the
image content. The named object has one of two forms:

- A **manifest** describes how to assemble the image for one platform.
- An **index** lists manifests, one descriptor per platform, and can also
  list build-attestation manifests.

A build that records build attestations produces an index even when it builds
one platform. The index and each manifest it lists have different digests. A
signature or attestation names exactly one digest, so a record naming the
index says nothing about a child manifest unless the verifier also fetches
the index bytes and checks that the child is a member.

### What NEAR signs

NEAR builds `nearaidev/compose-manager-launcher` in the `launcher-image` job
of the [`build.yml` GitHub Actions workflow](https://github.com/nearai/compose-manager/blob/bf97be3eb430e78898622c765a37e22fd40b2d22/.github/workflows/build.yml)
in `nearai/compose-manager`. The job builds the `launcher/` directory for
`linux/amd64` and pushes it to Docker Hub:

```yaml
- name: Build and push launcher image
  id: build
  uses: docker/build-push-action@v6
  with:
    context: ./launcher
    push: true
    tags: ${{ env.LAUNCHER_IMAGE_REFERENCE }}
    platforms: linux/amd64
```

The registry object that this push creates is an OCI image index with two
members: the `linux/amd64` manifest and an `unknown/unknown`
build-attestation manifest. For the launcher builds examined here,
`steps.build.outputs.digest` identifies that index. The same job records
exactly that digest in Sigstore:

```yaml
- name: Sign launcher image with cosign (keyless)
  run: |
    cosign sign --yes "${{ env.REGISTRY }}/${{ env.LAUNCHER_IMAGE_REPOSITORY }}@${{ steps.build.outputs.digest }}"

- name: Generate artifact attestation
  uses: actions/attest-build-provenance@v3
  with:
    subject-name: ${{ env.REGISTRY }}/${{ env.LAUNCHER_IMAGE_REPOSITORY }}
    subject-digest: ${{ steps.build.outputs.digest }}
    push-to-registry: true
```

NEAR's signed records for this image therefore name the index digest. For
builds on `master`, the GitHub Actions signing identity is
`https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master`.
Rekor's digest search, `POST /api/v1/index/retrieve`, finds records for a
digest directly when that digest is a record's subject.

### Which digest the deployment names

The deployment's attested Docker Compose file supplies the digest that a
client must authenticate. The retained GLM captures of 2026-09-09 pin the
signed index:

```yaml
compose-manager-launcher:
  image: nearaidev/compose-manager-launcher@sha256:91fdff3cfa3543d72656b2368c7d8a0a83d95a0f1087378c897aa1537acdba56
```

This excerpt is from the NearDirect capture in
[NEAR signed TLS-only captures](../../internal/integration/testdata/near_tls_only/);
the NearCloud capture pins the same digest. A pin in this form can be searched
in Rekor directly, because the pinned digest is the subject digest of NEAR's
records. `TestNearGLMIndexPinPassesEnforcedSigstore` replays both provider
captures through the production verifier with this factor enforced.

The DeepSeek deployments observed on 2026-11-11 pin a different digest of the
same build: the `linux/amd64` child manifest of that index.

```text
nearaidev/compose-manager-launcher@sha256:91fdff3c…   OCI image index; NEAR's CI signs and logs this digest
├── sha256:079a14b4…   linux/amd64 manifest; the DeepSeek compose pins this digest
└── sha256:c3e4bbb1…   unknown/unknown build-attestation manifest
```

The affected compose pins
`nearaidev/compose-manager-launcher@sha256:079a14b41deb11e0e27f9b69648e8b3d89bd6fb9ccf6071643b8f447fa415085`,
while NEAR's workflow logged
`sha256:91fdff3cfa3543d72656b2368c7d8a0a83d95a0f1087378c897aa1537acdba56`.
The [provider reference](../providers/near/near_attestation.md#supply-chain-image-index-and-platform-manifest)
lists both complete digests and commands for inspecting them. This is the
whole gap: the compose names the manifest, NEAR's records name the index that
lists it, and nothing connects the two. Searching Rekor for the pinned
manifest digest returns no records (checked on 2026-11-12); searching for the
index digest returns NEAR's records. A client that finds a containing index
must then check the index hash and exact manifest membership before NEAR's
signed record for that index applies to the pinned manifest.

### Why discovery depends on tags

Rekor is searchable only by record subject digest, and an OCI registry offers
no lookup from a manifest to the indexes that list it. Registry tags are the
only public source of candidate indexes. A tag is a mutable name for a
manifest or index, and the
[OCI distribution specification](https://github.com/opencontainers/distribution-spec/blob/97274622c11112caa21efb8c52acca3c6b8fa7f1/spec.md#definitions)
permits a manifest to have no tags, so a tag list cannot enumerate every
index that contains a given platform manifest. The detailed analysis below
records what the current tags show for this image and how NEAR's publishing
workflows move them.

---

## Detailed Gap Analysis

### Scope and evidence

The lookup failure starts in the compose's launcher image reference. This
report does not describe a change in the attestation response schema or the
Rekor record format. The reported affected models are:

- `deepseek-ai/DeepSeek-V4.1-Flash-1017`
- `deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated`

| Evidence | Launcher digest named by compose | Rekor lookup for the pinned digest |
| --- | --- | --- |
| `z-ai/glm-5.3-flash`, NearDirect and NearCloud captures of 2026-09-09 | Index `91fdff3c…` | Direct lookup finds Rekor entries; `sigstore_verification`, which checks that an entry exists, passes with enforcement enabled. |
| Both DeepSeek models, NearDirect investigation of 2026-11-11 | Platform manifest `079a14b4…` | No records; first find the containing signed index `91fdff3c…`. |
| NearCloud model evidence reported with PR #191 for the affected DeepSeek deployment | Platform manifest `079a14b4…` | Same mismatch in model-tier evidence; this does not establish a changed gateway image format. |

The [model investigation](https://github.com/13rac1/teep/issues/189#issuecomment-6807723408)
and [PR #191](https://github.com/13rac1/teep/pull/191) record the DeepSeek
observations. The retained signed GLM captures establish the earlier index
pin; `TestNearGLMIndexPinPassesEnforcedSigstore` replays both providers
through the production verifier with this factor enforced. This comparison
establishes lookup behavior for the two image-reference forms.

These observations describe specific deployments and dates, not the whole
NEAR fleet or the present state of every backend. The GLM captures establish
the prior format; they do not prove that a live GLM backend still supplies
the same compose today.

### Finding the containing index through registry tags

The [NEAR provider reference](../providers/near/near_attestation.md#supply-chain-image-index-and-platform-manifest)
records the affected digests: the compose pins launcher manifest `079a14b4…`,
while the build provenance names containing index `91fdff3c…`. Searching
Rekor for the pinned digest returns no entries; the previous index pin
permitted a direct lookup of the measured digest.

The registry's tags are the only public candidates for a containing index.
On 2026-11-12, the [Docker Hub tag listing](https://hub.docker.com/v2/repositories/nearaidev/compose-manager-launcher/tags?page_size=100)
contained 38 tags. The tags pointing into the affected build were:

| Tag | Digest it names |
| --- | --- |
| `prod-20260702-8e07c35` | Signed index `91fdff3c…` |
| `prod`, `latest`, `prod-rollback-20260925-213344-from-20260702-8e07c35`, `staging-20260624-8e07c35` | Child manifest `079a14b4…` |

The affected production image was therefore discoverable through the tag list
at that time. This observation does not establish tag retention guarantees,
a history of pruning, or the frequency of discovery failures.

NEAR's publishing workflows explain the split in that table. The
[build workflow](https://github.com/nearai/compose-manager/blob/bf97be3eb430e78898622c765a37e22fd40b2d22/.github/workflows/build.yml)
signs the launcher build's output digest, then copies a stamped staging tag
without `--all`:

```yaml
- name: Push immutable launcher staging tag
  if: env.ALSO_TAG_LAUNCHER_STAGING_STAMP == 'true'
  run: |
    STAGING_STAMPED_REF="${{ env.REGISTRY }}/${{ env.LAUNCHER_IMAGE_REPOSITORY }}:staging-${STAMP}-${SHORT_SHA}"
    skopeo copy "docker://${{ env.REGISTRY }}/${{ env.LAUNCHER_IMAGE_REPOSITORY }}@${{ steps.build.outputs.digest }}" "docker://${STAGING_STAMPED_REF}"
```

[Skopeo's copy documentation](https://github.com/containers/skopeo/blob/8360e9e41548eee4bd1e41d231955ba85529e303/docs/skopeo-copy.1.md#options)
states that a copy without `--all` copies only the image for the current
platform. Each stamped staging tag therefore names the `linux/amd64` child
manifest, and no stamped staging tag names the signed index.

The [launcher promotion workflow](https://github.com/nearai/compose-manager/blob/bf97be3eb430e78898622c765a37e22fd40b2d22/.github/workflows/promote.yml)
copies the launcher with `--all` and then confirms that `prod`, its stamped
tag, and `latest` resolve to the promoted digest:

```yaml
# --all copies the full OCI manifest index (not just the current platform),
# so :prod resolves to the same multi-arch index digest as :staging.
skopeo copy --all "docker://${LAUNCHER_IMAGE}@${LAUNCHER_DIGEST}" "docker://${LAUNCHER_IMAGE}:prod"
skopeo copy --all "docker://${LAUNCHER_IMAGE}@${LAUNCHER_DIGEST}" "docker://${LAUNCHER_IMAGE}:${LAUNCHER_PROD_STAMPED_TAG}"
skopeo copy --all "docker://${LAUNCHER_IMAGE}@${LAUNCHER_DIGEST}" "docker://${LAUNCHER_IMAGE}:latest"
```

A stamped production tag can therefore name the signed index, and
`prod-20260702-8e07c35` does.

The [rollback workflow](https://github.com/nearai/compose-manager/blob/bf97be3eb430e78898622c765a37e22fd40b2d22/.github/workflows/rollback.yml#L151-L153)
copies the rollback target to `prod`, `latest` and a `prod-rollback-…` audit
tag without `--all`:

```yaml
skopeo copy "docker://${image}@${digest}" "docker://${image}:prod"
skopeo copy "docker://${image}@${digest}" "docker://${image}:latest"
skopeo copy "docker://${image}@${digest}" "docker://${image}:${{ steps.resolve.outputs.audit_tag }}"
```

Each of these tags therefore names a platform manifest, not the signed index.
Observed on 2026-11-12, Docker Hub showed `prod`, `latest` and
`prod-rollback-20260925-213344-from-20260702-8e07c35` last updated on
2026-09-25 between 21:33 and 21:34 UTC, each naming `079a14b4…`. NEAR's
build, promotion and rollback workflows explain the split in the tag table.
None of the three workflows guarantees that a tag names the signed index of a
deployed manifest when a client searches.

Candidate searches add registry requests, pagination and rate-limit exposure.
A bounded search can stop before it finds a valid parent. A complete search
can still fail when no current tag names that parent, even while the parent
stays available by digest. Neither outcome proves the image is malicious.
An untrusted registry can withhold candidates; it cannot make a false
candidate pass the index hash check, the exact membership check, and NEAR's
signature check.

---

## Remediation

### Publish signed records for the digest in Docker Compose

For the affected DeepSeek deployments, NEAR can sign the platform manifest
that the compose pins, or pin the signed index in the measured compose again.
Either choice removes reverse discovery.
Alternatively, publish a stable parent-index hint with the deployment evidence
and retain the index by digest. The hint need not be trusted if the client
checks the index hash, exact child membership and the index digest named in
NEAR's signed build record. Retaining tags helps clients find the index;
verifying NEAR's signature authenticates the build.

A rollback that copies with `--all`, as the promotion workflow does, keeps
`prod` and `latest` on the signed index.

### Bound discovery and preserve enforcement

Bound pagination, candidate counts, response sizes and verification time.
Coalesce concurrent retrievals and reuse verified evidence under the applicable
policy. A cache cannot recover evidence that was never acquired. Missing
evidence or an exhausted search must fail an enforced check; it must not
be converted into successful publisher verification.

Missing discovery evidence must remain visible as a failed check until it is
resolved. Making NEAR's signed image records discoverable does not close the
separate [dstack boot-measurement gap](dstack_integrity.md).

---

## References

- **Scope evidence:** [DeepSeek model investigation](https://github.com/13rac1/teep/issues/189#issuecomment-6807723408) and [PR #191](https://github.com/13rac1/teep/pull/191).
- **Provider behavior:** [NEAR provider reference](../providers/near/near_attestation.md#supply-chain-image-index-and-platform-manifest), [Docker Hub tags](https://hub.docker.com/v2/repositories/nearaidev/compose-manager-launcher/tags?page_size=100), [build workflow](https://github.com/nearai/compose-manager/blob/bf97be3eb430e78898622c765a37e22fd40b2d22/.github/workflows/build.yml), [promotion workflow](https://github.com/nearai/compose-manager/blob/bf97be3eb430e78898622c765a37e22fd40b2d22/.github/workflows/promote.yml), [rollback workflow](https://github.com/nearai/compose-manager/blob/bf97be3eb430e78898622c765a37e22fd40b2d22/.github/workflows/rollback.yml).
- **Formats and tools:** [OCI distribution definitions](https://github.com/opencontainers/distribution-spec/blob/97274622c11112caa21efb8c52acca3c6b8fa7f1/spec.md#definitions), [Skopeo copy options](https://github.com/containers/skopeo/blob/8360e9e41548eee4bd1e41d231955ba85529e303/docs/skopeo-copy.1.md#options).
- **Client implementation:** [NEAR policy](../../internal/provider/neardirect/policy.go), [Rekor client](../../internal/attestation/rekor.go), [factor evaluation](../../internal/attestation/report.go), [verify retrieval](../../internal/verify/attest.go), [proxy retrieval](../../internal/proxy/proxy.go).
- **Captured evidence:** [NEAR signed TLS-only captures](../../internal/integration/testdata/near_tls_only/) and [capture replay tests](../../internal/verify/near_capture_test.go).
- **Related gap:** [Dstack integrity](dstack_integrity.md).

---

## Teep Status

The platform-manifest lookup failure is reported for the two DeepSeek
models listed in [Scope and evidence](#scope-and-evidence). The older signed
GLM captures pass that lookup, which checks only that a Rekor entry exists,
with enforcement enabled. Teep currently reports
`sigstore_verification` failures as allowed for both NEAR providers; the
exception therefore affects models that did not require it too. The
parent-index resolver described above is not implemented.

### Temporary teep policy

Both NEAR defaults allow `sigstore_verification` to fail to accommodate the
reported DeepSeek deployments. The older GLM captures pass without this
exception, but the default policy also relaxes their enforcement. This permits
absent entries and lookup errors for every model image, plus gateway images for
NearCloud. The exception is not restricted to the affected launcher digest.
Restoring default enforcement is a separate policy change and requires live
fleet evidence that every instance passes.

The [verify path](../../internal/verify/attest.go) and
[proxy path](../../internal/proxy/proxy.go) fetch provenance only for digests
whose initial Rekor search succeeded. The remaining provenance factors
evaluate the retrieved subset. They can pass while a missing component has
no provenance record to evaluate. If other enforced factors fail, the
request still blocks. Compose binding and event-log replay do not supply
the missing publisher authentication.
