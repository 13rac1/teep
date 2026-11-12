# NEAR routing and attestation

## Attestation response parsing

Teep selects the parser from the configured provider before decoding evidence.
A parsing failure blocks verification. Teep does not try another envelope or
select a valid subset of a malformed response.

| Provider | Required envelope |
| --- | --- |
| NearDirect | A complete flat model report and `all_attestations` containing exactly one copy of that report. Both reports must identify the requested model and agree in every supported field. |
| NearCloud | `gateway_attestation` and a nonempty `model_attestations` array containing exactly one requested-model entry. Every entry must be structurally valid, and model names must be unique. Flat model fields and `all_attestations` are forbidden. |

The shared fetch and parser response limit is 1 MiB. Model arrays are limited to 256 entries; each event
log and compose-manager action array is limited to 10,000 entries. Missing
required fields, null supported fields, duplicate object members (including
equivalent escaped names), and invalid field types are errors. These structural
errors cannot be permitted through `response_schema` allowances. Compose-manager
service arrays also reject null elements.

Typed nested decoders validate model reports, info, TCB information, event
entries, gateway evidence, and supported auxiliary objects before assigning
the decoded values. TCB information accepts an object or one JSON-string
encoding of that object. Gateway event logs require one JSON-string encoding
of an array. Duplicate-member checks also apply inside those decoded strings.
Additional encoding layers are rejected.

Unknown fields are returned with their paths for the caller's `response_schema`
policy. Low-level parsers do not log or deduplicate these diagnostics. Unknown
members are excluded before typed decoding, so a differently cased unknown
name cannot overwrite a supported member. An explicit schema allowance can
permit additions; it does not make them authenticated verification inputs.

Direct-report comparison includes the model identifier, signing algorithm,
public key, signing address, TLS fingerprint, nonce, quote, NVIDIA payload,
all supported info and TCB fields, and ordered event logs. Supported hex values
are decoded and compared in constant time. Other evidence strings retain their
exact content. Object member order and the supported TCB string encoding do
not change equality. Comparison does not verify quote signatures or authenticate
a public key; the [model-key binding check](../../../README_ADVANCED.md#near-ai-direct-tls-pinning)
remains required.

The gateway has its own signing-address scheme and TLS identity. Its evidence
is validated separately, not compared with a repeated model report. Auxiliary
OHTTP and compose-manager objects have their own typed schemas; their presence
does not authorize inference or replace the model and gateway checks.

Exact-name and null-field handling use the shared
[strict object decoder](../../../internal/jsonstrict/object.go). It re-encodes
objects only when unknown members must be removed. Independently callable
decoders retain duplicate-member checks, including decoded JSON strings.

The schemas are defined in [shared NEAR decoders](../../../internal/provider/nearparse/),
the [direct parser](../../../internal/provider/neardirect/parser.go), and the
[gateway parser](../../../internal/provider/nearcloud/parser.go). Protocol evidence
includes the pinned upstream response definitions referenced by the
[NEAR backend-selection design](../../plans/near_backend_selection.md#investigation-and-evidence)
and the signed NEAR captures in [integration testdata](../../../internal/integration/testdata/).
Captures describe the provider at capture time; replay cannot establish the
current deployed schema or a current TLS handshake.

Regression coverage includes the direct and cloud `parser_contract_test.go`
files, `TestNearSignedModelKeySubstitution`, and the provider signed-evidence
fixture suites. Transport requirements remain in the
[shared transport reference](../../transport/README.md).

## Supply chain: image index and platform manifest

The lookup mismatch was reported on 2026-11-11 for NEAR's
`deepseek-ai/DeepSeek-V4.1-Flash-1017` and
`deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated` deployments. The retained
`z-ai/glm-5.3-flash` captures use the earlier index pin and pass the same
lookup without the temporary exception. This is a change in the compose's image
reference; it is not evidence that every NEAR model or its entire attestation
response changed format.

| Deployment evidence | Launcher compose pin | Parent-index discovery needed? |
| --- | --- | --- |
| GLM-5.3-Flash, NearDirect and NearCloud captures of 2026-09-09 | Signed index `91fdff3c…` | No; the pinned digest can be looked up directly. |
| Both DeepSeek-V4.1-Flash-1017 models, reported on 2026-11-11 | Platform manifest `079a14b4…` | Yes; the publisher evidence names the containing index. |

The [gap report's scope and evidence](../../attestation_gaps/near_image_provenance.md#scope-and-evidence)
separates the reported DeepSeek deployments, retained GLM captures, and
provider-wide policy effects. Captures establish behavior at their recorded
dates, not the current state of every backend.

NEAR's [supply-chain policy](../../../internal/provider/neardirect/policy.go)
names the `build.yml` or `promote.yml` workflow of `nearai/compose-manager`
on `refs/heads/master` for `nearaidev/compose-manager-launcher`.
`sigstore_verification` looks up each image digest of the measured compose
in Rekor. Separate factors check the provenance records that were retrieved.
The [NEAR image provenance gap report](../../attestation_gaps/near_image_provenance.md)
describes the DeepSeek lookup failure. The separate teep publisher-verification
defect is tracked in [issue #164](https://github.com/13rac1/teep/issues/164).

A container image index lists platform manifests and can also contain build
attestation manifests. Even a single-platform build can produce an index.
NEAR's launcher build workflow signs the index digest,
and Rekor indexes the attestation under that digest. A compose can pin
either digest. Teep finds a Rekor entry only for the digest that the
attestation names, and Rekor has no lookup from a platform manifest to the
index that lists it.

Example, checked on 2026-11-11:

- `nearaidev/compose-manager-launcher@sha256:91fdff3cfa3543d72656b2368c7d8a0a83d95a0f1087378c897aa1537acdba56`
  is an OCI image index (Docker Hub). Its `linux/amd64` manifest is
  `sha256:079a14b41deb11e0e27f9b69648e8b3d89bd6fb9ccf6071643b8f447fa415085`.
- Rekor has two entries for the index digest. One of them is a DSSE
  attestation signed by
  `https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master`
  in [workflow run 28089759418](https://github.com/nearai/compose-manager/actions/runs/28089759418)
  of 2026-06-24. Rekor has no entry for the manifest digest.
- The investigation of `deepseek-ai/DeepSeek-V4.1-Flash-1017` and
  `deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated` reported this platform
  manifest pin on NearDirect. PR #191 also reports it in NearCloud model
  evidence. This does not establish a changed gateway image format.
- The retained `z-ai/glm-5.3-flash` captures instead pin index `91fdff3c…`
  directly. `TestNearGLMIndexPinPassesEnforcedSigstore` verifies that both
  provider captures pass with `sigstore_verification` enforced.

The index, its manifest, and the Rekor entries of each digest:

```sh
crane manifest nearaidev/compose-manager-launcher@sha256:91fdff3cfa3543d72656b2368c7d8a0a83d95a0f1087378c897aa1537acdba56
curl -s -H 'Content-Type: application/json' \
  -d '{"hash":"sha256:91fdff3cfa3543d72656b2368c7d8a0a83d95a0f1087378c897aa1537acdba56"}' \
  https://rekor.sigstore.dev/api/v1/index/retrieve
curl -s -H 'Content-Type: application/json' \
  -d '{"hash":"sha256:079a14b41deb11e0e27f9b69648e8b3d89bd6fb9ccf6071643b8f447fa415085"}' \
  https://rekor.sigstore.dev/api/v1/index/retrieve
```

With the index pin in the GLM captures, teep can query Rekor directly for
the measured digest. The reported DeepSeek platform manifest pin requires
an additional discovery step:
find a signed index that contains that manifest. One possible procedure is:

1. List the candidate indexes of the image from the registry (its tags).
2. Fetch each candidate index by digest and check that its bytes hash to
   that digest, so that the registry needs no trust.
3. Accept an index only if it lists the exact pinned manifest digest for
   the platform of the measured compose.
4. Obtain the complete signed statement or bundle for the index. Verify its
   signature, certificate trust and workflow identity, its subject digest,
   and its transparency evidence. A Rekor search result alone is insufficient.

This would establish: measured compose → manifest digest → index membership
and hash → independently verified signed index. Teep does not implement
this procedure today. It would add tag enumeration and candidate-index
retrievals to the existing provenance requests. Search work grows with the
number of candidate tags and indexes; pagination, rate limits, outages and
bounded search limits can prevent a new authorization.

Tags do not enumerate all stored indexes. A signed index can remain available
by digest after its last tag moves, disappears, or is copied as a platform
manifest. On 2026-11-12, Docker Hub still listed the example's signed index
under `prod-20260702-8e07c35`, while `prod`, `latest`, and
`staging-20260624-8e07c35` identified the child manifest. This establishes
current discoverability for that image, not a retention guarantee or a
history of tag pruning. NEAR's build workflow copies stamped staging tags
without `--all`; its launcher promotion workflow uses `--all` to retain the
index. See the gap report's
[source evidence and limits](../../attestation_gaps/near_image_provenance.md#finding-the-containing-index-through-registry-tags).

Discovery failure must block an enforced image check. It does not prove the
image is malicious, and a missing tag does not make a forged signature valid.
A verified cache can reduce repeated discovery, but cannot supply evidence
that was never acquired. A stable parent-index hint can supply candidates
without being trusted, provided the verifier checks the complete chain.

### Teep publisher-verification defect

[Issue #164](https://github.com/13rac1/teep/issues/164) tracks a teep verification
defect: the Rekor path reads the claimed publisher identity from a certificate
without validating its chain to Fulcio, and does not independently verify the
signed statement's subject against the image digest. It affects the older GLM
captures too and is independent of the DeepSeek compose digest choice.

The current NEAR policy sets `NoDSSE: true` for the launcher and
compose-manager. The captured [Rekor DSSE records](https://github.com/sigstore/rekor/blob/2c0ee5be82d2b88ddf94d456a6d92f35d20fa45f/pkg/types/dsse/README.md)
contain `spec.signatures`,
`payloadHash` and `envelopeHash`; they omit the full signed payload.
Teep's `verifyDSSESignature` expects a complete envelope at
`spec.content.envelope`, so it cannot verify these signatures through that
path. `NoDSSE` ignores signature errors generally, including errors caused
by incomplete records and invalid signatures.

For retrieved records, teep checks Rekor log evidence and expected identity
metadata extracted from the certificate.
[Rekor verifies envelope signatures on submission](https://github.com/sigstore/rekor/blob/2c0ee5be82d2b88ddf94d456a6d92f35d20fa45f/pkg/types/dsse/v0.0.1/entry.go#L282-L300),
but its signed log record is not a substitute for the missing client checks.
Parent-index discovery alone would retain this defect.
This can be corrected in teep by retrieving complete signed evidence,
validating certificate trust and signing-time eligibility, and verifying the
signature and subject digest. Rekor's record alone omits the payload needed
for that last step. Removing `NoDSSE` without implementing this pathway would
block the currently supported records. The code fix belongs to issue #164;
it is not a provider boot-measurement limitation or a consequence of the
DeepSeek image-reference change.

### Temporary default enforcement

To accommodate the two reported DeepSeek deployments while teep cannot
resolve their chain,
`sigstore_verification` is in `NeardirectDefaultAllowFail` and
`NearcloudDefaultAllowFail`: teep reports the failure, and it does not block
requests. The exception applies to every model image for both providers
and to gateway images for NearCloud, including models such as the captured
GLM deployment that already pass the lookup. Its scope is broader than the
reported DeepSeek launcher mismatch.
Missing log entries and search errors can therefore leave other components
without provenance verification too.

Both `serve` and `verify` fetch Rekor provenance only for digests whose
search succeeded. `build_transparency_log` and signer-recognition factors
evaluate that retrieved subset; a passing result does not establish
coverage of a missing component. A deployment must still pass the other
enforced factors. Compose binding and event-log integrity authenticate the
supplied configuration, not the publisher of an image whose provenance
was not verified. The
[NEAR image provenance report](../../attestation_gaps/near_image_provenance.md#teep-status)
records this policy exposure separately from the existing signature limitation
and the [dstack boot-measurement gap](../../attestation_gaps/dstack_integrity.md).

## NearDirect backend selection

Each provider instance establishes one route per model. For the default NEAR
origins, it reads `/endpoints`, validates `/backends/count` for the canonical
model authority, and selects a random unsigned 64-bit index below the healthy
count. The resulting `model-iN.completions.near.ai` authority remains fixed for
the resolver's lifetime. An index identifies a routing name, not a permanent
physical machine. NEAR can map that name to another backend when its fleet changes.

| Configured HTTPS origin | Initial metadata | Route |
| --- | --- | --- |
| `api.near.ai` or `completions.near.ai`, including port 443 | Endpoint list and count | Selected indexed model authority |
| Canonical model name under `completions.near.ai` | Endpoint list must match the model; count required | Selected indexed model authority |
| Explicit `model-iN.completions.near.ai` | Endpoint list must match the canonical model; no count | Configured indexed authority |
| Any valid origin with a non-default port | None | Exact static authority |
| Other valid HTTPS origin | None | Exact static authority |

Indices use canonical decimal uint64 syntax. Invalid, overflowing, ambiguous,
or excessively long names are rejected. An explicit index need not be below
the current healthy count. Model identifiers must contain 1–256 bytes and no
C0 or DEL control characters. Metadata cannot authenticate the selected backend:
full evidence verification and the attested TLS handshake remain required.

Endpoint and count snapshots last five minutes and serve only initial route
selection. Established routes never refresh discovery, including after
metadata expiry, an outage, authorization eviction, or failed TLS authentication.
Each new full NearDirect verification owns a fresh attestation connection pool
and closes it after the fetch. If an index now reaches another TLS identity,
the failed handshake sends no inference bytes; the next request verifies the
new backend on the same route. Other model selections and authorizations remain
unchanged. See the [shared retry rules](../../transport/retries.md).

Endpoint membership is checked before a route slot is reserved, including during
cold discovery and refresh. Unknown models consume no selection slots.
Shared selection lasts at most 60 seconds; metadata operations last at most
30 seconds. Caller cancellation ends its wait without canceling other callers.
The resolver retains at most 4096 established or pending selections, 4096 count
records, and 16 active count fetches. Established routes are not evicted. Eligible
completed count records can be evicted; pending fetches and the one-second delay
after a metadata failure remain protected. Shutdown cancels and joins owned work.

Invalid or unknown models return HTTP 400. Metadata retrieval, validation, and
configured-model mismatches return 502. Capacity, protected failure delays, and
metadata expiry before publication return 503 with `Retry-After: 1`. Cancellation
and caller deadlines retain their existing HTTP classifications. These failures
do not authorize a different backend or plaintext inference.

Report requests read an established selection and cached authorization, or return
404. An explicit authority selects only that exact cached scope. Report reads do
not fetch metadata or update selection recency.

## Standalone inference and captures

The standalone verifier probes streaming chat only. It does not validate image,
embedding, rerank, score, or audio inference. A failed chat probe remains a failed
verification outcome, including for a model that supports only another endpoint.
NEAR probes use the configured E2EE mode. Live proxy tests use online admission
in both modes; TLS-only tests add only the documented `e2ee_usable` allowance. As in `serve`, TLS-only configuration
requires `e2ee = false` and an explicit allowlist containing `e2ee_usable` in
addition to the provider defaults. A configured `allow_fail` list replaces the
default list; disabling
encryption alone does not waive an enforced E2EE factor. TLS-only probes create no encryption
session and record `tls_inference` separately from `e2ee_usable`. An unattempted,
nonfailed probe remains visible as an unenforced `Skip`. Attempted probes and recorded failures
remain enforced operational outcomes, outside `allow_fail`. Successful TLS-only
chat does not establish E2EE success or independently prove gateway backend-key
selection. Offline, missing-credential, and replay conditions do not start a live probe.

NEAR captures record the effective origin and E2EE boolean even when
inference is skipped. For NearDirect, the origin is its normalized configured origin. For NearCloud,
it is the fixed `https://cloud-api.near.ai` gateway; `base_url` does not select
attestation, inference, or capture routing. Replay rejects a change to the
effective origin or E2EE mode before verification.
NearDirect captures also record a typed discovered, explicit-index, or static route.
Replay validates the selected authority and exact index against the required captured
metadata, then verifies the recorded attestation peer and signed evidence at that
route. It performs no random selection or live inference. Missing selection metadata
requires a new capture; a manifest cannot substitute for authenticated evidence.

Regression coverage includes [selection tests](../../../internal/provider/neardirect/selection_test.go),
[metadata admission tests](../../../internal/provider/neardirect/metadata_capacity_test.go),
[fresh fetch tests](../../../internal/provider/neardirect/transport_binding_test.go),
[replay checks](../../../internal/verify/near_capture_test.go), and
[TLS-only probe tests](../../../internal/verify/tls_probe_test.go). The probe validates
every chunk and choice, including after valid text, while permitting null content,
usage-only chunks with an empty choices array, and provider extensions. Only
exactly named supported fields contribute to probe success; case-variant
extensions cannot overwrite supported values. An explicit
standalone attestation client factory is retained when the collateral client is omitted.

## NearCloud model routing

NearCloud uses the fixed `cloud-api.near.ai` gateway authority. Attestation
requests select `provider=near`, with a fresh client nonce, Ed25519 signing,
and TLS binding. Teep does not select a gateway backend index or accept a
Chutes report as NEAR model evidence.

Every supported inference request carries exactly one `X-Model-Pub-Key` header:
the acquired authorization's 32-byte Ed25519 model key, encoded as 64 lowercase
hexadecimal characters. The stateless preparer replaces inbound hints. E2EE
requests use that same authorization for their fresh encryption session.
Authorization admission retains the immutable validated model key and its
X25519 conversion. Encryption and header preparation use that acquired value
without repeating conversion for each request. TLS-only preparation uses its
canonical encoding without creating an encryption session. Each encrypted
request still creates fresh ephemeral session material. Key validation does
not replace REPORTDATA authentication. Standalone admission retains the same
value across connection retries and validates new material after key rejection.
NearDirect does not send this gateway hint.

TLS-only NearCloud requests also require a valid model key and successful
REPORTDATA binding before authorization publication or standalone inference.
An allowance for the binding factor cannot authorize a substituted key. Retaining
the routing key does not enable encryption or establish E2EE success.

The header is a routing hint, not independent evidence of backend selection.
Gateway deployment settings and endpoint implementations can ignore it. Teep
does not claim non-chat backend affinity; E2EE responses must still authenticate.
The gateway remains the TLS peer, and its SPKI must match the reported fingerprint.
Attestation-authenticated gateway TLS also requires successful gateway REPORTDATA
binding; `gateway_tee_reportdata_binding` is separately allowed to fail by default.
A model-key replacement can reuse gateway connections whose transport identity
remains valid.

Only the exact documented chat HTTP 421 stale-key envelope invalidates the
used authorization generation in both modes. E2EE permits one retry with newly
acquired authorization and fresh session material; TLS-only returns the rejection
without replay. A replacement already published by another request remains
usable. See the [exact envelope and retry contract](../../transport/retries.md#nearcloud-stale-routing-key).

Generic image errors, including 404 and 500, do not establish key retirement or
rejection before inference. They cause no replay, authorization removal, or
cooldown. Ordinary malformed bodies, read failures, and cancellation retain
these rules; independent transport or response-authentication failures retain
their own invalidation contracts. If a retired image key produces only generic
errors, requests can fail until authorization is otherwise evicted or the
process restarts. There is no automatic image key-retirement recovery or
authorization TTL. The standalone chat probe does not validate image recovery.

Coverage includes [routing header tests](../../../internal/provider/nearcloud/preparer_test.go),
[admission tests](../../../internal/proxy/authorization_near_keys_test.go),
[stale-key tests](../../../internal/proxy/nearcloud_stale_key_test.go),
[image error tests](../../../internal/proxy/nearcloud_image_policy_test.go), and
signed capture replay in [verification tests](../../../internal/verify/near_capture_test.go).
