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
