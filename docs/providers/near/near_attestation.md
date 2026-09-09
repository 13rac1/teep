# NEAR attestation response parsing

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
