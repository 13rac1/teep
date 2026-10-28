# Plan: Attestation Cache (`teep cache`)

## 1. Goals and runtime baseline

`teep cache` has two goals:

1. **Reduce or eliminate additional requests before inference starts.** Prepare
   reusable evidence, distribute it to replicas, and evaluate it locally with the
   current verifier and policy on every new admission, including after updates. Specify
   the remaining requests for discovery, fresh endpoint admission, report-bound
   services, and missing or ineligible collateral. Measure request reduction;
   do not equate HTTP/2 connection reuse with fewer
   HTTP requests. See [request accounting](#4b-request-reduction-and-elimination).
2. **Provide an optional operator decision path to pin observed evidence despite
   policy violations.** `teep cache --update-whitelist` records exact TOFU pins or
   policy exceptions for selected failures. It does not relabel a failed check as
   cryptographic success. Define ordinary, elevated-risk, and unsupported decisions
   and the checks and requests each decision replaces. See the
   [exception inventory](#5a-whitelist-inventory).

### Command and flag synopsis

The following is the complete proposed command surface for this plan, in addition
to existing configuration and service flags. Brackets indicate optional arguments;
`TARGETS` means either `--all-models` or one or more `--model provider:model`
arguments. These are proposed interfaces, not commands available before implementation.

```text
teep cache TARGETS [--cache-file PATH]
teep cache TARGETS --update-whitelist [--reason TEXT] [--cache-file PATH]
teep cache TARGETS --update-whitelist --proposal-out PATH [--reason TEXT] [--cache-file PATH]
teep cache --update-whitelist [--reason TEXT] [--cache-file PATH]
teep cache --update-whitelist --proposal-out PATH [--reason TEXT] [--cache-file PATH]
teep cache --update-whitelist --apply-proposal PATH [--cache-file PATH]
teep serve [--cache-file PATH] [--autocache]
teep verify [existing target/options] [--cache-file PATH | --no-cache]
```

| Command or flag | User interaction |
| --- | --- |
| `teep cache` | Collect and verify evidence, then merge complete successful targets into the cache file. Ordinary caching does not change policy. |
| `--all-models` | Discover models from active providers. Available for ordinary caching, interactive whitelist updates, and proposal generation; subject to the provider support restrictions below. |
| `--model provider:model` | Select specific targets instead of all models. Repeat the flag or use comma-separated fully qualified names. Mutually exclusive with `--all-models`; no provider positional argument. |
| `--cache-file PATH` | Select the cache input/output for `cache`, the prefill file and optional autocache destination for `serve`, or the read-only evidence/decision input for `verify`. |
| `--update-whitelist` | Review concrete eligible policy changes, select them, provide a reason, and confirm before writing. Supports bulk selection of ordinary changes; elevated changes require separate acknowledgement. Never accepts failures automatically. |
| `--reason TEXT` | Supply the operator explanation for interactive review or proposal generation. Interactive review can collect it when omitted; apply uses the reviewed proposal's explanations. |
| `--proposal-out PATH` | With `--update-whitelist`, write a reviewable proposal for automation instead of changing cache policy. Selections and risk acknowledgements start unset. |
| `--apply-proposal PATH` | With `--update-whitelist`, validate and apply the exact reviewed selections noninteractively. Targets, explanations, and acknowledgements come from the proposal; no new model discovery or silent substitution. Mutually exclusive with proposal generation and target flags. |
| `teep verify --cache-file PATH` | Verify fresh endpoint evidence against the candidate cache and effective policy without modifying the file. The flag is optional: default cache resolution is identical across all three commands. |
| `teep verify --no-cache` | Run baseline live verification without cache evidence or operator decisions. Mutually exclusive with `--cache-file`; explicitly overrides environment/config/default cache selection. Reports that cache policy was not tested. |
| `teep serve --autocache` | Automatically persist eligible evidence after successful admission through the shared runtime path. Portable writes are asynchronous and create no whitelist decisions or runtime authorizations. Without the flag, `serve` reads portable cache material without writing it. |

Without target flags, `cache --update-whitelist` edits removals only; it lists
existing decisions without discovery, including inactive providers and removed
models. The same targetless form with `--proposal-out` generates a removal-only
proposal. It cannot collect evidence or add decisions. Ordinary caching still
requires targets. Applying a removal-only proposal requires no active providers.

Policy revisions and the active decision set belong to the cache artifact and are managed
by explicit whitelist edits. There is no separate whitelist input.

Cache path precedence is `--cache-file`, `$TEEP_CACHE_FILE`, configured `cache_file`,
then `~/.config/teep/cache.yaml`, identically for `cache`, `serve`, and `verify`.
All three load an existing default without requiring `--cache-file`; a missing
implicit default starts empty. `cache` and `serve --autocache` can create their
output file. An explicitly selected missing file is an error for `verify` and for
`serve` without `--autocache`.
Autocaching requires a writable cache destination. Noninteractive whitelist
updates require proposal generation or explicit apply; there is no implicit consent.

`teep verify` imports eligible portable evidence and operator decisions, performs
fresh endpoint admission, and never exports or updates the cache file. It does not
reuse a previous process's authorization. There is no separate `--whitelist` input.
Replace `--update-config` and `--config-out` with the operator decision workflow in Phase 10.
Retain validated measurement-policy configuration as base policy, including its
ability to restrict the measurements accepted from the built-in defaults.
Existing `--force` is not a whitelist-selection or trusted-cache-generation option.
See [commands and deployment](#5-commands-and-deployment) and
[operator decisions](#5b-operator-decision-command-and-reporting) for detailed
validation, partial-failure, proposal, and acknowledgement rules.

### Evidence and runtime baseline

An image must satisfy its effective provenance policy and compose/attestation
binding. Where release authentication is required, it must use an authenticated
release unless an explicit supported operator decision replaces that requirement.
Existing compose-only requirements and `allow_fail` controls retain their distinct
guarantees; they do not become signature-verification successes. It does not have to use the latest release. Ordinary
caching never expands policy automatically.

This document specifies proposed cache behavior. The maintained runtime contracts
are in the [transport reference](../transport/README.md),
[retry rules](../transport/retries.md),
[NEAR reference](../providers/near/near_attestation.md), and
[Tinfoil reference](../providers/tinfoil/tinfoil_support.md).

For NearDirect, NearCloud, Tinfoil direct, and Tinfoil cloud, the current proxy
publishes the report, authenticated public encryption key, and transport identity
as one authorization. It reuses that authorization while the identity and required
keys remain usable, until invalidation, eviction, or process exit. Evidence expiry
and loss of all connections do not cause renewal. HTTP/2 connections and
attestation authorizations have independent lifetimes. Other providers retain
their runtime behavior until explicitly migrated.

The disk cache distributes portable evidence and operator decisions across replicas
through the trusted deployment path.
Endpoint-authorization persistence is deferred beyond this implementation. Runtime
authorizations end at process exit. Every restart performs fresh endpoint admission,
using eligible portable evidence to reduce retrievals.
This plan defines no cross-restart authorization format or lifecycle protocol.

### Provider scope and migration prerequisites

Initial cache support covers NearCloud, NearDirect, Tinfoil cloud, and Tinfoil
direct. Chutes and Venice are planned extensions, **blocked until each provider
migrates to the shared HTTP/2 attestation authorization machinery used by Near and
Tinfoil**. This prerequisite applies to portable prefill, `--update-whitelist`,
and automatic portable export. HTTP/2 negotiation alone does not satisfy it.

Do not add adapters to legacy report/key caches, parallel admission paths, or
provider-specific cache lifetimes to enable either provider early. Their migrations
are separate prerequisite work and must not delay the initial cache implementation.
After migration, enable only capabilities supported by the common interfaces and
provider evidence. Until then, reject cache targets for these providers with a clear
migration-required diagnostic; do not silently omit targets from a multi-provider run.

PhalaCloud (`phalacloud`) and NanoGPT (`nanogpt`) are not planned for cache support
or migration under this work. Reject these cache targets as unsupported. This scope
does not remove or change their existing provider implementations.

### Tinfoil direct live-validation prerequisite

`tinfoil_v3_direct` remains in initial implementation scope through its existing
shared transport and authorization machinery. Its live inference validation is
blocked by [cvmimage issue 337](https://github.com/tinfoilsh/cvmimage/issues/337),
which concerns billing authenticated requests sent directly to model endpoints.
Defer direct live inference tests and live request-reduction measurements until the
upstream fix is deployed to the endpoints under test. Issue closure or a merged
change alone does not establish deployment readiness.

Continue direct-provider implementation, unit tests, captured-evidence tests, and
deterministic TLS/HTTP/2 request-count tests. Record live validation as blocked,
not passed or replaced by offline coverage. This is an external live-validation
prerequisite, not a missing provider migration or a reason to add alternate cache
machinery. `tinfoil_v3_cloud` is unaffected by this issue and retains its live
validation requirements. Cloud results do not establish direct-provider coverage.

Define acceptance by the evidence shape the current production parser and policy
actually support. The shared V3 parser currently accepts an empty `device_evidence`
item list and rejects every nonempty list. This parser restriction applies to both
aliases; it does not establish whether a particular live direct endpoint supplies
GPU evidence. For the cloud SEV router, an empty device list describes the gateway,
not the backend inference servers. Its acceptance must preserve the existing
gateway-only guarantees and must not infer backend GPU verification.

Use the supported cloud router shape for the complete Tinfoil portable scenario.
Keep direct CPU/release, key/route, and transport tests at their stated test layers.
A direct positive admission scenario requires a concrete supported response that
satisfies unchanged effective policy; an empty list is not permission to waive
required GPU checks. Nonempty V3 device evidence remains a rejection test until
independent parser/verifier support is implemented in separate provider work. Do
not assign a successful direct TDX/GPU request budget to an unsupported shape.
Billing readiness and evidence-format readiness are separate live prerequisites.

### Implementation goal: prefill shared attestation state

Implement both goals by sharing as much machinery as possible with the attestation
data management used by the HTTP/2 transport. `teep cache` is a preparation and
export path; loading its output is a prefill path into that same data management.
Disk and network are sources of material, not separate definitions of trust.

Reuse the production verification, policy evaluation, immutable authorization
construction/publication, scope matching, shared-work coordination, and conditional
invalidation paths. Extract shared interfaces where necessary; do not add a second
verifier, a cache-only request handler, or independently maintained key/pin lifetimes.
The existing [authorization implementation](../../internal/proxy/authorization.go)
and [transport contract](../transport/README.md) define the integration boundary.

## 2. Data model and trust boundaries

The serialized classes describe persistence and operator-visible meaning. They do
not require a parallel hierarchy of runtime stores. Supply them to shared material
resolvers; only fresh verified admission can populate the authorization store.
Keep separate storage only where scope or semantics require it, such as portable
artifact evidence and deployment policy decisions.

### 2a. Persisted evidence and runtime evaluations

Persist original signed artifacts, certificate chains, transparency proofs, compose
bytes, and authenticated reference material. Store the complete inputs needed for
local verification, deduplicated by content digest. URLs are retrieval hints, not
trust roots. Preserve authenticated origin and original retrieval time where the
material's eligibility depends on them; copying the file cannot renew that time.

Do not persist derived verification successes, reports, or executable-keyed approval
records. Every new process evaluates retained evidence with its current verifier,
trust roots, and effective policy. Local verification cost is acceptable; removing
unnecessary online retrievals is the optimization. Missing or ineligible inputs use
the normal authenticated retrieval path. This applies equally to unchanged builds
and upgrades, including every required material freshness check.

Only validated evidence enters reusable material storage or portable export.
Keep newly fetched or decoded inputs in bounded staging until the owning production
verifier establishes their authenticity, structure, subject relationships, and
type-specific eligibility. A digest match or successful download is insufficient.
Software export additionally requires the successful-target boundary in Section 5.
Malformed or cryptographically invalid inputs never become reusable evidence.

Getter adapters return staged inputs to the owning verifier before that verifier
can finish; returning bytes is not promotion. Track exact original bodies, headers,
and retrieval context in a bounded acquisition scope owned by the evaluation.
The production typed verifier explicitly identifies which objects passed their
required material checks. Promote only those immutable objects; failure, cancellation,
or missing validation leaves the remaining objects unpromoted. An allowed factor
failure cannot supply that validation. A getter must not recursively invoke the
enclosing quote verifier to decide whether it may return an input.

Concurrent evaluations may join a bounded in-flight acquisition and receive the
same staged bytes, then each perform its own checks. This sharing grants no trust
and does not make staging a reusable material cache. Completed unvalidated work has
no retained cache entry; validated promotion follows the typed owner's rules. Keep
acquisition-scope references separate from report formatting and authorization
generations, and release them on completion. Test partial material success followed
by quote failure, cancellation before promotion, and concurrent validation of shared
staging. Complete software export still requires successful target admission.

Authenticated TUF transitions and explicitly reviewed decision observations retain
their separate validation boundaries; neither represents a passed software check.
An `allow_fail` admission does not make the failed material check cache-eligible.
Retained material that has since expired can remain stored, but cannot satisfy a
new admission until its current eligibility requirements are met.

Defer memoization of software and admission-subcheck verification results beyond
this plan. Each new admission runs the local cryptographic and policy checks over
selected evidence, even if another admission previously validated those bytes.
Share validated bytes and coalesce retrieval; do not add a cache of successful
component evaluations or their dependency-invalidation machinery. Imported inputs
must pass current typed validation before promotion from staging to reusable stores.
The existing runtime authorization cache and bounded shared full-admission path
remain unchanged: requests covered by an acquired authorization do not repeat
admission. Existing material-owner mechanisms such as parsed JWKS storage and CT
certificate checking retain their documented checks and eligibility.

Runtime evaluations belong to the admission that produced them and record exact
evidence/subject identities, applicable policy, actual checks, failures, exemptions,
and transient eligibility. The portable format
contains evidence, descriptive subject/input relationships, trusted retrieval and
TUF state, and explicit operator decisions only. Reports describe the current run;
serialized result flags cannot authorize reuse.

### 2a-i. Stapled evidence and independent subjects

Design collection around a response carrying evidence for one or more attested
subjects, including a gateway and selected backend. Delivery through a gateway does
not make backend evidence a gateway assertion: verify each supported child quote,
nonce, REPORTDATA, key, compose, and applicable collateral independently. Treat
stapling as the preferred extension pattern for future providers, not a claim that
all existing providers supply or cryptographically bind the same evidence.

NEAR already follows this pattern. [NearCloud parsing](../../internal/provider/nearcloud/parser.go)
selects a model from `model_attestations`; [NearDirect parsing](../../internal/provider/neardirect/parser.go)
validates its direct/repeated representation. Both use
[nearparse.Model.Raw](../../internal/provider/nearparse/model.go) to construct
`FormatNear` model evidence. NearCloud additionally supplies separate gateway quote,
compose, nonce, event-log, and transport fields. Preserve their strict envelope
validation and model selection; do not accept a direct/gateway envelope interchange
merely because the extracted model representation is shared.

Separate delivery provenance, intrinsic evidence identity, consumer policy evaluation,
and endpoint authorization. Retain original response envelopes only when eligible
for portable storage. Exclude envelopes containing consumable request tokens, secrets,
or inference content; do not retain prohibited values inside base64 payloads.
Supported
extractors may retain original child quotes, compose strings, signed artifacts, and
collateral as independently content-addressed evidence, alongside their containing
envelope digests. Byte extraction must preserve the exact cryptographic inputs;
never reserialize signed content or equate a normalized compose with the attested
bytes. Validate every retained containment relationship through the production parser.
When an envelope is excluded, retain independently verifiable signed child bytes
and the safe verification context required by the supported extractor, without a
reference to an absent parent. Do not redact or reserialize signed inputs. If safe
extraction cannot retain every cryptographic prerequisite, that evidence is not
portable; use fresh collection. Complete HTTP capture is separate from this cache.
Mere
containment proves no signature, key ownership, or gateway/backend relationship.

The same child bytes can be shared whether fetched directly, stapled by a gateway,
or loaded from disk. Different envelopes do not prevent sharing an identical child;
different child bytes must not be merged because their fields look similar. Matching
component repository/digest pairs permit artifact evidence sharing even when complete
compose subjects differ. Each new admission evaluates its own trust roots, identity
requirements, tier applicability, and exemptions over those bytes; matching provider
lineage or signing keys does not share a consumer policy result.

Fresh gateway/backend admission remains bound to the caller's nonce and selected
model/key/route. A saved stapled quote cannot answer a later nonce. A shared backend
key or software subject does not merge NearCloud and NearDirect authorizations:
NearCloud authenticates its gateway TLS peer and backend model key, while NearDirect
authenticates the selected backend TLS peer. Gateway-only evidence, including current
Tinfoil cloud and Venice ACI/1, must remain gateway-only. Cache generality must not
manufacture backend CPU or software coverage that a provider does not supply.

### 2b. Software subjects and runtime verification

A software subject identifies an artifact or complete configuration independently
of delivery. Persist its exact evidence and descriptive component relationships;
reconstruct and validate those relationships through the production parser/verifier.
A stored subject is not an approval. Each consumer evaluates it under current
provider/tier policy. A verified subject exists only with an eligible runtime
evaluation; disk input cannot create one by asserting success.

Two NEAR endpoints with the same compose/image digests can share validated evidence.
Each new admission evaluates every component under its own signer and tier policy;
sharing bytes between providers does not share policy results. Complete-set
coverage depends on membership/binding rules and all required component evaluations.

Live attestation must still bind that software to the endpoint. Complete compose
coverage cannot convert `compose_binding_only` into an image-signature success or
prove an image digest absent from the attested configuration.

### 2b-i. Complete component coverage

One CVM authorization can depend on several component repositories and artifact
versions. Model and gateway tiers each need an explicit complete component set;
neither the primary application repository nor a successful first component stands
for the whole environment. Keep per-component evidence independently reusable in
memory and evaluate every required component during each new admission.
Persist the corresponding evidence and component identities. An endpoint
references the complete sets required by its admission, not one representative image.

Component repositories are record values, never predefined YAML field names or
parser branches. Store arbitrary-length component collections within the schema's
bounds. Nest component identities and evidence references under readable software records.
Use content digests for evidence and exact subject selectors for software. Runtime
evaluations additionally carry consumer scope and applicable policy. Validate digest integrity and selector
uniqueness. No local record names or list positions carry identity or trust. Section 6
defines the common serialization; runtime stores need not mirror that hierarchy.

Provider replacement, addition, or removal of components changes data and set
identity, not schema structure. Trust policy still applies: NEAR/Venice repository
entries declare required provenance and signer checks, while Tinfoil also supports
a constrained organization-signer rule for eligible release repositories. Neither
policy structure mandates a fixed set of components per CVM. A structurally valid
new repository can still fail policy; accepting arbitrary component records does
not grant arbitrary repository trust.

Identify a component by canonical repository, immutable digest or authenticated
release subject, role/tier, and applicable policy. Preserve multiple digests of the
same repository and multiple repositories sharing a digest. Deduplicating content
bytes must not merge signer, repository, tier, or decision requirements. The current
compose helper uses a digest-to-repository map; the cache coverage model must retain
the full repository/digest relations instead of copying that lossy representation.
Resolve ambiguous input or fail explicitly; do not silently choose the first policy.

Complete membership requires replacing the current text/regex extraction, not only
its digest-to-repository map. Use one bounded production parser for the supported
compose forms and enumerate actual service image references. Define supported
fields and syntax explicitly; return unknown fields to the owning caller. Preserve
tag-only services as components with weaker binding, and do not count image-like
strings in comments or unrelated values as deployed components. Reject malformed
input, duplicate/ambiguous service definitions, and component-limit overflow instead
of truncating enumeration. Never use the local environment to expand provider image
references. For NEAR image expressions with an explicit literal digest-pinned
default, authenticate the default repository/digest presented in the bound compose
through the normal provenance policy. Record that it is the compose default, not
proof that an override cannot select another running image. This preserves the
existing NEAR coverage while exposing its provider-side deployment-binding gap;
it requires no new operator decision or automatic policy edit. Do not execute
pre-launch scripts or read override files to resolve an expression. Expressions
without a supported literal default require authenticated resolution or the
corresponding enforced failure. Raw compose bytes remain the binding input.

The named NearCloud fixture uses `COMPOSE_MANAGER_IMAGE` with a digest-pinned
default, and its pre-launch script can load a different value from an override
file. Authenticate the presented default for this plan's scenarios, while retaining
that distinction in component coverage and reports. At plan completion, document
this existing gap in [dstack integrity](../attestation_gaps/dstack_integrity.md),
including the override mechanism and the difference between authenticating the
declared default and proving the image actually executed. Correct any claim there
that compose authentication alone covers dynamically selected images.

Derive required membership from the exact bound compose or supported authenticated
release/measurement relationships, not every repository in a provider allowlist.
Policy lists include alternatives, not necessarily co-resident components. Check
set membership, each component's required provenance, and aggregate coverage before
publishing an authorization or exporting the complete set's evidence. A compose-only component has a policy
result, not a fabricated image signature. A valid signature without its required
measurement/compose relationship does not establish deployment coverage.

Keep raw supplied collateral, independently verified artifacts, and complete
admission coverage distinct. Tinfoil V3 can supply code, platform, and freshness
collateral. Its [parser](../../internal/provider/tinfoil/attestation.go) currently
validates the envelope without reading entry data. The existing
[verifier](../../internal/verify/attest.go) fetches the selected code release and,
for TDX, `tinfoilsh/hardware-measurements`, collecting separate component results.
The current route's single `SupplyChainRepo` selects the primary release; it is not
a complete component inventory. Do not interpret a supplied
`tinfoilsh/platform-endorsements` bundle as the existing hardware-registry result.
Adding its independent signature/subject/measurement verification is separate shared
verifier work, required before that evidence can contribute a verified subject.
Do not require latest-release freshness as a substitute for authenticated binding.

HTTP/2 authorization scope remains provider/route/attested identity/key epoch. Do
not create a connection pool or endpoint authorization per component repository.
Complete component coverage is an admission dependency of the atomic report/key/
identity publication. Reusing that authorization follows the existing transport
lifetime; a background metadata change alone must not invent a new renewal rule.

### 2c. Endpoint authorizations

An endpoint authorization contains the current report, immutable route scope,
attested TLS identity, and required public E2EE key. The shared evaluator must resolve
complete evidence and establish all required checks before atomic publication;
the authorization need not retain the raw evidence graph. No partially loaded authorization may become visible to requests.
Fresh admission uses the shared authorization constructor and publication path.
The portable format cannot insert reports, pins, or keys directly into the runtime
authorization store. Incomplete evidence cannot authorize an endpoint.

Scope follows the existing provider authorization key, not a universal
`(provider, model)` tuple:

| Provider | Endpoint authorization scope and bindings |
| --- | --- |
| `neardirect` | Provider, model, selected indexed or static authority, attested TLS SPKI, and the required model encryption key. The selected index is not a permanent machine identity. |
| `nearcloud` | Provider, model, fixed `cloud-api.near.ai` authority, gateway TLS SPKI, separately attested backend identity, and the model Ed25519 key used for the gateway hint and E2EE conversion. |
| `tinfoil_v3_direct` | Provider, model, resolved backend authority, attested TLS SPKI, and HPKE public key. Different backend selections need separate authorizations. |
| `tinfoil_v3_cloud` | Provider and router authority, router TLS SPKI and HPKE public key. The router authorization is model-independent; E2EE outcomes remain model-specific. It is not independent attestation of the router's backend models. |

Do not persist TLS connections, session tickets, client ephemeral private keys,
shared session secrets, inference data, or a successful E2EE probe as a promise of
future usability. Historical nonce-bound evidence explains an existing admission;
it cannot satisfy a new fresh-nonce challenge.

### 2d. Who may supply the cache

A YAML file is not self-authenticating. Require the operator's trusted deployment
path and validated ownership/access controls for cache input, including image-layer
deployment. This protects operator decisions, authenticated-retrieval observations,
and retained TUF state. Digests alone cannot authenticate those observations.
Independent cryptographic checks still apply to all retained signed material under
the current verifier. Hand editing bytes or descriptive metadata never creates a
verification success. Reject unsupported result/approval fields.

Ordinary `teep cache` authenticates under existing policy and never creates an
operator decision. Values authenticated under an already trusted authority may
satisfy that policy without TOFU. Only `--update-whitelist` changes policy through
the explicit decision workflow.

### 2e. Operator decisions

Store operator decisions separately from software evidence and runtime evaluations.
Each decision records its kind, provider and tier, exact subject/value, selected
failure code, supporting observed evidence, source policy identity, decision time,
operator-supplied reason, and any additional risk acknowledgement. Pinning a signer
must identify the key or OIDC issuer and exact identity, not only an organization
name. Pinning measurements must identify the register/platform and its relationship
to the complete attested state. Never turn a set of observations into wildcards.

TOFU means the operator elects to trust the currently observed value without an
existing trusted reference establishing that value as permitted. It still requires
the independent authentication and binding prerequisites in the inventory. Updating
a reference from a source already authorized by policy is not itself TOFU.

A decision can substitute an operator-selected expected value or explicitly exempt
a supported requirement for an exact subject. It cannot claim that the original
policy passed. Keep the underlying outcome and show `operator_decision_applied`
with the decision reference in diagnostics. Existing `allow_fail` remains a separate
factor-wide policy control; a pin is a narrower subject-specific decision.

Retain the existing model/gateway measurement allowlists in validated configuration
as base policy. Preserve `MergedMeasurementPolicy` and
`MergedGatewayMeasurementPolicy` semantics: for each register, a nonempty
per-provider list replaces the global list, which replaces the built-in list.
Replacement can narrow the accepted measurements; do not convert it to a union
with defaults. These configured expected values are supplied by the operator,
not generated from observations by the cache command. Removing automated config
editing does not remove or reinterpret this base-policy input.

Evaluate decisions against that resolved base policy and preserve any applicable
explicit `allow_fail` outcome separately. A decision can explicitly permit its
supported named failure, but absence of a decision cannot expand a restrictive
configured list. Reports and proposals include the configured base policy in their
identity and show any decision that permits a value it rejects. Changing a relevant
configured list makes a proposal stale and requires renewed review. No second
whitelist file or new restriction schema is needed.

A runtime evaluation records only properties actually verified. Where a decision
was used, reference its digest and retain the failed base check in the current report.
The decision retains its original observation inputs and named failure, not a
portable assertion that prerequisite verification passed. A subject admitted solely by a content pin belongs
to `operator_decisions`, not to a fabricated signature-verification result. Endpoint
authorizations can reference both verified subjects and applicable operator decisions.

Represent each factor's complete base failures as typed reasons with their exact
subjects. Evaluate every applicable reason; do not return after the first failed
measurement or component check. Record the disposition of each reason separately:
unresolved, permitted by the existing factor-wide `allow_fail`, or covered by an
applicable exact decision. A decision covers only its matching reason and subject;
it cannot change the factor's `Enforced` setting or hide another failure. Keep base
check status distinct from effective admission permission, and never turn an
excepted base failure into `Pass`.

Use one authoritative calculation of unresolved enforced failures for `Blocked()`,
authorization construction, CLI exit status, report totals, and dashboard output.
Update all of those consumers in the same change. Preserve separate counts and
diagnostics for base failures, factor-wide allowances, exact decisions, and remaining
blocking failures. Deep-copy any nested reason/disposition collections when cloning
published reports; callers must not mutate another request's policy result.

Effective policy identity identifies the policy tested in reports and proposals;
it is not a verification-result cache key. Hash the complete applicable provider/
tier base policy, trust roots, required checks, exemptions, and active decisions.
Evaluate from immutable validated policy objects on every new admission. Do not
implement per-component policy projections or selective result invalidation.
Unrelated provider rules, evidence additions, and evaluation timestamps do not
change this identity. The rollout report additionally
identifies the whole artifact digest and policy revision. A build update does not
erase operator intent or make it an unconditional override. The current verifier checks whether the decision kind,
scope, risk acknowledgement, and base-policy compatibility remain permitted. New
hard restrictions or unsupported decisions block affected reuse with a clear error;
do not reinterpret them as broader exemptions. Revalidating a decision is local
unless its documented evidence prerequisites require retrieval.

Canonical policy descriptors use RFC 8785 JSON, with an explicit domain and version
prefix before hashing. Sort set-valued rules/decisions by canonical identity; preserve
order only where evaluation semantics depend on it. Exclude source-file formatting,
paths, diagnostic strings, retrieval times, and unrelated provider rules. Record build information in reports/proposals for diagnostics, not as an approval
key. There is no executable-hash reuse protocol: persisted evidence is always
evaluated by the running implementation. Proposal application reruns current checks
and confirms the exact reviewed subject, failure, prerequisites, and applicable
policy; a printed build identifier never replaces that evaluation.

Decision observations have a historical validation purpose distinct from material
selected for current admission. Authenticate their original signatures, nonce and
subject relationships, and required evidence dependencies under the current
implementation. The trusted policy artifact records the operator's reviewed choice
and observation time; it is not a portable assertion that a verification check
passed. Interactive collection and proposal apply establish all class-specific
prerequisites through fresh shared evaluation. For ordinary decisions, check time
eligibility when that evaluation completes; later human review or file-lock delay
does not require the observation's tokens or collateral to remain current. The
policy transaction still checks selected subjects, current policy compatibility,
and its authority/revision precondition. Do not require the historical quote to answer a new challenge or
the historical collateral, certificate, NRAS token, or PoC token to remain eligible
for current admission. Expiry of that historical material alone does not expire an
ordinary measurement decision. Never backdate a current verification or refresh
historical timestamps to achieve this distinction.

Each decision kind must specify the original signature/binding relationships its
observation retains, the creation-time conditions recorded through the trusted
policy transaction, and the prerequisites that fresh admission must establish
again. Reuse matches the exact selected subject against fresh authenticated evidence
and runs every current prerequisite not explicitly replaced by that decision.
Historical material cannot satisfy current freshness or revocation checks. Invalid
historical signatures or relationships, missing required observation dependencies,
and currently prohibited decisions fail validation; an old observation never
overrides a new hard restriction. Use historical authentication helpers owned by
the production verifier, with no alternate signature implementation or generic
ignore-expiry option on current admission.

The shared evaluators must apply these requirements on each new admission:

| Operation | Included policy dependencies |
| --- | --- |
| Component provenance | Provider/tier/format applicability; complete matching `ImageProvenance` rules (provenance mode, source repositories, OIDC issuer/identity alternatives, key fingerprint, `NoDSSE`, provider-signer and workflow constraints); applicable organization-signer rule; log/root identities; checks/exemptions/decisions actually used. |
| Compose/release coverage | Exact required membership and binding semantics plus current evaluation of every required component; no first-component scalar can substitute for the set. |
| Intel/AMD material | Build-owned trust anchors/chains, allowed retrieval authority, platform/CA/product/TCB matching rules, and actual certificate/CRL validity and revocation requirements. Fresh quote measurements are inputs, not policy. |
| NVIDIA/CT/TUF material | Accepted authority and trust/bootstrap roots, refresh and key-rotation rules, signature/time/version requirements, and current withdrawal restrictions. Metadata contents/version/expiry are evidence dependencies, not arbitrary user policy. |
| Endpoint admission | Provider/route and required TLS/E2EE binding rules, model and gateway measurement policies, factor applicability, merged default/configured `allow_fail`, all applicable exact decisions, and current software/material checks. |

Define report/proposal policy descriptors beside the evaluators and test their completeness.
Read `ImageProvenance`, `OrgSignerPolicy`, and measurement rules from the validated
policy objects; never maintain a separate incomplete policy copy in cache code.
Cryptographic equality checks retain constant-time comparison. Canonical decision
digests include the full record; aggregate policy identity includes only applicable
active decisions. Material evidence updates need not invalidate unrelated policy.

Decisions may be portable when their subjects are portable (image digest, signer,
measurement set). Endpoint-specific key/identity facts retain endpoint scope.
Removing a decision changes affected effective policies and requires a deployment
update and restart to withdraw its runtime effect. `--update-whitelist` also presents
existing decisions for explicit removal, including in proposals; removal does not
require current provider evidence or successful admission. A restrictive withdrawal
must remain possible during an outage. Its report identifies affected targets even
when they no longer pass. Additions still require the admission rules below.

Separate strict structural decoding from permission to consume a decision. A
withdrawal-only operation can identify and remove a structurally valid decision
whose known kind or scope the current policy now prohibits. It authenticates the
trusted file, validates the schema, references, and decision identities, and checks
the normal policy transaction precondition; it does not treat the prohibited
decision as admission permission or require fresh provider evidence. Every retained
decision must be supported for consumption before committing the replacement, so
the operator must remove all prohibited decisions in that transaction. Serving,
verification, additions, and ordinary evidence writes still reject prohibited
decision consumption.

This removal path does not accept unknown schemas, unknown kinds/fields, malformed
records, or invalid evidence relationships, and does not preserve obsolete schemas
or verifier behavior. If the current parser cannot safely identify a record, fail
without modifying it. Recovery then requires the trusted deployment system to
supply a valid replacement preserving established policy authority and revision
continuity; deletion and revision-zero recreation are not recovery procedures.

The artifact contains `policy_state` with a stable deployment-policy authority and
monotonic revision. The first artifact writer creates an opaque authority with
`crypto/rand` and preserves it thereafter. Empty policy starts at revision zero;
read-only use of a missing implicit default creates no authority or file. Only explicit policy
operations advance it. For an existing artifact, proposals bind the authority,
revision, and canonical digest of that state plus the complete active decision set. Under the file lock, apply
requires an exact match; stale proposals require renewed review. Selected removals
and eligible additions commit atomically. Reintroduction requires a newly reviewed
addition against the current revision. Keep the authority and revision even after
the last decision is removed; do not recreate revision-zero state.

A first-use proposal for a missing default or explicitly selected cache destination
records `artifact_precondition: absent`, with no invented authority or revision.
Generation validates the destination but creates neither the artifact nor a policy
authority. Apply validates the selected evidence and effective policy, then acquires
the stable destination lock and confirms that the artifact is still absent. Only
then does it generate the authority with `crypto/rand` and atomically commit the
initial decisions and eligible evidence at revision one. Creation by any competing
writer makes this proposal stale, even if the new artifact has empty policy;
require renewed review rather than substituting its authority. Existing-artifact
proposals never treat a missing artifact as empty policy. Trusted deployment must
prevent deletion/rollback of established policy; absence is not a reset procedure.
First-use interactive updates use the same transaction precondition. No selections
or failed additions create no initial policy artifact through this workflow.

Evidence writers have no decision-write capability. Under the lock they reread and
preserve the current active decision set and policy state verbatim. Their snapshots
contain evidence only, never an old policy copy or derived approvals. Retaining raw
evidence after withdrawal does not authorize it: every new admission evaluates the
current active decisions. This removes the need for permanent removal records,
tombstones, or an additional checkpoint protocol. Test stale evidence writers and
proposals racing removal, removal of the final decision, and explicit reintroduction.

The trusted deployment must prevent whole-artifact rollback; replacing both current
policy and its revision cannot be detected from the replacement file alone. Changes
do not reload a running service's policy. Distribute updated policy and restart
affected instances as required by the transport withdrawal contract.

### 2f. Provider and format capabilities

Cache support is a set of capabilities, not a provider-wide boolean. Select the
format from strictly parsed evidence, not a model-name list or cached assumption.
Include provider, evidence format, principal/tier, authenticated subject, and
applicable policy in each admission's evaluation scope. Content-addressed original
bytes may be deduplicated without sharing policy conclusions. A format change
requires fresh evaluation of its evidence coverage and enforcement policy.

| Provider / format | Portable input prefill | Operator decisions | Unified runtime authorization |
| --- | --- | --- | --- |
| NearDirect / near | Model compose/images, eligible collateral | Applicable exact model software/measurement decisions | Existing shared runtime path; fresh admission after restart. |
| NearCloud / gateway plus model evidence | Separate gateway/model subjects and eligible shared collateral | Tier-specific decisions | Existing shared runtime path; fresh admission after restart. |
| Tinfoil direct / V3 | Model release predicates, hardware references, eligible CPU collateral | Applicable model software/measurement decisions | Existing shared runtime path; each authority has its own scope. Live inference validation awaits the upstream billing fix (see Section 1). |
| Tinfoil cloud / V3 | Router release and applicable CPU collateral; no independent backend software result | Gateway-scoped decisions | Existing router-scoped runtime path; do not infer backend attestation. |
| Venice / dstack | Model compose/image evidence actually supplied and eligible Intel collateral | Applicable model-tier inventory classes | Blocked on shared authorization migration; all listed cache capabilities are post-migration candidates. |
| Venice / ACI/1 | Gateway compose/digests, eligible Intel collateral, original keyset/custody material for scoped local verification | Gateway software/measurement classes plus separately scoped KMS-root and application-ID candidates | Blocked on shared authorization migration. No inferred model CPU/software evidence or automatic router-wide sharing; persistence requires separate eligibility. |
| Chutes / sek8s | Eligible Intel collateral and original authenticated measurement evidence; no client-verifiable image provenance assumed | Exact MRTD/MRSEAM decisions and other independently eligible measurement classes | Blocked on shared authorization migration, including instance/key scope and single-use nonce separation. |
| PhalaCloud / NanoGPT | Not planned | Not planned | No migration planned under this work. |

Chutes and Venice entries describe post-migration candidates, not initial support.
Their separate migrations must satisfy the prerequisites below. Model-catalog
maintenance is not part of cache implementation.
Implement capabilities through the shared admission interfaces; do not duplicate
verification per provider or force an E2EE-only provider into a TLS-SPKI contract
whose live-peer binding it does not establish. Cache-aware CLI acceptance tests run
after the runtime migration is complete; they are cache-enablement tests, not a
circular prerequisite for completing the transport migration.

## 3. Reuse, upgrades, and lifetime

### 3a. Evidence reuse and current verification

Prefill supplies retained inputs to the shared material resolvers. It does not
publish runtime evaluations or endpoint authorizations. Strict loading validates
structure, references, trusted provenance, and supported decisions; each typed
verifier authenticates and evaluates selected inputs under current policy.

For every new admission:

1. Resolve the subject required by fresh attested compose or measurements.
2. Select complete retained evidence and required dependency material.
3. Run current cryptographic verification and policy evaluation for every required
   component and material check; do not reuse another admission's subcheck result.
4. Fetch only missing or ineligible inputs; failed required retrieval blocks.
5. Construct and publish authorization through the existing runtime owner.

Same-build restarts and upgrades follow this identical path. In particular, a
previous release success never bypasses TUF eligibility: expired trust metadata
requires authenticated refresh even if image evidence is unchanged. Local signature
verification may use authenticated signing-time semantics supported by production;
other validity rules use the current admission clock. Do not backdate evaluations.
A changed verifier or policy can reject retained evidence. No persisted success,
executable digest comparison, or schema compatibility path can restore approval.
Runtime authorization lifetime remains the separate contract in Section 3b.

### 3b. Runtime authorization lifetime

After live admission, use the same runtime store and
retain the existing TLS/E2EE key-use lifetime. Do not add a `max_cache_age` deadline to authorizations, require the latest image release, or
refresh attestation merely because collateral, certificates, or an NRAS JWT expire.
On new admission, recheck NRAS time eligibility immediately before initial
publication, then discard transient admission deadlines from the runtime
authorization. A new process requires fresh admission and its normal NRAS
eligibility checks; retained responses cannot satisfy a new report or nonce.

Each new inference connection still requires TLS 1.3, WebPKI, CT, and applicable
attested-SPKI validation before request bytes. Each request acquires authorization
for its immutable route and required E2EE key. Persisting a verification result does not persist
successful TLS validation. Preserve TLS-SPKI session-resumption restrictions.

Identity/key changes and classified trust failures require new admission according
to the [retry contract](../transport/retries.md). A new admission requires fresh
client-nonce evidence and all enforced factors; portable evidence and eligible collateral may supply their respective subchecks. A cache miss never
authorizes transmission by itself. Offline admission keeps its explicit factor
policy and does not manufacture successful online results from cached booleans.

### 3c. Restart and invalidation boundaries

Every restart uses Section 3a's fresh admission and current verification. Runtime
acquisition, generation-safe invalidation, eviction, and already acquired attempts
follow the [transport contract](../transport/README.md). Optional persistence failure
does not invalidate an independently admitted authorization. Atomic replacement
leaves the previous or new complete artifact; neither restores an authorization.

Policy withdrawals require delivery and restart under the transport withdrawal
contract. Evidence writers cannot restore decisions (Section 2e). TUF version
knowledge across restart is limited to committed/deployed state as specified in
[trusted version state](#tuf-trusted-version-state). No live policy reload or
cross-restart authorization protocol is introduced.

## 4. Portable material

| Material | Identity and portable use | New-admission requirements |
| --- | --- | --- |
| Sigstore bundles, signatures, provenance, and Rekor proofs | Exact artifact digest, authenticated signer, provenance requirements, and policy. Share evidence bytes across providers; scope verification results to policy. | Verify all required signature, identity, transparency, and binding checks. A log entry's presence alone is not signature verification. |
| Compose evidence | Exact original compose bytes and complete image-evidence references. | Bind to fresh endpoint attestation and evaluate complete coverage under current tier/policy; no saved policy result is accepted. |
| Signed hardware measurement registry | Exact signed registry artifact, platform, signer policy, and authenticated predicate. | Compare actual attested measurements; do not equate a platform label with a verified measurement. |
| AMD VCEK and signing chains | Product, chip HWID, TCB extensions, certificate digest, and issuer. Share among replicas contacting applicable hardware. | Match HWID/TCB to the fresh report; check chain, signature, validity, and applicable revocation policy. No arbitrary short TTL on immutable certificate bytes. |
| Intel PCS collateral and CRLs | Exact issuer/platform scope, signed collateral version, and content digest. | Respect signed validity and revocation requirements for new admissions; do not cache a timeless `tcb_current: true`. |
| NVIDIA certificates and reference material | Exact supported hardware/firmware and issuer scope. | Independently verify the material with the production pathway. A cached reference is not a verdict on a new GPU report. |
| NRAS response | Exact submitted GPU evidence and client-nonce context, signed JWT, and authenticated response binding. | Not a reusable verification result for another report, GPU, or nonce. A new submission needs its own eligible result and publication-time check. |
| Release metadata | Repository, authenticated release artifact, digest, and measurement predicate. | Match attested content. No latest-release requirement or release-age check. A remembered tag alone does not authenticate deployed bytes. |
| Proof of Cloud evidence | Exact hardware identity, authenticated authority, and response scope. | Specify the authority's verification and withdrawal contract before portable reuse; do not assume registrations are append-only or forever valid. |

Retain evidence validity metadata for admission, not as runtime authorization
expiry. Successful requests must not extend evidence validity or rewrite retrieval
times. Missing or expired mutable collateral triggers the existing retrieval and
verification path when needed for admission. Failure remains a factor failure
under its applicable policy; do not substitute stale evidence.

Transient network errors and malformed responses are not portable negative
verified subjects. Keep bounded negative-cache behavior under the existing retry contract;
never persist an outage as a permanent rejection of an image.

Tinfoil already uses embedded AMD signing chains and its VCEK proxy. Add caching to
that verified retrieval path. Preserve its configured origin and fail-closed
retrieval behavior. See [AMD certificate retrieval](../providers/tinfoil/tinfoil_support.md#amd-certificate-retrieval).

### Material adapters established by source research

The following boundaries use the versions pinned in `go.mod`, rather than assumed
upstream APIs. They are implementation choices, not completed adapters.

| Material | Existing owner and concrete integration |
| --- | --- |
| Intel | `attestation.NewCollateralGetter` already implements `trust.HTTPSGetter.GetContext`, returning both headers and bytes. Wrap it with validated typed lookup and acquisition/export; keep `VerifyTDXQuoteOnline` and go-tdx-guest signature, revocation, and current-time checks. The verifier invokes both quote verification and TCB-level extraction with the same options; deduplicate by authenticated scope, not just invocation count. |
| AMD | `tinfoil.NewSEVCertGetter` returns embedded product signing chains and rewrites validated VCEK requests to Tinfoil's proxy. Insert typed VCEK lookup at this boundary; preserve product/HWID/TCB and certificate verification. Current `sevverify.Options{Getter: ...}` does not enable CRL retrieval. `evalSEVTCBNotRevoked` explicitly says AMD CRL is not checked. The cache must not manufacture a revocation success or add an unbudgeted CRL guarantee. |
| Rekor | `RekorClient` retrieves UUIDs/entries and computes parsed provenance, SET, inclusion proof, and DSSE results. Split byte acquisition from the existing entry verifier, retaining the complete response fields needed for SET/proof verification. Current certificate parsing extracts OIDC extensions; it is not a general independent Fulcio-chain verifier. Retain that actual assurance distinction. |
| Sigstore/TUF | `SigstoreVerifier.fetchAndVerifyAttestation` creates its own root client and calls `FetchTrustedRootWithOptions`. Inject the verified trust-material resolver and use the local metadata sequence in Section 6. The pinned lower-level API supports in-memory verification; the higher-level updater also owns disk cache and refresh behavior and is not a transparent YAML adapter. |
| NVIDIA | `NVIDIAVerifier` owns JWKS entries, singleflight retrieval, creation times, capacity, and rotation retry. Add immutable import/export on that owner, preserving its one-hour eligibility and refresh throttling. Do not copy JWT result caches into a new report. |
| CT | `tlsct.DefaultChecker` currently refers to a process-wide checker; normal and pinned clients attach it. Its log list has a 24-hour lifetime and a separate bootstrap HTTP client. Introduce checker dependency injection per service/command and pass it through normal, pinned, proxy, and dependency-client construction. Sharing one configured checker within that owner is sufficient; mutating the process global from cache import is not. Preserve the bootstrap client's existing WebPKI behavior and every live SCT check. |

All three commands use the same admission service, typed verifiers, material
owners, and production HTTP client factories. `teep cache` initiates ordinary
collection through that service; it has no separate downloader, retry loop, or
failure-throttling policy. Persistence receives immutable inputs only after their
owning verifier validates them, subject to the successful-target export boundary.
Unvalidated acquisition staging belongs to the verifier, never to the file writer.
Retain the existing retrieval retries, shared verification, and terminal-failure
cooldowns. Material coordination shares work and cancellation handling; it adds no
cache-specific retry framework. Any additional cross-scope dependency throttling
must be justified by a failing bounded request-count test and implemented in the
shared material owner for all callers, not in cache orchestration.

This includes two explicit ownership changes: shared evidence orchestration and
per-owner CT injection. None of these dependencies currently supplies a complete
portable artifact snapshot/export operation. Existing getters and verifiers provide
the integration points; wrappers still need immutable bytes, eligibility, scoped
singleflight, and bounded retention. No validated evidence snapshot may be formed
by parsing a display report or trusting an asserted `pass` field.

Material-owner reuse also requires a cancellation refactor. NVIDIA's current
`getOrCreateKeyfunc` runs singleflight retrieval with the leader's context; canceling
that context fails other waiters. CT's current `loadLogListWithRequest` holds
`logListLock` across retrieval, so waiters cannot cancel their lock wait and a
failure can trigger sequential per-waiter fetches. Snapshot/import wrappers alone
do not satisfy the shared-work contract. Phases 6 and 7 must replace those behaviors:

- Configure each owner and its clients before concurrent use. A shared retrieval
  has a finite timeout and a context derived from the service/command lifecycle,
  independent of the first admission's context. Keep a bounded active-operation
  record and let callers wait for its immutable completion through a channel.
- A caller with a context can cancel its own wait without canceling shared work.
  All current waiters receive the same retrieval failure; do not retry separately
  for each waiter. Later attempts follow the owner's bounded retry/rotation policy.
  Preserve NVIDIA's refresh throttling and transport retry/capacity classification.
- Keep network I/O outside state mutexes. Validate returned bytes before publication
  and ensure a delayed completion cannot replace newer imported/refreshed material.
  Use the owner's operation identity and synchronization; do not introduce an
  endpoint authorization generation or a generic generation store for material.
- TLS verification callbacks expose no request context. CT handshake waits must
  therefore use the bounded owner operation/lifecycle and retain the bootstrap
  client's hard timeout. Do not claim immediate per-request callback cancellation
  or disable CT when a caller times out. Direct context-aware checks retain
  independently cancellable waits.
- Owner shutdown rejects new work, cancels outstanding retrieval, releases waiters,
  and prevents later publication. Close owned idle clients, including CT bootstrap
  and dependency clients; do not close caller-owned injected clients. Connect this
  cleanup to `Server.Close` and command cleanup using existing transport factories
  and socket budgets. No material refresh failure invalidates unrelated authorization
  or authorizes inference replay.

Factor identical retrieval coordination into a small internal helper shared by
material owners. It owns only bounded active operations, lifecycle-derived timeout
contexts, independently cancellable waits, immutable completion delivery, and
shutdown. Owners supply exact operation keys and acquisition functions; they retain
typed validation, retention, refresh throttling, operation reconciliation, and
publication policy. Preserve typed capacity/trust errors without adding retry policy
to the helper. Introduce it with the first concrete adapter that needs it and reuse
it for NVIDIA and CT; avoid separate implementations of the same waiter lifecycle.
Test cancellation, shared failure, bounded capacity, and shutdown once at that helper,
then test each owner's validation and publication races through its production path.

This is not a generic trust or generation store. The existing proxy authorization
store remains the sole runtime authorization owner; do not move its acquisition,
invalidation, E2EE promotion, or HTTP/2 pool semantics into material coordination.
Keep the proposed `internal/admission` service as the common collection/evaluation
boundary for proxy and commands, with typed material owners below it.

### Chutes support after transport migration

Chutes is a planned extension for measurement decisions and portable verification
inputs. It is blocked until report, authenticated ML-KEM key, immutable route, and
instance identity use the shared authorization publication/acquisition/invalidation
path. Keep relay TLS reuse independent of backend authorization; never invent an
attested relay SPKI from backend evidence. Scope authorization to provider, chute,
model, instance, and authenticated key epoch, including explicit rules for any
sharing. A new unauthenticated identity requires full admission.

The existing nonce pool is request-material management, not an independent trust
source. Consume each provider-issued request nonce atomically against the matching
authorization. These request nonces are distinct from client-generated attestation
challenges. Exclude consumable nonces and ephemeral encryption secrets from portable
files and endpoint snapshots. Nonce exhaustion or expiry requires replenishment;
it does not alone invalidate an authenticated backend key. Prove key/instance
matching and concurrent consumption before enabling reuse through the shared path.

Exact MRTD and MRSEAM membership decisions are a concrete `--update-whitelist` use
case. Record the authenticated observed configuration and selected exceptions,
without broadening all failures of `tee_measurement`. Such decisions do not assert
build reproducibility, repair invalid GPU signatures or nonce binding, or waive
missing CPU/GPU binding. Retain existing allowed failures in reports, separately
from supported operator decisions. Collect fresh authenticated evidence when
creating decisions; a previous test log is not admission evidence.

Cache eligible Intel collateral through common services. Chutes currently exposes
no compose/component supply-chain surface for client image verification; do not
invent image-signature results or promise image retrieval savings. No integration
with its legacy report/key caches is permitted for early cache support.

### Venice support after transport migration

Venice portable input prefill is planned after migration, separately for dstack and ACI/1.
Its [parser](../../internal/provider/venice/aci.go),
[policy](../../internal/provider/venice/policy.go),
[key-custody verifier](../../internal/provider/venice/keyset.go), and
[attestation-gap reference](../attestation_gaps/venice_aci_gateway.md) define the
available evidence. Do not infer deployment coverage from historical model counts.

For ACI/1, the quote, event log, and measured compose describe the gateway. Cache
its exact compose bytes, digest-pinned component evidence, and
eligible Intel collateral. The gateway images have `ComposeBindingOnly` provenance
in current policy. Reuse may establish compose coverage and repository recognition;
it must not create a Sigstore-signature result when no such verification exists.
For dstack responses, cache model-tier material only when supplied and verified.
Evidence bytes shared with NEAR still require Venice's own policy evaluation.

Retain original ACI workload keysets and custody signature chains for local checks,
but never trust `workload_keyset_digest` alone: it is a self-asserted consistency
check. Preserve the production chain through the quote-bound E2EE signing key,
keyset membership, custody signatures, accepted KMS root, and event-log-authenticated
application ID. Recheck the keyset's applicable `not_after` condition on admission.
A stored custody result cannot supply a fresh quote/nonce or authenticate arbitrary
keyset fields. Define exact signed inputs and policy scope before retaining custody
evidence, and verify it locally on every new admission; do not add a separately
authoritative encryption-key cache.

`source_provenance.repo_url` and `repo_commit` are provider assertions, not
quote-bound release provenance. Retain them only as diagnostic observations.
`downstream_tls_binding` and keyset TLS entries describe the gateway's downstream
hop, not teep's TLS peer. Do not use them to populate teep's attested transport
identity, or assume keyset consistency authenticates that entire downstream claim.

ACI/1 does not provide model-host CPU attestation or its compose manifest. Cache
loading must preserve visible missing-model failures and the exact format-specific
exemptions. It must not turn those gaps into successful or inapplicable factors.
Relayed GPU signatures and nonce checks do not establish CPU/GPU colocation, backend
software identity, or encryption to an attested model host. Keep NRAS and other
report-bound operations under their actual admission rules.

A separate Venice migration must define authorization scope, E2EE identity/custody
lifetime, keyset admission conditions, conditional invalidation, and connection
requirements before enabling any cache capability. Use the shared runtime path;
do not preserve a parallel generic-cache integration for portable prefill. Similar
captured gateway keys across models are not sufficient to enable router-wide reuse.

### Required checks and diagnostic retrieval

The current factor implementation establishes the classification. In
`evalSigstoreVerification`, missing compose-only digest lookups are tolerated, but an
empty result list becomes Skip (or an explicit ACI/1 missing-backend failure).
`buildTransparencyNoRekor` returns NotApplicable when no signed components are
required. Provider/component signer evaluators also exclude compose-only components.
Consequently removing HTTP queries without adjusting the typed report inputs can
change enforcement or hide an ACI/1 backend gap.

Represent each compose-only component explicitly as a locally bound component with
no required transparency query. Keep all expected signed components in the required
work set and preserve ACI/1's separate absence of model evidence. Evaluate factors
from typed component coverage, not a fabricated successful Rekor index response.
Regression tests must compare enforced outcomes and preserved gaps before/after this
change. Signed components reuse complete verified Rekor entry bytes and proofs;
index search results are retrieval hints, not the cryptographic proof to cache.

Classify each supply-chain retrieval by the production check it serves. The current
merged-digest path can perform Rekor index/provenance requests even for compose-only
components. Current policy and typed coverage determine whether a query is required;
the portable schema contains no `not_required` override. Route all required checks through shared
prefill-aware services, retaining cached evidence for any query-dependent required
result. When a query serves only an optional diagnostic, explicitly separate it from
admission and avoid a new pre-inference request; report that the diagnostic was not
refreshed. Verify this distinction against current factor aggregation, not just the
component's signer policy. Never turn skipped diagnostics into successful checks.
If an enforced diagnostic factor still requires a query, retain that request and
revise the budget until its complete reusable evidence has a defined contract.
Apply the same behavior to cache preparation, serving, and verification, with their
specified completion differences. Venice's budget is conditional on this work and
its shared-runtime migration; the compose-only example promises no image signatures.

### 4a. Release and image binding

For digest-pinned compose images, match the full canonical repository and digest.
For attestation-bound release measurements, match the signed release predicate to
the live measurements through the existing verifier. Retain release tags for
operator readability, not as evidence that a release is current or immutable.

A tag-only compose reference does not prove which image digest was pulled. Resolving
the tag during caching does not close that gap. Such entries must retain their
actual weaker binding classification and diagnostics; they cannot consume an
verification result that claims digest-bound image authentication. The existing factor policy
controls the resulting failure or explicit exemption. Do not add an automatic
`allow_any_version` exemption or label an unbound image as authenticated.

Provider-controlled artifact delivery is acceptable only where independent checks
establish the required authenticity and binding. Choosing an older authenticated
release is not itself a failure. Caching does not require a switch to direct GitHub
or routine `/releases/latest` requests. On a miss, resolve sufficient evidence for
the attested release through the supported retrieval path.

### Resolving authenticated Tinfoil releases on a miss

Use a local index of verified release predicates keyed by repository and measured
subject first. The permitted GitHub proxy supports latest-release metadata,
`/<repo>/releases/download/<known-tag>/tinfoil.hash`, and digest-addressed attestation
bundles. Planning probes of the router repository established that latest metadata
and a known older release download work, but release enumeration (with or without
pagination parameters) and `/releases/tags/<tag>` return HTTP 400 with an unsupported
path response. Do not implement speculative pagination or numeric tag guessing.

On a miss, candidate hints may come from independently verified retained bundles,
a tag delivered by the existing model-to-repository discovery response, and the
supported latest-release response. A discovered tag is only a retrieval hint;
verify the fetched bundle, repository/signer policy, and exact attested measurements.
Retain that hint when resolving direct routes instead of discarding it. Supplied V3
collateral is a candidate only after its format has an implemented verifier; merely
parsing its envelope cannot establish trust. Deduplicate candidates before retrieval.

Bound the known-candidate search to 32 candidates, 32 MiB aggregate response bytes,
and the existing bounded admission deadline, with the existing per-response limits.
Stop on an authenticated exact match. Exhaustion, a missing bundle, or no matching
known candidate fails the affected admission loudly. A latest mismatch never becomes
acceptable because another release could not be located. Record which candidate
source and dependency required each request, separately from verification costs.

A previously prepared matching release remains usable without asking whether it is
latest. However, cold preparation cannot guarantee discovery of every older deployed
release through the currently permitted proxy. A fixed cloud router has no
guaranteed discovery hint for an unknown older tag; bounded candidate search does
not remove that limitation.
No new tag flag, direct-GitHub bypass, or alternate whitelist input is introduced.
A broader discovery contract or a reviewed reference-hint interface is separate work.
Fixture coverage must include supported known-tag retrieval, unsupported enumeration,
matching older retained evidence, and failure when no known candidate matches.

### 4b. Request reduction and elimination

Count outbound HTTP attempts initiated by teep, including retries and redirects
where supported. Count HTTP/2 streams as requests, not connections. Report TLS
handshakes separately; DNS, TCP, and TLS exchanges are not additional HTTP requests.
Include library-owned clients, Sigstore TUF bootstrap/refresh, NVIDIA JWKS, and CT
metadata retrieval if triggered. Do not infer zero network activity from a cache hit
in only the application-level verifier.

Keep three separate counters: logical calls into the HTTP transport, transport
attempts (including retries inside one `RoundTrip`), and requests observed by the
destination test server. `tlsct.WrapCounting` supplies the first only; it cannot
establish the second. Instrument transport attempts with request trace events and
protocol-level observations where necessary, and reconcile them with deterministic
server counters. Record attempts that fail or are cancelled before transmission
separately from transmitted requests. Define the start event and terminal outcome
for each counter in the test helper so partial writes are not counted as completed
requests. Do not disable production retries to make the counters agree.

Implement accounting with transport decorators, existing request trace events, and
test-server observations. Keep protocol observations in test helpers where possible.
Do not replace or fork production transports, alter retry decisions, or introduce a
new scheduler solely to obtain counts. Extend existing transport regression tests
when they already exercise the required attempt boundary. If an observation cannot
distinguish attempts, report its coverage limit until a tested observation exists.

Count redirects and library retries at their actual attempt boundaries. Report
proxy CONNECT requests separately from origin HTTP requests and TLS handshakes;
retain this proxy overhead in total outbound HTTP accounting without adding it to
provider-service budgets. A cancelled request may have reached the server, so
response captures alone cannot prove its absence. Prove instrumentation coverage
with reused-connection failures, HTTP/2 retry cases, partial writes, cancellation,
redirects where allowed, and HTTP/HTTPS proxy paths before asserting complete counts.

The following is a source-derived request inventory, not a measured benchmark.
Counts describe successful first-attempt paths; dependencies, input size, cache
state, early failures, and retries can change totals. Chutes and Venice targets
apply only after their migration prerequisites are met.

| Request group | Current source-derived work | Prepared-cache target |
| --- | --- | --- |
| NearDirect discovery | Default initial selection retrieves `/endpoints` and `/backends/count`; explicit-index selection needs membership metadata but not a count; configured static routes may need neither. | Preserve route selection rules. No recurring discovery for established selections; a portable image cache does not eliminate cold discovery. |
| Tinfoil discovery | Model/backend mapping through `/.well-known/tinfoil-proxy` where required by the route. | Retain required discovery and its freshness policy. Do not use cached software to authorize stale route mappings. |
| Endpoint attestation | One response per full admission on the normal first-attempt path. NearCloud's response includes gateway and selected model evidence. | Zero on eligible in-process runtime reuse; fresh client-nonce request on new admission. Count gateway/backend verification separately from HTTP fetch count. |
| NEAR and applicable Venice image transparency/provenance | For each queried digest: one Rekor index search; for each successful digest, another index search and one or more entry retrievals. Model/gateway digest sets are deduplicated before this pass. | Zero retrievals for complete matching cached evidence. On a miss, share lookup work and retain all material needed for verification, rather than repeating the index search. |
| Tinfoil release evidence | Three explicit requests per repository: release tag, `tinfoil.hash`, and digest-addressed attestation bundle. A TDX admission also fetches the hardware-measurement repository. Sigstore TUF work is additional. | Zero release requests when retained signed predicates match the attested measurements under current policy. No latest-release request just to test freshness. |
| Venice ACI/1 | A model-selected attestation request supplies gateway quote/compose/keyset; generic verification may also query gateway digest evidence, Intel collateral, PoC, and relayed GPU services. Custody signature verification itself is local. | Eliminate eligible repeated artifact/collateral retrievals only. Preserve fresh gateway admission and report-bound work; do not promise that absent model provenance becomes verified or that every gateway image has Sigstore material to cache. |
| Chutes discovery, attestation, and request nonces | Model resolution when needed; fresh attestation fetches instances and nonce-bound evidence. Runtime nonce-pool replenishment fetches another instance/nonce batch. Count collateral and report-bound services separately. | After migration, reuse matching instance/key authorization and eligible collateral. Count nonce replenishment separately; zero extra requests requires both a valid authorization and an available matching nonce. Portable files never supply consumable nonces. Measurement decisions alone eliminate no quote or collateral requests. |
| Sigstore trust-root material | Tinfoil's verifier invokes the Sigstore TUF client. Exact downloads depend on dependency bootstrap and local metadata. | Retain authenticated root/metadata dependencies needed for local verification. Zero downloads only when their current verification requirements are satisfied; measure bootstrap and refresh separately. |
| AMD VCEK | Per-chip certificate retrieval through Tinfoil's VCEK proxy; signing chains are embedded. | Zero retrievals when an eligible VCEK matches product, HWID, and TCB. A changed chip/TCB can require a new certificate. |
| Intel PCS / revocation | Dependency-driven retrievals for applicable quote/collateral scope; exact count depends on quote and existing caches. | Zero when retained material satisfies new-admission validity requirements. Fetch only missing/ineligible objects, sharing applicable collateral between gateway/model and replicas. |
| NVIDIA NRAS / JWKS | One NRAS submission per applicable payload on the normal path, plus JWKS retrieval on a key-cache miss or eligible refresh. | Fresh report-bound NRAS submission remains on new admission. Persisting eligible verification-key material may remove JWKS retrieval, subject to an explicit issuer/key-refresh contract. |
| Proof of Cloud | Quote-bound protocol: stage 1 contacts configured peers; stage 2 chains responses through collected quorum peers. Current default has three peers and quorum three; successful full fan-out normally starts six requests. Cancellation and early results can change attempts observed. | Do not reuse a prior quote's JWT for a new quote. Count these calls as live until an independently verified portable registration contract exists or an explicit supported operator exception replaces that requirement. |
| Inference / E2EE | Normal inference sends a request and establishes actual encryption usability. `verify` performs its required live probe; portable `cache` preparation does not add a probe. | Do not add a preliminary inference probe to `serve` merely to consume the cache. Count `verify` probes separately from portable preparation and pre-inference metadata overhead. |

Source references: [NearDirect selection](../providers/near/near_attestation.md#neardirect-backend-selection),
[NearCloud fetch](../../internal/provider/nearcloud/nearcloud.go),
[proxy supply-chain verification](../../internal/proxy/proxy.go),
[Rekor index checking](../../internal/attestation/sigstore.go),
[Rekor provenance retrieval](../../internal/attestation/rekor.go),
[Tinfoil release verification](../../internal/provider/tinfoil/sigstore.go),
[NVIDIA verification](../../internal/attestation/nvidia.go), and
[Proof of Cloud protocol](../../internal/attestation/poc.go).

Let `D` be distinct NEAR digests queried, `S` the subset with index matches, and
`E` the total Rekor entries retrieved. The current successful image path costs
`D + S + E` requests before retry overhead. If every digest succeeds and one entry
per digest suffices, this is `3D`; complete reusable material reduces this group to
zero. For Tinfoil, `R` repositories cost `3R` explicit release requests plus TUF
requests. A one-repository SEV path can eliminate three explicit requests; a
TDX release plus hardware registry can eliminate six. These are conditional
source-derived counts, not claims about total provider startup traffic.

For `N` replicas with identical software subjects, let `M` be the measured portable
metadata retrieval cost and `L_i` each replica's necessary live work. Without shared
preparation, the comparable cold runs cost `N*M + sum(L_i)`. With one preparation,
they cost `M + sum(L_i)`, plus artifact distribution and preparation-specific live
work. Report both preparation and serving costs: moving requests earlier eliminates
them from the inference critical path, but not necessarily from total network use.
Avoid double-counting shared objects or already effective dependency caches.

### 4c. Scenario budgets and acceptance measurements

| Scenario | Locally reused or reevaluated | Requests still permitted before inference |
| --- | --- | --- |
| Cold start without prepared material | None assumed | Required discovery, fresh attestation, software evidence, collateral, report-bound services, and dependency metadata. Establish the baseline. |
| Prepared portable file, new replica | Current evaluation of matching evidence | Discovery, fresh endpoint admission, NRAS/PoC where applicable, and only missing/ineligible dependency material. Cached image groups must issue zero requests. |
| Read-only replica restart | Portable file only | New endpoint admission and its report-bound checks. No promise of zero admission requests. |
| Teep build update, evidence sufficient for local reevaluation | Recompute software verification and validate decision compatibility locally | Zero software retrievals; fresh endpoint admission remains required after build mismatch. Admission-time expiry may require collateral retrieval. |
| Policy change or missing/new verifier dependency | Recompute only eligible facts under current policy | Fetch precisely the missing/ineligible dependencies. Report which requirement caused each request. |
| Endpoint key rotation / new authority | Reuse unchanged software subjects | Fresh endpoint admission, route work as required, and new hardware collateral if needed. No retrieval of unchanged software merely because a key changed. |
| Operator decision applied | Match exact decision and evaluate its prerequisites locally | Only the request group explicitly replaced by that decision can be omitted. All other admission and trust checks remain. |

Define a deterministic request-count suite before implementing reuse. Use production
verifiers, TLS test servers, valid captured/signed evidence, and counters around
all outbound clients. For `nearcloud`, `neardirect`, `tinfoil_v3_cloud`,
`tinfoil_v3_direct`, record the baseline and proposed counts for every scenario.
Add Chutes and both Venice formats only when their migrations permit cache support.
Include both CPU evidence types where supported and multi-model/router sharing.
Keep deterministic Tinfoil direct scenarios in this suite. Defer its live
measurements under the Section 1 prerequisite, then run them against fixed
endpoints; continue Tinfoil cloud live measurements independently.
Mark all pre-migration Chutes/Venice cache scenarios blocked, not zero-call successes.
For Chutes, cover nonce exhaustion/expiry, concurrent nonce consumption, same-key
reuse, new instance/key admission, and independent model activity. Exercise dstack and ACI/1 concurrently at the same Venice
origin, including a model changing response format; no cached model result may
satisfy a gateway-only response. Measure Venice discovery separately when model
listing is requested, and retain its format-specific factor outcomes.
Count network envelopes separately from attested subjects and component checks.
NearCloud can deliver gateway and selected backend evidence in one HTTP response;
do not budget another backend fetch when complete valid stapled evidence suffices.
Count independently required collateral/provenance/NRAS requests, and distinguish
material present in a response from material the shared verifier actually consumes.
Compare direct-first/cloud-second and cloud-first/direct-second preparation with
identical component evidence: fetch shared eligible objects once while evaluating
each consumer's policy. Repeat for identical versus different compose bytes, fresh
nonces, changed keys, and missing or ineligible stapled material. No cached report
or matching key can replace fresh required admission or missing backend evidence.

Measure component counts independently of CVM, model, and authorization counts.
Include shared components across tiers, multiple repositories per compose/release
set, one changed component, and a cache containing only the first required member.
A newly added component incurs only its required retrievals, but complete-set
coverage must be reevaluated. Supplied Tinfoil collateral saves no retrieval until
the shared verifier independently accepts it. Inspect actual parser/verifier use,
not just metadata presence, when claiming request elimination.
Do not weaken enforcement or replace cryptography with success mocks for benchmarks.

Measure request attempts by destination and purpose, bytes fetched, cache hits,
local reevaluations, and handshakes, separating cold and warm dependency caches.
Latency targets and timing benchmarks are not goals or acceptance criteria of this
plan: network conditions, proxy use, and deployment conditions vary. Bounded operation
deadlines remain correctness/resource limits, not performance targets.
Keep fixture counts as assertions; live counts are observations
with provider/model, build/policy, date, and dependency-cache conditions recorded.
Use the existing live-test opt-in. Store measurements in test artifacts, not a
running validation log in this plan.

Acceptance requires zero calls to cached software groups, zero metadata/admission
calls for eligible already-acquired authorizations (with Chutes nonce replenishment
counted separately), local software reevaluation on
upgrade without retrieval when evidence suffices, and precise remaining-call counts.
Test network denial to cached groups while necessary live groups remain available.
Use the normal handler and authorization acquisition path for transport/lifecycle
scenarios, and the shared evaluator for signed-evidence replay. Apply the
[test-layer contract](#test-layers-and-fixture-prerequisites) when establishing
complete budgets; no separate cache-only admission path is permitted.
Unknown counts must be measured, not reported as zero. A result that skips required
checks does not count as a cache saving.

### 4d. Provider scenario budgets

These are conditional, source-derived successful first-attempt budgets for one
selected route, not measured cache-implementation results. Assume matching software,
hardware-scoped collateral, policy, eligible trust metadata, and the GPU evidence
shown. Count all teep-owned and library-owned HTTP requests, excluding the inference
request itself and separately reported proxy CONNECT overhead. These are origin
service budgets; Section 4b's total outbound accounting includes proxy overhead.
Complete portable prefill targets zero software, collateral,
JWKS, TUF, and CT metadata retrievals. TLS handshakes and local checks still occur.
`verify` adds its required live probe and always performs fresh admission. All
process restarts use the portable-prefill columns, including same-build restarts.
"Complete validation" means every applicable check is
evaluated under effective policy, retaining permitted failures and provider limits;
it does not imply that unavailable backend evidence becomes authenticated.

| Route assumptions | Software evidence only; other dependency stores cold | Complete eligible evidence, same build or update |
| --- | --- | --- |
| NearCloud (6a): one response, gateway/backend TDX, backend GPU | 23 + CT requests | 14 |
| NearDirect: default selection with two discovery requests, TDX/GPU | 15 + CT requests | 10 |
| Tinfoil direct: supported CPU/release and transport test layers; full admission requires a supported concrete response and unchanged effective policy | Measure groups exercised by each layer; no successful TDX/GPU total asserted | Zero requests to eligible prepared groups; full-admission total remains unestablished |
| Tinfoil cloud: fixed SEV router, no backend GPU evidence | 2 + CT + TUF requests | 1 |
| Venice ACI/1 after migration: selected model, gateway TDX and relayed GPU | 13 + CT + any required diagnostic image requests | 8, conditional on diagnostic-query work |

Software-only prefill always evaluates retained signatures with current trust
material. Cold Sigstore/TUF stores therefore add TUF retrievals for Tinfoil on both
same-build restarts and upgrades. Complete eligible TUF inputs remove those calls;
expiry requires refresh in either case. NEAR compose-only diagnostic classification
must also be complete before claiming zero image queries. No stored status waives
an enforced check. The decompositions below exclude CT/TUF retrievals unless stated.

Every complete-prefill number requires the asserted dependency
coverage, including CT. If that contract is not implemented or material is ineligible,
report the added requests and the unmet requirement; do not advertise the smaller
number as achieved. Current captures omit some library/bootstrap traffic and cannot
establish these end-to-end totals by themselves.

The decompositions are:

- NearCloud: 1 attestation + 8 Intel collateral + 1 NRAS + 1 JWKS + 12 Proof of Cloud
  = 23 before CT. Full portable dependencies remove 9, leaving 14.
- NearDirect: 2 discovery + 1 attestation + 4 Intel + 1 NRAS + 1 JWKS + 6 Proof of Cloud
  = 15 before CT. Full dependencies remove 5, leaving 10.
- Tinfoil direct: measure discovery, CPU collateral, release/TUF, and any applicable
  report-bound work for the supported fixture or live response. The shared parser
  cannot currently admit nonempty V3 device evidence, so no successful NRAS/JWKS
  decomposition is assigned to that shape. Component and transport counts do not
  establish a full-admission total; apply both prerequisites in Section 1.
- Tinfoil cloud: 1 attestation + 1 VCEK = 2 before CT/TUF; matching VCEK and eligible TUF material leave 1.
  AMD signing chains are embedded. No backend validation is inferred.
- Venice ACI/1: 1 attestation + 4 Intel + 1 NRAS + 1 JWKS + 6 Proof of Cloud = 13
  before CT and diagnostic image lookups; eligible dependencies leave 8.

The NEAR captures used for these scenarios are
`nearcloud_z-ai_glm-5.3-flash_20260910_153519` and
`neardirect_z-ai_glm-5.3-flash_20260909_201111` under
[provider replay data](../../internal/integration/testdata/). NearCloud contains eight
Intel requests with five distinct URLs: sharing retrievals can reduce that group
to five before persistence, while complete eligible prefill reduces it to zero.
The captures contain early Proof of Cloud 403 responses; fewer recorded responses
are not successful quorum budgets or proof that no cancelled attempts started.
Count six requests per successful default three-peer quote verification, separately
for gateway and backend. Do not persist failure shortcuts as positive evidence.

A measurement decision replaces a local expected-value comparison and
eliminates no quote/collateral requests by itself. Combine it with complete portable
material; the decision fragment in Section 6c is not a complete provider scenario.
Every restart performs fresh admission using eligible portable material. A currently
acquired in-memory authorization needs no renewed admission while its existing
scope/lifetime remains valid; HTTP/2 reuse does not authenticate a new scope.

Each core provider scenario needs coverage for all applicable columns through the
[test layers](#test-layers-and-fixture-prerequisites). Assert zero calls to prepared
dependency groups with access denied. Assert exact report-bound counts only with
suitable signed fixtures; measure full fresh-admission totals in live coverage. Repeat with expired
collateral, stale JWKS/CT metadata, unknown key IDs, changed hardware, missing TUF
transitions, and build/policy changes. Verify the precise necessary retrieval or
failure rather than filling missing data from ambient developer caches. Publish
preparation costs, cold-start costs, and per-request reuse separately.

### 4e. Captured baseline and populated-evidence experiment

The planning baseline below counts recorded HTTP responses in the named fixtures,
not all attempts or current live-provider traffic. Library-owned bootstrap requests
and cancelled requests may be absent. Fixture verification uses capture-time rules;
these old bytes cannot be imported as currently eligible collateral without current
eligibility checks. The successful NEAR fixture tests confirm existing production
verification behavior under their configured factor policy, not every factor passing.

| Fixture under `internal/integration/testdata/` | Recorded request groups | Total responses |
| --- | --- | --- |
| `nearcloud_z-ai_glm-5.3-flash_20260910_153519` | Attestation 1; Intel 8; NRAS 1; JWKS 1; PoC 2 (403); Rekor 33 | 46 |
| `neardirect_z-ai_glm-5.3-flash_20260909_201111` | Discovery 2; attestation 1; Intel 4; NRAS 1; JWKS 1; PoC 1 (403); Rekor 10 | 20 |
| `tinfoil_v3_cloud_glm-5-2_20260817_003424` | Attestation 1; AMD chain/VCEK 2; release 3 | 6 |
| `venice_aci_e2ee-glm-5-2-p_20260826_010725` | Attestation 1; Intel 4; NRAS 1; JWKS 1; PoC 6 (200); Rekor 10 | 23 |

The Tinfoil capture predates embedded signing-chain retrieval, so one recorded AMD
request is no longer necessary in the current source. Neither these response totals
nor a 403 shortcut replaces the successful-service budgets in Section 4d.

A planning experiment populated content-addressed evidence lists from original
response bodies and issuer-chain header values, deduplicated by SHA-256, and checked
base64 round-trip/digest integrity. Serialized size below is compact JSON (valid YAML)
with digest/kind/payload fields. It includes retained historical service/discovery
responses for coverage analysis, not a prescription to export all those responses.
No inference exchanges, credentials, consumable nonces, or private keys were imported.

| Fixture | Distinct retained objects | Decoded bytes | Serialized bytes |
| --- | --- | --- | --- |
| NearCloud | 38 | 568,000 | 762,303 |
| NearDirect | 20 | 466,552 | 624,705 |
| Tinfoil cloud | 6 | 95,635 | 128,331 |
| Venice ACI/1 | 23 | 313,948 | 421,614 |

These establish representative byte costs and the need for header preservation;
they are evidence-only research artifacts, not completed cache-loader fixtures.
TUF and CT material are absent from these captures
and must come from their authenticated acquisition paths. Build executable scenario fixtures by extracting the actual original compose strings, complete Rekor responses,
and typed CPU collateral from these fixtures; never accept historical bytes without current verification (using an explicit
clock only in replay tests). Keep live request-count observations separate from
deterministic request-count acceptance.

A separate local prototype used the pinned go-tuf/Sigstore libraries on authenticated
public repository metadata: bootstrap root 14, signed transition to root 15,
timestamp 782, snapshot 165, targets 14, and the hash-verified `trusted_root.json`
target. The `trustedmetadata` update sequence and Sigstore root parser completed
locally without constructing a network client.
This demonstrates API feasibility, not proof of latest
metadata or full offline Tinfoil admission. Retain root transitions in the examples:
the pinned bootstrap root alone was expired at the research date, while the verified
successor was eligible. Production uses current time and actual metadata versions.

## 5. Commands and deployment

```sh
teep cache --all-models
teep cache --model nearcloud:example-model
teep cache --model neardirect:example-model --model tinfoil_v3_direct:example-model
teep cache --model nearcloud:example-model,tinfoil_v3_cloud:example-model
```

All names above are illustrative. `--model` requires fully qualified
`provider:model` names and is mutually exclusive with `--all-models`. Resolve active
providers as `teep serve` does; reject unknown/inactive providers, ambiguous models,
invalid names, and an empty active set for collection/addition operations.
Withdrawal-only editing validates existing decision identifiers independently of
active provider/model configuration. There is no provider positional argument.

`teep cache` constructs the shared admission services with command-owned bounded
lifecycle and dependencies, resolves each target, obtains fresh client-nonce
attestation, and runs normal online admission using eligible portable evidence.
In `--update-whitelist` mode, apply the selected decisions as specified below and
require successful evaluation under the resulting effective policy. It uses
the production verification and binding pathways; it does not create success
results by copying a stored report. Offline and debug-force operation must not
produce trusted cache output. Record explicit `allow_fail` outcomes accurately;
never reuse a waived check as a passed check under stricter policy. Export immutable
snapshots of the persistable material produced by those shared services. Do not
reconstruct trust from display reports or reimplement verification in the command.

Write complete successful software targets only. Accepted TUF state is the explicit
exception: persist authenticated trust transitions even after later target failure,
as specified in [trusted version state](#tuf-trusted-version-state). For a multi-target run, preserve unrelated
entries except for the explicit capacity collection rules in Section 7, retain
dependencies of every retained entry, collect target failures, and
exit nonzero if any target failed. Failed targets contribute no software export or endpoint authorization. Decision scope can cover several models: an explicitly
reviewed decision admitted through a successful target may affect a failed target's
future policy, but must not claim that target passed. Show known affected models and
any wider provider/tier scope before confirmation; do not imply complete fleet coverage.
Commit an addition only if at least one selected successful target establishes all
its prerequisites. Reevaluate successful targets against the exact committed subset.
Withdrawals are independent restrictive policy operations and may commit even when
all live targets fail, with nonzero target-validation status reported separately. A portable cache target is successful after all non-deferred admission checks under
its effective policy are satisfied, as defined below; deferred live usability is
reported separately. Validate all target syntax before network activity or writes. Do not
claim that `--all-models` discovered every physical backend: it covers discovered
models and the routes actually verified. Tinfoil cloud may share router evidence
while retaining separate per-model probe diagnostics.

Use `--cache-file`, then `$TEEP_CACHE_FILE`, then configured `cache_file`, then
`~/.config/teep/cache.yaml` as identical location precedence for `cache`, `serve`,
and `verify`. Use one shared resolver and loader; all three automatically read an
existing default file. A missing implicit default starts empty. An explicitly
selected path (flag, environment, or configuration) that is missing is an error in
`verify` and in `serve` unless `--autocache` is selected. `teep cache` and `serve --autocache` may create their
output file after validating its destination. A malformed or insecure file always fails loudly.

`teep serve` constructs the shared admission services and authorization store
whether or not a disk file is configured. Startup loads eligible material through
the prefill interfaces before it becomes available to request acquisition. Cache
misses join the same bounded live verification used without prefill. Newly verified
material populates the same stores and can be exported to a configured writable
file only when `--autocache` is selected, using the same snapshot/export path as
`teep cache`. Without this option, `serve` does not write portable evidence. A read-only cache destination
supports image-layer deployment without attempted writes. Failed optional evidence write-back
leaves a separately completed in-memory verification valid, emits an error, and
must not claim persistence. Runtime invalidation remains governed by the existing
in-memory authorization contract.

### Configuration and persistence controls

Use `cache_file` for the shared artifact path. Ordinary `serve` is a read-only
portable consumer unless `--autocache` is selected; filesystem permissions provide
the deployment's read-only restriction. No separate undefined read-only declaration
is required. An autocache writer validates destination writability at startup.

### Admission and command completion

Software evidence becomes export-eligible when all non-deferred admission checks
satisfy effective policy. Accepted TUF transitions have their separate trust-state
persistence boundary even if later admission fails. A deferred `e2ee_usable` result is recorded as deferred,
not passed; independently verified software can be exported without an inference
probe. `serve --autocache` uses this boundary before the inference outcome is known.
`cache` is preparation, so it performs no inference probe solely to populate portable
software and reports deferred usability separately. `verify` retains its live probe
behavior and cannot report complete live verification when its required probe fails.
An inference 429 may therefore leave valid cached software while making live `verify`
fail. Shared checks must agree across commands; their completion criteria differ
explicitly. Runtime publication and E2EE-usability promotion retain their existing separate checks.

Deferring remote usability does not defer local key validation. Before software
export or decision creation, shared admission must validate required key encoding,
NEAR key conversion, and EHBP key agreement through the production cryptographic
pathways, including rejection of low-order keys. It must also establish required
REPORTDATA binding and route/transport-identity consistency. A present, correctly
sized, attested key is not sufficient. These checks require no inference probe.

### Read-only policy validation with `teep verify`

`teep verify` loads eligible portable evidence and explicit operator decisions from
the same resolved cache path as `cache` and `serve`. It obtains fresh endpoint
attestation and evaluates it through the same shared admission and effective-policy
services. It may reuse eligible software evidence and collateral to avoid repeated
retrievals, but must not substitute a
previous endpoint report for current admission. Retain required online checks and
verification probes; apply the Tinfoil direct live-validation prerequisite.

Report original factor failures, matching decisions, remaining enforced failures,
and unused decisions separately. An unused decision is diagnostic, not by itself a
verification failure. Success requires every selected target to satisfy effective
policy and required verification steps. An enforced cryptographic failure still
blocks; an existing explicit `allow_fail` remains visible as a permitted failure.
The unsupported-decision inventory prohibits creating new exceptions through this
command, not application of existing factor policy. Report selected models and observed endpoints without implying coverage of
unobserved backends. The purpose is to show that effective policy accounts for all
enforced failures, not to require whitelist entries for factors that already pass.

For automated rollout, identify the exact loaded cache content digest, effective
policy identity, and teep build in the report. Compute the digest from the bytes
actually loaded, not a later reread of a concurrently replaced file. Report an absent
implicit default explicitly. Evaluate one immutable loaded snapshot per invocation,
so automation can associate results with the tested artifact.

Verification is read-only: do not create a missing cache, persist retrieved evidence,
create decisions, or run the autocache writer. Offer no separate whitelist input;
operator decisions and their supporting evidence use the single cache artifact.
Refactor CLI orchestration to call shared admission services where necessary; proxy
unification alone is not proof that the CLI uses them. Test equivalent effective-policy
outcomes across `cache`, `serve`, and `verify`, accounting for fresh admission versus
permitted runtime reuse.

### Capture and replay with portable inputs

Preserve `verify --capture` and its successful-run replay self-check when evidence
comes from portable or in-memory material. HTTP recording alone cannot capture
inputs that required no request. Retain the exact loaded artifact snapshot in the
capture, together with any additional consumed material not represented by recorded
responses. Use the existing typed evidence encoding and shared acquisition owners;
do not create a second verifier or synthesize HTTP exchanges for cache hits.
Capture observation hooks retain inputs only and cannot promote them into trusted
runtime material. Preserve original retrieval times, input associations, and the
loaded-artifact digest separately from additional inputs collected during the run.

Keep shared material clients and their transports immutable after construction.
The existing per-invocation capture code replaces an attempt client's transport;
that client cannot become a shared material client. Retain attempt-owned recording
for live evidence and attach synchronized input observations to material acquisition
and consumption. Each consumer records the exact inputs it used, including inputs
acquired by another target. Completion or cancellation of one target detaches only
its observer; it cannot close a shared client or cancel another target's retrieval.
The service/command owner closes its material clients at lifecycle completion.

Retain the relevant non-secret base-policy inputs and exact operator-decision
context needed to reproduce the report, including unused-decision diagnostics.
Never copy a configuration file containing credentials. Validate capture additions
with strict parsing, digest/reference checks, and the same evidence resource bounds.
Keep current cryptographic evaluation and the existing explicit replay clock/nonce
semantics; recorded results are not verification inputs.

Replay uses only its captured inputs and recorded responses, with unexpected
retrieval denied. It must not load a default cache, consult current cache-path
environment/configuration, or acquire missing material from ambient owner stores.
Missing or altered capture dependencies fail explicitly. Capture policy and
authenticated-retrieval observations reproduce a historical diagnostic run; they
cannot install policy or authorize live admission. Capture directories remain
ineligible as trusted portable-cache input.

Deliver software capture/replay coverage with Phase 3a, extend it with each material
adapter when consumed, and add decision-context coverage in Phase 9. Test successful
warm-cache capture and its self-check, then replay after removal or replacement of
the original artifact and changes to ambient cache selection. Cover inputs reused
from memory across targets, dependency tampering, missing inputs, applied and unused
decisions, and unchanged outbound request counts. No capture-only requests may be
added to recover evidence already consumed locally.
Run two targets sharing one material acquisition with independent captures. Cancel
or complete one while the other waits; assert continued retrieval, race-free capture
snapshots, and complete inputs for the surviving target. Repeat when one target
reuses already retained material. Replay each successful capture independently,
with the original clients and portable artifact unavailable.

### Mixed-provider verification and deployment

Cache-aware verification is a post-migration cache-enablement requirement for Chutes and Venice.
Until migration, these providers use ordinary live verification without portable
prefill. Validate the selected artifact, then determine applicability from each
target's policy and implemented capabilities, independently of whether the path
came from a flag, environment, configuration, or implicit default. Unrelated policy
and provider-independent evidence bytes do not require an unsupported provider to
consume cache material. Report that the target used ordinary live verification and
that its cache capabilities were not validated; do not claim cache-rollout coverage
for it. Never apply cached decisions through a legacy verification adapter.

If an active decision's declared scope could apply to the selected unsupported
target, reject that target explicitly because its decision evaluator is unavailable.
Do not assume the decision would be unused merely because no current subject has
been fetched. In `serve`, check this condition for all active routes at startup and
reject startup with the affected providers/scopes before accepting requests. A
mixed-provider server with cache material for supported providers and no applicable
unsupported policy starts normally; unsupported routes retain their live behavior.
In `verify`, report target-specific failures with the normal nonzero aggregate
status. Explicit file selection never changes these applicability rules.
`verify --no-cache` provides an explicit baseline path even when a default exists;
it reads no cache, applies no cache decisions, and must not claim rollout validation.
PhalaCloud and NanoGPT remain outside cache scope. Apply the same relevance rules to
ordinary `serve` routes; do not silently discard matching policy or add legacy adapters.
Explicit `cache` targets remain rejected, with multi-target failure reporting.

Remove `--update-config` and `--config-out` when delivering the operator decision
workflow in Phase 10. Only `--update-whitelist` authors cache decisions from
observations; it must not edit measurement-policy configuration. Retain the existing
validated measurement allowlists and their replacement precedence as base policy,
including restrictive lists. Reject removed CLI options and unknown configuration
fields, but do not classify the retained measurement-policy fields as obsolete.
Update CLI help, configuration examples, and provider documentation together.

Operators can generate one trusted cache file and distribute it to replicas through
their trusted deployment system. Replicas evaluate matching software evidence locally
without independent GitHub/Sigstore retrievals when dependencies are complete and
eligible. Both unchanged and different builds use current verification. Read-only replicas perform fresh endpoint
admission and keep runtime authorization in memory.

Prompt-cache secret generation/persistence from issue #134 is separate optional
work. Such secrets are not portable public evidence and must not be distributed in
this shared artifact by default. Never include API credentials in the artifact.

### Automatic persistence with `teep serve --autocache`

`--autocache` is an opt-in writer to the cache location selected above. It persists
reusable evidence encountered during normal service; it
does not add a discovery loop, poll for newer releases, or introduce a second
verification path. Explicit `teep cache` prepares material before traffic arrives.
Autocaching pays the normal retrieval cost on the first encounter and reduces
later retrievals across restarts or replicas that receive the file.

Export eligible software material after successful admission under current policy,
through an immutable evidence snapshot. Accepted TUF transitions may be queued
independently after authentication, including when a later admission step fails;
the same bounded writer and persistence-failure reporting apply. Inference
response success is not the publication trigger: an upstream rate limit does not
undo independently completed verification. Do not export failed or incomplete
admissions as reusable successful results. Apply the existing per-object portability
rules even when the containing authorization was admitted successfully.

For example, a newly encountered compose with changed image digests requires normal
compose binding and verification of those image subjects. Newly encountered Tinfoil
release metadata must authenticate a release matching the attested measurements.
Only then can eligible software evidence be persisted. A mutable tag, provider
assertion, or latest-release lookup alone cannot establish a verified subject.

Autocaching does not create, expand, or revive operator decisions. New evidence must
pass current policy or match an existing explicit decision. Preserve base failures,
`allow_fail` exemptions, and applied decision references in the current report.
The file contains raw evidence, never a permitted failure relabeled as a success.
Every import is subject to current verification and policy. Keep decision creation exclusive
to `teep cache --update-whitelist`; `serve` does not offer automatic TOFU.

Use a server-owned asynchronous writer with bounded pending work, deduplication,
and coalescing by exact evidence/subject identity. Request handlers enqueue or mark
eligible shared state for export without waiting for filesystem I/O. If capacity
is exhausted, retain a bounded dirty-state indication for later snapshot work and
emit a diagnostic; do not create an unbounded queue or delay authorized inference.
Use the same locked read-merge-write transaction as `teep cache`, preserving
operator decisions and retaining unrelated targets subject to Section 7's capacity
collection rules. Preserve the authoritative policy state and active decisions under the lock;
evidence snapshots have no policy-write capability. Do not hold runtime store mutexes during disk I/O.

Reject `--autocache` with a read-only cache destination or an unusable destination at
startup, before accepting requests. Validate existing files strictly; the option
must not overwrite malformed or insecure input. A later write failure leaves an
independently verified in-memory authorization usable, emits a non-secret error,
and records that persistence failed. Use bounded retry with backoff, coalescing
repeated work; expose pending writes, failures, and the last successful write.
On orderly shutdown, attempt a bounded flush and report unfinished persistence.
A crash may lose pending optional evidence writes; atomic replacement must preserve
a valid committed file. Never claim that asynchronous enqueueing guarantees durability.

Automatic export contains portable evidence and accepted TUF state only.
Never serialize TLS connections, session tickets, inference data, ephemeral secrets,
or consumable Chutes request nonces. Chutes and Venice remain blocked until their
shared runtime migrations; PhalaCloud and NanoGPT remain outside scope. Apply the
same provider eligibility checks to automatic export as to explicit cache targets.

### 5a. Whitelist inventory

This is an inventory of proposed decisions, mapped to the current factor families
in [report.go](../../internal/attestation/report.go) and the provider
[NearDirect](../../internal/provider/neardirect/policy.go),
[NearCloud](../../internal/provider/nearcloud/policy.go), and
[Tinfoil](../../internal/provider/tinfoil/policy.go) policies. Gateway equivalents
follow the same rule but have separate scope. One report factor can combine
multiple failures: implementation must expose typed reasons before allowing a
specific reason to be overridden. Whitelisting `tee_hardware_config` as a whole
would also waive unrelated hardware checks and is not an exact pin.

**Ordinary** means eligible for explicit selection with `--update-whitelist`.
**Elevated** means a proposed candidate that additionally needs a concrete per-change
risk acknowledgement. Elevated support must remain disabled until its typed checks,
prerequisites, and tests exist; the generic flag does not enable it. **Unsupported**
means this command cannot turn the failure into a reusable decision. These are
requirements for the new decision path, not changes to existing `allow_fail` or
release/debug enforcement semantics.

| Observed condition / factor family | Exact decision and prerequisites | Class | Request effect on later admission |
| --- | --- | --- | --- |
| Unlisted repository: `component_recognition` | Add exact canonical repository within provider/tier; retain signature, signer, and attested-content checks. Repository recognition alone grants no signature trust. | Ordinary | Local list update; independently verified image evidence is still required. |
| New or changed component/provider signer: `provider_signer_recognition`, `component_signature_recognition` | Pin exact key fingerprint or OIDC issuer plus workflow identity, repository, and tier. Verify possession/signature and existing certificate chain independently; do not pin a mere name or arbitrary root. | Ordinary TOFU | Identity comparison becomes local; cached signature/transparency material eliminates retrieval only when otherwise sufficient. |
| Unlisted TDX MR_SEAM/MRTD/RTMR or SEV launch measurement: `tee_measurement`, allowlist portions of `tee_hardware_config` / `tee_boot_config` | Pin the explicitly selected measurement fields as one correlated match condition, with platform/provider/tier scope, from an authenticated fresh quote. Retain the full observation as evidence; unselected registers are not added to the decision match. Keep inseparable security conditions required by the decision class. Retain debug, TCB, revocation, quote-signature, event-log, and REPORTDATA checks; never combine independently observed fields into an unobserved allowed tuple. | Ordinary TOFU | Local expected-value comparison. Does not eliminate PCS, NRAS, or fresh quote requests. |
| Valid signed code/boot reference does not cover current attested measurements: `sigstore_code_verified`, signed-registry match in boot/gateway measurement factors | Pin exact current authenticated measurement tuple as an operator reference, preserving the mismatch with the publisher's reference. Do not claim the provider signed these measurements. | Elevated: `unpublished_measurement` | May replace reference lookup for this exact tuple only; no removal of hardware authentication or unrelated image checks. |
| New compose or image digest with valid signature/provenance | Pin exact attested compose hash or repository/digest; compute complete dependency coverage. If existing policy already permits it, use ordinary caching without an operator decision. | Ordinary when only expected-value policy fails | Matching retained software evidence eliminates repeated artifact queries; live compose binding remains. |
| Missing image signature or transparency evidence: `sigstore_verification`, `build_transparency_log`, provenance requirements | Pin exact digest-bound content or authenticated compose/measurement subject, explicitly waiving only the named missing provenance requirement. Require a definite absence result or an explicit operator-selected provenance waiver; a timeout alone must not automatically create one. | Elevated: `unverified_provenance` | Can eliminate the specifically waived provenance query for the pinned subject; records operator trust, never signature/transparency success. |
| Tag-only image reference / mutable tag | A tag cannot identify deployed bytes. An exact compose pin may trust the observed configuration, with an explicit weaker image-binding classification; it cannot invent a digest binding. | Elevated: `unbound_image_version` for configuration-only pin; unsupported as an image-digest pin | No claim of authenticated release caching. Other required evidence and live compose binding remain. |
| Authenticated outdated TCB or advisory: `tee_tcb_current` and gateway equivalent | Pin exact platform/TCB/measurement and authenticated status/advisory identifiers, after all cryptographic checks. Do not generalize to all future firmware on the machine. | Elevated: `outdated_tcb` | Status-policy comparison is local. Valid collateral retrieval and revocation checks remain unless separately and explicitly excepted. |
| Explicitly revoked content, platform, or certificate: `tee_tcb_not_revoked` and applicable authenticated revocation decisions | Candidate exact subject, issuer/revocation record, TCB or certificate serial, and acknowledged reason. Require a verifiable chain/signature apart from the selected revocation failure. Never apply an image exception to a revoked hardware key. | Elevated: `revoked_subject`; disabled until the precise supported revocation classes are defined | A decision about one observed revocation does not waive new revocations or stop retrieval needed for other checks. Zero-request behavior requires a separately specified scoped status pin. |
| Expired collateral or certificates used for new admission | Candidate exact signed object/issuer/subject with explicit time-policy exception and intact signatures. Separate certificate validity, CRL next-update, and collateral expiry; do not reset timestamps. | Elevated: `expired_material`; disabled until per-type semantics are defined | May remove only the refresh required by the excepted time check. It cannot replace fresh nonce evidence or treat an expired NRAS/PoC JWT as a new report result. |
| Hardware registration absent: `cpu_id_registry`, gateway equivalent | Pin authenticated hardware identity and observed registration failure; describe this as waiving registration, not proving cloud membership. Define a stable authenticated hardware selector before support. | Elevated: `unregistered_hardware` | Can omit the exact registration requirement when supported. A quote-bound PoC JWT cannot itself serve as a portable registration pin. |
| Venice ACI/1 accepted KMS root mismatch: typed `aci_key_custody` reason | Pin an exact recovered KMS root for Venice ACI/1 gateway custody, with retained valid signature chains, derivation purpose, quote/key binding, and authenticated app ID. This changes the key-releasing authority, not an image signer. Record independent corroboration when available; otherwise identify the decision as TOFU. | Elevated: `kms_authority`; disabled until isolated typed checks and scope are implemented | Root membership is local; all custody, nonce, key, and quote checks remain. No general removal of attestation or collateral requests. |
| Venice ACI/1 gateway application ID mismatch: typed `aci_key_custody` reason | Pin exact event-log-authenticated app ID under a specified accepted KMS root and gateway scope. Retain event-log replay and custody signatures; do not permit arbitrary applications of that KMS. | Elevated: `gateway_application`; disabled until isolated typed checks and scope are implemented | Application membership is local; fresh gateway evidence and all other admission checks remain. |
| Debug enabled, insecure guest policy, insufficient CPU/GPU/key-custody binding | These can remove confidentiality guarantees despite correct signatures. Do not conflate them with a changed register allowlist. | Unsupported in this cache decision path | No request saving or reusable pin from the failure. |
| Invalid quote/image/JWT signature, untrusted hardware root, nonce mismatch, REPORTDATA/compose/event-log mismatch, key substitution, malformed evidence, unusable encryption, TLS/WebPKI/CT failure | No new decision may waive this failure. Existing explicit factor policy is evaluated separately; never label a permitted failure as successful cryptographic verification. | Unsupported | No new bypass or successful result for the failed check. |

For missing provenance, distinguish absence from an invalid supplied signature.
The absence decision must not absorb a definitive cryptographic failure. For
measurement changes, separate authentication of the quote from trust in its measured
software: TOFU supplies the latter only. An authenticated but revoked subject is
not the same condition as a forged signature; inventory and diagnostics must retain
that distinction even where elevated support is not yet implemented.

### Ordinary decision implementation boundaries

Source research identifies two different expected-value mechanisms. Model/gateway
`MeasurementPolicy` contains MRTD, MRSEAM, and indexed RTMR allowlists; a selected
unlisted-field tuple can become an ordinary measurement decision while preserving
all other quote and configuration checks. In contrast, mismatch with a signed
Tinfoil code/hardware predicate remains `unpublished_measurement`, an elevated
candidate. Do not classify it as an ordinary register-list edit merely because
both compare measurements.

Repository recognition and signer recognition are separate evaluators. An ordinary
repository decision may extend the recognized repository/tier while retaining a
fully specified existing applicable signer/provenance rule. If no such rule exists,
repository recognition alone cannot create it. Organization-signer rules apply only
when their repository/workflow/issuer predicates independently match. New image or
compose versions already accepted by current policy require ordinary caching, not
an artificial expected-digest decision: the current `ImageProvenance` policy does
not define a universal expected-image-digest whitelist.

Use typed verification failures and observations emitted before factor formatting;
never identify an exception by matching error-message text. A signer candidate needs
independently verified key possession and its required trust prerequisites even when
the expected identity comparison fails. In the Tinfoil path, separate that comparison
from bundle authentication instead of treating `FetchAndVerify`'s combined error as
an authenticated observation. In the NEAR path, parsing certificate OIDC extensions
alone does not independently validate the issuer chain. The current raw-key Rekor
path verifies log evidence, not possession of the artifact-signing key. A raw-key
fingerprint decision therefore remains unavailable until separate production
verification work establishes possession and the required artifact binding. Do not
claim additional assurance for existing `NoDSSE` or compose-only components.

The initial decision implementation has the following capability boundary. The
broader inventory above does not enable additional classes:

| Decision | Initial scope and prerequisite |
| --- | --- |
| Unlisted TDX measurements | Exact selected MRTD, MRSEAM, and indexed RTMR fields under the model/gateway register-list policy for supported providers. Preserve all other quote checks. Signed code/hardware-reference mismatches remain elevated. |
| Repository recognition | Exact repository and tier only where a fully specified existing signer/provenance rule independently applies. Reject creation of a missing provenance rule. |
| Tinfoil OIDC signer recognition | Exact repository/tier, issuer, and workflow identity after Phase 9 separates bundle authentication from expected-identity comparison. Required certificate-chain, signature, transparency, artifact, and measurement bindings must independently pass. |
| NEAR OIDC signer recognition or raw-key fingerprint TOFU | Deferred pending separate production verification of the missing chain or key-possession prerequisite. Neither parsing OIDC fields nor verifying a Rekor entry supplies it. |
| New image/compose version already accepted by policy | Ordinary caching; no decision is created. No new expected-digest policy is introduced. |
| Other measurement mechanisms and elevated inventory classes | Deferred until their exact evaluator and prerequisites are implemented separately. Chutes and Venice also require their stated transport migrations. |

Before authoring candidates, classify each as implemented ordinary, existing-policy
accepted, elevated/deferred, or unsupported. Preserve all base failures, prerequisite
outcomes, applicable exemptions, and exact selected fields. These capability limits
apply equally to interactive and proposal workflows. They introduce no class flag
or separate policy input. Phase 9 tests each supported typed reason and rejects the rest.

### 5b. Operator decision command and reporting

The normal workflow selects concrete proposed changes, not decision-class names.
Keep the typed inventory internal to validation, serialization, and diagnostics;
operators do not need to learn it to select a firmware or repository change.

```sh
teep cache --model neardirect:example-model --update-whitelist
teep cache --all-models --update-whitelist
```

For additions, fetch and verify current evidence before presenting choices. Offer
existing-decision removal without requiring that collection. Show each eligible
change in plain language, such as “Accept this firmware measurement for Chutes” or
“Accept this TDX module measurement for Chutes,” with the exact value, provider,
target/tier, scope, supporting evidence, retained checks, remaining failures, and
requests eliminated or retained. Chutes examples apply after its required migration.
Show unsupported failures with explanations, but never make them selectable.
Already permitted subjects need ordinary caching, not a new operator decision.

Require explicit selection of concrete changes, a nonempty operator explanation,
and confirmation of the complete policy delta before writing. Accept the explanation
interactively or through `--reason`. Nothing is selected implicitly; an empty
selection or cancellation writes no decisions. Support both explicit model targets
and `--all-models` in interactive and proposal-generation workflows. All-model
selection controls discovery scope; it does not automatically accept failures. Also
present existing in-scope decisions for removal even if discovery fails. A targetless `teep cache --update-whitelist` lists all existing decisions for
removal, including disabled providers and models absent from discovery. Its
`--proposal-out` form supports the same selection for automation. A removal-only
transaction does not require discovery, an active provider, or provider connectivity; report any separately
requested live validation failure without blocking the withdrawal.
Group proposed changes by provider and authenticated subject, show all affected
models, and deduplicate identical decisions only when their trust scope permits it.
Allow explicit bulk selection of the displayed ordinary changes, followed by review
and confirmation of the complete delta. Elevated changes retain their individual
acknowledgements; unsupported failures remain unselectable. Freeze the discovered
targets and exact proposals for review so later discovery cannot silently expand
what is applied. Use the same per-target success and partial-failure rules as other
multi-target cache runs. Do not print inference data or credentials.

Interactive confirmation and proposal application use one policy-application
implementation. Interactive review supplies the in-memory observation validated by
shared collection; an untrusted proposal must first pass the shared current
validation and fresh-evidence requirements below. Neither path adds a retrieval
loop to keep evidence alive while waiting for a human or the file lock. Once an
ordinary decision's observation evaluation completes successfully, its evidence is
historical for policy authoring. Expiry during review has the same consequence as
expiry after writing: later live admission needs currently eligible evidence, while
the observation continues to explain the exact operator choice. Preserve original
times and evidence; policy changes still require the prescribed renewed review.
No persisted validation flag substitutes for proposal validation. Withdrawal-only
operations require no collection. Elevated classes need their own explicit time
conditions before enablement; they introduce no generic refresh scheduler.

For each supported elevated-risk change, require a separate explicit acknowledgement
that describes its concrete consequence and is bound to that selected decision.
Do not require the operator to type internal risk-class names. Reject missing,
unused, or mismatched acknowledgements. Inventory categories whose prerequisites
are not implemented remain unselectable. Do not reuse `--force`: the existing
[debug-only flag](../../cmd/teep/force_debug.go) bypasses enforced factors broadly
and cannot select failures or generate trusted cache state.

For automation, provide a reviewable proposal and explicit apply workflow:

```sh
teep cache --all-models --update-whitelist --proposal-out decisions.yaml
teep cache --update-whitelist --apply-proposal decisions.yaml
```

Targeted proposal generation collects and verifies evidence; withdrawal-only
generation uses existing decisions without discovery. Both leave the cache artifact
unchanged, including TUF state. Any new TUF knowledge remains command-local or is
packaged as untrusted proposal evidence for apply to authenticate. The proposal contains
exact candidate changes, stable identifiers, evidence references and content digests,
provider/target/tier scope, base-policy identity, diagnostic build information, prerequisites, remaining
failures, and request effects. Include explicit selection, explanation, and per-change
risk acknowledgement fields for review; leave selections and acknowledgements unset.
Retain or package the referenced original evidence so apply can validate it. A
proposal is untrusted input, not an authorization or a loadable cache file.

Validate `--proposal-out` before collection. Reject a destination that collides with
the resolved cache, its stable transaction-lock file, or any loaded configuration
file. Compare normalized destinations through safely opened parent directories and
existing file identities, not only argument strings; cover relative paths, hard
links, and symlinks. Reject an existing proposal destination rather than overwrite
it. Use the secure directory/file contract in Section 7, restrictive temporary
files, and atomic publication that fails if the destination already exists. A
competing creator must cause failure, never truncation. Sync successful publication
and report write failures. Proposal generation cannot replace a cache or policy
input even when the operator gives both options the same path.

Include exactly one transaction precondition: existing policy authority/revision/
state digest, or `artifact_precondition: absent` for first use as defined in
Section 2e. Reject mixed or incomplete preconditions. A first-use proposal can be
generated when base-policy failures prevent ordinary preparation; selected additions
must still satisfy all effective-policy prerequisites at apply.

Apply is an explicit noninteractive operation on the reviewed selections. Use strict,
bounded parsing and the shared evaluator. Validate evidence integrity, scope, current
applicable policy, supported decision kinds, and all admission prerequisites under
the current implementation.
Fetch fresh evidence where required; if a subject or relevant failure differs, reject
that selection and require a new proposal. Never substitute newly observed values,
expand selection to additional failures, or accept a stale verification-result flag.
Keep the reviewed historical observation and fresh apply evidence distinct. A new
nonce, quote signature, or eligible collateral version alone is not a changed
decision subject. Compare the reviewed selected values, scope, relevant failures,
and policy; validate the new evidence's own binding and current prerequisites.
The reviewed proposal supplies the resolved targets, including those collected by
`--all-models`; apply does not rediscover or add models. Reject conflicting target flags.
Noninteractive invocation without proposal generation or explicit apply fails with
instructions for this workflow, rather than assuming consent. Proposal generation
may report unresolved failures; successful apply still requires effective-policy
success for each target receiving an addition or a successful evaluation. Selected
withdrawals may commit independently under the policy transaction rules.

Run ordinary checks first, then construct decisions only for selected eligible
failures. Rerun policy evaluation with the exact decisions without suppressing
unrelated failures. If any remaining enforced failure exists, write no additions or software evidence justified solely by that failed target;
shared decisions and withdrawals follow Section 5 transaction rules. Return nonzero with
the unresolved conditions. An operator can therefore TOFU-pin evidence rejected
by the base policy, but cannot export an apparently verified endpoint that still
fails the effective policy. Do not mutate service policy during collection.
Evaluate the selected decisions through the shared policy evaluator with explicit command-local inputs, then export
them. The command must not patch factor results after verification to simulate a
successful effective-policy evaluation.

Store the original failed-check evidence and decision in the artifact. Reuse may
perform the replacement value comparison without repeating the specifically waived
lookup; retain explicit diagnostics instead of fabricating `Pass` for the original
check. If a later live operation observes a different failure, value, signer, or
revocation, it needs its own decision. Service operation never auto-expands pins.

For each implemented decision kind, document whether reuse needs zero retrievals,
current status retrieval, or fresh endpoint evidence. Test this using request
counters as well as factor results. A build update rechecks decision compatibility
locally and reevaluates retained evidence where possible. It must identify any new
retrieval requirement rather than unconditionally refetching everything.

## 6. YAML structure and examples

Use typed lists. Repository names, roles, platforms, and scopes are values, not
predefined field names or record ordinals. The format contains no derived
verification results. Unknown result/approval fields fail strict parsing.

| Collection | Contents and relationship |
| --- | --- |
| `evidence` | Original bytes, kind, and content digest. Optional `source_envelopes` references preserve validated containment without granting trust. |
| `software` | Provider-independent compose/release subjects, exact evidence references, and complete descriptive component membership. Validate membership from original inputs. |
| `verification_material` | Typed collateral, certificates, issuer keys, and trust metadata with original input references and, where required, authenticated retrieval observations. |
| `policy_state` | Stable deployment-policy authority and monotonic revision. Preserve after the last decision is removed. |
| `operator_decisions` | Active exact decisions, named original failures, supporting observed evidence, explanations, and acknowledgements. |
| `trust_state` | Per-TUF-authority accepted signed metadata references, retained independently of software for rollback protection. |

Evidence references use `sha256:<hex>` over exact bytes and resolve uniquely.
Duplicate/conflicting evidence records fail import; writers deduplicate identical
bytes. Role-specific names and encodings belong on input references, so one object
can serve multiple roles. No YAML anchors, relative paths, or display names carry
identity. Optional containment references must be validated through the production
parser; exclude ineligible envelopes rather than redact signed inputs.

Software records contain `subject`, `evidence`, and `components`. A component has
`role`, `artifact`, and `evidence`; release components also state `required_binding`.
For compose, the subject digest covers exact `app_compose` bytes. For a release set,
hash `teep:release-set:v1\n` followed by RFC 8785 JSON of complete component `role`,
`artifact`, and `required_binding` values sorted by canonical bytes. Reject duplicate
identities. Policy, provider, timestamps, outcomes, and the resulting digest itself
are excluded. The parser/verifier establishes actual membership and binding; fields
cannot assert a release or image was authenticated. Multiple evidence candidates
may support one subject, within bounds; each selected candidate must verify.

`verification_material` records contain `subject` and `inputs`, plus `retrieval`
only for authenticated-retrieval material. For a material set, hash
`teep:material-set:v1\n` and canonical kind/applicability fields and complete named
input references, including header roles/encodings; exclude the resulting digest
and retrieval observations. Single-object subjects hash
original bytes. Material dependencies use exact typed subject selectors; embedded
roots and configured origins are selected by the current verifier, not installed
by YAML declarations. A configured URL is never a new trust root.

Complete-set evaluation covers membership/binding plus each component's identity
and current policy on every new admission. Changing B's signer rule or decision
does not require downloading A's unchanged eligible evidence, but both components
are evaluated locally. No policy hashes or result flags on software/material
records can substitute for current evaluation after import.

Writers merge evidence and descriptive references by exact intrinsic subject and
input identity. Revalidate conflicting associations rather than select a newer
assertion. Authenticated-retrieval observations retain the origin and original time;
identical bytes observed on two occasions must not acquire a fabricated combined
observation. Preserve the actual selected observation and apply current eligibility.
Current policy and TUF state have their separate transaction rules. Sort output
for review, with encoded evidence last; presentation order has no trust meaning.

For mutable authenticated-retrieval material, retain one current observation per
configured authority and material kind, separately from historical evidence bytes.
The `verification_material` list contains at most one JWKS or CT record for each
such selector. Superseded inputs needed by a decision remain in `evidence` and its
historical references, not as additional selectable `verification_material` records.
Select that observation when evaluating material for a token or an uncached
certificate check; never search older
JWKS or CT lists for one that makes verification succeed. A successfully validated
refresh supersedes the owner's previous observation, including removal of keys or
logs. Concurrent refresh/import publication uses the owner's operation identity.
Delayed work cannot restore a superseded observation. CT certificate-check results
retain their separate one-hour lifetime as specified below; replacing log-list
material does not retroactively invalidate those results.

File merge selects the latest eligible authenticated retrieval observation by its
original retrieval time, not by content digest or signature success. Apply the clock
checks below before considering an incoming observation; an ineligible future time
cannot supersede current state. Equal timestamps with different bytes are ambiguous
and fail the merge. Identical bytes may have multiple genuine observations, but the
selected time must belong to an actual authenticated retrieval. An older writer
cannot replace the selected observation. This ordering relies on the deployment's
clock discipline; retrieval times are not issuer-signed versions or proof of global
publication order. Authorities with signed versions use their typed version rules.

Keep the selected observation as the sole current candidate even after expiry;
expiry requires authenticated refresh or failure, never selection of historical
bytes. Protect the current observation and its bytes from capacity collection while
eligible so a delayed writer cannot revive an earlier still-eligible version.
After expiry, capacity collection may remove that material root entirely, causing
a normal retrieval miss; historical observations cannot be promoted and expired
incoming observations cannot populate a current root.
Historical dependencies of decisions are not current material roots. Import and
restart preserve this distinction without creating endpoint authorization epochs.

Section 6a is the complete NearCloud structural example, covering separate model
and gateway compose and shared dependencies. Its payload/digest placeholders are
not deployable values: fixtures replace them with exact original bytes and computed
digests. Every reference is included. Current policy determines required checks,
including `NoDSSE` and compose-only handling; the YAML cannot waive a query or check.
Other providers use the same shape, with differences listed after that example.

### Material selection and dependency coverage

`verification_material` is a typed list, not a generic HTTP response cache. Each
record has `subject` and `inputs`, with typed `retrieval` observations where required. Its kind defines the required
subject fields, input roles, checks, and eligibility rules. A collateral set's digest
covers its canonical complete input membership with a versioned, kind-specific
encoding; a single-object subject uses the original content digest. FMSPC, CA,
product/HWID/TCB, issuer, or authority are applicability fields, not user-defined
record names. Recompute them from authenticated material. Fresh quote/token/TLS
inputs select eligible records through the shared production verifier. A matching
lookup key alone never authenticates a new report, key, or connection.

`inputs` names each original evidence object by digest, including certificate chains
returned in HTTP headers. Preserve each original header name and value and its
percent-encoded-PEM representation. A typed decoder reconstructs the expected
getter headers; do not replace them with a generic merged certificate blob.
The `intel_issuer_chain_header` evidence kind stores only the original header-value
bytes and their digest. Each `inputs.issuer_chains` reference carries `evidence`,
`header_name`, and `encoding: percent_encoded_pem`. The containing material digest
covers these role/name/encoding associations as well as the referenced byte digests.
One byte object can serve several header names: the captured TCB-information and
QE-identity issuer-chain values are identical. Preserve both associations without
duplicating the evidence object. The typed adapter validates the association and
actual chain, rather than trusting a header name. No payload placeholder implicitly includes other evidence
objects. Required signed bundles retain their complete original representation;
additional roots, metadata, and chains use explicit references. Each typed adapter
must reject incomplete inputs and resolve cached dependencies under current policy.
A material record's descriptive applicability must agree with authenticated inputs.
The owning verifier supplies current embedded trust roots and configured origins.
Original evidence remains deduplicated; adapters supply inputs to existing owners,
not a second authorization store. Fresh and retained evidence use the same verifier.

### Signed and authenticated-retrieval time

Eligibility is a typed verifier obligation, not a YAML override or cached verdict. Signed validity, versions, and revocation data
come from the original inputs. Recheck them at new admission with the real clock.
For authenticated-retrieval material such as JWKS and the CT log list, preserve the
original retrieval time through trusted export/import and apply the current issuer
or log-list refresh rules. Preserve NVIDIA's key-rotation refresh behavior. Import
must not extend the current time-based eligibility window or supply a timeless
key authorization. Incompatible new policy, expired metadata, or an unknown key
requires the existing retrieval or rejection path. These constraints do not add
expiry to an already published endpoint authorization.

For authenticated-retrieval ages, allow at most 10 seconds of future clock skew.
A `retrieved_at` more than 10 seconds ahead of the admission clock makes that object
ineligible; obtain current material through its normal authenticated retrieval path
or fail the required check. For a future time within that allowance, use age zero.
The remaining lifetime is at most the type's normal TTL; do not add an expiry grace
period or rewrite the stored timestamp. Existing signed-evidence and NRAS time rules
remain unchanged; this allowance does not override certificate or TUF expiry.

On import or acquisition, establish a process-local monotonic deadline from the
remaining lifetime. Later eligibility must satisfy both that deadline and the
wall-clock age/skew checks. A backward clock adjustment cannot extend that deadline;
a larger rollback makes the object ineligible under the future-time rule. Repeat
these checks at each new admission that uses the material, without introducing an
expiry on a published endpoint authorization. Across restart, the trusted original
timestamp and the new process clock determine eligibility; no monotonic time is
serialized. Test future timestamps just inside/outside 10 seconds, exact TTL expiry,
replica clock differences, and backward/forward adjustments with an injected clock.

### CT and Sigstore dependency coverage

CT material must prefill every relevant CT checker, including dependency-owned
clients; loading it into only the inference client cannot establish zero CT HTTP
requests. Continue live WebPKI, TLS identity, and SCT validation.

The TLS CT guarantee in this plan is local SCT signature validation using known
log public keys. The downloaded log list describes log identities and keys, not
the certificates contained in their append-only trees. This pathway does not
retrieve or verify certificate Merkle inclusion proofs and must not report
independently verified inclusion or equivalence to Chrome's complete CT policy.
Stronger CT verification, including log trust policy, authenticated tree heads,
inclusion and consistency proofs, and merge-delay/admission semantics, is separate
work. It is not a prerequisite for this cache implementation and adds no requests
to this plan's budgets. This distinction concerns TLS CT, not existing required
Rekor or Sigstore transparency checks.

Preserve the existing two cache lifetimes: successful host/certificate SCT checks
remain reusable for one hour, and log-list material has a 24-hour lifetime, subject
to the authenticated-retrieval time rules above. Certificate-check results remain
process-local and are not exported. A valid result can satisfy a subsequent
connection's CT check even after log-list refresh or import; replacement does not
retroactively invalidate that result. A check already using the previous list may
finish and publish its normally bounded certificate-check result without restoring
that list as current material. An uncached check selects the current eligible list.
Cache hits do not renew either lifetime.

Expiry alone schedules no work. After certificate-result expiry, a subsequent
connection repeats local SCT verification; it retrieves log-list material only
when that material is missing or ineligible. Expiry and metadata replacement do
not recheck, terminate, or renew established HTTP/2 connections or endpoint
authorizations. Every new connection still performs its required WebPKI and
attested-identity checks. Do not add certificate-result invalidation machinery to
make metadata replacement immediate in this plan.

Sigstore material must cover the root transition chain from the current build's bootstrap root,
timestamp/snapshot/targets and any delegated metadata needed for the selected trust
target. Retain every required transition and delegated metadata object as a typed input.
Run existing TUF signature, expiry, version, target-hash, and rollback checks locally;
a root update may require additional evidence. Neither TUF nor CT prefill may weaken
bootstrap authentication to avoid a request.

Local Sigstore metadata evaluation uses the pinned go-tuf `trustedmetadata` API:
create a fresh session for each evaluation or refresh, initialize from the build's
bootstrap root, apply each consecutive `UpdateRoot`,
then `UpdateTimestamp`, `UpdateSnapshot(..., false)`, and
`UpdateDelegatedTargets` for targets and each required delegation. Verify target
length/hashes before `root.NewTrustedRootFromJSON` and normal bundle verification.
Set the session's `RefTime` from the current admission clock, never the capture
time. Do not reuse a session's construction-time clock across admissions. Compare incoming
versions with the resolver-owned [trusted version state](#tuf-trusted-version-state);
a fresh verifier instance alone does not provide historical rollback protection.

This evaluates a retained signed metadata snapshot within its validity bounds; it
does not establish that no newer root or timestamp exists. Do not synthesize a 404
for an absent next-root file. The regular updater probes for newer roots and the
Sigstore wrapper refreshes by default; `DisableLocalCache` does not disable retrieval.
Neither `ForceCache` nor `UnsafeLocalMode` is the cache adapter. On expired, missing,
incompatible, or revoked-by-current-policy material, run bounded authenticated live
refresh through an injected fetcher and retain the complete returned graph. Keep
that fetcher isolated from ambient `$HOME/.sigstore` state and from other deployments.
Local verification provides the snapshot's bounded validity, not immediate awareness
of every upstream trust change. An online newest-metadata check would add requests
to the zero-TUF budget. Withdrawal and restart responsibilities follow the
[trusted version-state contract](#tuf-trusted-version-state).

The NearCloud example uses two quote-derived TCB-information objects and shared
QE/CRL inputs. NearDirect can use the backend evidence under its own policy. Neither
a saved quote nor NRAS/PoC response answers a new challenge. Embedded Rekor keys and
NVIDIA device-identity roots add no retrievals; no independent portable NVIDIA RIM
verifier is assumed. Scenario budgets remain in Section 4d.

### TUF trusted version state

The verifier owns an immutable per-authority set of supported historical bootstrap
anchors as well as its current bootstrap. An ordinary bootstrap advancement retains
the historical anchors required to authenticate supported checkpoints; these anchors
authenticate historical knowledge only and cannot make an old snapshot currently
eligible. Identify anchors by exact root digest. Artifact references select an
already supported anchor, never install a root supplied by YAML. Authenticate the
consecutive forward chain from that anchor and check any overlap with the current
bootstrap by exact content identity. Never attempt to authenticate an older root
by running root updates backwards from a newer bootstrap.

Current-material sessions start from the current bootstrap and honor restored
rollback knowledge and authenticated key-rotation resets. If the retained root is
newer, authenticate its forward transitions before selecting current material; if
the build bootstrap is newer, reconcile the intervening authenticated transitions
before resetting any role knowledge. Missing transitions require bounded retrieval
outside the file lock or explicit failure, not checkpoint deletion. A complete
retained chain permits local reconciliation without a new request.

Withdrawal of a historical anchor is an explicit trust-policy change, not an
incidental consequence of updating the bootstrap version. Unsupported or withdrawn
historical dependencies fail with the authority and required anchor identified.
Before rollout, the trusted preparation/deployment path must produce a checkpoint
authenticated under supported anchors while preserving every applicable rollback
bound, or complete the authenticated rotation that permits its reset. If that cannot
be established, rollout remains blocked; do not clear state or recreate policy
authority. Document retained anchors and withdrawals beside the verifier's roots.

`trust_state` retains TUF rollback knowledge separately from reusable software.
Each entry identifies the configured TUF authority and references its last accepted
root, timestamp, snapshot, and targets/delegated-role metadata by evidence digest.
Its `bootstrap_anchor` is the exact digest of the supported verifier-owned historical
root that authenticates the retained chain; it grants no authority to file bytes.
Role names are explicit on references. Derive versions and hashes from those signed
bytes; do not accept unsigned version counters. The current verifier authenticates
the root chain from a supported verifier-owned anchor and validates these associations.
Policy revision is independent of TUF updates. Root is required; other roles are present only when
accepted and not reset by authenticated key rotation. A partial update can retain
accepted roles from different update attempts: this records rollback knowledge,
not a complete usable trust snapshot. Reuse still needs a mutually consistent,
currently eligible dependency set. Expired signed metadata can retain version
knowledge while being ineligible for admission; it must not prevent normal refresh.

The injected TUF resolver owns one bounded, synchronized state per authority. Check
new metadata against that state with the pinned library's update rules. Advance
accepted roles at the library's trust transition, even if a later target download or
endpoint admission fails. This is trust-state maintenance, not a successful target
export. Keep the root transitions needed to authenticate the retained state. Root
rotation must apply the library's timestamp/snapshot-key reset rules; do not take a
numeric maximum across different key epochs. Same-version conflicting content is
an error, not a choice of the newer writer.

Allow one active authenticated refresh per authority per service/command owner.
Coalesce refresh callers through the shared bounded retrieval coordinator; one
caller's cancellation does not cancel work needed by others. Admissions may evaluate
immutable retained snapshots concurrently, with fresh local verification sessions.
They do not each start a competing refresh. Keep network I/O outside the authority
mutex and recheck the authoritative state before completing an evaluation. Imports
and cross-process file writers still require transition reconciliation; this rule
reduces in-process refresh races without weakening those checks. Reevaluation is
bounded by the admission deadline and must not become an unbounded retry loop.

The resolver's retained rollback knowledge is separate from each mutable
`trustedmetadata.TrustedMetadata` session. The pinned API rejects root updates
after timestamp loading and timestamp updates after snapshot loading. An expired
timestamp prevents snapshot loading; a newer timestamp can also reject an older
snapshot's hashes. Therefore the usable-snapshot sequence above is not the restore
algorithm for a partial checkpoint, and a long-lived session is not the authority
store. Define and test the following restore/refresh boundary before the rest of
the Phase 5a checkpoint implementation, before Phase 5b's current-material adapter:

1. Authenticate the retained root chain from its supported verifier-owned historical
   anchor and reconcile it with the current bootstrap under the rules above.
   Each retained role reference includes its authenticating root/key epoch and
   the parent metadata needed to establish its accepted signature, hash, and
   version relationships. Preserve these dependencies even when a later accepted
   timestamp references a snapshot that was not downloaded. Delegated roles retain
   their authenticated delegation context. Schema fields cannot assert acceptance.
2. Restore historical rollback knowledge by verifying those original signatures
   and relationships with the pinned library's verification primitives. Expired
   metadata can establish only historical version knowledge; do not backdate the
   clock, clear the checkpoint, or treat it as currently eligible evidence. Do not
   pass `isTrusted=true` merely because bytes came from YAML. A missing dependency
   or invalid signature fails restore; expiry alone does not prevent live refresh.
3. Start a fresh session for the candidate current snapshot. Check its versions
   and same-version content against the restored knowledge, using the library's
   root-key rotation/reset rules. Perform normal signature, expiry, parent-hash,
   version, and target checks. Historical role restoration cannot authorize a
   current target. Reset only the roles permitted by authenticated key rotation.
4. Capture each accepted transition even when an update method returns an error
   after accepting intermediate metadata. Inspect the resulting authenticated
   state and classify the error; a non-nil error is never admission success, and
   an error before acceptance produces no transition. Publish transitions under
   the authority lock, reconciling against changes by other sessions. Fetch outside
   that lock. Recheck current authority state before completing the material
   evaluation; reject or reevaluate an incompatible candidate. This does not
   invalidate an already published endpoint authorization.

Use separate helpers for checkpoint authentication, session construction, transition
reconciliation, and current target eligibility. Keep the pinned library's checks;
do not implement a second TUF signature verifier or silently drop historical roles
to make a session load. File transactions use the same authenticated transition
reconciliation without network I/O.

Retain a minimal authenticated checkpoint, not an update history. Its roots are the
last accepted root and applicable last accepted role metadata, including rollback
bounds known from accepted parent metadata even when a child download failed.
Retain each root's signature/hash/delegation dependencies and any separate metadata
required by a currently usable snapshot or decision. After a reconciled transition,
collect superseded objects only when this complete closure no longer needs them.
Do not retain every timestamp or snapshot merely because it was once accepted.
Do not drop an absent delegated role's rollback knowledge unless the library's
authenticated transition rules permit that reset.

Represent consecutive root transitions as an ordered, bounded list, not recursively
nested records. Allow at most 256 root objects per authority, subject also to the
artifact byte/record limits. This list has an explicit sequential-work bound; its
length is not dependency depth. All other dependency traversal retains Section 7's
depth bound. Start a retained chain at a later verifier-owned supported anchor only
when every retained historical relationship and applicable rollback bound remains
authenticated. Old contexts needed by decisions or partial checkpoints remain.

If the minimal protected closure exceeds capacity, fail persistence with required
bytes, records, root count, and limiting dependency identified. A bounded writer
must not repeatedly retry an unchanged capacity failure. Recovery uses a trusted
preparation run to remove explicitly selected decisions or replace superseded
dependencies where safe. If irreducible state still exceeds limits, deploy a verifier
with reviewed larger bounds or suitable supported anchors, then prepare and validate
the replacement. Preserve policy authority/revision and all non-reset rollback bounds;
file deletion, unsigned counters, and silently discarded history are not recovery.

Ordinary `cache`, explicit policy apply, and `serve --autocache` merge accepted
state under the file transaction lock. `verify`, proposal generation, and ordinary
`serve` are read-only artifact consumers. Revalidate
an incoming transition against the authoritative retained state before committing;
a delayed older snapshot cannot replace newer accepted state or combine roles into
an unauthenticated graph. If the transition cannot be reconciled, reject that update
and preserve current state. No network work occurs under the file lock. Garbage
collection retains the signed metadata and root chain referenced by `trust_state`,
independently of software references. Capacity exhaustion fails persistence visibly;
it cannot erase rollback knowledge to make room.

Read-only consumers initialize from the deployment's trusted artifact and retain
newly learned state in memory until exit. They do not persist it. After restart,
rollback protection starts at the deployed state, not at versions learned only by
the previous process. The same limit applies to uncommitted autocache updates after
a crash or write failure. Operators who require fleet-wide restart protection must
distribute an updated artifact from a writable preparation run and prevent artifact
rollback. Reports distinguish loaded, in-memory, and durably committed trust state;
the plan does not promise cross-restart knowledge that was never committed.

Test older-after-newer updates, concurrent writers, same-version conflicts, partial
updates followed by target failure, authenticated root-key rotation/reset, evidence
collection, restart after committed refresh, and restart of a read-only consumer.
Include acceptance of a new timestamp followed by snapshot-download failure,
persistence, restart after timestamp expiry, and successful authenticated refresh
that still rejects rollback of previously accepted delegated-role versions. Test
two successive refreshes in one process, expiry while the owner remains alive,
errors before versus after a trust transition, and a refresh or import advancing
the authority while an older material evaluation completes. Concurrent refresh
requests must share one operation, including its failure and cancellation handling.
Use the pinned library's trusted metadata rules in both local and live paths.
Exercise thousands of timestamp/snapshot replacements and repeated partial failures;
retained size must follow the necessary dependency closure rather than update count.
Test root chains at and beyond the 256-object bound, anchor-based collection,
delegated-role knowledge, restart, protected overflow, and recovery with unchanged
policy authority and rollback bounds.

### 6a. Near cloud: complete evidence example

This example retains four model and seven gateway components. Membership comes
from each exact compose. Shared OpenTelemetry provenance and identical TCB/QE
issuer-chain bytes occur once in `evidence`; both header-name associations remain
in each material's inputs. A compose-only component has no provenance input here,
but current policy, not an empty list, determines whether more evidence is required.
NearCloud does not use TUF in this example, so `trust_state` is empty. The CT origin
must match the current checker configuration. The illustrative retrieval times do
not make old material currently eligible. Fresh gateway/model binding, NRAS, PoC,
and live TLS/E2EE work remain outside the portable file.
The model's `compose-manager` entry identifies the authenticated literal default
in its image expression. It does not establish the contents of a runtime override;
preserve the NEAR deployment-binding limitation specified in Section 2b-i.

```yaml
schema_version: 1
policy_state:
  authority: "<deployment policy authority>"
  revision: 0
operator_decisions: []
trust_state: []
software:
  - subject:
      kind: "compose"
      digest: "sha256:<model compose>"
      encoding: "app_compose_json"
    evidence:
      - "sha256:<model compose>"
    components:
      - role: "container_image"
        artifact:
          repository: "nearaidev/compose-manager"
          digest: "sha256:<nearaidev/compose-manager image>"
        evidence:
          - "sha256:<nearaidev/compose-manager provenance>"
      - role: "container_image"
        artifact:
          repository: "nearaidev/compose-manager-launcher"
          digest: "sha256:<nearaidev/compose-manager-launcher image>"
        evidence:
          - "sha256:<nearaidev/compose-manager-launcher provenance>"
      - role: "container_image"
        artifact:
          repository: "certbot/dns-cloudflare"
          digest: "sha256:<certbot/dns-cloudflare image>"
        evidence: []
      - role: "container_image"
        artifact:
          repository: "otel/opentelemetry-collector-contrib"
          digest: "sha256:<otel/opentelemetry-collector-contrib image>"
        evidence:
          - "sha256:<otel/opentelemetry-collector-contrib provenance>"
  - subject:
      kind: "compose"
      digest: "sha256:<gateway compose>"
      encoding: "app_compose_json"
    evidence:
      - "sha256:<gateway compose>"
    components:
      - role: "container_image"
        artifact:
          repository: "nearaidev/cloud-api"
          digest: "sha256:<nearaidev/cloud-api image>"
        evidence:
          - "sha256:<nearaidev/cloud-api provenance>"
      - role: "container_image"
        artifact:
          repository: "nearaidev/cvm-ingress"
          digest: "sha256:<nearaidev/cvm-ingress image>"
        evidence:
          - "sha256:<nearaidev/cvm-ingress provenance>"
      - role: "container_image"
        artifact:
          repository: "nearaidev/dstack-vpc"
          digest: "sha256:<nearaidev/dstack-vpc image>"
        evidence:
          - "sha256:<nearaidev/dstack-vpc provenance>"
      - role: "container_image"
        artifact:
          repository: "nearaidev/dstack-vpc-client"
          digest: "sha256:<nearaidev/dstack-vpc-client image>"
        evidence:
          - "sha256:<nearaidev/dstack-vpc-client provenance>"
      - role: "container_image"
        artifact:
          repository: "datadog/agent"
          digest: "sha256:<datadog/agent image>"
        evidence:
          - "sha256:<datadog/agent provenance>"
      - role: "container_image"
        artifact:
          repository: "alpine"
          digest: "sha256:<alpine image>"
        evidence:
          - "sha256:<alpine provenance>"
      - role: "container_image"
        artifact:
          repository: "otel/opentelemetry-collector-contrib"
          digest: "sha256:<otel/opentelemetry-collector-contrib image>"
        evidence:
          - "sha256:<otel/opentelemetry-collector-contrib provenance>"
verification_material:
  - subject:
      kind: "intel_tdx_collateral"
      digest: "sha256:<model canonical collateral set>"
      fmspc: "<model FMSPC>"
      pck_ca: "processor"
      api_version: 4
    inputs:
      tcb_info: "sha256:<model TCB information>"
      qe_identity: "sha256:<Intel QE identity>"
      pck_crl: "sha256:<Intel PCK CRL>"
      root_ca_crl: "sha256:<Intel root CA CRL>"
      issuer_chains:
        - evidence: "sha256:<shared TCB and QE issuer chain>"
          header_name: "Tcb-Info-Issuer-Chain"
          encoding: "percent_encoded_pem"
        - evidence: "sha256:<shared TCB and QE issuer chain>"
          header_name: "Sgx-Enclave-Identity-Issuer-Chain"
          encoding: "percent_encoded_pem"
        - evidence: "sha256:<PCK CRL issuer chain>"
          header_name: "Sgx-Pck-Crl-Issuer-Chain"
          encoding: "percent_encoded_pem"
  - subject:
      kind: "intel_tdx_collateral"
      digest: "sha256:<gateway canonical collateral set>"
      fmspc: "<gateway FMSPC>"
      pck_ca: "processor"
      api_version: 4
    inputs:
      tcb_info: "sha256:<gateway TCB information>"
      qe_identity: "sha256:<Intel QE identity>"
      pck_crl: "sha256:<Intel PCK CRL>"
      root_ca_crl: "sha256:<Intel root CA CRL>"
      issuer_chains:
        - evidence: "sha256:<shared TCB and QE issuer chain>"
          header_name: "Tcb-Info-Issuer-Chain"
          encoding: "percent_encoded_pem"
        - evidence: "sha256:<shared TCB and QE issuer chain>"
          header_name: "Sgx-Enclave-Identity-Issuer-Chain"
          encoding: "percent_encoded_pem"
        - evidence: "sha256:<PCK CRL issuer chain>"
          header_name: "Sgx-Pck-Crl-Issuer-Chain"
          encoding: "percent_encoded_pem"
  - subject:
      kind: "nvidia_jwks"
      digest: "sha256:<NVIDIA JWKS>"
      authority: "https://nras.attestation.nvidia.com/.well-known/jwks.json"
    inputs:
      jwks: "sha256:<NVIDIA JWKS>"
    retrieval:
      origin: "https://nras.attestation.nvidia.com/.well-known/jwks.json"
      retrieved_at: "2026-09-13T00:00:00Z"
  - subject:
      kind: "ct_log_list"
      digest: "sha256:<CT log list>"
      authority: "chrome_ct_log_list"
    inputs:
      log_list: "sha256:<CT log list>"
    retrieval:
      origin: "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
      retrieved_at: "2026-09-13T00:00:00Z"
evidence:
  - digest: "sha256:<model compose>"
    kind: "compose"
    payload_base64: "<complete original model compose bytes>"
  - digest: "sha256:<nearaidev/compose-manager provenance>"
    kind: "rekor_provenance"
    payload_base64: "<complete original nearaidev/compose-manager provenance bytes>"
  - digest: "sha256:<nearaidev/compose-manager-launcher provenance>"
    kind: "rekor_provenance"
    payload_base64: "<complete original nearaidev/compose-manager-launcher provenance bytes>"
  - digest: "sha256:<otel/opentelemetry-collector-contrib provenance>"
    kind: "rekor_provenance"
    payload_base64: "<complete original otel/opentelemetry-collector-contrib provenance bytes>"
  - digest: "sha256:<gateway compose>"
    kind: "compose"
    payload_base64: "<complete original gateway compose bytes>"
  - digest: "sha256:<nearaidev/cloud-api provenance>"
    kind: "rekor_provenance"
    payload_base64: "<complete original nearaidev/cloud-api provenance bytes>"
  - digest: "sha256:<nearaidev/cvm-ingress provenance>"
    kind: "rekor_provenance"
    payload_base64: "<complete original nearaidev/cvm-ingress provenance bytes>"
  - digest: "sha256:<nearaidev/dstack-vpc provenance>"
    kind: "rekor_provenance"
    payload_base64: "<complete original nearaidev/dstack-vpc provenance bytes>"
  - digest: "sha256:<nearaidev/dstack-vpc-client provenance>"
    kind: "rekor_provenance"
    payload_base64: "<complete original nearaidev/dstack-vpc-client provenance bytes>"
  - digest: "sha256:<datadog/agent provenance>"
    kind: "rekor_provenance"
    payload_base64: "<complete original datadog/agent provenance bytes>"
  - digest: "sha256:<alpine provenance>"
    kind: "rekor_provenance"
    payload_base64: "<complete original alpine provenance bytes>"
  - digest: "sha256:<model TCB information>"
    kind: "intel_tcb_info"
    payload_base64: "<complete original model TCB information bytes>"
  - digest: "sha256:<Intel QE identity>"
    kind: "intel_qe_identity"
    payload_base64: "<complete original Intel QE identity bytes>"
  - digest: "sha256:<Intel PCK CRL>"
    kind: "x509_crl"
    payload_base64: "<complete original Intel PCK CRL bytes>"
  - digest: "sha256:<Intel root CA CRL>"
    kind: "x509_crl"
    payload_base64: "<complete original Intel root CA CRL bytes>"
  - digest: "sha256:<shared TCB and QE issuer chain>"
    kind: "intel_issuer_chain_header"
    payload_base64: "<complete original shared TCB and QE issuer chain bytes>"
  - digest: "sha256:<PCK CRL issuer chain>"
    kind: "intel_issuer_chain_header"
    payload_base64: "<complete original PCK CRL issuer chain bytes>"
  - digest: "sha256:<gateway TCB information>"
    kind: "intel_tcb_info"
    payload_base64: "<complete original gateway TCB information bytes>"
  - digest: "sha256:<NVIDIA JWKS>"
    kind: "jwk_set"
    payload_base64: "<complete original NVIDIA JWKS bytes>"
  - digest: "sha256:<CT log list>"
    kind: "ct_log_list"
    payload_base64: "<complete original CT log list bytes>"
```

### 6b. Other provider mappings

NearCloud covers the NearDirect evidence shape, but not its authorization scope.
Use the same typed records with these differences; do not duplicate the schema.

| Consumer | Evidence and current evaluation |
| --- | --- |
| NearDirect | Select backend compose/components and applicable collateral from the same shape as 6a. Evaluate under NearDirect policy and freshly bind the selected backend TLS peer/model key. No gateway authorization is inherited. |
| Tinfoil direct | Retain a complete release set: code and, for TDX, hardware-reference components with authenticated measurement relationships. `sigstore_trust_material.inputs` includes `root_chain`, `timestamp`, `snapshot`, `targets`, optional named delegations, and `trusted_root`; each refers to original bytes. Include applicable CPU collateral and TUF `trust_state`. |
| Tinfoil cloud | Retain the SEV router release, matching VCEK, and Sigstore/TUF inputs. Embedded AMD signing chains are verifier-owned. Do not add backend software/GPU claims. |
| Venice ACI/1, after migration | Retain gateway compose/components and supported custody/keyset inputs. Current compose-only policy grants no image-signature success; absent model evidence stays absent. |
| Venice dstack / Chutes, after migration | Use only independently supported evidence kinds and scopes from the capability table. Chutes consumable request nonces are never portable. |

Identical subjects can serve several consumers. Evidence has no inherited provider
approval; the current evaluator computes each consumer's checks, decisions, and
exemptions. A policy exception for one consumer cannot satisfy another's checks.
Provider scenarios and request budgets remain separate in Section 4d.

### 6c. Operator decision fragment

This fragment extends the same artifact with one reviewed decision. Its evidence
reference must resolve to the complete original observation and verification inputs.
Store the selected failure and observation context, not historical `pass` fields.
Current decision compatibility and fresh admission checks remain mandatory.

```yaml
policy_state:
  authority: "<deployment policy authority>"
  revision: 1
operator_decisions:
  - scope:
      provider: neardirect
      evidence_format: near
      tier: model
    kind: measurement
    subject:
      platform: intel_tdx
      measurements:
        mrseam: "<observed MRSEAM>"
        mrtd: "<observed MRTD>"
    replaces_failure: measurement_not_listed
    action: pin_observed_value
    observation:
      base_policy: "sha256:<reviewed base measurement policy>"
      client_nonce: "<original client-generated challenge>"
      evidence:
        - "sha256:<complete original observation inputs>"
      observed_at: "2026-09-13T00:00:00Z"
    reason: Operator accepts this observed measurement configuration.
    decided_at: "2026-09-13T00:01:00Z"
    risk_acknowledgements: []
```

The correlated match selects MRTD and MRSEAM only; unselected registers keep their
existing policy. No signature, nonce, REPORTDATA, or unrelated failure is waived.
Decision identity is the digest of its canonical complete record. Withdrawal removes
it from the active list and advances policy revision, without a tombstone. Original
observations explain the decision; they cannot answer a new admission challenge.

## 7. Storage, parsing, and concurrency

Use bounded, strict YAML decoding. Reject unknown or missing required fields,
duplicates, null required values, invalid identifiers, unsupported schema versions,
multiple documents, cycles, aliases, and ambiguous references. Initial implementation
limits are 64 MiB encoded file size, 48 MiB total decoded evidence, 16 MiB per decoded
evidence object, 65,536 records, nesting depth 32, and dependency depth 16; lower
existing kind-specific parser/network bounds still apply. Check bounds while reading
and before allocating decoded payloads. Consecutive TUF root transitions use the
separate 256-object ordered-list bound in Section 6, not recursive dependency depth;
their bytes and records still count against the artifact totals. These cover the sampled sub-MiB artifacts
without promising unlimited model coverage; all-model selection remains supported,
and an oversized explicit write fails with a size diagnostic rather than dropping
policy or required evidence. Exercise the maximum allowed artifact and parallel
loads in storage tests. Bound file size,
object count, decoded payload size, nesting, and reference traversal. Dispatch
evidence kinds explicitly; reject unsupported kinds. Parse embedded JSON through
`internal/jsonstrict`. Low-level parsers return unknown field names to the caller.

Validate digests against retained bytes and compare cryptographic values in
constant time. Require descriptive subjects and input roles to agree with original evidence
through typed validation. Reject derived approval fields and incomplete graphs;
never drop a malformed entry and continue with the rest. Portable records cannot
define report factors or exempt a check.

Validate ownership, restrictive permissions, regular-file type, and absence of
symlinks for cache paths. Use safe file opening and replacement
to prevent path substitution between validation and access. No group/world writable
trust files. Treat read-only image-layer files as deployment inputs with equivalent
integrity guarantees. Preserve complete evidence on export; URLs alone are not an
offline artifact. YAML comments may be regenerated rather than preserved.

On supported POSIX systems, accept regular trust files owned by the effective user
or root, with no group/world write permission. Read permission is not policy-write
authority; public evidence may be deployed read-only by root for an unprivileged
consumer. Require every containing directory from a trusted ancestor to the file
to be root- or effective-user-owned and not group/world writable. A sticky writable
directory is not a trusted policy directory. Newly created private directories use
mode 0700 and writer-created files use mode 0600. Validate the same ownership and
directory rules for proposal output and the stable lock file.

Resolve and access paths through validated directory handles without following
symlinks, and perform replacement relative to the retained parent handle. Reject
multiply linked cache/lock files for writing so path aliases cannot create separate
transaction locks for one input. Create the lock safely if absent, validate it if
present, and never unlink it during normal operation. Cooperating writers must use
the same stable destination and lock; deployment must not replace the lock inode.
Test substitution of parent directories and lock files in addition to the final
artifact, and verify that unsafe paths fail before any trust-file modification.

Writable operation requires a local filesystem with the tested cross-process lock,
atomic rename, file sync, and directory sync semantics. Network/distributed writable
filesystems are outside initial support; do not claim those durability guarantees
for them. Read-only image-layer or mounted regular-file deployment remains supported
when it satisfies the integrity rules. Symlink-based configuration projections are
not supported: deploy a regular file in a trusted directory or mount instead. A
trusted deployment agent must enforce rollback prevention and coordinate replacement
with writers; permissions alone do not identify an older valid artifact.

Put validated import, immutable export, and source-independent admission interfaces
beside the shared data-management code. Keep filesystem decoding and locking outside
request handlers. Reuse existing runtime synchronization, authorization capacity,
generation ownership, and cancellation semantics rather than wrapping them in a
competing cache. Coordinate prefill and live publication under the same ownership
rules: imported inputs cannot overwrite a newer runtime authorization or bypass
an invalidation; any new authorization requires fresh admission. Perform disk and network I/O outside the runtime store mutex; recheck
publication eligibility under synchronization before publishing the result.

A software snapshot exports a complete evidence graph for each successful set.
Accepted TUF transitions export their separate complete trust-state dependencies. Canonicalize
set membership independently of presentation order; reject duplicate component
identities, ambiguous software selectors, and evidence-digest/content conflicts.
Do not bind parser behavior to the illustrated repositories or collection positions.
Autocache merges raw component evidence without combining different compose versions
into a configuration never observed. Current evaluation establishes consumer scope,
component policy, and complete-set coverage. Adding/removing a component
changes set identity; unchanged components remain reusable. Preserve evidence used
by any retained set. Whitelist proposals name the exact component and affected sets;
a decision for one repository cannot waive a sibling's provenance failure.

Use immutable snapshots for published entries. Keep mutable state on constructed
stores, not package globals. Bound entries, retained evidence bytes, and concurrent verification work. Use
reference-aware collection of unneeded evidence, preserving
active decisions and required dependencies. If safe collection cannot make room,
fail the explicit cache write or report failed optional persistence; never write
an oversized file that its own loader rejects. Bound envelope history and retain trust-state dependencies. Removal tombstones
are unnecessary because evidence writers cannot modify policy.

Software subjects and independently retained material sets are collectible roots,
not permanent references. Apply the same bounded capacity procedure to explicit
writes and autocache under the file transaction lock:

1. Protect the authoritative policy state, every active decision and its complete
   supporting evidence, and all TUF rollback metadata and authentication dependencies.
   Protect eligible current JWKS/CT observations and their bytes as specified in
   Section 6; historical observations cannot replace these roots through collection.
   Also protect the complete successful software targets and material sets selected
   for this transaction. Protect their transitive dependencies, including required
   containment references. No collector may remove a protected dependency.
2. Remove unreferenced evidence. If the prospective artifact still exceeds any
   storage bound, remove unprotected software/material roots and then their newly
   unreferenced evidence until it fits. Prefer mutable material already ineligible
   under its typed time rules; order other candidates by canonical subject identity
   for deterministic selection. This ordering grants no trust or release freshness.
   No persisted recency index or verification-result cache is required.
3. Validate the remaining graph and encoded/decoded bounds before replacement.
   If protected data alone exceeds capacity, fail the explicit transaction or report
   failed optional persistence. Never drop a selected successful target silently.
   Report removed subjects, reclaimed bytes, and protected bytes preventing recovery;
   collected subjects can require normal retrieval on a later admission.

Collecting a software subject removes only a retrieval optimization. It never
changes policy, TUF rollback knowledge, or an acquired runtime authorization.
A delayed evidence writer may reintroduce previously collected validated bytes
under the same bounded merge rules; collection is not a security withdrawal and
needs no tombstone. Such bytes still require current verification on new admission
and cannot restore a removed decision. Avoid repeatedly enqueueing a snapshot solely
because another writer collected it; a later successful admission can request export.
Do not instruct operators to delete the artifact to recover capacity. Ordinary
replacement writes can reclaim reconstructible evidence while retaining trust state.

Deduplicate retrieval by exact material identity and authenticated origin. Validate
before publishing reusable bytes; do not memoize admission subcheck results. Each owning service uses
bounded shared contexts; one client's cancellation cannot cancel another's work.
Do not add a generic generation store around each material adapter. Retain independent routing/discovery stores.

Use process-local synchronization for memory and a separate lock file for the
cross-process read-merge-write transaction. Under the lock, reread, validate, merge
without reviving invalidated records, write a restricted temporary file, sync,
rename atomically, and sync the containing directory. Lock files must survive
cache-file replacement. Disjoint provider updates preserve each other's objects
unless capacity requires the documented collection procedure; collection must not
delete evidence used by another retained subject.

Directory sync means syncing the open parent directory after replacement so the
new directory entry is durable, in addition to syncing the temporary file's data.
Distinguish failure before rename from failure after successful rename. Before
rename, report failure without claiming a replacement. If rename succeeds but
parent-directory sync fails, return an error stating that replacement completed
but durability could not be confirmed; identify the written artifact digest and
policy authority/revision. Do not report that the original file is unchanged or
that persistence succeeded. Do not restore older policy or blindly repeat a policy
edit. A later operation rereads authoritative state under the normal lock and
preconditions. Optional persistence reports the same uncertainty without changing
an independently acquired authorization. No additional recovery protocol is needed.

Use a fixed lock order: acquire the file transaction lock without a runtime mutex;
load the authoritative artifact and policy revision; validate the immutable snapshot
against that state; resolve additions/removals and collect references; write/sync the
replacement; release the file lock. Runtime publication/invalidation independently rechecks its own generation;
optional disk writes never delay those operations. Never acquire a file lock while holding the
runtime authorization mutex. A cancelled observer cannot cancel a transaction another
client needs; writes have a bounded owner context.

An optional evidence write failure can leave verified memory state intact. Explicit
cache writes and policy-edit transactions must report their persistence failures. Logs identify target,
check, and failure without API keys, inference content, or private key material.

## 8. Planning findings and implementation phases

### Shared admission design established during planning

The current commonality is lower-level verification, not one shared orchestration
service. `proxy.Server.fetchVerified` owns serving orchestration and calls proxy
helpers; `verify.runEvidence` independently constructs verifiers, fetches evidence,
collects factors, and completes probes. The existing `SYNC` comments identify this
duplication. Both use attestation/provider primitives, but cache code must not be
inserted twice. `proxy.authorizationStore` owns the live generation, bounded shared
work, report/key/identity publication, eviction, and usability promotion. Its
`publish` method rechecks admission time immediately before storing a generation.

Extract `internal/admission` as a service layer importing provider and attestation
primitives, never proxy or CLI packages. Proxy and verify consume it. Keep provider
route resolution in existing immutable route APIs. Use three boundaries:

1. `Collect`: fetch a fresh nonce-bound raw response for the resolved route through
   the provider-owned attester and injected clients. Preserve original evidence and
   strict parsing; no cached historical quote can satisfy this operation.
2. `Evaluate`: run the shared CPU, GPU, PoC, software, binding, and effective-policy
   operations, returning an immutable verified-evidence snapshot and admission-time
   eligibility. Material resolvers are injected per owner; the snapshot includes
   original dependencies, actual failures/exemptions, and authenticated key/identity.
3. `ExportPortable`: derive only complete eligible portable graphs from that snapshot
   through the typed material adapters. A report's display fields are not export input.

These are responsibilities and proposed internal names, not new public CLI APIs.
Phase 1 extracts live collection, evaluation, and validated candidate construction
only. Introduce concrete portable snapshots, prefill, and export interfaces with
the first typed adapters that consume them in Phase 3 and later material phases.
Phase 2 supplies bounded storage primitives. Do not implement speculative adapter
interfaces or an empty portable evidence hierarchy in the orchestration refactor.
Keep the existing proxy authorization store as the sole runtime generation owner;
it consumes a shared validated candidate and retains its publication checks.
Extract local candidate construction and validation from the proxy constructor so
`cache`, `verify`, and `serve` all enforce the same key, binding, and route checks.
The store still checks that the candidate matches its acquisition scope and rechecks
NRAS admission time at publication. Shared construction creates no stored authorization.
Shared command evaluation checks transient admission eligibility when evaluation
completes, before its observation is presented for review or passed to persistence.
That completed observation may justify an ordinary policy decision after human
review without keeping report-bound tokens alive. File writes and human review do
not publish endpoint authorization or extend evidence validity. Every new live
admission retains the runtime publication-time check; policy additions still need
all required observation checks and effective-policy evaluation.
Keep its report/key/identity representation and generation lifecycle independent of
portable graphs. The evidence snapshot is transient, with bounded references into
material owners; do not attach full raw evidence graphs to each authorization.
Material retention and export use their own byte bounds and never require an
endpoint generation. Collection or disk writes cannot rotate an HTTP/2 pool.
Shared admission and material-retrieval coordination are useful independently of
disk persistence and remain part of this refactor. Share transport factories and
bounded retrieval coordination, but do not combine authorization generations,
material freshness, TUF rollback state, and file transactions into a universal cache
lifecycle. Their owners retain their distinct validation and synchronization rules.
Extend existing client factories through dependency injection and reuse the
[transport regression coverage](../transport/testing.md) for socket capacity,
retry classification, and pool cleanup. Material adapters do not introduce another
transport or retry framework. Add integration tests where an adapter changes client
ownership; unchanged transport behavior keeps its existing tests and authoritative
contract in `docs/transport/`.
`verify` always calls fresh collection/evaluation and then its required probe, without
acquiring proxy runtime authorization. `cache` uses the same collection/evaluation
and exports after non-deferred checks. Serving promotes E2EE usability only for the
generation/model that actually completed it. Portable export does not require a
successful inference response; live E2EE usability retains its own completion checks. Do not move probe or
retry policy into a second cache orchestration path.

Material lookup/population and effective-policy reporting are specified in Sections 2e, 4,
and 6. Preserve caller cancellation and server-owned bounded shared work; perform
network/disk I/O outside runtime locks. Prefill supplies raw inputs to material owners; it does not publish a runtime
authorization or borrow its generation. Only live admission reaches the existing
constructor and generation-checked publication path. The remaining work in Phases 0/1 is
permanent test infrastructure and this tested refactor, not rediscovering ownership.
Material, policy, and interface acceptance still require production-path tests; the
planning prototypes do not replace them.



Implement Phases 0 through 11 in order, including 2a after 2, 3a after 3,
and 5a–5c in place of 5.
Each phase builds on the completed preceding
phases; it is not independently applicable to an earlier checkout. Each phase must
produce one reviewable commit with a complete implementation, tests, and maintained
documentation for the behavior it introduces. If a phase proves too large for one
reviewable commit, divide its implementation and acceptance boundaries explicitly
before starting it, and update the dependent phase references.

Run `make check` before each commit. Major runtime changes also require
`make integration` and `make reports`; positive coverage uses production factor
enforcement. Apply the Section 1 Tinfoil direct live-validation prerequisite: retain
all unblocked checks and deterministic direct coverage, record deferred live checks
in the commit description, and complete them after the upstream fix is deployed.
Do not claim complete direct live validation while it remains blocked. These phases
specify work and acceptance requirements, not implementation status or test logs.

Every implementation phase owns its scope, upgrade, concurrency, failure, and request
count tests. There is no later phase that supplies missing correctness coverage.
Later phases add tests for the new interactions they introduce. Use production
cryptography, TLS test servers, bounded contexts, and real signed fixture material.
Never depend on ambient developer caches to satisfy a request budget. Each material
adapter must demonstrate current verification after same-build and upgraded imports, and
precise retrieval or rejection for missing/ineligible dependencies before completion.

Reject unsupported record kinds, decisions, and options until their implementing
phase enables them; never accept an uninterpreted trust record or silently ignore
its policy. The withdrawal-only path may remove understood but currently prohibited
decisions under Section 2e; this does not enable their consumption. Schema declarations
do not enable a capability. Do not add compatibility
paths for intermediate implementations. Shared interface changes belong to the phase
that needs them, with all existing callers and tests updated in that commit.

| Milestone | First phase delivering the behavior |
| --- | --- |
| Shared live admission and candidate construction | 1 |
| Strict live compose parsing and complete component coverage | 2a |
| Portable storage and concrete prefill/export | Storage in 2; interfaces with their first adapters in 3–7 |
| Goal 1, first supported delivery: NEAR software preparation/reuse through all three commands | 3a |
| Goal 1, complete initial provider/dependency scope and portable budgets | 8 |
| Consumption of exact operator decisions through shared effective policy | 9 |
| Goal 2: reviewed whitelist authoring, proposals, and withdrawals | 10 |
| Automatic portable persistence during serving | 11 |

Chutes/Venice enablement and unresolved elevated decision classes are separate
conditional extensions described below; they do not block Near/Tinfoil delivery.
Each phase updates the documentation identified in
[Section 9c](#9c-phase-requirements-and-completion-checks).

Planning source map: [serving orchestration](../../internal/proxy/proxy.go),
[standalone verification](../../internal/verify/verify.go),
[runtime authorization ownership](../../internal/proxy/authorization.go),
[policy and factor evaluation](../../internal/attestation/report.go),
[Rekor verification](../../internal/attestation/rekor.go),
[TDX adapter](../../internal/attestation/tdx.go),
[SEV adapter](../../internal/attestation/sev.go),
[Tinfoil certificate retrieval](../../internal/provider/tinfoil/kds.go),
[Tinfoil release retrieval](../../internal/provider/tinfoil/sigstore.go),
[NVIDIA key ownership](../../internal/attestation/nvidia.go), and
[CT checker/client construction](../../internal/tlsct/checker.go).
Pinned dependency behavior comes from [go.mod](../../go.mod),
[Sigstore v1.2.1 TUF client](https://github.com/sigstore/sigstore-go/blob/v1.2.1/pkg/tuf/client.go),
[go-tuf trusted metadata](https://github.com/theupdateframework/go-tuf/blob/7e8f69f906ef/metadata/trustedmetadata/trustedmetadata.go),
and [go-tuf updater](https://github.com/theupdateframework/go-tuf/blob/7e8f69f906ef/metadata/updater/updater.go).
These establish the API boundaries; implementation tests must exercise the pinned
versions rather than assuming newer library behavior.

### Test layers and fixture prerequisites

Acceptance uses three complementary layers. Do not claim that historical signed
quotes can authenticate a newly generated local TLS key or a new random nonce.

| Layer | What it establishes | Required setup and limits |
| --- | --- | --- |
| Signed-evidence replay | Production parsing, cryptography, current-policy evaluation, portable import/export, and exact dependency request counts | Pin fixture paths, captured nonce, and explicit test clock. Deny unexpected retrievals. Test expiry separately by advancing the clock. A replay transport does not establish real TLS, fresh admission, or inference success. |
| Deterministic TLS/HTTP/2 and lifecycle | Real production TLS/CT/SPKI/E2EE pathways, multiplexing, generation ownership, cancellation, and material-service request counts | Use test-owned TLS/encryption keys and the existing transport test facilities. Any constructed authorization is an explicit boundary fixture, not proof of hardware admission. Exercise fresh-nonce and rejection paths separately. Do not substitute passing cryptographic verdicts to claim full admission. |
| Full live admission | Fresh production nonce, actual quote/key/TLS binding, report-bound services, end-to-end command equivalence, and observed startup budgets | Use normal provider enforcement and live-test opt-in. Keep Tinfoil direct's stated external prerequisite. Record failures as failures, not reduced successful-request counts. |

Phase 0 must provide one executable core-provider case in each unblocked layer and
identify which assertions compose across layers. The captured NEAR PoC failures
cannot establish successful quorum counts. Successful report-bound replay assertions
need suitable signed captures; until available, those assertions remain explicitly
blocked and successful total budgets remain live observations. No historical
fixture alone satisfies full fresh-admission acceptance. A controlled environment
with valid hardware evidence for test-owned keys could add that coverage, but is
not assumed or required by this plan.

Mandatory deterministic fixtures use exact checked-in paths and fail when missing;
do not use a newest-fixture selector or `Skip` for required acceptance. Live tests
may skip only under their documented opt-in/prerequisite rules. Complete request
budgets combine exact deterministic assertions for the groups they exercise with
separately identified live measurements; never describe that composition as one
deterministic end-to-end execution. Current-time production rules remain unchanged.

### Phase 0: Permanent request accounting

First establish the executable test-layer prerequisites above. Implement permanent
counters and regression fixtures for the baseline in Sections 4b–4e. Inventory and
instrument every teep-owned and dependency-owned client construction path, including
CT/TUF bootstrap and refresh, discovery, live attestation, NRAS, and Proof of Cloud.
Separate preparation, pre-inference work, inference/probe requests, and TLS handshakes.
Record provider, format, hardware scope, policy, and dependency-cache conditions.
Implement and test the three-counter contract in Section 4b, including an internal
transport retry that produces multiple attempts within one outer `RoundTrip`.
Provide destination counters and network-denial controls for deterministic cached
groups. These foundations are required before implementing reuse; exhaustive
partial-write, HTTP/2 retry/cancellation, redirect, and HTTP/HTTPS proxy accounting
tests may accompany the adapter/transport phases that exercise those paths. Track
their required assertions in the test suite and testing reference, with explicit
coverage limits. Count proxy CONNECT separately. Complete Section 4b coverage is
required by Phase 8 before claiming comprehensive outbound or full scenario totals.
No earlier result may label outer-wrapper counts as all transport attempts or use
uncovered paths as proof of zero requests. Production retries remain enabled.
Keep this phase limited to the counters, denial controls, and executable baseline
cases needed by subsequent phases. Reuse existing transport tests for retry and
proxy observations; add the remaining assertions with the adapters that need them.
Do not delay Phase 3a's software-only delivery for the comprehensive totals due in
Phase 8, or change production scheduling or retries to simplify measurement.

Test successful service sequences and early failures separately; a shorter failure
sequence is not a successful-admission budget. Provide deterministic counters and
network-denial controls for later adapters without asserting unimplemented savings.
Adapt the [NEAR fixture loader](../../internal/integration/helpers_test.go) for exact
required fixture selection; do not inherit its newest-fixture/skip behavior. Use
[NearCloud fixtures](../../internal/integration/nearcloud_test.go),
[NearDirect fixtures](../../internal/integration/neardirect_test.go), and
[model-key binding tests](../../internal/integration/near_model_binding_test.go).
Establish extracted-byte and component parity without assuming different captures
share quotes, nonces, TLS identities, or complete compose bytes. This phase changes
no caching, policy, command, or admission behavior.

### Phase 1: Shared live admission

Extract shared live collection, evaluation, and validated candidate construction
from the existing orchestration, with immutable candidate results.
Connect existing Near/Tinfoil live serving and ordinary live `verify` to the shared
services. Keep provider scope, key-use lifetime, report/key publication, admission-time
checks, bounded verification ownership, and generation-safe invalidation there.
Keep the existing authorization store's publication and generation ownership;
do not create a second authorization store or build trust from display reports.
Limit this phase to interfaces required by existing live callers. Concrete portable
graphs, prefill/export, staging/promotion, and new material coordination belong to
the first adapter phases that need them, rather than this refactor.

Test unchanged live outcomes, complete report/key/identity publication, required
NRAS admission-time checks, cancellation isolation, eviction, replacement races,
and unrelated HTTP/2 streams. Preserve existing capture/replay behavior and verify
that acquired runtime authorization still avoids readmission. Two distinct fresh
admissions must still run their required checks; this phase adds no material cache.
No new CLI is enabled in this phase.
Test the shared candidate constructor through all consumers: low-order X25519 keys,
invalid NEAR key conversion, missing required binding, and route/identity mismatch
must fail without an inference probe. Preserve deferred remote usability separately.

### Phase 2: Portable artifact storage

Implement strict decoding, canonical software/material identities, explicit
dependency resolution, immutable storage snapshots, and bounded reference-aware
storage. Storage validation cannot promote inputs into runtime material; concrete
typed admission import/export arrives with the owning adapters. Define the typed-list
envelope and supported-kind dispatch used by later adapters. Include the empty
policy-state contract; nonempty operator policy remains unsupported until Phase 9.

Implement secure file access and the cross-process read/validate/merge/write transaction:
separate stable lock file, restrictive temporary files, fsync, atomic replacement,
and directory synchronization. Keep encoding and disk I/O outside runtime mutexes.
Preserve the current policy state under the lock without copying policy from an
evidence snapshot; do not implement whitelist editing here. Merge exact raw inputs
and reject conflicting descriptive associations. Derived result fields are invalid.
Reserve typed TUF state support for Phase 5a and current TUF evaluation for Phase 5b.

Test malformed/unknown input, aliases/cycles, forged checks, duplicate or ambiguous
selectors, dangling dependencies, content mismatch, unsupported approval fields, untrusted
imports, size bounds, reference collection, symlinks, path substitution, permissions,
concurrent disjoint writers, cancellation, write failure, and crash boundaries.
Inject failure before rename and after rename at directory sync. Assert the
reported replacement/durability outcome, visible artifact digest and policy state,
and normal revision checks by subsequent readers and writers. A post-rename error
must not trigger restoration of the old file or claim successful durability.
Cover root-owned read-only deployment, effective-user-owned writable deployment,
untrusted parent ownership/permissions, parent and lock substitution, hard-link
aliases, symlink projections, and lock-inode stability across atomic replacement.
Run transaction/durability tests on each supported local filesystem/platform and
document the supported deployment assumptions.
Test software-version churn through capacity, removal of collectible roots with
shared dependencies, deterministic selection, and recovery without resetting policy
authority or TUF state. Extend protected-decision/TUF cases when their phases enable
those kinds. Test protected-data overflow, delayed writers reintroducing evidence,
and size/peak-memory/write-cost measurements at the maximum supported artifact.
Use supported production evidence representations for storage tests; new material
kinds become usable only with their verified adapter. No command is enabled yet.
Fuzz YAML decoding, embedded strict JSON, base64 sizing, and reference traversal.
Include deeply nested input, aliases, duplicate fields, cycles, and near-limit
payloads; reject structural/resource violations before unbounded parser allocation
or traversal. Exercise bounds on parser structures as well as decoded evidence.

### Phase 2a: Strict live compose parsing and component coverage

Replace regex membership extraction with the bounded production component parser
specified in Section 2b-i. Update existing live callers together, using Phase 1's
shared admission service where applicable. Remove silent 64-digest truncation and
the malformed-JSON text fallback. Preserve exact bound compose bytes, full
repository/digest relations, tag-only binding limitations, and literal-default
classification. Return unknown fields to the owning caller.

Feed complete typed component coverage into the live supply-chain and report
evaluators. Implement Section 4's required-versus-diagnostic retrieval classification
here so compose-only components need no fabricated successful Rekor response.
Keep every required signed component and the independent gateway/model boundaries.
Preserve Venice's existing missing-backend failures without enabling its cache path.
This phase changes live parsing and coverage; it introduces no portable adapter,
material store, operator decision, or new CLI.

Test mixed pinned/tag-only services, malformed manifests, duplicate service names,
image strings in comments/environment values, unresolved variable references, and
65 distinct images. Assert complete membership or an explicit bound/format failure.
Cover list reordering, two versions of one repository, repository/digest aliasing,
and failure of a later required component. Compare factor enforcement through live
callers, including compose-only coverage and absent backend evidence. Assert required
and diagnostic request counts independently of any cache saving.
Fuzz component parsing and prove that local environment changes cannot change the
membership or binding classification of identical authenticated compose bytes.
Use the named NEAR capture to test authentication of the literal default in
`COMPOSE_MANAGER_IMAGE` while retaining the runtime-override gap. Assert that
default-image provenance success does not claim authentication of override contents,
and that no script execution or local environment lookup occurs. Deliver this
production parser and its coverage tests in a separate reviewable commit before
introducing portable software reuse.

### Phase 3: NEAR software reuse

Implement compose and component export/prefill through the shared supply-chain
verifier. Introduce the concrete input, staging/promotion, and portable snapshot
interfaces needed by this first adapter. Later adapters extend these boundaries
only where their typed requirements need it. Preserve original stapled envelope
relationships and independent gateway and backend verification. Share exact validated
evidence across NearCloud/NearDirect without sharing endpoint authorization or
consumer policy. Use Phase 2a's parser and typed component evaluations for retained
inputs as well as live inputs; add no portable-only parser or coverage evaluator.
Never suppress an enforced factor because a saved record claims it is not required.

Test prefill/publication ownership through the shared services. Malformed,
unauthenticated, and failed material must stay outside reusable stores, including
after admission permitted by `allow_fail`. Two distinct admissions sharing the
same evidence share eligible retrievals but each runs its required local checks.
Acquired runtime authorization continues to avoid readmission. Add the bounded
retrieval coordinator only when a concrete acquisition path requires it, preserving
the authorization store as the sole owner of runtime generations.

Test complete membership, later-component signature failure, arbitrary replacement,
list reordering, two versions of one repository, repository/digest aliasing, wrong
model selection, incomplete backend evidence, envelope containment tampering, and
same/different compose subjects sharing image bytes. Cover tier/provider isolation,
changed gateway/backend keys, changed signer policy requiring local reevaluation of
all components without downloading unchanged eligible evidence, same-key refresh,
concurrent imports, and prefill racing publication or eviction. Deny provenance
network access for eligible reuse and local upgrade reevaluation; assert remaining
required queries and accurately report unrefreshed optional diagnostics. These tests
complete the software portion of the NearCloud/NearDirect scenarios, not collateral budgets.
Round-trip Phase 2a's supported component fixtures through portable export/import
and assert identical membership, binding classification, and policy outcomes.

### Phase 3a: Supported NEAR software preparation and reuse

Enable ordinary `teep cache` for NearCloud/NearDirect software evidence, read-only
NEAR prefill in `serve`, and cache-aware NEAR `verify`. Deliver the shared path
resolver, strict loader, target selection, partial-failure reporting, immutable
loaded snapshot, and `verify --no-cache` interfaces here. Use the final command
shapes; unsupported targets/kinds fail explicitly and later phases extend the same
services without compatibility adapters. Operator decisions and autocache remain
disabled. The complete command surface in Section 1 is the final scope, not a claim
that every provider or material adapter is available at this milestone.

Export only complete eligible NEAR software sets through Phase 3's production path.
CPU collateral, JWKS, CT metadata, NRAS, PoC, and discovery retain their normal live
requirements; do not require the later adapters for this supported release. CLI
reports and documentation identify software-only prefill and count the remaining
dependency work explicitly. Mixed-provider service uses Section 5's capability
rules, so unrelated unsupported routes retain ordinary live behavior.

Test the command/path and mixed-provider contracts for this supported scope, strict
input handling, read-only use, successful-target export, partial failure, and exact
loaded-artifact reporting. Deny prepared NEAR software retrievals on restart while
necessary live groups remain available. Prove command enforcement equivalence through
the established test layers, and report preparation cost separately from serving
cost. This commit delivers an independently usable request-reduction milestone;
it does not claim complete collateral budgets or Tinfoil cache support.
Implement the Section 5 capture/replay contract for software inputs in this commit,
including successful capture self-check and replay without the source cache file.

### Phase 4: CPU collateral reuse

Add Intel collateral and AMD VCEK adapters through the existing CPU verifiers and
certificate retrieval paths. Implement quote-derived applicability, canonical input
sets, explicit issuer-chain dependencies including captured HTTP headers, signed
validity/revocation eligibility, and verified export. Preserve embedded signing roots
and chains and Tinfoil's configured VCEK origin. Cached material is not a verdict
on a new CPU quote.

Test FMSPC/CA selection, shared QE/CRL objects across scopes and providers, distinct
TCB objects, AMD product/HWID/TCB mismatch, certificate extensions, expiry, revocation,
missing chains, incorrect signatures, upgrade reevaluation, and concurrent retrieval
sharing. Round-trip the captured identical TCB/QE chain bytes under both header
names, including cross-provider merging and rejection of substituted input roles. Prove zero eligible CPU-collateral retrievals with those origins denied,
and exact retrieval or rejection for ineligible objects. Do not add evidence expiry
to an already admitted runtime authorization or weaken fresh quote validation.

### Phase 5a: TUF checkpoint authentication and persistence

Implement typed TUF state and historical checkpoint authentication independently
of current target eligibility. Retain root transitions, authenticating key epochs,
parent metadata, delegated-role context, and accepted partial transitions through
the existing storage transaction. Use the pinned library's signature primitives
and rotation/reset rules. This phase cannot authorize a trust target from historical
knowledge or enable portable Tinfoil release consumption.

Test complete and partial checkpoint restoration, expired historical metadata,
missing dependencies, invalid signatures, same-version conflicts, authenticated
key rotation, concurrent transaction reconciliation, protected collection, and
restart from committed versus read-only state. Demonstrate transition-on-error
capture with the pinned library. This phase is one reviewable commit.
Test advancing the embedded bootstrap with old-epoch roles, partial checkpoints,
expired historical metadata, retained roots ahead of the bootstrap, missing forward
transitions, and deliberate historical-anchor withdrawal. YAML cannot introduce an
anchor, and an ordinary build update cannot silently erase rollback knowledge.

### Phase 5b: Current TUF evaluation and bounded refresh

Build fresh current-time verification sessions over Phase 5a's authenticated state.
Implement local eligible-snapshot evaluation and bounded authenticated refresh,
including exact trust-target hash/length checks and Sigstore root parsing. Publish
accepted transitions even when a later step fails, and reconcile concurrent sessions
before completing material evaluation. Isolate clients and metadata from ambient
Sigstore caches. Historical rollback knowledge alone never makes a target eligible.

Test local verification with retrieval denied, expiry and missing-input refresh,
two successive refreshes, timestamp acceptance followed by failed snapshot download,
restart after timestamp expiry, rollback rejection, root-key resets, and a newer
concurrent transition superseding a candidate. Verify client cleanup, request counts,
and bounded shared retrieval. This phase is one reviewable commit.

### Phase 5c: Tinfoil release selection and binding

Implement complete code/platform release sets and signed measurement-reference reuse
through Phase 5b's trust-material resolver. Add bounded known-candidate release
retrieval on a miss, using existing signature and measurement-binding verifiers.
Supplied V3 collateral lacking shared verification remains unsupported as a verified
result; a parsed envelope cannot add coverage.

Test direct TDX code/hardware binding independently and cloud SEV router scope.
Cover an older authenticated matching release, a newer unbound release, tag-only
references, incomplete bundles, component failures, and known-candidate count/byte/time
limits, including explicit failure of unsupported release enumeration. Test scoped
policy changes and local build-update reevaluation with eligible release/TUF retrieval
denied. Count cold discovery separately and preserve router sharing and direct
authority isolation. This commit completes the release portion of both Tinfoil
scenarios; CT prefill follows in Phase 7. Phases 5a, 5b, and 5c together implement
the complete [trusted version-state contract](#tuf-trusted-version-state).
Use the supported empty-device-list cloud router fixture for complete admission
coverage under its normal policy. Direct component tests must not fabricate GPU
success. Test rejection of nonempty V3 device lists for both aliases until the
production parser/verifier supports them; separate those failures from billing.

### Phase 6: NVIDIA key-material reuse

Implement authenticated JWKS snapshot/import/export through the existing NVIDIA
verifier. Preserve issuer/origin policy, original retrieval time, cache eligibility,
key-rotation refresh, and bounded concurrent retrieval. This phase does not introduce
a portable NRAS verdict or an independent NVIDIA reference-image verifier.
Replace leader-context singleflight ownership with the bounded material-owner
lifecycle and shared retrieval-coordination helper specified in Section 4;
import/export alone is insufficient. Keep NVIDIA eligibility and refresh throttling
in the NVIDIA owner.

Test trusted import, stale and malformed keysets, incorrect authority, unknown key
IDs, eligible key rotation, refresh failure, concurrent consumers, and build/policy
changes. Deny JWKS requests on an eligible match while proving that new GPU evidence
still produces its required NRAS submission and signature/claim validation. Test
the 10-second imported-clock allowance and monotonic remaining-lifetime cap. Prove
that copying a file does not extend key eligibility and another report's NRAS result
cannot satisfy a new nonce. Retain initial publication-time eligibility checks.
Test two independent admissions sharing retrieval, leader cancellation/timeout,
waiter cancellation, failure delivered to all current waiters without duplicate
retrieval, refresh racing import, and shutdown during fetch. Verify prompt waiter
release, no post-shutdown publication, and unchanged unrelated authorizations.
Test key removal with two still-eligible keysets, reversed import order, equal-time
conflicting observations, a stale writer after refresh, and restart from merged
state. A token accepted only by the superseded keyset must not cause its selection.

### Phase 7: CT metadata reuse

Implement CT log-list snapshot/import/export and prefill every relevant checker,
including clients owned by dependencies. Preserve bootstrap origin authentication,
original retrieval time, refresh rules, and live WebPKI, TLS identity, and SCT checks.
Use the same material interfaces; do not use an inference-client-only cache or
weaken bootstrap verification to avoid a request.
Replace network I/O under `logListLock` with bounded shared retrieval and completion
notification through the same helper used by NVIDIA. Keep CT bootstrap and log-list
policy in the checker. Implement owner cleanup for the bootstrap client and distinguish
context-aware waits from the bounded TLS-callback wait described in Section 4.

Test all checker construction paths, eligible prefill, expiry, malformed/substituted
lists, changed log policy, refresh failure, concurrent use, imported clock skew,
clock rollback, and local upgrade reevaluation. Deny log-list retrieval on eligible inputs while checking live peer
certificates through production TLS. Compose with the TUF adapter to expose hidden
client traffic. Existing provider routing and connection scopes remain unchanged.
Test blocked retrieval with concurrent handshakes/direct checks, independent caller
cancellation where a context is available, a shared failure without serial retries
by queued waiters, timeout, shutdown, and refresh/import races. Verify that active
unrelated HTTP/2 streams continue and no failed refresh becomes a successful CT check.
Test superseded log lists with the same selection/merge cases as JWKS. Preserve
existing certificate-check cache eligibility; historical list bytes cannot become
current merely because a certificate fails evaluation against the selected list.
Test the separate one-hour result and 24-hour material lifetimes, without renewal
on cache hits. Cover a cached result surviving list replacement, a check completing
against a previously acquired list, and an uncached check using the new list.
Advance the clock without new connections and assert zero background requests and
uninterrupted live HTTP/2 streams. Then establish new connections to prove local
reverification after result expiry and retrieval only for missing/ineligible list
material. Assert that portable output contains no certificate-check successes and
that reports describe SCT signature validation without claiming inclusion proofs.

### Phase 8: Complete command capabilities and portable budgets

Extend Phase 3a's commands to Tinfoil and all implemented portable material adapters.
Complete the deferred Section 4b transport-accounting assertions from Phase 0 before
publishing comprehensive request totals; identify any blocked live coverage separately.
Reuse its path resolver, target handling, successful-target export, partial-failure
reporting, and immutable loaded snapshots. Connect the established material adapters
through shared services and the disk transaction layer; introduce no provider-specific
verification inside command orchestration or second command implementation. Complete
the cross-provider/collateral budgets without changing the earlier software-only
milestone's enforcement contract.

Test all target forms and invalid syntax, discovery changes, complete dependencies,
missing implicit versus explicit files, destination creation, secure/read-only files,
concurrent replacement, and explicit unsupported providers. Cover the relevance rules
for all path sources and `verify --no-cache`. Test the identical mixed-provider configuration and
artifact selected by flag, environment, configuration, and default: all have the
same applicability and enforcement outcomes. Cover unrelated shared evidence,
unsupported policy rejection before traffic, and explicit per-target reporting of
live-only verification. Extend matching-decision applicability tests in Phase 9
when decision consumption is enabled. Verify reports identify the exact
loaded artifact/build/policy; no-cache verification must not claim policy-rollout
validation. Test fresh admission, deferred usability versus required live probes,
and absence of cache/decision writes from `verify` or ordinary `serve`.

Make the NearCloud example and NearDirect/Tinfoil scenario records executable with
real signed fixture bytes. Validate Section 4d through the specified test layers:
deny prepared groups, use independent cold replica state, and distinguish exact
replay counts from observed full live totals. Do not require captured keys to
authenticate a new local TLS server. Exercise cross-command enforcement equivalence, scoped policies,
multi-component failure, and partial success. Include multi-model/cloud-router scope
and concurrent clients. This phase completes Goal 1's initial provider/dependency
scope beyond Phase 3a; operator decisions and autocaching
remain disabled until their respective phases.

### Phase 9: Operator policy evaluation

Implement exact operator-decision interpretation in the shared policy evaluator and
all three command consumers. Expose typed failure reasons in the owning verifiers:
unlisted measurements, repository/signer/content policy violations, missing evidence,
invalid signatures, expiry, and authenticated revocation must remain distinguishable.
Implement the initial capability table in Section 5a. Separate Tinfoil bundle
authentication from expected signer comparison in the production verifier before
enabling its exact OIDC signer decisions; test valid authentication with an unlisted
identity and failures of every retained cryptographic prerequisite. Keep NEAR OIDC
and raw-key decisions deferred as specified there. Enumerate supported provider,
tier, reason, and prerequisite combinations in tests and maintained documentation.
Elevated or otherwise unresolved classes remain explicitly rejected. Accept nonempty policy
only through validated trusted imports at this stage; authoring follows in Phase 10.

Include effective-policy reporting, cumulative decisions, compatibility with
a new build, policy-revision validation, and references to the actual failed base checks.
Make existing evidence writers preserve authoritative policy under their transaction
lock and merge raw evidence without copying decisions or derived approvals. No class
inherits a factor-wide override simply because several failures share a factor.
Read the same configured model/gateway measurement base policy in all command
consumers; decision evaluation must not replace restrictive configuration with defaults.

Test every implemented class and retained prerequisite with production verification,
including selected MRTD/MRSEAM tuples, unrelated measurement fields, subject/tier
separation, sibling component failures, unknown decision kinds, and remaining enforced
failures. Test exact value comparison, decision dependency tampering, unrelated versus
applicable policy edits, withdrawn decisions, and new verifier restrictions. Prove
matching effective-policy outcomes across cache/serve/verify, including existing
`allow_fail` behavior, matching/unused decisions, and absence of relabeled successes.
Count requests replaced by each class separately from its creation prerequisites.
Test built-in acceptance of A and B with configured acceptance of A only: B remains
rejected in cache, serve, and verify when no applicable decision or explicit factor
allowance permits it. Cover global/per-provider replacement precedence, gateway
registers, an explicitly reviewed B exception with the base failure still reported,
and withdrawal of that exception restoring rejection. A cached evidence file cannot
erase the configured restriction.
Update security and review instructions in this commit, when exceptions become usable.
Test an ordinary measurement decision after its original collateral, certificate,
and report-bound tokens expire: fresh valid admission of the same selected subject
remains possible. Separately reject invalid historical signatures, missing observation
dependencies, and failed current prerequisites. Test that old tokens cannot satisfy
new report-bound work. Test mixed-provider decision applicability independently of
cache path selection, including matching unsupported scopes rejected at startup.
Test two failures within one factor with only one exact decision, both MRTD and
MRSEAM failing together, and two component failures with only one excepted subject.
Assert agreement between blocking, authorization publication, CLI status, report
totals, and dashboard output. Race-test independent report clones containing nested
failure/disposition data. No authoring workflow may expose incomplete failure sets.
Extend capture/replay tests to applied and unused operator decisions and their
observation dependencies. Replay must reproduce the captured policy context after
the live cache changes, without installing that context as live admission policy.

### Phase 10: Whitelist editing and policy transactions

Enable interactive `--update-whitelist`, `--reason`, proposal generation, and explicit
proposal application on top of Phase 9's evaluator and Phase 2's transaction layer.
Implement concrete selections, explanations, frozen target discovery, ordinary bulk
selection, exact proposal validation, and the acknowledgement representation required
by future elevated classes. Do not enable those classes through the UI prematurely.
Replace `--update-config` and `--config-out` in this commit; reject those obsolete
options and update help/configuration together. Retain measurement-policy input
as base policy with its existing restrictive and precedence semantics. Add examples
that distinguish configured restrictions from reviewed exceptions; no command
automatically converts configured restrictions into additive decisions.

Use the single policy-application implementation specified in Section 5b for
interactive confirmation and proposal apply. Keep fresh retrieval in shared
admission and check observation eligibility at evaluation completion. Test expiry
during human review and lock waiting: ordinary decisions require no extra requests
solely for that delay, and later live admission still checks current eligibility.
A proposal's asserted prior success is never accepted as a validated observation.
Test policy changes during review and cancellation without introducing a refresh loop.

Implement policy authority/revision/state comparisons under the lock, explicit removal,
newly reviewed reintroduction, and atomic eligible additions plus withdrawals. Bind
proposals to exact reviewed subjects/evidence/failures/applicable policy and current
policy state. Build information is diagnostic; apply reruns the current implementation. Reevaluate successful targets against the committed subset. Report known shared
scope when a successful target's decision also affects a failed target; do not export
software evidence justified solely by that failed target.

Implement first-use absence preconditions for proposals and interactive edits.
Test generation/application against missing default and explicit destinations,
base-policy failure resolved by the first decision, two competing first writers,
ordinary artifact creation between review and apply, disappearance of an existing
artifact, cancellation, and empty selection. Only a successful first policy commit
creates its authority; an existing artifact requires renewed review.
Test a relevant configured measurement-policy change between proposal generation
and apply; require renewed review without discarding or broadening the restriction.

Test interactive cancellation/confirmation, nonempty reasons, all-model and selected
model flows, empty/unbounded selections, unsupported failures, strict/tampered proposals,
stale revisions, changed policy or verifier requirements, and noninteractive use without explicit
apply. Test that apply accepts changed nonce/evidence bytes only when the exact
reviewed subject, relevant failures, and policy remain unchanged. Test no trust writes
during proposal generation and proposal-output collisions with cache/configuration/lock paths,
alternate path spellings, hard links, symlinks, existing outputs, and a competing
creator at publication. Assert original input bytes remain unchanged on every failure.
Test withdrawals without provider connectivity, disabled providers, removed models, empty active configuration,
targetless removal proposals, mixed additions/removals, nonzero live failures after a committed withdrawal,
and removal racing ordinary evidence writers. Test removal after an upgrade prohibits
a known decision kind or scope, including removal of the final decision, multiple
prohibited decisions, and preservation of authority/revision. Unknown or malformed
records still fail without writes. Reject missing or extraneous elevated
acknowledgements without enabling unsupported classes. Keep prompts/reports free of
credentials and inference content. This phase delivers Goal 2's authoring workflow.

### Phase 11: Automatic portable persistence

Enable `serve --autocache` through the established immutable snapshot/export and
current-policy disk transaction. Implement bounded queues, coalescing, startup
writability checks, destination creation, asynchronous errors, shutdown handling,
and crash-safe replacement. Export only material eligible at the specified admission
boundary, plus independently authenticated TUF transitions; inference response
success is not required. Never create operator decisions,
poll releases, or add background discovery/verification requests.

Test first live admission followed by restart from the committed file, changed compose
and release evidence, complete component coverage, permitted failed checks, and deferred
E2EE usability. Assert the same portable budgets as explicit preparation. Cover concurrent
cache-command/service writers, queue saturation, read-only conflicts, slow/failed writes,
recovery, shutdown flush, and stale snapshots racing policy withdrawal/reintroduction.
Exercise sustained deployment changes through capacity, bounded collection without
requeue loops, and subsequent restart using the newly persisted software evidence.
Prove optional write failure leaves independently completed in-memory authorization
usable, does not claim persistence, and cannot revive removed decisions or replace another consumer's evidence incorrectly. Restart always requires fresh endpoint admission.

### Conditional extensions: provider enablement and elevated decisions

For Chutes and Venice, complete separate transport migrations before cache enablement.
Require immutable routes, atomic report/key publication, shared bounded verification,
generation-safe invalidation, and concurrent acquisition through the common interfaces.
Ordinary live `verify` must use shared admission services. Test actual HTTP/2 negotiation
and multiplexing under production TLS/CT; streaming success is insufficient. Migration
is tested with live-populated state and does not depend on disk support. No phase may
add a legacy-cache adapter to work around an incomplete migration.

After each migration and applicable core phases, use a separate provider-enablement
commit with explicit capabilities and full live/prefill equivalence. Venice covers both
dstack and ACI/1, format changes, independent gateway/model scopes, weaker compose
provenance, unbound metadata, custody/app-ID/KMS failures, and expired keysets. Extend
[ACI coverage](../../internal/integration/venice_aci_test.go),
[concurrent-format coverage](../../internal/integration/venice_concurrent_formats_test.go),
and [custody/keyset tests](../../internal/provider/venice/keyset_test.go). Add the Venice scenario to the test layers and validate its conditional budgets. Never promote exempted failures or
absent backend evidence into verified results. Fresh admission remains mandatory
after restart.

Chutes covers chute/instance/key scope, ML-KEM binding, consumable nonce ownership,
nonce exhaustion/expiry/replenishment, concurrent consumption, and exact MRTD/MRSEAM
decisions with retained unrelated failures. Test that portable files cannot supply
consumable request nonces. Provider enablement uses the established policy, command,
and writer contracts and introduces no parallel caching machinery. PhalaCloud and
NanoGPT remain out of scope.

Enable each elevated decision class only in a separately bounded implementation after
its typed prerequisites, exact replacement check, scope, acknowledgement, and retrieval
consequences are specified. Its commit must include evaluator, authoring, consumer,
reporting, security/review documentation, and per-class negative/request-count tests.
Unresolved classes remain rejected, not implicitly included in core completion.

## 9. Maintained documentation and agent discovery

Create a maintained `docs/cache/` reference directory alongside `docs/transport/`.
The cache reference covers evidence persistence, typed evidence and its freshness/dependency contracts, per-provider request budgets, operator decisions, command use,
and deployment as well as transport integration. Organize files around the changes
an agent needs to make, with a small entry point and focused contract documents.
The paths below are planned files; add working links when the files are created.

| Document | Authoritative content |
| --- | --- |
| `docs/cache/README.md` | Entry point: purpose, terminology, architecture, portable prefill and runtime admission, command/configuration reference, deployment modes, and links to detailed contracts and implementation entry points. |
| `docs/cache/storage.md` | Evidence-only typed schema, descriptive component membership, input/header references, retrieval eligibility and clock skew, TUF state, operator decisions, validated import/export, atomic transactions, bounds, and current verification after every restart. Retain one complete NearCloud YAML example and a compact provider-difference table. |
| `docs/cache/operator-decisions.md` | `--update-whitelist` interactive selection, proposal generation and explicit apply, exact subject scope, supported/unsupported and elevated-risk classes, acknowledgements, retained checks, diagnostics, decision deployment/removal, and interactions with retained restrictive measurement configuration and other policy controls. |
| `docs/cache/testing.md` | Request-count methodology and scenario budgets, live/prefill equivalence, concurrency and persistence-failure coverage, commands to reproduce checks, and links to actual regression tests. |

### 9a. Ownership and cross-references

Keep runtime authorization scope, construction/publication, acquisition, TLS/E2EE
key-use lifetime, eviction, and invalidation effects authoritative in
`docs/transport/`. Retry eligibility remains in `docs/transport/retries.md`. Cache
references describe how persisted material enters that shared machinery and link
to those contracts instead of maintaining another copy of them.

`docs/cache/storage.md` owns portable-record eligibility, dependency validation,
atomic file replacement, and policy-preserving transactions. The transport reference
links there for admission prefill and explains that runtime authorizations end at
process exit. Storage links to the transport's live scope and invalidation contracts;
do not duplicate those rules or specify cross-restart authorization behavior.

Keep provider-specific routing, gateway/backend boundaries, evidence limitations,
and public-key semantics in the provider references. Those documents link to the
shared cache and transport contracts and identify provider-specific applicability.
Cache examples illustrate these differences without creating independent provider
specifications. Create `docs/providers/venice/venice_support.md` for both dstack and
ACI/1, including configuration, endpoints, routing, evidence, gateway/backend trust
boundaries, E2EE/custody, supply-chain provenance, factor exemptions, cache capability
matrix, and tests. Link it from the cache entry point and retain a link to the
[Venice ACI gap analysis](../attestation_gaps/venice_aci_gateway.md). Do not describe unimplemented decision classes as supported behavior. Create `docs/providers/chutes/chutes_support.md` with the same
coverage, plus chute/instance routing, ML-KEM key binding, consumable nonce ownership,
measurement decisions, and the lack of client image-provenance evidence. Link its
[sek8s gap analysis](../attestation_gaps/sek8s_integrity.md). Both references must
clearly distinguish current runtime behavior, blocked cache capabilities, and
post-migration contracts. Document the migration prerequisite in the cache support
matrix and agent entry points. State that PhalaCloud and NanoGPT are not planned;
do not create cache integration requirements for them.

### 9b. Agent discovery and repository entry points

Update [AGENTS.md](../../AGENTS.md) when the reference files are introduced. Add a
short task-to-reference mapping to its directory/documentation guidance:

| Change being made | Required reference entry point |
| --- | --- |
| HTTP/TLS transport or runtime authorization | `docs/transport/README.md` |
| Evidence reuse, cache schema, persistence, or `teep cache` | `docs/cache/README.md` |
| Portable prefill and fresh admission after restart | Both cache and transport entry points |
| Operator pins or policy exceptions | `docs/cache/operator-decisions.md` and the applicable provider policy reference |

Mirror relevant guidance in [.github/instructions](../../.github/instructions/)
so code review uses the same contracts. Keep these instructions short and link to
the authoritative documents rather than embedding their detailed rules.

Update [README.md](../../README.md) with setup and basic cache-command examples.
Update [README_ADVANCED.md](../../README_ADVANCED.md) with the shared admission,
prefill, and transport architecture and links to both reference directories. Update
[provider documentation](../providers/) for supported cache scope and limitations,
and [API support](../api_support.md) if endpoint or encryption behavior changes.
Keep configuration examples and CLI help consistent with the maintained command
reference. Give each cache document a clear scope and a link back to its entry point;
use stable descriptive headings and links to relevant source files and tests so an
agent can locate the implementation without reading this plan or discussion history.

### 9c. Phase requirements and completion checks

Update maintained references with each phase's actual contracts, tests, supported
inputs, and limitations. Planned options stay in this plan until implemented; do
not present them as usable commands in reference documentation. Provider references
must identify migration blockers rather than suggesting incomplete cache support.

| Phase | Documentation delivered or updated in the same commit |
| --- | --- |
| 0 | Establish `docs/cache/README.md` and `testing.md`, reproducible counting methodology, fixture links, and AGENTS.md discovery links. |
| 1 | Document shared live collection/evaluation and candidate construction; cross-reference transport ownership, lifetime, publication, and invalidation. Defer portable interfaces to concrete adapters. |
| 2 | Create/update `storage.md` for strict evidence schema, identities, dependency resolution, rejected approval fields, trusted imports, bounds, and secure transactions. |
| 2a | Document supported live compose syntax, complete component coverage, literal-default authentication and its override limitation, and required-versus-diagnostic retrieval. Update affected provider references and regression links. |
| 3 | Document concrete prefill/export interfaces, NEAR software sharing, independent consumer evaluations, envelope handling, and parity with Phase 2a's live component coverage and binding classifications. |
| 3a | Publish supported NEAR software-only cache/serve/verify use, common path resolution, `--no-cache`, capture/replay inputs and isolation, mixed-provider behavior, partial failures, and exact software request savings. State remaining live dependency work and unavailable capabilities. |
| 4 | Document Intel/AMD material applicability, header-delivered dependencies, freshness/revocation rules, sharing, and regression tests. |
| 5a | Document authenticated historical TUF checkpoints, partial transitions, key epochs, reconciliation, protected dependencies, and restart limits. |
| 5b | Document current TUF eligibility, bounded refresh, request counts, concurrent transitions, and isolation from ambient caches. |
| 5c | Document Tinfoil release sets, matching-release discovery, TUF integration, direct/cloud scope, and the direct live-validation limitation. |
| 6 | Document NVIDIA JWKS trust and refresh rules, original retrieval-time handling, and retained report-bound NRAS work. |
| 7 | Document CT prefill across all client owners, bootstrap/refresh rules, independent result/material lifetimes, SCT-only TLS assurance, retained live TLS checks, and counting coverage. |
| 8 | Extend command/provider documentation to complete initial scope and dependency prefill, including Tinfoil, complete core YAML examples, and measured request budgets. Update setup/help/configuration and provider links. |
| 9 | Create/update `operator-decisions.md` for supported exact classes, prerequisites, effective policy, decision consumption, retained failures, and upgrade/withdrawal semantics. Update AGENTS.md and affected review instructions when exceptions become usable. |
| 10 | Publish interactive/proposal/withdrawal workflows, reasons, revision conflicts, partial/shared scope, deployment instructions, and replacement of automatic config-editing options while retaining restrictive measurement-policy input. Keep help and configuration examples consistent. |
| 11 | Document autocache opt-in, admission/export boundary, bounded asynchronous writes, errors, policy-preserving transactions, and restart budgets. |
| Conditional extensions | Update provider capability matrices and per-class decision references with their implementing commits. Add newly supported examples, budgets, regression links, and security/review rules without changing the core contracts implicitly. |

Before completing the implementation, check that all references are reachable from
AGENTS.md and the repository entry points, links and test names resolve, YAML and CLI
examples match the implemented schema and flags, and each shared rule has one
authoritative home. Verify that the cache and transport descriptions agree on
fresh admission after restart, lifetime, and invalidation. Keep measured run output in test artifacts;
the maintained docs describe contracts, methodology, and supported behavior.

At implementation completion, add the existing NEAR compose-default/runtime-override
gap to [dstack integrity](../attestation_gaps/dstack_integrity.md), as specified in
Section 2b-i, and align its image-authentication claims with that limitation.

At implementation completion, mark this plan as completed design context and link
to the maintained cache and transport entry points. Those references must be
sufficient for subsequent code changes without consulting the plan. Do not retain
unimplemented designs as statements of current behavior or turn the plan into a
running implementation/validation log.

## 10. Discussion sources and remaining policy work

The applicable limitations and operator consequences are specified in
[release discovery](#resolving-authenticated-tinfoil-releases-on-a-miss),
[trust metadata reuse](#ct-and-sigstore-dependency-coverage),
[ordinary decision boundaries](#ordinary-decision-implementation-boundaries), and
[restart boundaries](#3c-restart-and-invalidation-boundaries). These sections define
the implementation requirements without a separate research-issues document or
additional CLI flags.

The following discussions provide source context; the requirements are specified
in this document:

- [#51](https://github.com/13rac1/teep/pull/51#issuecomment-4187937622): authenticate before caching; keep HTTP capture/replay separate.
- [#97](https://github.com/13rac1/teep/pull/97#issuecomment-4322899545): reduce repeated attestation work through caching and key reuse.
- [#118](https://github.com/13rac1/teep/issues/118#issuecomment-4984041862): provider-scoped repositories, signers, and operator decisions.
- [#127](https://github.com/13rac1/teep/pull/127#discussion_r3581356163): persist AMD certificate material and distinguish it from revocation freshness.
- [#134](https://github.com/13rac1/teep/issues/134): optional prompt-cache secret persistence, separate from public evidence.
- [#139](https://github.com/13rac1/teep/issues/139): measurement authority and Intel collateral enforcement prerequisites.
- [#140](https://github.com/13rac1/teep/issues/140): explicit policy authoring versus values authenticated under existing trust; noninteractive artifact deployment.
- [#143](https://github.com/13rac1/teep/pull/143#issuecomment-5387850387): avoid repeated GitHub retrievals and VPN/shared-IP rate limits. Latest-release enforcement is not a requirement of this plan.

Repository audit-status tracking and automatic advisory updates remain separate
work. The operator decision path is part of this plan. MR_SEAM and Intel collateral
exceptions must use the exact decision classes above, never an incidental weakening
of ordinary caching. Provider assertions of measurements require the
independent verification defined by the applicable policy.
