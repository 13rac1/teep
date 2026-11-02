# ACI/1 Specification: Assurance Limits and Deployment Requirements

> **Specification read:** `spec/aci.md` of Dstack-TEE/private-ai-gateway at
> commit
> [`dd333b24324a96468bc19137fbcf6c45aeecc366`](https://github.com/Dstack-TEE/private-ai-gateway/blob/dd333b24324a96468bc19137fbcf6c45aeecc366/spec/aci.md)
> (version `aci/1`, marked draft). Section numbers below refer to that text.

This document lists security properties that the attested inference
specification does not require. For each one, it states what the
specification defines, what a deployment must add to get the property, and
what a verifier cannot assume when the deployment does not add it.

## The Problem

ACI/1 gives a client a proof about the service it connects to: a hardware
quote binds the service's public keys and the client's nonce, and every
later artifact refers back to those keys. When the service is an
aggregator, the prompt then leaves that service and runs on an
upstream service. For that second hop, the specification standardizes what
the aggregator must show and what a client can inspect and pin, but not
every property a verifier may want.

The six gaps are independent of each other. They are in one document
because each has the same form: the specification does not require a
property, so a deployment that wants it must add it, and a verifier cannot
assume it without evidence that the deployment added it. The specification
does not require:

1. Upstream evidence that answers the client's own challenge.
2. A role for an intermediary that is not itself an ACI service.
3. Measurement of the routing configuration.
4. A monotonic order between keysets, or a deny-list format and channel.
5. A standard custody profile: which key-release authority to accept and
   how to authenticate its root.
6. CPU-GPU binding, model identity, or an external record of receipts. The
   specification states these limits itself.

## Impact

**Security impact.** Each item states the controls the specification gives
and what remains for a verifier that uses them.

- **Upstream evidence (Gap 1).** A client can list, fetch and re-verify an
  upstream's session evidence before it sends (§8.1, §9.2), and pin the
  sessions it accepts (§5.3). The evidence still answers the aggregator's
  challenge, not the client's. A verifier that requires upstream evidence
  collected for its own request cannot get it, and §9.2 step 4 tells it to
  reject the snapshot.
- **Intermediaries (Gap 2).** A conformant client sends sensitive data only
  over a channel bound to the attested keyset (§1.4 item 9): a pinned TLS
  SPKI or an attested E2EE key. A reseller's own TLS endpoint is not such a
  channel. A reseller that passes TLS through to the service, or forwards
  the service's E2EE unchanged, keeps the client on a bound channel, and
  the client can get the service's report (§4 defines no credential for it)
  and its sessions (which MAY be served without authentication, §8.1). What
  the reseller's users cannot get is the receipts of their requests: a
  receipt is fetched with the API key that made the request (§7.6), which
  is the reseller's.
- **Routing (Gap 3).** A client that verifies sessions before it sends and
  pins them with `aci_session_ids`, or sets `aci_verified`, is served only
  through upstreams that meet that constraint, or refused (§5.3, §9.1).
  The attested code enforces this (§9.3 step 6). For a client that uses
  neither control, the runtime routing data, which the quote does not
  measure, decides which upstream receives the prompt; on a route that is
  not TEE-only, that can be an upstream with no TEE.
- **Rollback and revocation (Gap 4).** Re-presenting an older renewal of
  the same keyset gives the same keys, provenance and family workload
  identifier with an earlier expiry. For dstack that identifier is only
  `sha256(app_compose)`: MRTD, RTMR0-2 and the TCB level can differ between
  members, so the renewal loses nothing only when the verifier's §9.1
  policy pins those values. A workload at an older accepted commit is a
  different family, and nothing in the specification orders families: a
  verifier rejects it only when its own policy pins the newer provenance or
  deny-lists the older one, and the deny-list reaches it by a channel the
  deployment must define (§3.4).
- **Custody root (Gap 5).** A verifier policy can preconfigure the
  key-release authority's root and must state how it checks custody
  (§1.3, §3.3). A verifier without such a configured root has no
  protocol-defined place to obtain or authenticate one.
- **Stated limits (Gap 6).** The relayed GPU evidence proves a genuine GPU,
  not that it serves the attested CPU workload; no claim identifies the
  model weights by a defined mechanism; and receipts have no external
  order or timestamp (§8.3, §11).

**Operational impact.** The specification leaves trust roots, custody
checks and revocation sources to each verifier policy by design (§1.3). A
verifier that needs one of the properties above must state it in its policy
and obtain the evidence from the deployment; two verifiers with different
policies can reach different results from the same evidence.

---

## Technical Background

### The ACI/1 chain

A service's identity is its **workload keyset**: the receipt-signing, E2EE
and TLS public keys, an optional `subject`, and an expiry `not_after`
(§3.1). The quote's `report_data` is the SHA-256 of a one-line statement
that names the keyset digest and the client's nonce (§3.2), so one
recomputation shows that the keyset is exactly what the hardware bound and
that the quote is newer than the client's challenge (§9.1 step 2). Private
keys must stay in TEE custody, and "Verifier policies MUST specify how
custody is checked" (§3.3).

An **aggregator** forwards prompts to **upstreams** (§1.2). It must verify
each TEE upstream before it serves and reach it only over the channel that
verification bound. A successful verification creates an **attested
session**: an immutable, content-addressed snapshot of the upstream's
identity, channel binding, typed claims and evidence (§8). Each request
gets a signed **receipt** with an `upstream.verified` event (§7.5): a
`verified` event cites the session admitted for the forwarding attempt, and
a `failed` event carries a `reason` and no session. Before it sends, a client can list the sessions that
currently back a model (§8.1), verify them (§9.2), and pin the ones it
accepts with `aci_session_ids` (§5.3).

### Assurance compared with direct dstack attestation

| Property | Direct dstack attestation | ACI/1 aggregator |
| --- | --- | --- |
| TEEs the prompt passes through | One: the workload that runs the model. | Two: the aggregator, then the upstream. The client must accept both. |
| Evidence for the machine that runs the model | A quote that answers the client's nonce. | A session snapshot of evidence the aggregator collected. The client can re-verify it before sending (§9.2), but it does not answer the client's nonce (Gap 1). |
| Choice of the machine that runs the model | The client connects to it. | The aggregator chooses. The client can restrict the choice to sessions it verified (`aci_session_ids`, §5.3). |
| Recency of the service evidence | The client's nonce. | The client's nonce, bound through the §3.2 statement. |
| Key expiry | Not defined by dstack. | `not_after` in the hardware-bound keyset (§3.1, §3.2). |
| TLS keys | Not part of the attestation unless the deployment adds a binding. | `tls_public_keys` in the hardware-bound keyset; a client pins the SPKI (§1.1). |
| Key custody | Per deployment. | Required for every listed key; the verifier policy states how it is checked (§3.3). |
| Per-request record | None. | A signed receipt with hashes of the request, the forwarded bytes and the response (§7). |
| Verified serving | Not applicable: there is no second hop. | Fail closed per request when the endpoint is TEE-only or the request carries `aci_verified` (§1.2, §5.3). |

ACI/1 therefore adds auditable records and keyset rules, and replaces the
upstream quote the client challenges with a snapshot the client can
re-verify and pin but not challenge. A **direct** ACI/1 service
(`serving: "direct"`, §4.1) has no second hop and keeps the one-TEE property
of the left column with the records of the right one.

---

## Detailed Gap Analysis

### Gap 1: Upstream evidence is a snapshot, not an answer to the client

**What the specification defines.** A session "is an immutable snapshot of
the verification used to establish that channel" (§8). A service "MAY reuse
an unexpired session when a successful verification establishes equivalent
channel material", and reuse "MUST NOT modify the session document" (§8).
`established_at` "records session creation, not necessarily evidence
collection" (§8). For the deep audit, "Later revalidation is the
aggregator's assertion (§7.5)", and "A policy requiring independently
verifiable evidence from each authorizing round MUST reject a session
snapshot as insufficient" (§9.2 step 4). A verified event "does not
independently prove a later revalidation or reconstruct the verification
round that authorized a particular request" (§7.5).

**The gap.** The specification does not require or define upstream
evidence that answers a client's challenge. The evidence in a session
answers the aggregator's challenge at session creation, and no defined
mechanism gives a client evidence for the round that admitted its request.
Two consequences follow:

- The aggregator's own report describes the aggregator's workload (§4).
  §4.2 leaves other evidence to the verifier policy, so client-bound
  upstream evidence in the report is a deployment choice, not a protocol
  property. A deployment can relay it: Venice's ACI/1 response of
  2026-08-26 carried 8 upstream GPU entries whose EAT nonce is the client
  nonce; its response of 2026-10-30 carried no GPU evidence.
- A session's evidence is a snapshot whose collection time the client
  cannot learn: `established_at` "records session creation, not
  necessarily evidence collection" (§8), and the nonce that the upstream
  evidence binds is the aggregator's, not the client's.

**What a deployment must add.** A path that carries a client nonce to the
upstream and returns evidence bound to it, or one session per verification
round that authorizes a request (see Remediation).

**What a verifier cannot assume.** A verifier that accepts the snapshot
accepts the aggregator's statement that the upstream did not change after
the snapshot. Session pinning (§5.3) restricts which snapshot applies; it
does not make the evidence newer.

### Gap 2: No role for an intermediary that is not an ACI service

**What the specification defines.** The protocol has two roles on the
serving side: an ACI service and an aggregator, which "is itself the
client-facing workload" (§1.2). A client must "Send sensitive data only over
channels bound to the attested keyset" (§1.4 item 9). The `Authorization`
header "binds the receipt to this credential" (§5.1), and a receipt "is
protected by the same API key: present the key that made the request to
fetch its receipt" (§7.6).

**The gap.** The specification does not define a delegation or intermediary
role. A reseller that forwards requests to an aggregator under its own API
key is neither an ACI service nor an aggregator. Its own TLS endpoint is not
in any keyset (§1.1). A client stays on a bound channel only when the
reseller passes TLS through to the service or forwards the service's E2EE
unchanged (§1.4 item 9). The report and the sessions stay available to the
client from the service. No defined mechanism lets a user fetch a receipt
for a request that the reseller made under its own key (§7.6), or lets the
reseller pass receipts on.

**What a deployment must add.** The reseller must run as an attested ACI
service itself, or the protocol must define an intermediary role (see
Remediation).

**What a verifier cannot assume.** A verifier cannot treat an ACI/1 report
that a reseller relays as evidence about the reseller's channel. A verifier
on a bound channel through a reseller gets the report, the sessions and the
channel binding, but not the receipts: it cannot authenticate the response
or audit the upstream that served it. A verifier that sends over the
reseller's own TLS endpoint does so outside the specification.

### Gap 3: The routing configuration is not part of the measurement

**What the specification defines.** ACI v1 "does **not** define routing
policy" (introduction) and standardizes the aggregator's "transparency
surface, not its routing policy" (§1.2). How the aggregator verifies an
upstream "is verifier-specific and out of scope" (§1.2). Behind an
aggregator, the session list "shows which upstreams currently back a model.
Verify the ones you would accept (§9.2) before you send, and pin them with
`aci_session_ids` (§5.3)" (§9.1). For a dishonest service, "the fail-closed
rule (§1.2) rests on the attested code" (§9.3 step 6).

**The gap.** The specification requires the code to be measured, but it
does not require measurement of the configuration that tells that code
which upstreams exist, which model maps to which upstream, and which
upstream verification policy applies. The reference deployment keeps that
configuration outside the measurement:

- In the checked-in Venice capture of 2026-08-26
  ([`venice_aci_e2ee-gpt-oss-120b-p_20260826_010734`](../../internal/integration/testdata/venice_aci_e2ee-gpt-oss-120b-p_20260826_010734/responses/0001_api.venice.ai_api_v1_tee_attestation.body)),
  the measured `evidence.app_compose` (sha256 `21d93ac7…`) seeds the
  upstream table with `[]` (`docker_compose_file` lines 194-196), with the
  comment "then managed at runtime via PUT /v1/admin/upstreams" (line 193).
  The middleware "consults the control plane at `control_url`" (lines
  168-171), and `control_url` and `control_token` are `${VAR}` values that
  dstack injects and does not measure (lines 186-188). The August
  deployment therefore already depends on a control plane whose address is
  not measured. The `tee_only_domains` list is in the measured static
  configuration (line 189).
- A live observation of 2026-10-29, not checked in: the report of
  `tee.redpill.ai` (`GET /v1/aci/attestation`) had an `app_compose` of
  sha256 `aa767dbc886174737fcc77083851e3dbdea093b976404755a3f5a68c0d9e7992`.
  The line numbers below index the `docker_compose_file` member of that
  `app_compose`. It keeps the same empty seed and runtime administration
  (lines 283-287) and the same middleware `control_url` (lines 270-274).
  It adds an `upstream_pull` section that fetches the upstream
  configuration every 300 seconds (lines 256-261); the pull URL is a
  measured literal, and its token and the content it returns are not
  measured. The report is a public GET, so anyone can repeat the
  observation and compare the compose hash; a redeployed gateway answers
  with another hash.

**What a deployment must add.** A measured routing configuration, or a
content-addressed routing document that each session or receipt cites (see
Remediation).

**What a verifier cannot assume.** A client that pins verified sessions, or
sets `aci_verified`, depends on the routing configuration only for which of
its accepted upstreams serves it, or for a refusal. A client that does
neither cannot assume that the quote describes where its prompt goes: an
operator can add or change an upstream without a new quote. On a TEE-only
route the attested code still verifies each upstream and records a session
the client can audit afterwards (§9.2). On a route that is not TEE-only the
prompt can go to an upstream without a TEE. The receipt then records an
`upstream.verified` event with `result: "failed"`, a `reason` and no
`session_id` (§7.5). `required: false` alone is not that marker: it states
that the policy did not demand verification, and it also appears on
best-effort serving through a verified session.

### Gap 4: No order between keysets, and no deny-list channel

**What the specification defines.** A renewal "changes only `not_after`
within the family" (§3.1). Two reports are in one renewal family exactly
when their keysets are identical apart from `not_after`, and their
`tee_type`, source provenance and policy-verified measured workload are
equal (§3.1). A fresh verification of a same-family keyset "keeps continuity
while that keyset is unexpired, even when its `not_after` is earlier than
the previous member's", and "This rule provides no monotonic version or
rollback protection" (§3.1). A verifier "SHOULD reject an implausibly
distant `not_after`" (§3.1), with no bound defined. To drop a compromised
workload, "a relying party deny-lists its stable identifiers ... or one
specific keyset digest", and "How the list reaches verifiers ... is up to
the deployment" (§3.4).

**The gap.** Two cases differ:

- **Renewal rollback within a family.** A service presents an older,
  unexpired renewal. It has the same keys, provenance and family workload
  identifier; `not_after` is earlier. For dstack the family compares only
  `sha256(app_compose)` (§3.1): MRTD, RTMR0-2 (OS image and firmware) and
  the TCB level are not family identifiers and can differ between members.
  The renewal loses no confidentiality or integrity only when the
  verifier's §9.1 policy pins those values. With that policy, a renewal
  cannot carry a security signal: a key rotation or a change of
  provenance or compose produces a new family.
- **Security rollback.** A service presents a workload at an older commit,
  or with older keys. That is a different family. The specification
  defines no order between families, no maximum keyset lifetime, and no
  deny-list format or channel.

**What a deployment must add.** A provenance policy that names the minimum
accepted commit or measurement, a deny-list with a defined distribution
channel, and a bound on `not_after`.

**What a verifier cannot assume.** A verifier whose provenance policy
accepts both an older and a newer commit accepts the older workload. A
compromised keyset stays usable until its `not_after` for every verifier
that has not received a deny-list entry for it.

### Gap 5: No standard custody profile

**What the specification defines.** Custody means the private key is
generated in, sealed to, or "released to it only after successful
attestation of an equivalent workload (for example by an attestation-gated
KMS)", and "Verifier policies MUST specify how custody is checked ... for
example by validating a KMS signature chain published in the report's
evidence" (§3.3). The verifier policy holds "the TEE roots it trusts ... how
it checks key custody, and any platform-specific checks such as dstack KMS
validation" (§1.3). Under the dstack `tdx` policy, the evidence carries "KMS
`key_custody`" (§4.2).

**The gap.** The specification requires custody checking and lets a
verifier preconfigure the roots it trusts. It does not define a standard
custody profile: which key-release authority a verifier should accept for
a custody mechanism, where that authority publishes its root, and how a
verifier authenticates the root.

**What a deployment must add.** A published, authenticated root for its
key-release authority, for example in a registry that the evidence names.

**What a verifier cannot assume.** Two verifiers can check the same custody
chain against different roots. A verifier that takes the root from the
evidence itself, without a configured or independently authenticated root,
accepts whichever authority signed the chain.

### Gap 6: Limits that the specification states

**What the specification defines.** `gpu_attested` "attests the GPU exists
and is genuine. It does not by itself prove the GPU is bound to the serving
CPU TEE" (§8.3), and §11 lists the same limit. "How a verifier establishes
that GPU evidence is fresh and belongs to this channel is its own policy"
(§8.3). ACI v1 does not define "canonical model identifiers"
(introduction). The claim `model_weights_provenance` means "The served
weights match their claimed provenance" (§8.3), with no mechanism defined
that establishes it. §11: "No non-repudiation: `served_at` is
self-asserted, and nothing orders or timestamps receipts. Durable proof
needs an external transparency log." §12 names SCITT as "the anticipated
transparency-log binding".

**The gap.** These are stated limits, not omissions. The specification does
not require a CPU-GPU binding, a model identity, a mechanism for the weights
claim, or an external record of receipts.

**What a deployment must add.** A GPU-to-CPU binding extension, a model
signing format that the weights claim cites, and a transparency log for
receipts.

**What a verifier cannot assume.** GPU evidence can show genuine hardware
and, where the deployment relays it with the client's nonce, that it is
bound to the client's request, but not that it belongs to the CPU workload
the quote describes. A
`model_weights_provenance` claim has no defined evidence behind it, so a
verifier can treat it only as its stated `source`. A receipt proves what the
service signed, not when, and the service can withhold or reorder receipts
without a third party being able to see it.

---

## Remediation

### Implementation Options

**Gap 1: client-challenged upstream evidence.** Define an optional request
member that carries a client nonce through the aggregator to the upstream,
and an `upstream.verified` form that cites evidence bound to that nonce. A
smaller change: require `established_at` to be the evidence collection
time, and require a session for each verification round that authorizes a
request, so that the snapshot a receipt cites is the round that admitted it.

**Gap 2: intermediaries.** Define an intermediary role: it forwards the
service's report unchanged, passes receipt and session lookups through for
its own users' requests (or lets the service bind a receipt to a user-held
token in addition to the API key), and states in an attested or signed
document which service and format answer each model it lists.

**Gap 3: measured routing.** Require that the upstream table, the model to
upstream mapping and the upstream verification policy are either part of
the measured workload, or published as a content-addressed document whose
digest the receipt or the session cites, so that a client can see the
routing state that applied to its request.

**Gap 4: order and deny-lists.** The security rollback is between
families, so the remedy is an order between families: for example a
provenance sequence in the source provenance, with a rule that a verifier
rejects a family with a lower sequence once it has verified a higher one.
A generation number inside one family, excluded from the family comparison,
orders only renewals of the same family, which the analysis above finds
harmless under a policy that pins the measurements; it does not address
the gap. Define a maximum `not_after` distance. Define a deny-list
document format and a discovery location, or a binding to a transparency
log.

**Gap 5: custody profile.** Define, per custody mechanism, where the
authority's root is published and how a verifier authenticates it. For the
dstack KMS, the on-chain `KmsAuth` registry is a candidate: name the
contract and chain in the evidence, and specify which registry state a
verifier must read.

**Gap 6: stated limits.** Bind a published GPU-to-CPU binding extension when
one exists; define a model identifier and the evidence that
`model_weights_provenance` requires (for example a model-signing format);
and make the SCITT transparency-log binding normative for receipts.

### Deployment Priority

1. Gap 3 (measured routing): it requires only that existing configuration
   become measured or content-addressed, and it gives clients that do not
   pin sessions a view of where their prompts go.
2. Gap 4 (order and deny-list format): a common deny-list format lets
   verifiers share revocations; an order between families needs a
   provenance sequence that the deployment publishes.
3. Gap 5 (custody profile): without it, each verifier configures and
   authenticates the same authority's root on its own.
4. Gap 2 (intermediaries): it needs a new role in the protocol.
5. Gap 1 (client-challenged upstream evidence): it changes the request path
   of every aggregator and upstream.
6. Gap 6: depends on GPU binding, model signing and transparency log work
   outside ACI.

---

## References

- **Specification:** [ACI/1, `spec/aci.md` at `dd333b24`](https://github.com/Dstack-TEE/private-ai-gateway/blob/dd333b24324a96468bc19137fbcf6c45aeecc366/spec/aci.md)
- **Deployment evidence:** the measured gateway compose in
  [the Venice ACI/1 capture of 2026-08-26](../../internal/integration/testdata/venice_aci_e2ee-gpt-oss-120b-p_20260826_010734/responses/0001_api.venice.ai_api_v1_tee_attestation.body)
  (`evidence.app_compose`), and a live observation of 2026-10-29 of the
  public report of `tee.redpill.ai`, not checked in (`app_compose` sha256
  `aa767dbc886174737fcc77083851e3dbdea093b976404755a3f5a68c0d9e7992`)
- **Standards named by the specification:** [RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785), [RFC 9334 (RATS)](https://www.rfc-editor.org/rfc/rfc9334), [RFC 9458 (Oblivious HTTP)](https://www.rfc-editor.org/rfc/rfc9458), [RFC 9943 (SCITT architecture)](https://www.rfc-editor.org/rfc/rfc9943)
- **Deployment-level analysis:** [Venice ACI/1: Attested Gateway, Unattested Inference Host](venice_aci_gateway.md)
- **Related gaps:** [Hardware Attestation Binding Issues and Mitigations](gpu_cpu_binding.md), [Model Weight Authentication](model_weights.md)

---

## Teep Status

teep verifies ACI/1 responses for Venice
(`internal/provider/venice/aci.go`, `internal/provider/venice/keyset.go`).
The gaps of that deployment are in
[Venice ACI/1: Attested Gateway, Unattested Inference Host](venice_aci_gateway.md).
teep's behavior for each gap:

- **Gap 1:** teep fetches no sessions or receipts and pins no sessions. It
  verifies the aggregator's quote, and it enforces `nvidia_signature` and
  `nvidia_nonce_client_bound` on the GPU evidence that the deployment
  relays with the client's nonce. No CPU evidence of the upstream reaches
  teep, so the core `tee_*` factors fail and are allowed by default
  (`VeniceACIDefaultAllowFail`).
- **Gap 2:** teep has no per-model binding to an expected attestation
  format; the response format selects the allow-fail list. A provider that
  changes the format for a model therefore changes which factors teep
  enforces, without a protocol signal. This is residual exposure 3 of the
  [Venice document](venice_aci_gateway.md).
- **Gap 3:** teep does not use `aci_verified` or `aci_session_ids` and
  cannot observe the routing configuration. It reports the measured
  gateway compose through `gateway_compose_binding`.
- **Gap 4:** teep checks `now < not_after` in `aci_key_custody`. For
  Venice this `not_after` is self-asserted: the REPORTDATA binds the
  signing key and the client nonce, not the §3.2 statement, so the quote
  does not cover `not_after`, and a party that rewrites the response can
  change it (residual exposure 7 of the
  [Venice document](venice_aci_gateway.md)). teep accepts
  the maximum `not_after` value as a keyset that never expires and applies
  no other upper bound, although §3.1 says a verifier "SHOULD reject an
  implausibly distant `not_after`". teep has no provenance ordering and no
  deny-list source.
- **Gap 5:** teep pins the dstack-KMS root and the gateway app id that it
  took from live attestations (trust on first use); residual exposure 2 of
  the Venice document describes the on-chain corroboration that would
  replace it.
- **Gap 6:** `cpu_gpu_chain` and `measured_model_weights` fail and are
  allowed by default for ACI/1. teep keeps no receipt record.

teep's report for an ACI/1 response says which of these limits apply on
every request, because the allowed factors render as failed, not skipped.
When a deployment adds the evidence for a gap, teep can verify it and move
the matching factors out of the default allow-fail list.
