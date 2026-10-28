# ACI/1 Specification: Gaps That No Deployment Can Close

> **Specification read:** `spec/aci.md` of
> [Dstack-TEE/private-ai-gateway](https://github.com/Dstack-TEE/private-ai-gateway)
> at commit
> [`dd333b24324a96468bc19137fbcf6c45aeecc366`](https://github.com/Dstack-TEE/private-ai-gateway/blob/dd333b24324a96468bc19137fbcf6c45aeecc366/spec/aci.md)
> (version `aci/1`, marked draft). Section numbers below refer to that text.

The Attested Confidential Inference specification (ACI/1) lets an inference
service prove which workload serves its API, and lets an aggregator prove
which upstream it verified before it forwarded a prompt. This document
records the properties that the specification itself does not define, so
that no conformant deployment provides them and no verifier can check them.
The gaps of one deployment, Venice's, are in
[Venice ACI/1: Attested Gateway, Unattested Inference Host](venice_aci_gateway.md);
this document covers only what a change of the specification must close.

## The Problem

ACI/1 gives a client a strong proof about the service it connects to: a
hardware quote binds the service's public keys and the client's fresh
challenge, and every later artifact refers back to those keys. When the
service is an aggregator, the prompt then leaves that service and runs on an
upstream service. For that second hop, the specification standardizes what
the aggregator must show, not what the client can check for itself.

Six areas follow from this. The upstream evidence a client can see is a
snapshot that the aggregator collected, not an answer to the client's own
challenge. A party in front of an aggregator that is not itself an ACI
service has no defined place in the protocol. The table that decides where
a prompt goes is not part of what the hardware measures. A service can serve
an older identity again, and a revoked one stays usable until each relying
party learns of it by means the specification leaves open. The authority
that releases the service's keys has no defined trust root. And the
specification states that it does not bind GPU evidence to the CPU, does not
identify models, and keeps no public record of receipts.

## Impact

**Security impact.**

- A client cannot detect that an upstream changed between the moment the
  aggregator verified it and the moment the client's prompt arrived. The
  aggregator's statement that it checked again is the only evidence.
- When an intermediary that does not run ACI sits in front of an
  aggregator, the end user cannot fetch receipts for their own requests,
  and the intermediary decides, outside any attested workload, which
  service and which attestation format answer each model.
- An aggregator whose code is attested can still be configured at runtime to
  send prompts to an upstream that no client has seen, because the routing
  table is data, not measured code.
- A service can present an older keyset of the same identity while it is
  unexpired, and a compromised keyset stays usable for each relying party
  until that party receives a deny-list by a channel the specification does
  not define.
- Every verifier takes the key-release authority's root on trust the first
  time it sees it, unless it finds a source outside the protocol.
- The relayed GPU evidence proves a genuine GPU, not that it serves the
  attested CPU workload; no claim identifies the model weights by a
  defined mechanism; and a service can deny or reorder receipts, because
  nothing records them outside the service.

Compensating controls: §3.1 bounds every keyset by `not_after`, §5.3 lets a
client require verified serving and pin the sessions it accepts, and §9.2
lets a client re-verify the evidence of a session. These narrow the
exposure; the sections below state what remains after them.

**Operational impact.** A verifier must supply the missing parts itself:
its own trust roots for key custody, its own deny-list channel, and its own
policy for which formats and services may answer a model. Two verifiers of
the same service can therefore reach different results from the same
evidence.

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
gets a signed **receipt** whose `upstream.verified` event cites the session
that served it (§7.5). A client can pin the sessions it accepts with
`aci_session_ids` (§5.3) and audit a session afterwards (§9.2).

### Assurance compared with direct dstack attestation

For a teep user, a full ACI/1 aggregator and a direct dstack attestation
differ as follows:

| Property | Direct dstack attestation | ACI/1 aggregator |
| --- | --- | --- |
| TEEs the prompt passes through | One: the workload that runs the model. | Two: the aggregator, then the upstream. Both must be trusted. |
| Evidence for the machine that runs the model | A quote that answers the client's nonce. | A session snapshot of evidence the aggregator collected; it does not answer the client's nonce (Gap 1). |
| Freshness of the service evidence | The client's nonce. | The client's nonce, bound through the §3.2 statement. |
| Key expiry | Not defined by dstack. | `not_after` in the hardware-bound keyset (§3.1, §3.2). |
| TLS keys | Not part of the attestation unless the provider adds a binding. | `tls_public_keys` in the hardware-bound keyset; a client pins the SPKI (§1.1). |
| Key custody | Per deployment. | Required for every listed key (§3.3). |
| Per-request record | None. | A signed receipt with hashes of the request, the forwarded bytes and the response (§7). |
| Verified serving | Not applicable: there is no second hop. | Fail closed per request when the endpoint is TEE-only or the request carries `aci_verified` (§1.2, §5.3). |

ACI/1 therefore adds auditable records and keyset rules, and moves the
upstream's evidence from a quote the client challenges to a snapshot the
aggregator vouches for. A **direct** ACI/1 service (`serving: "direct"`,
§4.1) has no second hop and keeps the one-TEE property of the left column
with the records of the right one.

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

**The gap.** No client nonce reaches the upstream. The evidence in a
session answers the aggregator's challenge at session creation, and the
specification defines no way for a client to obtain upstream evidence that
answers its own challenge, or that covers the round that admitted its
request.

**Consequence for a verifier.** A verifier that requires the machine running
the model to be fresh for the user's request cannot meet that requirement
through ACI/1 behind an aggregator: §9.2 step 4 tells it to reject the
snapshot. A verifier that accepts the snapshot accepts the aggregator's
statement that nothing changed since.

### Gap 2: No place for an intermediary that is not an ACI service

**What the specification defines.** The protocol has two roles on the
serving side: an ACI service and an aggregator, which "is itself the
client-facing workload" (§1.2). The `Authorization` header "binds the
receipt to this credential" (§5.1), and a receipt "is protected by the same
API key: present the key that made the request to fetch its receipt"
(§7.6). The attestation endpoint "is service-scoped: one report describes
the whole workload, not one model" (§4), and "Clients MUST NOT infer trust
from `/v1/models` entries" (§5).

**The gap.** A reseller that forwards requests to an aggregator under its
own API key is neither role. The specification does not define how such an
intermediary passes the report, the receipts or the sessions to its users,
and it defines no binding from a model name to the service and attestation
format that must answer it.

**Consequence for a verifier.** Behind a reseller, receipts bind to the
reseller's credential, so the end user cannot fetch them. The reseller
chooses, outside any attested workload, which service answers a model and
whether it answers with ACI/1 or another format, so it can answer a model
with a weaker format than before without a verifier being able to detect it
from the protocol. The TLS connection to the reseller is not in any keyset
(§1.1), so the protocol's channel binding ends before the reseller.

### Gap 3: The routing table is not part of the measurement

**What the specification defines.** ACI v1 "does **not** define routing
policy" (introduction) and standardizes the aggregator's "transparency
surface, not its routing policy" (§1.2). How the aggregator verifies an
upstream "is verifier-specific and out of scope" (§1.2). For a dishonest
service, "the fail-closed rule (§1.2) rests on the attested code" (§9.3
step 6), and §11 states that "Every guarantee is enforced by the measured
code itself."

**The gap.** The specification requires the code to be measured, but not
the configuration that tells that code which upstreams exist, which model
maps to which upstream, and which upstream verification policy applies. The
reference deployment shows the result: in the measured `app_compose` of the
gateway that teep observes, the `tee_only_domains` list is in the static,
measured gateway configuration, while the upstream table is seeded with
`[]`, pulled at runtime from a control-plane URL every 300 seconds, and
"managed at runtime via PUT /v1/admin/upstreams" (comments and
`gateway-config` in that compose file).

**Consequence for a verifier.** The quote shows which code runs and which
domains are TEE-only, but not where a prompt goes. An operator can add or
change an upstream without a new quote. On a TEE-only route the attested code
still verifies each upstream and records a session, so the client can audit
it afterwards (§9.2). On a route that is not TEE-only, the prompt can go to
an upstream without a TEE, and only the receipt's `required: false` records
it (§7.5).

### Gap 4: No rollback protection and no deny-list channel for keysets

**What the specification defines.** Members of one renewal family keep
continuity while unexpired, "even when its `not_after` is earlier than the
previous member's", and the section states: "This rule provides no
monotonic version or rollback protection" (§3.1). A verifier "SHOULD reject
an implausibly distant `not_after`" (§3.1), with no bound defined. To drop a
compromised workload, "a relying party deny-lists its stable identifiers
... or one specific keyset digest", and "How the list reaches verifiers ...
is up to the deployment" (§3.4).

**The gap.** The specification has no version number or counter that a
verifier can require to increase, no maximum lifetime for a keyset, and no
format or channel for a deny-list.

**Consequence for a verifier.** A service can present an older unexpired
member of its renewal family again, and a verifier cannot tell it from a
current one. A workload rolled back to an earlier accepted commit is a new
family that the verifier's provenance policy accepts unless that policy
pins the newer commit. A compromised keyset stays usable until its
`not_after`, unless the verifier has its own deny-list source, which each
verifier must build alone.

### Gap 5: No defined trust root for key custody

**What the specification defines.** Custody means the private key is
generated in, sealed to, or "released to it only after successful
attestation of an equivalent workload (for example by an attestation-gated
KMS)", and "Verifier policies MUST specify how custody is checked" (§3.3).
The trust roots belong to the verifier policy (§1.3). The specification
names dstack as the custody model of the reference implementation only in
its informative references (§12).

**The gap.** The specification does not define which key-release authority
a verifier should accept, where its root key is published, or how a
verifier authenticates that root.

**Consequence for a verifier.** For a dstack deployment, the KMS root is
recovered from the custody signature chain in the evidence. Without a
defined publication point, every verifier accepts that root on first use or
looks for a source outside the protocol. Whoever controls a verifier's
accepted root controls which authority it trusts to release every
service's keys.

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

**The gap.** These are stated limits, not omissions. The protocol defines
no CPU-GPU binding, no model identity, no mechanism for the weights claim,
and no external record of receipts.

**Consequence for a verifier.** GPU evidence can show genuine hardware and,
where the deployment relays it with the client's nonce, freshness, but not
that it belongs to the CPU workload the quote describes. A
`model_weights_provenance` claim has no defined evidence behind it, so a
verifier can treat it only as the stated `source`. A receipt proves what the
service signed, not when, and the service can withhold or reorder receipts
without a third party being able to see it.

---

## Remediation

### Implementation Options

**Gap 1: client-challenged upstream evidence.** Define an optional request
member that carries a client nonce through the aggregator to the upstream,
and an `upstream.verified` form that cites evidence bound to that nonce. A
lighter step: require `established_at` to be the evidence collection time,
and require a session for each verification round that authorizes a request,
so that the snapshot a receipt cites is the round that admitted it.

**Gap 2: intermediaries.** Define an intermediary role: it forwards the
service's report unchanged, passes receipt and session lookups through
for its own users' requests (or lets the service bind a receipt to a
user-held token in addition to the API key), and states in an attested or
signed document which service and format answer each model it lists.

**Gap 3: measured routing.** Require that the upstream table, the model to
upstream mapping and the upstream verification policy are either part of
the measured workload, or published as a content-addressed document whose
digest the receipt or the session cites, so that a client can see the
routing state that applied to its request.

**Gap 4: version monotonicity and deny-lists.** Add a monotonic keyset
generation number inside the hardware-bound keyset, with a rule that a
verifier rejects a lower number for the same family once it has seen a
higher one. Define a maximum `not_after` distance. Define a deny-list
document format and a discovery location, or a binding to a transparency log.

**Gap 5: custody trust root.** Define, per custody mechanism, where the
authority's root is published and how a verifier authenticates it. For the
dstack KMS, the on-chain `KmsAuth` registry is a candidate: name the
contract and chain in the evidence, and specify which registry state a
verifier must read.

**Gap 6: stated limits.** Bind a published GPU-to-CPU binding extension when
one exists; define a model identifier and the evidence that
`model_weights_provenance` requires (for example a model-signing format);
and make the SCITT transparency-log binding normative for receipts.

### Deployment Priority

1. Gap 3 (measured routing): it only requires that existing configuration
   become measured or content-addressed, and it closes the case where an
   attested aggregator sends prompts to an upstream no client has seen.
2. Gap 4 (generation number and deny-list format): the generation field is
   small, and a common deny-list format lets verifiers share revocations.
3. Gap 5 (custody trust root): each verifier otherwise repeats a
   trust-on-first-use decision for the same authority.
4. Gap 2 (intermediaries): it needs a new role in the protocol.
5. Gap 1 (client-challenged upstream evidence): it changes the request path
   of every aggregator and upstream.
6. Gap 6: depends on GPU binding, model signing and transparency log work
   outside ACI.

---

## References

- **Specification:** [ACI/1, `spec/aci.md` at `dd333b24`](https://github.com/Dstack-TEE/private-ai-gateway/blob/dd333b24324a96468bc19137fbcf6c45aeecc366/spec/aci.md)
- **Reference gateway source:** [Dstack-TEE/private-ai-gateway](https://github.com/Dstack-TEE/private-ai-gateway)
- **dstack KMS and custody model:** [Dstack-TEE/dstack](https://github.com/Dstack-TEE/dstack)
- **Standards named by the specification:** [RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785), [RFC 9334 (RATS)](https://www.rfc-editor.org/rfc/rfc9334), [RFC 9458 (Oblivious HTTP)](https://www.rfc-editor.org/rfc/rfc9458), [RFC 9943 (SCITT architecture)](https://www.rfc-editor.org/rfc/rfc9943)
- **Deployment-level analysis:** [Venice ACI/1: Attested Gateway, Unattested Inference Host](venice_aci_gateway.md)
- **Related gaps:** [Hardware Attestation Binding Issues and Mitigations](gpu_cpu_binding.md), [Model Weight Authentication](model_weights.md)

---

## Teep Status

teep verifies ACI/1 responses for Venice today
(`internal/provider/venice/aci.go`, `internal/provider/venice/keyset.go`).
Its behavior for each gap:

- **Gap 1:** teep fetches no sessions or receipts. It verifies the
  aggregator's quote, and it enforces `nvidia_signature` and
  `nvidia_nonce_client_bound` on the GPU evidence that the deployment relays
  with the client's nonce. No CPU evidence of the upstream reaches teep, so
  the core `tee_*` factors fail and are allowed by default
  (`VeniceACIDefaultAllowFail`).
- **Gap 2:** teep has no per-model binding to an expected attestation
  format; the response format selects the allow-fail list. This is residual
  exposure 3 of the [Venice document](venice_aci_gateway.md).
- **Gap 3:** teep cannot observe the routing table. It reports the measured
  gateway compose through `gateway_compose_binding`.
- **Gap 4:** teep checks `now < not_after` in `aci_key_custody`. It accepts
  the maximum `not_after` value as a keyset that never expires and applies
  no other upper bound, although §3.1 says a verifier "SHOULD reject an
  implausibly distant `not_after`". teep has no keyset generation tracking
  and no deny-list source.
- **Gap 5:** teep pins the dstack-KMS root and the gateway app id from live
  attestations (trust on first use); residual exposure 2 of the Venice
  document describes the on-chain corroboration that would replace it.
- **Gap 6:** `cpu_gpu_chain` and `measured_model_weights` fail and are
  allowed by default for ACI/1. teep keeps no receipt record.

teep's report for an ACI/1 response says which of these limits apply on
every request, because the allowed factors render as failed, not skipped.
When the specification closes a gap, teep can verify the new evidence and
move the matching factors out of the default allow-fail list.
