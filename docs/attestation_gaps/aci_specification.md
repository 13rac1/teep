# ACI/1 Specification: Assurance Limits and Deployment Requirements

> **Specification read:** `spec/aci.md` and `spec/e2ee-v2.md` of
> Dstack-TEE/private-ai-gateway at commit
> [`8d0018f81e8dbadfe7b733bb294a0350f82b338c`](https://github.com/Dstack-TEE/private-ai-gateway/blob/8d0018f81e8dbadfe7b733bb294a0350f82b338c/spec/aci.md)
> (version `aci/1`, marked draft). Section numbers below refer to that text.
> Gaps 1 to 6 were first read at commit `dd333b24`; the changes up to
> `8d0018f8` (a multipart constraint carrier, an E2EE v2 replay rule, and
> the publication of stream receipts at the protocol terminal) close none
> of them.

This document lists security properties that the attested inference
specification does not require. For each one, it states what the
specification defines, what a deployment must add to get the property, and
what a verifier cannot assume when the deployment does not add it.

## The Problem

Four kinds of party can attack a user of an attested AI service that passes
prompts on to other machines: the service operator, the operators of those
next-hop machines, a reseller between the user and the service, and anyone
who can intercept the user's connection. Through the gaps below they can
get prompts onto a next-hop machine that nobody checked recently or that the
service chose without proof, onto an older version of the service, or onto
a copy of the service whose key service the user cannot check. A user whose
client follows the protocol keeps encryption that ends only inside the
proven service, and can limit the next hop to machines that the client
checked itself; each gap below is something it does not keep.

## Impact

**Gap 1: the next-hop machine is checked only from time to time.**

- **Who:** the operator of a machine that the service passes prompts to.
- **What they do:** keeps serving from the machine after it changed, inside
  the period in which the service reuses its last check of that machine
  (one hour in the captures of 2026-10-31 and 2026-11-02).
- **What they get:** the user's prompts on a machine whose current state
  nobody checked.
- **What stops it today:** nothing in the protocol: the user can recheck
  the service's last check, but cannot ask the machine itself; only the
  service's own schedule of checks limits the period.

A deployment can pass on hardware evidence that answers the user's own
challenge (one passed on GPU evidence of this kind on 2026-08-26), but the
protocol does not require it.

**Gap 2: no role for a reseller.**

- **Who:** a reseller that buys the service under its own account, sells
  it to users, and ends their encrypted connection at its own server.
- **What they do:** decrypts each request and forwards it to the service.
- **What they get:** every prompt and answer of a user whose client sends
  through it.
- **What stops it today:** a client that follows the protocol refuses to
  send to a server outside the proof. A reseller that passes the
  encryption through reads nothing, but its users cannot fetch the
  service's signed record of each request, so they cannot prove that an
  answer was changed on the way.

**Gap 3: where a prompt goes is not part of the proof.**

- **Who:** the service operator, or whoever holds the credentials of its
  control service.
- **What they do:** changes the list of next-hop machines while the service
  runs; on 2026-10-29 the proven code loaded the list from the control
  service every 300 seconds.
- **What they get:** a user's prompt on any machine they choose, also a
  machine without TEE protection on a service address that does not
  require it.
- **What stops it today:** a client that checks the next-hop machines
  itself and allows only those, or that asks for TEE-protected machines
  only; the proven code then refuses every other machine.

**Gap 4: an older version can come back.**

- **Who:** the service operator.
- **What they do:** after a security fix, deploys an older version of the
  service that verifiers still accept and whose keys have not expired.
- **What they get:** users keep sending prompts to a version with the known
  defect.
- **What stops it today:** only a verifier that requires the fixed version.
  The protocol defines no order between versions and no way to publish a
  list of withdrawn versions or keys.

A leaked key also stays usable until its expiry for every verifier that has
not heard of the leak.

**Gap 5: no standard way to check the key service.**

- **Who:** anyone who runs the published service code on genuine TEE
  hardware under a key service of its own, and can intercept the user's
  connection to the service address.
- **What they do:** presents its own copy of the service, with keys that
  its own key service issued.
- **What they get:** a verifier that does not know which key service to
  expect accepts the attacker's keys, and the user's prompts go to the
  attacker.
- **What stops it today:** a verifier configured with the provider's key
  service. A verifier that remembers the key service it saw first is
  exposed only on that first contact.

**Gap 6: limits that the protocol states.**

- **Who:** the operator of the machine that runs the model.
- **What they do:** runs the model on a GPU that the proof does not tie to
  the checked machine, or with other model weights.
- **What they get:** the proof covers neither the work on the GPU nor which
  model answered, so the user cannot detect either change.
- **What stops it today:** nothing; the protocol states these limits.

The service's signed records of each request carry no independent time, so
the service can also withhold or reorder them without anyone seeing it.

**Gap 7: a streamed answer reaches the user before any signed record of it.**

- **Who:** a party that controls the service or its keys.
- **What they do:** changes a streamed answer while it is sent, or sends a
  forged answer and stops before its end.
- **What they get:** the content reaches the user before any signed
  statement about it exists.
- **What stops it today:** nothing before delivery. A client that fetches
  the signed record after the stream ends finds the change afterwards; a
  client that leaves the stream early has no record to check.

**Gap 8: the records of the next-hop machines have no size limit.**

- **Who:** the service operator.
- **What they do:** serves records of the next-hop machines that are large
  or many.
- **What they get:** a client that verifies them before sending pays for
  every record, or checks only some of them.
- **What stops it today:** only the client's own limit: the protocol sets
  none, and the list of records cannot be checked without the full record
  of each.

**Operational impact.** The protocol leaves the choice of trusted key
services, accepted versions and withdrawal lists to each verifier, so two
verifiers can reach different results for the same service.

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
  ([`venice_aci_e2ee-gpt-oss-120b-p_20260826_010734`](https://github.com/13rac1/teep/blob/2741df3874483ce1e9c0152f662c5e17cfdd2ea4/internal/integration/testdata/venice_aci_e2ee-gpt-oss-120b-p_20260826_010734/responses/0001_api.venice.ai_api_v1_tee_attestation.body)),
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

### Gap 7: A stream receipt exists only after the stream ends

**What the specification defines.** A receipt is "a signed, per-request
event log" (§7) whose `response.returned` event hashes the exact bytes
returned on the wire, including the framing of a stream (e2ee-v2 §8). It is
served by a separate endpoint (`GET /v1/aci/receipts/{id}`, §7.1). For a
streamed response, the gateway publishes the receipt when the stream
reaches its protocol terminal (§7.1). "Cancellation or failure can leave a
reserved id unpublished even if an error terminal was returned", and "A
receipt records the gateway's observed exchange; it does not prove client
delivery or model-generation completeness" (§7.1). E2EE v2 authenticates
each encrypted field with its AEAD tag; "Stream order and truncation are
checked against the signed ACI receipt over the complete wire bytes"
(e2ee-v2 §7).

**The gap.** The specification defines no authentication of a single chunk
or of a prefix of a stream. A client reads every chunk of a stream before
any signed statement about it exists, so the receipt check can find a
changed or forged stream only after delivery. A client that stops reading
a stream early has bytes that no receipt covers: the receipt of the full
stream hashes bytes it never received, and a cancelled stream may have no
receipt. Observed on 2026-11-13 on Phala Cloud (`qwen/qwen3.8-27b`): a
client that cut a stream after 4 seconds got HTTP 404 for the receipt
until it was served 25 seconds later, and its `response.returned` hash
matched no prefix of the received bytes.

**What a deployment must add.** A signature or a running hash for each
chunk, or a receipt for a cancelled stream over the bytes sent.

**What a verifier cannot assume.** A verifier cannot assume that streamed
content it has delivered is authentic: the receipt check is reactive, not
preventive. A verifier whose client leaves a stream early cannot check what
that client received.

### Gap 8: Session records have no size bound

**What the specification defines.** `GET /v1/aci/sessions/{session_id}`
returns one session with its full evidence, and the list endpoint returns
abbreviated entries that keep `evidence.digest` and drop `evidence.data`;
"An abbreviated entry does not hash to its id — fetch the full record to
verify (§9.2)" (§8.1).

**The gap.** The specification sets no bound on the size of a session
record or on the number of sessions that back a model, and defines no
paging. Observed on 2026-11-13 on Phala Cloud (`qwen/qwen3.8-27b`): the list
named 18 sessions, and the full record of one Chutes session was 4.2 MB.
Sessions that share one evidence bundle carry the same `evidence.digest`,
so one full record can stand for the bundle, but the specification does not
say so.

**What a deployment must add.** A bound on the record size and on the
number of sessions per model, or paging; and a statement that sessions with
the same `evidence.digest` share their evidence.

**What a verifier cannot assume.** A verifier that bounds what it fetches
verifies only part of the sessions that back a model. It cannot assume that
the sessions it did not fetch would pass, and it pins only the sessions it
verified.

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

**Gap 7: chunk authentication.** Define a signature or a running hash
over each chunk of a stream, which a client can check as it reads, or a
receipt that the gateway publishes for a cancelled stream over the bytes it
sent.

**Gap 8: session size.** Define a maximum record size and a maximum number
of sessions per model, or paging of the list; state that sessions with the
same `evidence.digest` share their evidence, so that one full record per
bundle suffices.

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
7. Gap 8 (session size): a bound and a statement about shared bundles;
   it changes no message.
8. Gap 7 (chunk authentication): it changes the stream format and the
   receipt.

---

## References

- **Specification:** [ACI/1, `spec/aci.md` at `8d0018f8`](https://github.com/Dstack-TEE/private-ai-gateway/blob/8d0018f81e8dbadfe7b733bb294a0350f82b338c/spec/aci.md) and [E2EE v2, `spec/e2ee-v2.md` at `8d0018f8`](https://github.com/Dstack-TEE/private-ai-gateway/blob/8d0018f81e8dbadfe7b733bb294a0350f82b338c/spec/e2ee-v2.md); Gaps 1 to 6 first read at [`dd333b24`](https://github.com/Dstack-TEE/private-ai-gateway/blob/dd333b24324a96468bc19137fbcf6c45aeecc366/spec/aci.md)
- **Deployment evidence:** the measured gateway compose in
  [the Venice ACI/1 capture of 2026-08-26](https://github.com/13rac1/teep/blob/2741df3874483ce1e9c0152f662c5e17cfdd2ea4/internal/integration/testdata/venice_aci_e2ee-gpt-oss-120b-p_20260826_010734/responses/0001_api.venice.ai_api_v1_tee_attestation.body)
  (`evidence.app_compose`), and a live observation of 2026-10-29 of the
  public report of `tee.redpill.ai`, not checked in (`app_compose` sha256
  `aa767dbc886174737fcc77083851e3dbdea093b976404755a3f5a68c0d9e7992`)
- **Standards named by the specification:** [RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785), [RFC 9334 (RATS)](https://www.rfc-editor.org/rfc/rfc9334), [RFC 9458 (Oblivious HTTP)](https://www.rfc-editor.org/rfc/rfc9458), [RFC 9943 (SCITT architecture)](https://www.rfc-editor.org/rfc/rfc9943)
- **Deployment-level analysis:** [ACI/1 Gateway: Attested Gateway, Unattested Inference Host](aci_gateway.md)
- **Related gaps:** [Hardware Attestation Binding Issues and Mitigations](gpu_cpu_binding.md), [Model Weight Authentication](model_weights.md)

---

## Teep Status

teep verifies the ACI/1 responses of Venice, Phala Cloud and NanoGPT
(`internal/provider/aci`). Phala Cloud answers with the canonical report of
`/v1/aci/attestation`; Venice and NanoGPT answer on a compatibility route
whose quote binds the signing key and the client nonce, not the §3.2
statement. The gaps of these deployments are in
[ACI/1 Gateway: Attested Gateway, Unattested Inference Host](aci_gateway.md).
teep's behavior for each gap:

- **Gap 1:** for Phala Cloud, teep lists the sessions of the model, fetches
  and audits a bounded set (`aci_session_verified`, enforced), pins the
  verified sessions on every request (`aci_session_ids`), and checks that
  each receipt cites a pinned session whose period holds `served_at`. The
  evidence is still a snapshot: it answers the gateway's nonce, not the
  client's. For Venice and NanoGPT teep fetches no sessions. Since
  2026-11-12 the Venice response carries no GPU evidence, so the GPU
  factors fail and are allowed for Venice.
- **Gap 2:** NanoGPT is the reseller case. It makes the gateway request
  under its own API key, so teep cannot fetch the receipts of NanoGPT
  requests. It did not forward E2EE v2 on 2026-10-30, so teep sends
  NanoGPT requests without E2EE by default and NanoGPT reads them.
- **Gap 3:** for Phala Cloud, the session pins limit routing to upstreams
  that teep verified. For Venice and NanoGPT teep cannot observe the
  routing configuration; it reports the measured gateway compose through
  `gateway_compose_binding`.
- **Gap 4:** teep ends an ACI/1 authorization at the keyset `not_after` on
  every route, and rejects a `not_after` more than 365 days ahead. For
  Phala Cloud the §3.2 statement binds `not_after`; on the compatibility
  route of Venice and NanoGPT it is self-asserted (residual exposure 7 of
  the [gateway document](aci_gateway.md)). teep has no provenance ordering
  and no deny-list source.
- **Gap 5:** teep pins the dstack-KMS roots and gateway app ids it accepts
  (`aci.GatewayPins`). The pair of the 2026-11-12 deployment was read once
  from Phala's KMS contract; teep does not read the contract itself
  (residual exposure 2 of the gateway document).
- **Gap 6:** `cpu_gpu_chain` and `measured_model_weights` fail and are
  allowed by default for ACI/1. teep verifies Phala Cloud receipts but
  keeps no record of them.
- **Gap 7:** teep checks the receipt of every Phala Cloud stream after it
  ends and ends the shared authorization on a failure; the check is
  reactive (residual exposure 12 of the gateway document). It holds a
  non-stream response until its receipt verifies.
- **Gap 8:** teep fetches the Phala model CVM bundles first, then Chutes
  bundles within its own bound of 8 MiB, and rebuilds the sessions of a
  fetched bundle from one full record; it pins only the sessions it
  verified.

teep's report for an ACI/1 response says which of these limits apply on
every request, because the allowed factors render as failed, not skipped.
When a deployment adds the evidence for a gap, teep can verify it and move
the matching factors out of the default allow-fail list.
