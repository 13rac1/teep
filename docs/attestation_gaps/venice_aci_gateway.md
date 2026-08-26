# Venice ACI/1: Attested Gateway, Unattested Inference Host

Venice's ACI/1 models (10 of 13 TEE models as of 2026-08) route through a
TEE-attested gateway, the `private-ai-gateway` CVM. The gateway is well
attested — hardware quote, measured compose manifest with digest-pinned
images, KMS-issued keys — but it is the only attested principal: no CPU
attestation of the machine that runs the model exists, and the encrypted
channel terminates inside the gateway. This document records the evidence
for that classification, what teep verifies and waives, and the residual
exposure.

## The Problem

A user who sends a prompt to a Venice ACI/1 model gets a hardware-backed
guarantee about the proxy that forwards the prompt, not about the machine
that processes it. The gateway decrypts the user's traffic and forwards it
over its own TLS connection to a downstream inference API. The GPUs that
answer are real and prove their identity fresh for each request, but
nothing proves which host they are in or what software drives them.

## Impact

The operator of the downstream inference host, and anyone who compromises
that host, can read every prompt and every response in plaintext. No
compensating control closes this. The end-to-end encryption terminates in
the gateway by design: the ACI/1 evidence exposes no mechanism to
re-encrypt to an attested backend, and the relayed GPU evidence proves
only that real Hopper GPUs answered, not which host holds them. This is an
architecture gap in the deployment, not a defect in teep's verification.

What the user does keep is worth stating precisely, because it bounds the
exposure. The gateway is a genuine TDX CVM running a measured compose
manifest of digest-pinned images. The key teep encrypts to is a member of
the gateway's KMS-issued keyset, bound to the gateway quote through
REPORTDATA and to the pinned dstack-KMS root and gateway app id through the
custody chain. Per-request freshness comes from the client nonce in
REPORTDATA. A network attacker, a WebPKI-position attacker, and an
unrelated tenant of the same KMS are all excluded. The exposure is to the
downstream host operator, and to Venice as the party that composes the
attestation response.

Two further impacts are provider-integrity rather than third-party risks.
A provider can select the response format per request, so a model that
today attests its own inference host can be answered with a genuine
gateway attestation and reported gateway-only (residual exposure 3).
Whoever controls the accepted KMS root and gateway app id lists controls
which key-releasing authority and which dstack app teep accepts as the
gateway (residual exposure 2).

teep states the gap on every ACI/1 report: the waived core factors render
as failed-but-allowed rather than absent, so a reader of any report sees
that the inference host is unattested.

## Technical Background

**The ACI/1 response.** An ACI/1 attestation carries `attestation.evidence`
(the TDX quote, the RTMR event log, the `app_compose` manifest, the
`key_custody` signatures, and a `downstream_tls_binding` for the hop the
gateway makes), a `workload_keyset` with its `workload_keyset_digest`, a
`source_provenance` block naming the source repository, and a
`service_capabilities` block whose `serving` field distinguishes an
aggregator from a model endpoint. This is a different wire format from the
dstack attestation Venice serves for its other models, and teep selects the
parser and the enforcement list from the format it finds in the response.

**dstack identity.** A dstack application has an `app_id`. The gateway's
app id is recorded in the RTMR3 "app-id" runtime event, which makes it a
value the event-log replay authenticates against the quote: for a dstack
runtime event the replay recomputes the digest from `(event_type, event,
event_payload)` rather than trusting the declared digest, so the app id
cannot be free text that survives a passing replay. `MRConfigID` holds
`sha256(app_compose)`, which binds the compose manifest — and therefore the
four pinned image digests — to the quote.

**dstack-KMS key custody.** Each workload key carries a two-signature
chain. The app key signs `{purpose}:{compressed kms_public_key}`, and the
KMS root signs `dstack-kms-issued:` || `app_id` || compressed app key. Both
are 65-byte recoverable secp256k1 signatures over keccak256 of the message.
Recovering the root from the second signature and requiring it to be an
accepted dstack-KMS root, together with requiring the recovered `app_id` to
be the authenticated gateway app id, is what ties a key to this gateway
rather than to any application the same KMS serves. dstack governs key
release through an on-chain `KmsAuth` contract that holds the KMS root
identity and the per-app authorization.

**Two REPORTDATA schemes.** The ACI/1 specification binds the
`workload_keyset_digest` — a statement digest over the whole keyset — into
REPORTDATA. Venice's gateway instead uses the dstack layout, which binds
the keccak256-derived address of the E2EE signing key and the client nonce.
The difference decides which keyset fields are hardware-anchored and which
are self-asserted, and it is the origin of residual exposure 7.

## Verification Surface

### Enforced and verified

- The gateway TDX quote: structure, Intel cert chain, signature, debug bit,
  MRTD/MRSEAM against the dstack base allowlist, event log replay against
  all four RTMRs, Proof of Cloud registration.
- `gateway_tee_reportdata_binding`: the quote's REPORTDATA binds the
  gateway's E2EE key (keccak256 address scheme) and the client nonce. E2EE
  authorization reads this factor for ACI/1 — the core
  `tee_reportdata_binding` never passes.
- `aci_key_custody`: the workload keyset digest recomputes (SHA-256 over
  the JCS-canonicalized keyset), the E2EE key teep encrypts to is a member
  of that keyset, the dstack-KMS custody chain verifies (the app key signs
  the key's derivation purpose, the KMS root signs the app key together with
  the gateway app id, and the recovered root must be an accepted dstack-KMS
  root), the app id is on an accepted-app-id list — so the chain identifies
  the private-ai-gateway, not merely a tenant of the same KMS — a non-null
  keyset subject must restate that app id, and the keyset must not have
  expired. The app id is read from the RTMR3 "app-id" runtime event, whose
  digest the event-log replay recomputes from its semantic fields, so
  `gateway_event_log_integrity` authenticates the value against the quote.

  What the quote hardware-binds is only the E2EE signing key and the client
  nonce. The rest of the keyset — `not_after`, `subject`,
  `tls_public_keys` — is self-asserted: the keyset digest is recomputed only
  against the same response, not against the quote. So `aci_key_custody`
  proves the E2EE key is the gateway's KMS-issued, hardware-bound key, and
  the expiry check is advisory (it holds against an honest gateway, not
  against one that rewrites `not_after` and recomputes the digest). See
  residual exposure 7.
- `gateway_compose_binding` (enforced): the gateway publishes its
  `app_compose` and `sha256(app_compose)` matches the quote's MRConfigID.
  The manifest pins its four images by sha256 digest
  (`dstacktee/dstack-ingress`, `ghcr.io/redpill-ai/private-ai-launcher`,
  `dstacktee/dstack-verifier`, `prom/node-exporter`); three of the four
  digests are present in the Sigstore transparency log.
- The relayed NVIDIA evidence: per-GPU cert chains and SPDM signatures
  verify, and the EAT nonce matches the client nonce (fresh, not replayed).

### Failed and waived (`VeniceACIDefaultAllowFail`)

Every core factor that describes the inference host: the twelve `tee_*`
factors, `measured_model_weights`, `event_log_integrity`,
`cpu_id_registry`, and the model-tier supply-chain factors. `cpu_gpu_chain`
fails because the GPUs cannot be bound to any attested CPU — the only
attested CPU is the gateway's, and the GPUs are not in it. These render as
failed-but-allowed so the gap stays visible in every report; removing an
entry from the list blocks every ACI/1 model.

## Detailed Gap Analysis

### Evidence: the attestation describes a shared gateway

Observed live on 2026-08-25 against two models with different upstream
vendors (`e2ee-glm-5-2-p` → z-ai/glm-5.2, `e2ee-gpt-oss-120b-p` →
openai/gpt-oss-120b); asserted continuously by
`TestVeniceACI_GatewayIdentityAcrossModels`
(`internal/integration/venice_aci_test.go`):

- The attested VM reports `num_gpus: 0` (16 vCPU, 32 GiB) while the
  response carries 8 Hopper GPU attestation entries — relayed evidence.
- Both models present identical gateway identity: the same
  `workload_keyset_digest`, signing key, TLS keys for three service
  domains, compose manifest, and TDX measurements. Only the relayed GPU
  evidence differs — each model's backend has its own GPUs.
- `evidence.downstream_tls_binding` pins `api.redpill.ai` — a downstream
  hop a backend would not have.
- `service_capabilities.serving` is `"aggregator"`.
- `source_provenance.repo_url` names `Dstack-TEE/private-ai-gateway`.

### Residual exposure

1. **The inference host is unattested.** The operator of the downstream
   host can read prompts and responses in plaintext. This is the gap the
   waived core factors state on every report. The downstream API
   (`api.redpill.ai`) is Phala's inference API, which teep models
   separately as the `phalacloud` provider — with per-instance attestation
   — but ACI/1 gives no way to connect this gateway's forwarding to a
   specific attested instance.
2. **The KMS root and gateway app id are trust-on-first-use.** The accepted
   dstack-KMS root and the accepted gateway app id in
   `internal/provider/venice/keyset.go` were recovered from live
   attestations of two models. Whoever controls those lists controls which
   key-releasing authority and which dstack app teep accepts as the gateway.
   Corroborate the KMS root against the dstack KmsAuth registry (Phala
   publishes it on-chain) before extending it.
3. **A malicious provider can downgrade a dstack model to ACI/1 reporting.**
   teep has no authenticated binding from a model name to its expected
   attestation format, so the provider chooses the format per response and
   thereby selects the enforcement list (`config.MergedAllowFail` keys on
   the parsed format). A Venice model that today attests its own inference
   host through the dstack format could instead be answered with a genuine
   ACI/1 gateway attestation, and teep would report it gateway-only —
   losing the host-attestation assurance while still passing. A third party
   cannot exploit this: passing the ACI/1 list now requires presenting the
   real gateway's quote (pinned app id and KMS root, REPORTDATA binding the
   client nonce), which only the gateway can produce. The residual is a
   provider-integrity downgrade of a specific model's assurance level.
   Closing it needs a per-model expected-format pin (from the model listing
   or trust-on-first-use), tracked as follow-up.
4. **Gateway measurements churn.** The gateway image is a dev channel
   (`dstack-dev-*`); RTMR0-2 change with each redeploy, so
   `gateway_tee_hardware_config` and `gateway_tee_boot_config` are waived.
   MRTD/MRSEAM (enforced) come from the shared dstack base list.
5. **The downstream TLS pin is reported, not verified.** The gateway
   attests the SPKI it pins for `api.redpill.ai`, but teep never dials that
   domain, so the report carries it as `gateway_downstream_tls` metadata.
   The field sits under `attestation.evidence` and is covered by neither
   the keyset digest nor the custody chain, so it is a self-asserted claim.
   Correlating it with the phalacloud provider's live SPKI would establish
   that the claim is currently accurate; it would not bind the gateway to
   that host, because a gateway that forwards elsewhere can still report
   the true pin.
6. **Gateway image provenance can tighten.** Rekor holds Fulcio provenance
   for `dstacktee/dstack-ingress` (built from Dstack-TEE/dstack-examples)
   and `dstacktee/dstack-verifier` (Dstack-TEE/dstack). The policy
   currently records the four gateway images as `ComposeBindingOnly` — the
   digest pin in the measured manifest; upgrading the two Dstack-TEE images
   to Fulcio-signed policy entries would add signer identity checks.
7. **Keyset metadata is not hardware-anchored.** Venice's gateway REPORTDATA
   binds only the E2EE signing key and the client nonce, so the
   `workload_keyset` fields other than that key — `not_after`, `subject`,
   `tls_public_keys` — are self-asserted (the keyset digest is recomputed
   only against the same response). A party that can rewrite the response
   and re-serve teep's request to the genuine gateway — the gateway operator,
   or a TLS-position attacker who has defeated WebPKI and Certificate
   Transparency — can change `not_after` and recompute the digest without
   detection. This does not affect the confidentiality claim: the E2EE key
   stays doubly bound (REPORTDATA plus the custody chain to the pinned KMS
   root and app id), and per-request freshness is the REPORTDATA nonce, not
   `not_after`. The `not_after` check is therefore a rotation bound that
   holds against an honest gateway, not a hardware-enforced expiry. Closing
   it requires Venice to emit the ACI/1 spec REPORTDATA (the statement digest
   over the whole keyset); no teep-side code closes it while the gateway
   uses the dstack REPORTDATA layout. A third party without a TLS position
   cannot reach it.

## Remediation

### Implementation Options

**Provider-side: attest the inference host and bind it to the forwarding
decision.** This is the only option that closes residual exposure 1. The
ACI specification's attested-session mechanism describes the shape — the
gateway establishes a session with a backend whose own attestation it
verified, and exposes that evidence — but no session evidence reaches
clients today. Until it does, a client cannot tell an attested backend from
an unattested one.

**Provider-side: expose the downstream instance identity.** A weaker but
much cheaper step. If the gateway reported which `phalacloud` instance it
forwarded to, a client could correlate that identity with the instance's
own attestation, which teep already verifies as a separate provider. This
narrows residual exposure 1 to the correctness of the correlation rather
than removing the gap.

**Provider-side: emit the ACI/1 specification REPORTDATA.** Binding the
`workload_keyset_digest` rather than the signing-key address would make
`not_after`, `subject` and `tls_public_keys` hardware-anchored, closing
residual exposure 7. No teep-side change closes it while the gateway uses
the dstack layout.

**Verifier-side: corroborate the KMS root and gateway app id on-chain.**
Reading the dstack `KmsAuth` contract corroborates both pins, and the
per-app authorization is the stronger anchor because it identifies the
private-ai-gateway rather than a tenant of the same KMS. Pin the contract
address and chain id rather than the root value: the address is immutable
and publicly auditable, and the root can rotate without a teep release.
Read finalized state through a multi-RPC quorum, the trust model teep
already uses for Proof of Cloud. This must fail closed and be governed like
other online collateral — skipped under `--offline`, subject to
`allow_fail`, never a silent fall-back to the stale pin. Addresses residual
exposure 2.

**Verifier-side: pin the expected attestation format per model.** A
per-model expected-format pin, from the model listing at startup or cached
trust-on-first-use alongside the report, that fails closed when a later
response changes a model to a weaker format. Addresses residual exposure 3.

**Verifier-side: tighten gateway image provenance.** Promote
`dstacktee/dstack-ingress` and `dstacktee/dstack-verifier` from
`ComposeBindingOnly` to Fulcio-signed policy entries in
`internal/provider/venice/policy.go`. Addresses residual exposure 6.

### Deployment Priority

1. The KMS root and app id corroboration, because the pins are the trust
   anchor for every ACI/1 authorization and are currently self-recovered.
2. The per-model format pin, because it is entirely within teep's control
   and prevents an assurance downgrade of models that attest their own host.
3. Image provenance for the two Dstack-TEE images, a small policy change.
4. The downstream TLS correlation, which yields a consistency check rather
   than a trust anchor.
5. The provider-side items, which teep cannot schedule.

## References

- **ACI specification and gateway source:** https://github.com/Dstack-TEE/private-ai-gateway
- **dstack, KMS and event-log semantics:** https://github.com/Dstack-TEE/dstack
- **dstack examples (ingress image provenance):** https://github.com/Dstack-TEE/dstack-examples
- **Phala inference API (the downstream hop):** https://api.redpill.ai
- **Related teep assessment:** [dstack_integrity.md](dstack_integrity.md)
- **ACI/1 parsing and custody verification:** `internal/provider/venice/aci.go`, `internal/provider/venice/keyset.go`
- **Gateway image policy:** `internal/provider/venice/policy.go`
- **Replay coverage:** `internal/integration/venice_aci_test.go`

---

## Teep Status

**Gateway evidence:** Verified and enforced. The gateway TDX quote,
`gateway_compose_binding`, `gateway_event_log_integrity`,
`gateway_tee_reportdata_binding` and `aci_key_custody` all run fail-closed.
An ACI/1 response with an empty `evidence.quote` is rejected at the parser,
and a report with no verified gateway TDX result fails `evidence_verified`,
which no `allow_fail` entry can suppress.

**Host evidence:** The twelve core `tee_*` factors,
`measured_model_weights`, `event_log_integrity`, `cpu_id_registry`,
`cpu_gpu_chain` and the model-tier supply-chain factors are in
`VeniceACIDefaultAllowFail`. They render as failed-but-allowed rather than
skipped, so every report states the gap. Removing an entry blocks every
ACI/1 model.

**E2EE:** `provider.GatewayBindsE2EEKey` returns true for Venice ACI/1 and
false for Venice dstack, so E2EE authorization reads the gateway REPORTDATA
factor for ACI/1 and the core factor for dstack.

**Pending:** If Venice exposes attested-session evidence or a downstream
instance identity, teep should verify it and move the core factors out of
the allow-fail list for the models it covers. The verifier-side remediation
items above are tracked independently of provider action.
