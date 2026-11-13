# ACI/1 Gateway: Attested Gateway, Unattested Inference Host

Venice, Phala Cloud and NanoGPT send some of their TEE models through one
shared, hardware-attested gateway that forwards each prompt to a separate
inference service. The gateway is well attested, but the machine that runs
the model is not attested to the client, so whoever operates that machine
can read prompts and responses. This document records the evidence, what
teep verifies and allows, and what remains for each provider.

## The Problem

A user who sends a prompt to one of these models gets a hardware-backed
guarantee about the gateway that forwards the prompt, not about the machine
that processes it. The gateway receives the user's traffic and forwards it
over its own connection to an inference service. The GPUs that answer
prove their identity fresh for each request, but nothing given to the
client proves which host they are in or what software drives them. Since
2026-11-12 the Venice response carries no GPU evidence at all (residual
exposure 10).

The three providers reach the gateway in different ways. Venice encrypts
each request to a key that only the gateway holds. Phala Cloud's clients
connect to the gateway directly. NanoGPT's clients connect to NanoGPT,
which then calls the gateway, so NanoGPT's own servers also see the
request.

## Impact

The operator of the inference host, and anyone who compromises that host,
can read every prompt and every response in plaintext. The gateway
decrypts the traffic by design: the gateway's evidence names no attested
backend, and the relayed GPU evidence proves only that real GPUs answered,
not which host holds them. On the gateway's TEE-only hostnames, the
measured gateway code verifies that each upstream runs in a TEE before it
forwards a prompt, but the client receives none of that upstream evidence.

What the user keeps bounds the exposure. The gateway is a genuine TDX CVM
that runs a measured compose manifest of digest-pinned images. Its keys
are issued by a pinned key-release authority to the pinned gateway
application, and its quote binds its signing key and the client's fresh
challenge. A network attacker, an attacker who holds only a WebPKI
certificate, and an unrelated tenant of the same key-release authority
cannot present the gateway's evidence.

For each provider, the remaining exposure is:

- **Venice:** the inference host operator, and Venice as the party that
  composes the attestation response. Venice's servers relay the encrypted
  request but cannot read it.
- **Phala Cloud:** the inference host operator. The client's TLS connection
  ends inside the gateway CVM.
- **NanoGPT:** the inference host operator and NanoGPT, whose servers
  receive the request in plaintext before they forward it to the gateway.

A provider can also choose the response format for each request, so a
model that today attests its own inference host can be answered with a
genuine gateway attestation (residual exposure 3).

---

## Technical Background

**The ACI/1 response.** An ACI/1 attestation carries `attestation.evidence`
(the TDX quote, the RTMR event log, the `app_compose` manifest, the
`key_custody` signatures, and a `downstream_tls_binding`), a
`workload_keyset` with its `workload_keyset_digest`, a `source_provenance`
block naming the source repository, and a `service_capabilities` block
whose `serving` field distinguishes an aggregator from a model endpoint.
The specification and its limits are in
[ACI/1 Specification: Assurance Limits and Deployment Requirements](aci_specification.md).

**Two response variants.** Venice relays the attestation with its own echo
fields (`nonce`, `model`, `upstream_model`, `verified` and others). Phala
Cloud and NanoGPT return the gateway's own form: no echo fields, and an
`all_attestations` list with one copy of the attestation. teep accepts that
list only when it holds exactly one entry equal to the top-level fields.

**Host-selected TLS binding.** The gateway terminates TLS for each of its
public hostnames inside the gateway CVM. Its keyset lists one TLS key for
each hostname (`tee.redpill.ai`, `inference.phala.com`, `api.redpill.ai`),
and `downstream_tls_binding` names the entry for the hostname that the
attestation request used: the key "clients of this deployment pin" (ACI/1
§4.2). The binding therefore shows which gateway hostname the gateway's
client used. It does not describe a hop from the gateway to the inference
host.

**TEE-only hostnames.** The measured gateway configuration lists
`tee.redpill.ai` and `inference.phala.com` as `tee_only_domains`. On those
hostnames the gateway sends a prompt only to an upstream it verified as a
TEE, and refuses the prompt otherwise (ACI/1 §1.2). `api.redpill.ai` is not
TEE-only; the gateway may route its requests to an upstream without a TEE,
unless the request carries `aci_verified` (ACI/1 §5.3).

**dstack identity.** A dstack application has an `app_id`. The gateway's
app id is recorded in the RTMR3 "app-id" runtime event, which makes it a
value the event-log replay authenticates against the quote: for a dstack
runtime event the replay recomputes the digest from `(event_type, event,
event_payload)` rather than trusting the declared digest, so the app id
cannot be free text that survives a passing replay. `MRConfigID` holds
`sha256(app_compose)`, which binds the compose manifest, and therefore the
pinned image digests, to the quote.

**dstack-KMS key custody.** Each workload key carries a two-signature
chain. The app key signs `{purpose}:{compressed kms_public_key}`, and the
KMS root signs `dstack-kms-issued:` || `app_id` || compressed app key. Both
are 65-byte recoverable secp256k1 signatures over keccak256 of the message.
Recovering the root from the second signature and requiring it to be an
accepted dstack-KMS root, together with requiring the recovered `app_id` to
be the authenticated gateway app id, ties a key to this gateway rather than
to any application the same KMS serves. dstack governs key release through
an on-chain `KmsAuth` contract that holds the KMS root identity and the
per-app authorization.

**Two REPORTDATA schemes.** The ACI/1 specification binds the
`workload_keyset_digest`, a statement digest over the whole keyset, into
REPORTDATA. This gateway instead uses the dstack layout, which binds the
keccak256-derived address of the signing key and the client nonce. The
difference decides which keyset fields are hardware-anchored and which are
self-asserted (residual exposure 7).

---

## Verification Surface

### Enforced and verified

- The gateway TDX quote: structure, Intel cert chain, signature, debug bit,
  event log replay against all four RTMRs, Proof of Cloud registration.
- `gateway_tee_reportdata_binding`: the quote's REPORTDATA binds the
  gateway's signing key (keccak256 address scheme) and the client nonce.
  Venice's E2EE authorization reads this factor for ACI/1; the core
  `tee_reportdata_binding` never passes.
- `aci_key_custody`: the workload keyset digest recomputes (SHA-256 over
  the JCS-canonicalized keyset), the signing key is a member of that
  keyset, the dstack-KMS custody chain verifies (the app key signs the
  key's derivation purpose, the KMS root signs the app key together with
  the gateway app id, and the recovered root must be an accepted dstack-KMS
  root), the app id is on the accepted list, a non-null keyset subject
  must restate that app id, and the keyset must not have expired. One pin
  set (`aci.GatewayPins`) serves the three providers. The app id is read
  from the RTMR3 "app-id" runtime event, so `gateway_event_log_integrity`
  authenticates it against the quote.

  The quote hardware-binds only the signing key and the client nonce. The
  rest of the keyset (`not_after`, `subject`, `tls_public_keys`) is
  self-asserted: the keyset digest is recomputed only against the same
  response, not against the quote. A keyset whose `not_after` is more than
  365 days after the verification time fails the check (ACI/1 §3.1). See
  residual exposure 7.
- `nonce_match` and `gateway_nonce_match`: a Venice-variant response must
  echo the client nonce exactly; one without the echo fails. A
  gateway-variant response, which carries no echoed nonce, passes only when
  the gateway quote's signature and certificate chain verify, its REPORTDATA
  binding verifies the client nonce and, when the GPU evidence carries a
  nonce, that nonce is the client nonce.
- `gateway_compose_binding`: the gateway publishes its `app_compose` and
  `sha256(app_compose)` matches the quote's MRConfigID. The manifest pins
  each image by sha256 digest. The policy (`aci.GatewayImages`) lists the
  images of the compose deployed on 2026-10-27 and 2026-10-29:
  `ghcr.io/dstack-tee/dstack-ingress`,
  `ghcr.io/redpill-ai/private-ai-launcher`,
  `ghcr.io/dstack-tee/dstack-verifier`,
  `ghcr.io/edgelesssys/privatemode/privatemode-proxy` and
  `prom/node-exporter`, all compose-pinned. The Privatemode proxy is
  Edgeless Systems' client for an upstream; teep verifies only its digest
  pin in the measured compose, not an attestation of its own. The Venice
  ACI/1 replay fixtures were captured in August 2026, when the compose ran
  `dstacktee/dstack-ingress`. That image is not in the policy, so their
  replay reports it as unrecognized in `provider_signer_recognition` and
  `component_signature_recognition`, which are allowed failures.
- The relayed NVIDIA evidence, when the response carries it: per-GPU cert
  chains and SPDM signatures verify, and the EAT nonce matches the client
  nonce. Since 2026-11-12 the Venice response carries none (residual
  exposure 10).

### Failed and allowed (`ACIDefaultAllowFail`)

Every core factor that describes the inference host: the twelve `tee_*`
factors, `measured_model_weights`, `event_log_integrity`,
`cpu_id_registry`, and the model-tier supply-chain factors. `cpu_gpu_chain`
fails because the GPUs cannot be bound to any attested CPU: the only
attested CPU is the gateway's, and the GPUs are not in it.
`aci_backend_named` fails because no attested evidence binds a backend for
the requested model: the gateway variant names no model, and the Venice
variant names one only as the provider's assertion, which the detail
repeats. `gateway_tee_measurement` is in the list too: teep checks the
gateway MRTD/MRSEAM against the dstack base allowlist
(`aci.GatewayMeasurementPolicy`, shared by the three providers), and a
gateway MRTD that is not in it fails the factor without blocking.
`nvidia_signature` and `nvidia_nonce_client_bound` are in the Venice list
(`VeniceACIDefaultAllowFail`), not in the shared ACI/1 list, because the
Venice response carries no GPU evidence (residual exposure 10). These
render as failed but allowed, so the gap stays visible in
every report; removing an entry from the list blocks every ACI/1 model of
the three providers.

---

## Detailed Gap Analysis

### Evidence: one shared gateway

- **Venice, 2026-08-25:** two models with different upstream vendors
  (`e2ee-glm-5-2-p` → z-ai/glm-5.2, `e2ee-gpt-oss-120b-p` →
  openai/gpt-oss-120b) present the same `workload_keyset_digest`, signing
  key, TLS keys for three gateway hostnames, compose manifest and TDX
  measurements; only the relayed GPU evidence differs.
  `TestVeniceACI_GatewayIdentityAcrossModels`
  ([Venice ACI/1 replay tests](../../internal/integration/venice_aci_test.go))
  asserts this for the checked-in captures.
- **Phala Cloud and NanoGPT, 2026-10-29:** the captures from
  `tee.redpill.ai` (`qwen/qwen3.8-27b`) and `nano-gpt.com`
  (`TEE/gemma-4-26b-a4b-uncensored`) carry the same keyset digest and the
  same `app_compose` (sha256 `aa767dbc…`).
  `TestVerifyRun_ConcurrentACIProviders`
  ([gateway ACI/1 replay tests](../../internal/integration/gateway_aci_test.go))
  verifies the three providers' captures against the one pin set.
- In every capture the attested VM reports `num_gpus: 0` while the response
  carries GPU attestation entries (relayed evidence),
  `service_capabilities.serving` is `"aggregator"`, and
  `source_provenance.repo_url` names `Dstack-TEE/private-ai-gateway`.

### Evidence: which gateway hostname each provider uses

The `downstream_tls_binding` of each capture names the gateway hostname
that the attestation request reached:

| Provider | teep connects to | Binding in the response | TEE-only hostname |
| --- | --- | --- | --- |
| Venice (2026-08-26) | `api.venice.ai` | `api.redpill.ai` | No |
| Phala Cloud (2026-10-29) | `tee.redpill.ai` | `tee.redpill.ai` | Yes |
| NanoGPT (2026-10-29) | `nano-gpt.com` | `api.redpill.ai` | No |

On 2026-10-29, requests from teep directly to each of the three gateway
hostnames received the binding for the hostname requested, and
`tee.redpill.ai` and `inference.phala.com` listed the same 22 models, a
subset of the 65 models of `api.redpill.ai`.

Venice and NanoGPT therefore fetched the attestation report through
`api.redpill.ai`, which is not TEE-only. The table shows only the hostname
used for the attestation request: teep cannot see which hostname a provider
uses for inference requests, or whether those requests carry
`aci_verified`. The Venice observation is from 2026-08-26 and can be out of
date.

### Residual exposure

1. **The inference host is unattested to the client.** The operator of the
   inference host can read prompts and responses in plaintext. This is the
   gap that the allowed core factors state on every report. On a TEE-only
   hostname the measured gateway code verifies the upstream before it
   forwards; on `api.redpill.ai` it may forward to an upstream with no TEE.
   teep fetches no attested sessions, so it receives no upstream evidence
   on either kind of hostname.
2. **The KMS root and gateway app id are trust on first use.** The accepted
   dstack-KMS root and gateway app id in `internal/provider/aci/keyset.go`
   were recovered from live attestations. Whoever controls those lists
   controls which key-releasing authority and which dstack app teep accepts
   as the gateway for the three providers. Corroborate the KMS root against
   the dstack KmsAuth registry (Phala publishes it on-chain) before
   extending it. The pair of the 2026-11-12 deployment (app id
   `89c51ab8…`, root `02a335ae…`) was read once from Phala's Base KMS
   contract at block 56,649,485: the contract registers the app id and
   pairs the root with the KMS CA key that the gateway quote measures. The
   pair of 2026-08-25 is not registered there. teep does not read the
   contract itself; the lists are still a pin.
3. **A provider can downgrade a dstack model to ACI/1 reporting.** teep has
   no authenticated binding from a model name to its expected attestation
   format, so the provider chooses the format per response and thereby
   selects the enforcement list (`config.MergedAllowFail` keys on the
   parsed format). A model that today attests its own inference host
   through the dstack format (Venice and NanoGPT serve such models) could
   instead be answered with a genuine gateway attestation, and teep would
   report it gateway-only. A third party cannot do this: passing the ACI/1
   list requires the real gateway's quote with the client nonce. Closing it
   needs a per-model expected-format pin.
4. **Gateway measurements change with each redeploy.** The gateway image is
   a dev channel (`dstack-dev-*`); RTMR0-2 change with each redeploy, so
   `gateway_tee_hardware_config` and `gateway_tee_boot_config` are allowed
   to fail. MRTD/MRSEAM come from the shared dstack base list, which
   changes only with a teep release; `gateway_tee_measurement` is allowed
   to fail until teep verifies an allowlist update without a release.
5. **The downstream TLS binding is reported, not compared.** teep reports
   the binding as `gateway_downstream_tls` metadata. For Venice and NanoGPT
   it names `api.redpill.ai`, a hostname teep does not connect to. The field
   sits under `attestation.evidence` and is covered by neither the keyset
   digest nor the custody chain, so it is a self-asserted claim.
6. **Gateway image provenance can be stricter.** The policy records the
   gateway images as `ComposeBindingOnly`: the digest pin in the measured
   manifest. Where an image has signed build provenance in a transparency
   log, a signed provenance entry would add signer identity checks; teep
   has not checked which of the current gateway images have it.
7. **Keyset metadata is not hardware-anchored.** The gateway REPORTDATA
   binds only the signing key and the client nonce, so `not_after`,
   `subject` and `tls_public_keys` are self-asserted. A party that can
   rewrite the response and re-serve teep's request to the genuine gateway
   (the provider that relays the response, or a TLS-position attacker who
   has defeated WebPKI and Certificate Transparency) can change `not_after`
   and recompute the digest without detection. This does not affect the
   confidentiality of Venice's E2EE: the E2EE key stays bound by
   REPORTDATA and by the custody chain, and per-request freshness is the
   REPORTDATA nonce. The `not_after` check is a rotation bound that holds
   against an honest gateway. Closing it requires the gateway to emit the
   ACI/1 specification REPORTDATA.
8. **The Phala Cloud TLS key is not compared with the keyset.** teep sends
   Phala Cloud requests over TLS to `tee.redpill.ai` with WebPKI and
   Certificate Transparency, but it does not compare the live certificate
   key with the keyset's `tee.redpill.ai` entry. An attacker who holds a
   certificate for that hostname that passes WebPKI and Certificate
   Transparency, and a network position, can therefore read the request. The keyset entry is also self-asserted
   (residual exposure 7). This closes in the authorization-store migration,
   which binds the live TLS key to the authorization.
9. **NanoGPT is an unattested hop.** NanoGPT's servers receive the request
   over TLS to `nano-gpt.com`, which no attestation covers, and forward it
   to the gateway. They see the plaintext and choose the gateway hostname.
   In the 2026-10-29 capture, NanoGPT fetched the attestation report
   through `api.redpill.ai`, which is not TEE-only; the hostname of its
   inference requests is not observed.
10. **The Venice response carries no GPU evidence.** The attackers are the
    operator of the downstream inference host and Venice, which builds the
    response. Since 2026-11-12 the Venice response leaves out the GPU
    evidence, so a prompt can be served on any machine, with or without
    confidential GPUs, and nothing in the evidence shows it. The user keeps
    the guarantee about the gateway and the key that teep encrypts to, and
    loses the proof that real GPUs answered the request. Nothing stops it
    today: teep reports the missing evidence on every Venice ACI/1 report
    and does not block. The live response of 2026-11-12 names a member
    `gpu_evidence_omitted` and has no `nvidia_payload`. `nvidia_signature`
    and `nvidia_nonce_client_bound` fail and are allowed to fail for Venice
    ACI/1 (`VeniceACIDefaultAllowFail`). They return to enforced when the
    response carries GPU evidence again. Phala Cloud and NanoGPT are not
    affected by this allowance.

---

## Remediation

### Implementation Options

**Provider-side: give the client the upstream evidence.** The only option
that closes residual exposure 1. The gateway records an attested session
for each verified upstream and can serve it (ACI/1 §8); a client can verify
the sessions before it sends and pin them with `aci_session_ids` (ACI/1
§5.3). Venice and NanoGPT must pass these sessions and the receipts on to
their own users for this to apply to them.

**Provider-side: use a TEE-only hostname.** Venice and NanoGPT can call the
gateway through `tee.redpill.ai` or `inference.phala.com`, or set
`aci_verified`, so that the measured gateway code refuses an upstream
without a TEE. This narrows residual exposure 1 for their users and does
not close it.

**Provider-side: emit the ACI/1 specification REPORTDATA.** Binding the
`workload_keyset_digest` rather than the signing-key address makes
`not_after`, `subject` and `tls_public_keys` hardware-anchored, which
closes residual exposure 7 and makes the keyset TLS key in residual
exposure 8 hardware-anchored.

**Provider-side: Venice-style E2EE for NanoGPT users.** If NanoGPT relays
an E2EE request to the gateway key unchanged, its servers no longer see the
plaintext (residual exposure 9). This depends on the gateway's E2EE
protocol and on NanoGPT.

**Verifier-side: bind the live TLS key for Phala Cloud.** Compare the live
certificate key of `tee.redpill.ai` with the keyset entry for that hostname
before any request bytes are sent, as part of the authorization. Addresses
residual exposure 8.

**Verifier-side: corroborate the KMS root and gateway app id on-chain.**
Reading the dstack `KmsAuth` contract corroborates both pins, and the
per-app authorization identifies the private-ai-gateway rather than a
tenant of the same KMS. Pin the contract address and chain id rather than
the root value. Read finalized state through a multi-RPC quorum, the trust
model teep already uses for Proof of Cloud. This must fail closed and be
governed like other online collateral: skipped under `--offline`, subject
to `allow_fail`, never a silent return to the stale pin. Addresses residual
exposure 2.

**Verifier-side: pin the expected attestation format per model.** A
per-model expected-format pin, from the model listing at startup or cached
alongside the report, that fails closed when a later response changes a
model to a weaker format. Addresses residual exposure 3.

**Verifier-side: signed provenance for the gateway images.** For each
gateway image with signed build provenance, add a signed provenance entry
in `internal/provider/aci/policy.go`. Addresses residual exposure 6.

### Deployment Priority

1. The live TLS key binding for Phala Cloud, because it is within teep's
   control and removes the WebPKI certificate as the only check on the
   Phala Cloud connection.
2. The KMS root and app id corroboration, because the pins are the trust
   anchor for every ACI/1 authorization of the three providers.
3. The per-model format pin, because it is within teep's control and
   prevents an assurance downgrade of models that attest their own host.
4. Signed provenance for the gateway images, a small policy change.
5. The provider-side items, which teep cannot schedule.

---

## References

- **ACI/1 specification:** [`spec/aci.md` at `dd333b24`](https://github.com/Dstack-TEE/private-ai-gateway/blob/dd333b24324a96468bc19137fbcf6c45aeecc366/spec/aci.md)
- **Specification limits:** [ACI/1 Specification: Assurance Limits and Deployment Requirements](aci_specification.md)
- **Related teep assessment:** [dstack_integrity.md](dstack_integrity.md)
- **Provider documents:** [Phala Cloud](../providers/phalacloud/phalacloud_support.md), [NanoGPT](../providers/nanogpt/nanogpt_support.md)
- **ACI/1 parsing and custody verification:** `internal/provider/aci/aci.go`, `internal/provider/aci/keyset.go`
- **Gateway image and measurement policy:** `internal/provider/aci/policy.go`
- **Replay coverage:** [Venice ACI/1 replay tests](../../internal/integration/venice_aci_test.go), [gateway ACI/1 replay tests](../../internal/integration/gateway_aci_test.go)

---

## Teep Status

**Gateway evidence:** Verified and enforced for the three providers. The
gateway TDX quote, `gateway_compose_binding`, `gateway_event_log_integrity`,
`gateway_tee_reportdata_binding` and `aci_key_custody` run fail-closed. An
ACI/1 response with an empty `evidence.quote` is rejected at the parser,
and a report with no verified gateway TDX result fails `evidence_verified`,
which no `allow_fail` entry can suppress.

**Host evidence:** The twelve core `tee_*` factors,
`measured_model_weights`, `event_log_integrity`, `cpu_id_registry`,
`cpu_gpu_chain`, `aci_backend_named` and the model-tier supply-chain factors
are in `ACIDefaultAllowFail`, which an ACI/1 response selects for Venice,
Phala Cloud and NanoGPT; the Venice list adds `nvidia_signature` and
`nvidia_nonce_client_bound` (residual exposure 10). Their other formats
keep their own lists.

**E2EE:** `provider.GatewayBindsE2EEKey` returns true for Venice ACI/1 and
false for Venice dstack, so Venice's E2EE authorization reads the gateway
REPORTDATA factor for ACI/1 and the core factor for dstack. Phala Cloud
and NanoGPT have no E2EE in teep; their `tls_key_binding` detail reads
"provider uses E2EE key exchange", which does not describe them.

**Pending:** the live TLS key binding for Phala Cloud (residual exposure
8) in the authorization-store migration; E2EE for Phala Cloud and NanoGPT
after a check of the gateway's E2EE protocol. If a provider passes on
attested sessions, teep should verify them and move the core factors out of
the allow-fail list for the models they cover.
