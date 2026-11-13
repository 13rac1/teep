# Plan: Shared ACI/1 Verification for Venice, Phala Cloud and NanoGPT

Status: approved with the operator decisions below; implementation in
progress, one commit per phase.

## Problem

Phala Cloud (`api.redpill.ai`, model `qwen/qwen3.8-27b`) and NanoGPT
(`nano-gpt.com`, model `TEE/gemma-4-26b-a4b-uncensored`) now answer the
attestation request with the ACI/1 gateway format. `formatdetect.Detect`
returns `aci/1`, and neither `phalacloud.ParseAttestationResponse` nor
`nanogpt.ParseAttestationResponse` has an ACI/1 case, so verification
fails with "unrecognized attestation format (no known format keys found)".
Venice verifies ACI/1 today in `internal/provider/venice` (`aci.go`,
`keyset.go`) with Venice-only pins and a Venice-only default allow_fail
list.

## Findings from the live attestations

Captured on 2026-10-27 with teep 95231cf plus the Chutes evidence bound
change (the ACI/1 code is that of main), with the operator's keys. Each
capture failed at parsing and was saved on error; it holds one response,
the attestation body. The captures are in
`/home/agent/Projects/hm/teep-live-tests/aci-shared-2026-10-27/captures/`:

| Provider | Model | Capture directory | captured_at (UTC) | Client nonce (prefix) |
|---|---|---|---|---|
| phalacloud | qwen/qwen3.8-27b | `phalacloud_qwen_qwen3.8-27b_20261027_000837` | 2026-10-27T00:08:37Z | 389ff5f5e1322777 |
| nanogpt | TEE/gemma-4-26b-a4b-uncensored | `nanogpt_tee_gemma-4-26b-a4b-uncensored_20261027_000910` | 2026-10-27T00:09:10Z | def9756015d3929a |

Both bodies were parsed with `venice.ParseAttestationResponse` and checked
with `venice.VerifyACIKeyset` (the Venice pins) in a temporary test that is
not committed.

1. **One gateway serves all three providers.** Both bodies name the same
   attested workload as the Venice ACI/1 fixtures of 2026-08-26:
   - workload keyset digest
     `sha256:df2a7cd6c1c6b697879f64f758c2dc378d6c60cde8aa272e9c536858466383f5`,
     identical in both bodies; signing address
     `0x79a5061efe5a46b0d1f33b11cf1c5adbedae6b79`.
   - gateway app id (RTMR3 `app-id` event) `fdb7a14e5a6675f752e2cb69c9067a98ca402918`,
     the value of `defaultACIGatewayAppIDAllow`.
   - dstack-KMS root recovered from the E2EE custody chain
     `0334c76e0c3f52ec64cbf9bbf5c910c272330166fd656c0a86bb330963e46910e1`,
     the value of `defaultACIKMSRootAllow`.
   - source provenance `https://github.com/Dstack-TEE/private-ai-gateway.git`
     commit `22d08e24129804c72b0bfce6f547636992a3f559`; `serving` is
     `aggregator`; `supported_e2ee_versions` is `["2"]`.
   - keyset TLS keys: `tee.redpill.ai` (spki `951885459fbd27ca…`),
     `inference.phala.com` (`32a2825658a7377a…`), `api.redpill.ai`
     (`8a90181d3d9e5a05…`); downstream TLS binding `api.redpill.ai`
     (`8a90181d3d9e5a05…`).
   - `VerifyACIKeyset` with the Venice pins passes for both: digest
     matches, signing key in keyset, custody chain to the accepted root for
     the accepted app id, keyset not expired.

   The pins therefore need no new trust-on-first-use values: the 2026-10-27
   captures of two more providers give the same values that Venice's
   captures of 2026-08-25 gave. This corroborates the pins; it does not
   replace the KmsAuth registry check that `keyset.go` asks for.

2. **The quote binds the client nonce.** `attestation.evidence.quote_report_data`
   is the signing address followed by the client nonce of the capture, and
   the relayed `nvidia_payload` carries the same nonce.

3. **The response shape differs from Venice's.** The Phala and NanoGPT
   bodies have no top-level `nonce`, `model`, `upstream_model`, `verified`,
   `tee_provider`, `tee_hardware`, `nonce_source`, `server_verification` or
   candidate counts, and they add `all_attestations`, a list of one ACI/1
   attestation object (`api_version`, `attestation`, `intel_quote`,
   `nvidia_payload`, `service_capabilities`, `signing_address`,
   `signing_algo`, `signing_public_key`, `workload_keyset_digest`). The
   Venice parser reports `all_attestations` as unknown and the other fields
   as missing.

4. **No echoed nonce.** `gateway_nonce_match` (enforced) reads the echoed
   nonce, so it fails with "gateway request_nonce absent" for these bodies,
   although `gateway_tee_reportdata_binding` (enforced) verifies the nonce in
   the quote's REPORTDATA.

5. **No model in the response.** The attestation does not name the model or
   the upstream model, so it does not show which backend serves the
   requested model. No teep factor compares the echoed model today.

6. **No E2EE in teep for Phala Cloud and NanoGPT.** Neither provider has an
   encryptor; requests go over WebPKI TLS to the provider's base URL. For
   Phala Cloud that host, `api.redpill.ai`, is a TLS key of the attested
   keyset. For NanoGPT, `nano-gpt.com` is not in the keyset: NanoGPT is an
   unattested hop in front of the gateway.

7. **`api.redpill.ai` is the gateway's own front door, not a hop to the
   inference host.** The measured gateway compose terminates TLS for every
   public hostname in the gateway CVM and routes them "by SNI to the same
   gateway listener"; the gateway "uses that Host to pick the matching
   `downstream_tls_binding`". The specification defines
   `downstream_tls_binding` as the keyset TLS entry "clients of this
   deployment pin" (ACI/1 §4.2). The gateway's static configuration lists
   `tee.redpill.ai` and `inference.phala.com` as `tee_only_domains`;
   `api.redpill.ai` is not TEE-only, so the gateway may route its requests to
   upstreams without a TEE.

## Operator decisions

1. **Pins:** one shared pin list for the gateway deployment (accepted KMS
   root, gateway app id), used by Venice, Phala Cloud and NanoGPT.
2. **Nonce:** `nonce_match` and `gateway_nonce_match` check the echoed nonce
   only. A gateway-variant response echoes none, so both fail visibly; its
   freshness rests on `gateway_tee_reportdata_binding`, and the GPU evidence
   nonce on `nvidia_nonce_client_bound` (revised 2026-10-31: the earlier
   rule passed both factors on the REPORTDATA binding, a second pass of an
   enforced factor).
3. **`all_attestations`:** exactly one entry, equal to the top-level fields;
   any other content fails the parse.
4. **Unnamed model:** a new factor, allowed to fail by default, that states
   that the attestation names no backend for the requested model.
5. **Host SPKI binding to the keyset TLS key:** recorded here and in the gap
   document as a gap until phase 7c, which moves Phala Cloud to the
   authorization store; no second pin path is added.
6. **E2EE for Phala Cloud and NanoGPT:** the final phase. A protocol check of
   the gateway's E2EE version against the Venice encryptor, made by reading
   the gateway source at the deployed commit, precedes it, and its result is
   reported before that phase is implemented.
7. **Gateway image policy:** `ghcr.io/dstack-tee/dstack-ingress` and
   `ghcr.io/dstack-tee/dstack-verifier` join the `ComposeBindingOnly` list;
   the `dstacktee/` names stay only while a deployed compose uses them.
   `ghcr.io/edgelesssys/privatemode/privatemode-proxy` is classified as
   compose-pinned, and the gap document states it.
8. **Phala Cloud route host:** the phalacloud base URL moves from
   `api.redpill.ai` to a TEE-only domain of the measured gateway
   configuration (`tee.redpill.ai` or `inference.phala.com`). The first live
   call with the key confirms that Phala's models are reachable there; the
   provider document records the change.
9. **Free text without an E2EE v2 field path (2026-10-30):** while E2EE v2
   is enabled, a request that carries `messages[].tool_calls`,
   `function_call`, `refusal` or `audio`, `prediction`, `tools`,
   `functions` or `response_format.json_schema` is refused before it is sent, with an
   error that names the field. `model`, `messages[].name` and `stop` pass in
   plaintext and are documented.
10. **Receipts (2026-10-30):** receipt verification is phase 7, for Phala
    Cloud and Venice ACI/1. NanoGPT keeps E2EE enabled by default,
    documented as confidentiality only: its receipts are bound to
    NanoGPT's API key.

## Design

One package, `internal/provider/aci`, holds the ACI/1 response types, the
strict parser, the JCS keyset digest, the custody chain verification and the
keyset checks. Venice, Phala Cloud and NanoGPT call it. Venice keeps its
REPORTDATA verifier, which the gateway quote uses for all three providers.

### Shared pins

```go
// Pins are the accepted identities of the ACI/1 gateway deployment.
type Pins struct {
	KMSRoots      []string // compressed secp256k1, hex
	GatewayAppIDs []string // RTMR3 app-id payload, hex
}
```

`aci.GatewayPins()` returns the one pin set of the Phala private-ai-gateway
deployment, as a copy, so that callers cannot change it. Each value keeps a
comment that names the captures it came from.

### Keyset expiry bound

A keyset whose `not_after` is more than 365 days after the verification time
fails `aci_key_custody`, as does the value that previously meant "never
expires". ACI/1 §3.1 says a verifier "SHOULD reject an implausibly distant
`not_after`"; the observed keysets expire 25 to 29 days after capture.

### Response variants

The parser accepts the Venice variant (dstack-compatible top-level fields)
and the gateway variant of finding 3 under strict decoding. Duplicate member
names fail both variants. Rules for the gateway variant:

- A present `all_attestations`, also a literal null, selects the gateway
  variant. It must hold exactly one entry, and that entry must equal the
  top-level attestation fields; any other content fails the parse.
- A field that the gateway variant does not define fails the parse, also a
  case-folded alias of a defined field.
- `nonce_match` and `gateway_nonce_match` of a gateway-variant response fail
  with the detail "no echoed nonce; freshness rests on
  gateway_tee_reportdata_binding". A Venice-variant response without its
  echoed nonce fails as before. The REPORTDATA comparison stays in
  `gateway_tee_reportdata_binding`.
- A new factor, `aci_backend_named`, passes only when attested evidence binds
  a backend for the requested model. No ACI/1 evidence does today, so it
  fails and its detail names the provider-asserted model and upstream model
  when the response has them. It is in the default allow_fail list of every
  ACI/1 provider.

### Transport

- Phala Cloud moves to a TEE-only domain of the gateway (decision 8).
- The live SPKI of the provider host is not compared with the keyset's TLS
  key in this plan (decision 5); the gap document records it.

### Default allow_fail

`VeniceACIDefaultAllowFail` becomes `ACIDefaultAllowFail`, the ACI/1 list of
all three providers in `providerFormatDefaultAllowFail`, with the new
unnamed-model factor added. Phala Cloud and NanoGPT have no E2EE until the
final phase; `aci_key_custody` and `gateway_tee_reportdata_binding` stay
enforced for all three.

### Gap document

`docs/attestation_gaps/venice_aci_gateway.md` becomes
`docs/attestation_gaps/aci_gateway.md`: the shared gateway, what teep
verifies, the residual exposure, then one section per provider (Venice:
E2EE to the gateway key; Phala Cloud: TLS to a TEE-only gateway host
without E2EE; NanoGPT: an unattested hop in front of the gateway). It
corrects the earlier description of `api.redpill.ai` as a hop to the
inference host (finding 7), records the host SPKI binding gap (decision 5)
and the compose-pinned privatemode proxy (decision 7), and links to the
specification gaps in `aci_specification.md`.

### Fixtures

The two captures above are pin provenance only: they were saved on error.
After phases 3 and 4, each model is recaptured with the new build and
`--capture` into `/home/agent/Projects/hm/teep-live-tests/<branch>-<date>/`.
A capture becomes a fixture only if teep exits 0, or the report is blocked
with the expected enforced failures only, and `teep verify --reverify`
exits 0. The key material scan runs before staging. Fixtures are named
`phalacloud_aci_<slug>_<ts>` and `nanogpt_aci_<slug>_<ts>`.

## Phases (one commit each, make check passes, >85% coverage of new code)

1. Move the ACI/1 types, parser, keyset and custody verification from
   `internal/provider/venice` to `internal/provider/aci`, with the shared
   `Pins`, and add the keyset expiry bound. Venice calls the package; its
   fixture reports do not change.
2. Accept the gateway response variant (finding 3): the `all_attestations`
   rule, the nonce evaluation of decision 2 and the unnamed-model factor of
   decision 4, with `ACIDefaultAllowFail`.
3. Phala Cloud: ACI/1 case in `ParseAttestationResponse`, the gateway
   REPORTDATA verifier in `verify/factory.go` and `proxy.fromConfig`, the
   shared keyset verification, the ACI/1 default allow_fail list, the
   gateway image policy of decision 7, the TEE-only base URL of decision 8,
   fixtures and replay tests.
4. NanoGPT: the same as phase 3, without the base URL change.
5. Gap document `aci_gateway.md` and documentation: README factor table,
   `measurement_allowlists.md`, provider documents, testing references.
6. E2EE for Phala Cloud and NanoGPT, after the protocol check of decision 6
   is reported.
7. Canonical report, sessions and receipts (below).

## Phase 7: canonical report, sessions and receipts

Status: designed on 2026-10-31 with the changes below. Principle: check
everything that teep can check, and allow to fail what the provider cannot
pass, so that the provider stays usable.

### Problem

An E2EE v2 response is confidential but not authenticated (aci_gateway.md
residual exposure 10). The signed ACI receipt authenticates it, but only if
teep trusts the receipt key. On the route that teep uses,
`/v1/attestation/report` (the gateway's dstack-vllm-proxy compatibility
route), the quote binds only keccak256(signing key) and the nonce, so the
keyset, and with it `receipt_signing_keys`, is self-asserted (residual
exposure 7). The key custody chain cannot fill the gap: the chain of
`aci.receipt.ed25519.v1` signs the secp256k1 key of the released scalar
(`kms_counterpart_public_key_hex`, gateway `src/dstack.rs:215-219`), not
the ed25519 public key that the keyset lists.

### Live observations

**Canonical report (2026-10-30).** `GET /v1/aci/attestation?nonce=<fresh>`
on `tee.redpill.ai` returned the ACI/1 §4.1 shape (`api_version`,
`workload_keyset_digest`, `service_capabilities`, `attestation` with
`tee_type`, `workload_keyset`, `report_data`, `source_provenance` and
`evidence`) for the same keyset as the legacy route. The quote's REPORTDATA
is sha256 of the §3.2 statement over the keyset digest and the client
nonce, followed by 32 zero bytes. It carries no GPU evidence.

**Sessions (2026-10-31).** `GET /v1/aci/sessions?model=qwen/qwen3.8-27b`
listed 15 sessions: one `phala-266` upstream
(`private-ai-verifier/phala-direct/v1`, endpoint
`https://qwen3-8-27b.use1-9b.phala.com`, a `tls_spki_sha256` channel
binding) and 14 `chutes` upstreams (`private-ai-verifier/chutes/v1`). Each
session lasts 3600 s. The full phala-266 session hashes to its id under
JCS (§8); its `evidence.data` is a `data:application/json;base64` URI whose
decoded bytes hash to `evidence.digest`. The decoded evidence is the dstack
report of the model CVM in the NEAR-direct layout: REPORTDATA is
sha256(signing_address ‖ tls_cert_fingerprint) ‖ request_nonce, the
`nvidia_payload` nonce is the same `request_nonce` (the gateway's
challenge), and `tls_cert_fingerprint` equals the session's channel SPKI.
The evidence format of the Chutes sessions is not observed.

### Design

**7a. Canonical report.** Phala Cloud fetches
`/v1/aci/attestation?nonce=<client nonce>`, the route that ACI/1 requires
verifiers to use, and no longer the legacy route. teep verifies the TDX
quote, event log and compose binding as today and the §3.2 binding:
recompute the keyset digest, build the statement with the client nonce,
require REPORTDATA = sha256(statement) ‖ 32 zero bytes. Every keyset field
is then hardware-bound (E2EE, receipt and TLS keys, `not_after`); this
closes residual exposure 7 for Phala Cloud. The report has no GPU
evidence: `nvidia_signature`, `nvidia_nonce_client_bound` and the other GPU
factors fail for Phala Cloud ACI/1 and are allowed to fail by default.

**7b. Replicas.** Replicas can share a keyset (the KMS derives keys from
the app id), so a keyset digest identifies the keyset, not one machine. An
inference response without `X-ACI-Keyset-Digest` fails: §5.2 requires it
on every response. A response that serves another digest is not failed:
§5.2 says that a changed digest "gates new sends until the client
re-verifies according to §3.1; responses already in flight continue
unaffected". teep relays it and ends the cached report, so that the next
send verifies again; a member of the same renewal family keeps continuity,
and another family becomes a new authorization (§3.1).

**7c. TLS key pin.** Compare the live certificate key of `tee.redpill.ai`
with the hardware-bound keyset entry for that host before any request
bytes are sent (residual exposure 8). Phala Cloud becomes a TLS-binding
provider in addition to E2EE, with the SPKI pool rules of the transport
reference. Own commit.

**7d. Sessions.** Implemented; the maintained description is
[Attested sessions](../providers/phalacloud/phalacloud_support.md#attested-sessions)
in the Phala Cloud provider document. The design as built:

- At each full verification, list the sessions of the model and fetch a
  bounded set (decision of 2026-11-01): every bundle of the Phala
  model CVM, then Chutes bundles by session count, largest first, within a
  constant 8 MiB of fetched Chutes records. One GET per bundle; the other
  sessions of a bundle are rebuilt and their ids recomputed.
- Audit each session (decision of 2026-11-01, all enforced): the
  TDX quote and TCB, MRTD and MRSEAM, REPORTDATA with the session nonce,
  the channel binding and identity, the GPU evidence verified locally, and
  for the Phala model CVM the compose binding and the event-log replay.
  The Phala model CVM REPORTDATA is the NEAR-direct layout with an ecdsa
  address, not the ed25519 one, so it has its own verifier.
- `aci_session_verified` (enforced) passes when one session passes; every
  request pins the passed sessions in `provider.aci_session_ids`, and a
  refusal (`session_not_accepted`) ends the authorization generation.
  Sessions stay pinned until the authorization ends; no session expiry
  applies to requests.

**7e. Receipts.** Over the same pinned pool: hash the raw SSE bytes, fetch
`GET /v1/aci/receipts/{X-Receipt-Id}` with the request's key, at most 3
attempts 200 ms apart on HTTP 404, and check the ed25519 signature over the
JCS form without `signature`, `workload_keyset_digest`, `model`,
`endpoint`, `method`, `response.returned.body_hash`, `upstream.verified`
with `result: "verified"`, `required: true` and a `session_id` that teep
pinned and whose period holds `served_at` (§9.3 step 6), and `served_at`
within the keyset lifetime. A non-stream request is buffered and answered
after the check; a stream is checked after it ends. A receipt that does not
verify invalidates the authorization generation that the request used and
logs at error level. A receipt that is not served fails the request and
keeps the generation, because its absence is not evidence against the
attestation. A response of a changed `X-ACI-Keyset-Digest` fails: its
receipt is signed under a keyset that teep has not verified. The in-flight
rule of §5.2 describes the gateway; teep verifies the new keyset before the
next send. `--capture` records the receipt and the raw SSE
bytes, and `--reverify` checks them. The request hash is checked only when
teep reproduces the gateway's serde_json form (preserve_order, serde string
escaping, f64 number output); otherwise `teep verify` states that it is not
checked. The receipt GET per request is a point of discussion:
[the provider document](../providers/phalacloud/phalacloud_support.md#point-of-discussion-one-receipt-get-per-request).

**Later.** VerifyReceipt does not require a `request.forwarded` event and
does not compare `chat_id` or the `model_id` of `upstream.verified` with the
request or the pinned session.

**Scope.** Phala Cloud only. Venice relays neither `X-Receipt-Id` nor the
ACI headers (2026-10-30) and stays confidentiality-only, as does NanoGPT.

### Resolved: Chutes sessions

The Chutes session evidence (observed 2026-11-01) is a multipart bundle of
the Chutes API responses for the gateway's evidence request. teep verifies
it with its Chutes verifiers. The pin needs Chutes sessions: on 2026-11-01
the gateway refused a pin of the Phala model CVM session alone (HTTP 412
`session_not_accepted`; its error named the Chutes model id
`Qwen/Qwen3.8-27B-TEE`), and served
a pin with two Chutes sessions once the October 2026 Chutes measurements
were allowed.

### Point of discussion: the bounded set of sessions

The bounded set narrows routing to the verified upstreams to limit the
load on the gateway. Measured: a Phala model CVM session is 276 KB, a
Chutes bundle 3.9 MB on 2026-10-31 and 4.2 MB on 2026-11-01, and the 14
Chutes sessions of 2026-10-31 shared 10 bundles, so verifying every session
would fetch about 39 MB per full verification. Under the 8 MiB limit the
growth from 3.9 to 4.2 MB leaves room for one Chutes bundle instead of
two. Each session adds Intel PCS requests: 16 for the 4 quotes of one
verification on 2026-11-01. Alternatives: every session, or the Phala
model CVM sessions only (the gateway refused that pin). Details:
[the provider document](../providers/phalacloud/phalacloud_support.md#point-of-discussion-the-bounded-set-of-sessions).

### Commits

1. 7a and 7b: canonical report and the served keyset digest check, with a
   new capture and replay tests.
2. 7c: TLS key pin.
3. 7d: session verification and pinning.
4. 7e: receipt verification in the proxy, then in `teep verify` and the
   capture.
5. Documentation: aci_gateway.md residual exposures 7, 8 and 10, the
   provider document and api_support.md.

## Tests

- Phase 1: every Venice ACI/1 unit test and fixture replay passes with
  unchanged report text; the expiry bound has tests at the bound and past
  it.
- Phase 2: parse tests for both variants; `all_attestations` with zero,
  two, or a differing entry fails; a field outside both variants fails; the
  nonce and unnamed-model factors for both variants.
- Phases 3-4: replay of the new fixtures through `verify.Run` with the
  production policy; a body with a KMS root or app id outside the pins
  fails `aci_key_custody`; concurrent replay of Venice, Phala Cloud and
  NanoGPT ACI/1 fixtures keeps each provider's policy.
