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
2. **Nonce:** the client nonce is evaluated where the evidence binds it: the
   quote REPORTDATA and the GPU evidence. A missing echoed `request_nonce` is
   not a failure on its own.
3. **`all_attestations`:** exactly one entry, equal to the top-level fields;
   any other content fails the parse.
4. **Unnamed model:** a new factor, allowed to fail by default, that states
   that the attestation names no backend for the requested model.
5. **Host SPKI binding to the keyset TLS key:** recorded here and in the gap
   document as a gap. It closes in the authorization-store migration, not in
   this plan; no second pin path is added.
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
- `nonce_match` and `gateway_nonce_match` of a gateway-variant response,
  which carries no echoed nonce, evaluate the client nonce that the verified
  gateway quote (signature and certificate chain) REPORTDATA and the GPU
  evidence bind, and the detail says so. A Venice-variant response without
  its echoed nonce fails as before. The REPORTDATA comparison itself stays in
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
