# NanoGPT Provider Support

NanoGPT serves TEE models from two kinds of backend. Some run on NanoGPT's
own dstack nodes and answer with a dstack attestation of the inference host.
Others go to the dstack private-ai-gateway, a TDX CVM that forwards each
request to an upstream inference service, and answer with the gateway's
ACI/1 attestation. For an ACI/1 model teep verifies the gateway; it has no
attestation of the machine that runs the model. The shared gateway analysis
is in [ACI/1 Gateway: Attested Gateway, Unattested Inference Host](../../attestation_gaps/aci_gateway.md),
and the limits of the ACI/1 specification are in
[ACI/1 Specification: Gaps That No Deployment Can Close](../../attestation_gaps/aci_specification.md).

## Configuration

```toml
[providers.nanogpt]
base_url = "https://nano-gpt.com/api"
api_key_env = "NANOGPT_API_KEY"
```

`NANOGPT_API_KEY` alone creates the provider with the base URL above and
E2EE off, as the configuration above does without `e2ee = true`. The
request then goes in plaintext over TLS to NanoGPT's servers, an
unattested hop (see [TLS and E2EE](#tls-and-e2ee)). E2EE on would serve no
NanoGPT model today: E2EE v2 cannot encrypt to a dstack-format model, and
NanoGPT does not forward E2EE v2 for ACI/1 models (observed 2026-10-30). A
user who wants to try it sets `e2ee = true` in `[providers.nanogpt]`.

## Routing

teep sends every request to `nano-gpt.com`. NanoGPT selects the backend for
the requested model; the attestation response shows which kind of backend
answered. `nano-gpt.com` is not a host of the gateway: for an ACI/1 model,
NanoGPT is an unattested hop between teep and the gateway, and its TLS key
is not in the gateway keyset.

The gateway names, in `downstream_tls_binding`, the keyset TLS entry for the
gateway hostname that the attestation request reached (ACI/1 §4.2). In the
capture of 2026-10-29 it names `api.redpill.ai`, which is not a TEE-only
hostname of the gateway: there, the gateway may route a request to an
upstream without a TEE. teep cannot see which hostname NanoGPT uses for
inference requests. SEE: [ACI/1 Gateway](../../attestation_gaps/aci_gateway.md).

## Attestation evidence and binding

`GET /v1/tee/attestation?model=<model>&nonce=<client nonce>` returns one of
these formats:

- dstack: the TDX quote of the inference host, with REPORTDATA
  `keccak256(signing key)` + nonce, the event log and the compose manifest.
  NanoGPT uses `signing_public_key` and accepts an event log as a JSON array
  or a JSON-encoded string.
- ACI/1, gateway variant: no echoed nonce or model, and an
  `all_attestations` list with one copy of the attestation. teep parses it
  with the shared ACI/1 parser (`internal/provider/aci`), which requires that
  copy to equal the top-level fields. Observed on 2026-10-29 for
  `TEE/gemma-4-26b-a4b-uncensored`.
- Chutes, `attestation_type` form: an `all_attestations` list of Chutes
  instances with their `e2e_pubkey`, parsed by `provider.ParseChutesFormat`.
- Chutes evidence response: a top-level `evidence` list with one entry per
  instance, and `failed_instance_ids` and `excluded_instance_ids`. Observed
  on 2026-11-12 for 10 of 20 models. SEE: [Chutes evidence](#chutes-evidence).

For a model that Tinfoil serves, NanoGPT gives no nonce-bound attestation:
it answers HTTP 400, and teep fails with that status and NanoGPT's error
text.

The quote of either Chutes form is checked with the Chutes REPORTDATA
binding, `SHA256(nonce_hex + e2e_pubkey)` (`chutes.ReportDataVerifier`), in
`teep verify` and `teep serve`.

### Chutes evidence

NanoGPT relays the Chutes evidence response without the instance list, so
no member names an `e2e_pubkey`. teep cannot check that any quote binds the
client nonce, and nothing names the instance that serves the request. SEE:
[NanoGPT Chutes Evidence: No Nonce Binding, No Serving Instance](../../attestation_gaps/nanogpt_chutes_evidence.md).

`chutes.ParseEvidence` parses the response:

- Every entry must pass the checks of the Chutes attested-session path:
  `tee_type` is `tdx`, a `signature` is present, and `attested_body` holds
  the quote of the entry and the nonce of the request. teep does not verify
  the signature: Chutes does not publish its key.
- `failed_instance_ids` and `excluded_instance_ids` are required. An empty
  instance id, or an id in two places (two entries, one list twice, or an
  entry and a list), refuses the response.
- A non-empty `failed_instance_ids` or `excluded_instance_ids` is logged at
  warn level and is not refused. Their meaning is assumed from the member
  names: Chutes does not document it.
- teep reports the first instance, with no signing key, and the number of
  listed instances (`Candidates: 1/n evaluated`).
- Members that teep does not know go to `response_schema`.
- The response body is bounded at 8 MiB and the evidence at 64 instances.
  On 2026-11-12 the largest body was 2,956,002 bytes and the most instances
  were 43.

`signing_key_present` and `e2ee_capable` fail and are enforced, so a model
that answers with this format is blocked.

For an ACI/1 response:

- The gateway TDX quote is verified in the gateway tier against the gateway
  measurement policy shared with Venice and Phala Cloud
  (`aci.GatewayMeasurementPolicy`); its REPORTDATA binds the gateway signing
  key and the client nonce (`gateway_tee_reportdata_binding`, enforced).
- The gateway variant echoes no nonce: `nonce_match` and
  `gateway_nonce_match` fail and are allowed (`NanoGPTACIDefaultAllowFail`).
  Freshness rests on `gateway_tee_reportdata_binding`, and the GPU evidence
  nonce on `nvidia_nonce_client_bound`, both enforced.
- `aci_key_custody` verifies the workload keyset digest and the dstack-KMS
  custody chain to the KMS root and gateway app id that Venice and Phala
  Cloud share (`aci.GatewayPins`).
- `aci_backend_named` fails: the attestation binds no backend for the
  requested model.

## TLS and E2EE

E2EE is off by default for NanoGPT. Without it, teep sends the whole
request in plaintext over TLS to `nano-gpt.com`: NanoGPT's servers, which no
attestation covers, read the prompt, and so does whatever NanoGPT forwards
it to (the attested dstack host of a dstack-format model, or, for an ACI/1
model, the gateway, which decrypts by design, and the inference host
behind it).

With `e2ee = true`, teep encrypts NanoGPT chat requests for ACI/1 models
with E2EE v2 of the gateway, the secp256k1 suite, to the gateway E2EE key
that the gateway quote binds. The field coverage and the fail-closed rules
are in
[API support](../../api_support.md#phala-cloud-and-nanogpt-e2ee-v2-of-the-private-ai-gateway).
NanoGPT must forward the E2EE v2 headers, the encrypted fields and the
model name to the gateway unchanged: the gateway decrypts a request field
only under the model and request context that teep encrypted it with, and a
plaintext response fails. E2EE v2 keeps the content confidential against
NanoGPT but does not authenticate the response against it: NanoGPT can
encrypt response fields of its own to teep's public key, or drop, reorder
and repeat chunks, and teep cannot detect it until it verifies the signed
ACI receipt. Under ACI/1 §7.6 a receipt is fetched with the API key that
made the request, which is NanoGPT's key, so teep cannot fetch the receipts
of NanoGPT requests. A model that answers with the dstack or Chutes
format fails closed while E2EE is enabled.

Requests go over TLS 1.3 to `nano-gpt.com`, with WebPKI and Certificate
Transparency enforced. No attestation binds the TLS key of `nano-gpt.com`.

## Supply chain

`nanogpt.SupplyChainPolicy` lists the dstack backend images in the model tier
and the gateway images (`aci.GatewayImages`) in the gateway tier, all
compose-pinned: the quote's MRConfigID measures the compose manifest.

## Factor enforcement

An ACI/1 response selects `NanoGPTACIDefaultAllowFail`: the list shared with
Venice (`ACIDefaultAllowFail`) and the two nonce factors. Other formats keep `NanoGPTDefaultAllowFail`.

## Known limitations

- For an ACI/1 model, the machine that runs the model is not attested, and
  NanoGPT is an unattested hop in front of the gateway. With E2EE it sees
  the message content and generated content only as ciphertext, but it sees
  the top-level `model`, `messages[].name`, `stop`, `tool_choice` and the top-level `function_call` (which name a function), and the other request parameters, including provider-specific prompt fields, which pass in plaintext.
- teep does not check `X-ACI-Keyset-Digest` on NanoGPT responses: the
  gateway variant binds the signing key, not the keyset digest, so teep
  has no hardware-bound digest to compare with.
- NanoGPT can forge, drop, reorder or repeat response content: E2EE v2
  responses are not authenticated against it.
- E2EE v2 defines field paths only for message content. teep refuses a
  request that carries `messages[].tool_calls`, `messages[].function_call`, `messages[].refusal`, `messages[].audio`, `prediction`, `tools`, `functions` and `response_format.json_schema`, and a response with tool calls.
- E2EE is off by default for NanoGPT, so NanoGPT's servers read the
  prompt. With `e2ee = true` it provides confidentiality only: NanoGPT
  relays the content as ciphertext but can forge responses, and teep cannot
  fetch NanoGPT's receipts.
- NanoGPT does not forward E2EE v2: a live E2EE v2 request on 2026-10-30 (`TEE/gemma-4-26b-a4b-uncensored`) received an SSE stream whose second chunk carried `choices.0.delta.content` in plaintext. teep refused the response (`e2ee_usable` failed: "expected encrypted string but not recognised"). The request content left teep as ciphertext. The gateway did not encrypt the response: this is consistent with NanoGPT not forwarding the E2EE v2 headers, or not forwarding the request to the gateway; a changed model would have made the gateway refuse the request instead. Until NanoGPT forwards E2EE v2, a NanoGPT ACI/1 model does not serve while E2EE is enabled.
- The TLS key of `nano-gpt.com` is not bound to any attestation.
- NanoGPT fetched the observed gateway attestation through `api.redpill.ai`,
  which is not TEE-only.
- NanoGPT gives no nonce-bound attestation for models that Tinfoil serves.
- A model that answers with the Chutes evidence response is blocked: the
  response names no instance key and no serving instance.

## Test coverage

- `TestVerifyRun_GatewayACI_Fixtures`, `TestGatewayACI_PinsDecideCustody`
  and `TestVerifyRun_ConcurrentACIProviders` in
  [gateway ACI/1 replay tests](../../../internal/integration/gateway_aci_test.go)
  replay a live capture of 2026-10-29 from `nano-gpt.com`.
- `TestFromConfigGatewayACIProviders` in
  [proxy gateway ACI/1 tests](../../../internal/proxy/gateway_aci_test.go).
- `TestParseAttestationResponseACI` and `TestSupplyChainPolicyGatewayImages`
  in [NanoGPT ACI/1 tests](../../../internal/provider/nanogpt/aci_test.go).
- `TestE2EERoundTrip`, `TestE2EEResponseOfAnotherRequestFails` and
  `TestE2EERejectsRequest` in
  [E2EE v2 encryptor tests](../../../internal/provider/aci/e2ee_test.go)
  check the request against a separate gateway implementation
  ([`aciv2test`](../../../internal/e2ee/aciv2test/gateway.go)).
- `TestACIv2DecryptChunkFailsClosed` and `TestACIv2AADTestVectors` in
  [E2EE v2 session tests](../../../internal/e2ee/aciv2_test.go), the AAD
  against the gateway's byte-exact test vectors.
- `TestParseChutesEvidence_RealBody`, `TestParseChutesEvidence_InstanceBound`,
  `TestParseChutesEvidence_Refused`, `TestParseChutesEvidence_UnknownMember`
  and `TestAttester_FetchAttestation_BodyBound` in
  [NanoGPT Chutes evidence tests](../../../internal/provider/nanogpt/chutes_evidence_test.go);
  `TestParseEvidence_Refused` and the other tests in
  [Chutes evidence tests](../../../internal/provider/chutes/evidence_test.go).
- `TestAttester_FetchAttestation_HTTP400Tinfoil` in
  [NanoGPT tests](../../../internal/provider/nanogpt/nanogpt_test.go).
- `TestNewReportDataVerifier_NanoGPTChutesFormat` in
  [verify factory tests](../../../internal/verify/factory_test.go) and
  `TestFromConfig_NanogptChutesReportData` in
  [proxy tests](../../../internal/proxy/relay_internal_test.go).
- `TestTestE2EE_ACIv2` in
  [verify E2EE v2 tests](../../../internal/verify/e2ee_aciv2_test.go) and
  `TestBuildUpstreamBodyACIv2RefusesOtherFormat` in
  [proxy E2EE v2 tests](../../../internal/proxy/aciv2_cache_test.go).
