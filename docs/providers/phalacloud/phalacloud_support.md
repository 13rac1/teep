# Phala Cloud Provider Support

Phala Cloud (RedPill) serves its TEE models through the dstack
private-ai-gateway, a TDX CVM that forwards each request to an upstream
inference service. teep verifies the gateway's ACI/1 attestation; it has no
attestation of the machine that runs the model. The shared gateway analysis
is in [ACI/1 Gateway: Attested Gateway, Unattested Inference Host](../../attestation_gaps/aci_gateway.md),
and the limits of the ACI/1 specification are in
[ACI/1 Specification: Gaps That No Deployment Can Close](../../attestation_gaps/aci_specification.md).

## Configuration

```toml
[providers.phalacloud]
base_url = "https://tee.redpill.ai"
api_key_env = "PHALA_API_KEY"
```

`PHALA_API_KEY` alone creates the provider with the base URL above. The base
URL must not carry a path; teep appends `/v1/...`.

## Routing

The base URL is a TEE-only domain of the gateway. The gateway's measured
configuration lists `tee.redpill.ai` and `inference.phala.com` as
`tee_only_domains`: for these hosts the gateway routes a request only to an
upstream that it verified as a TEE, and refuses the request otherwise
(ACI/1 §1.2). `api.redpill.ai` is not TEE-only; the gateway may route its
requests to upstreams without a TEE.

Observed on 2026-10-29 with an API key: both TEE-only hosts list the
same 22 models at `/v1/models`, a subset of the 65 models of
`api.redpill.ai`, and answer `/v1/attestation/report` with the same gateway
keyset. The gateway terminates TLS for every host in the gateway CVM and
selects the response's `downstream_tls_binding` by the requested host:
`tee.redpill.ai`, `inference.phala.com` and `api.redpill.ai` each receive the
keyset TLS entry for their own hostname (ACI/1 §4.2).

## Attestation evidence and binding

`GET /v1/attestation/report?model=<model>&nonce=<client nonce>` returns the
gateway variant of the ACI/1 format: no echoed nonce or model, and an
`all_attestations` list with one copy of the attestation. teep parses it
with the shared ACI/1 parser (`internal/provider/aci`), which requires that
copy to equal the top-level fields.

- The gateway TDX quote is verified in the gateway tier; its REPORTDATA binds
  the gateway signing key and the client nonce
  (`gateway_tee_reportdata_binding`, enforced).
- `nonce_match` and `gateway_nonce_match` evaluate the client nonce where the
  evidence binds it: the verified gateway REPORTDATA, and the relayed GPU
  evidence, which carries the client nonce.
- `aci_key_custody` verifies the workload keyset digest and the dstack-KMS
  custody chain to the KMS root and gateway app id that Venice and NanoGPT
  share (`aci.GatewayPins`).
- `aci_backend_named` fails: the attestation binds no backend for the
  requested model.

Phala Cloud responses in other formats (dstack, Chutes) still parse with
their own parsers.

## TLS and E2EE

teep encrypts Phala Cloud chat requests with E2EE v2 of the gateway, the
secp256k1 suite, to the gateway E2EE key that the gateway quote binds
(`gateway_tee_reportdata_binding`, `aci_key_custody`). E2EE is enabled by
default. The field coverage and the fail-closed rules are in
[API support](../../api_support.md#phala-cloud-and-nanogpt-e2ee-v2-of-the-private-ai-gateway).
A model that answers with another attestation format, and the embeddings
endpoint, fail closed while E2EE is enabled.

Requests go over TLS 1.3 to the base URL host, with WebPKI and Certificate
Transparency enforced. teep does not compare the live certificate key of
`tee.redpill.ai` with the keyset TLS key for that host; this binding closes
in the authorization-store migration. With E2EE, a party that holds a
certificate for the host sees the message content only as ciphertext, but
it can forge, drop, reorder or repeat response content: E2EE v2 responses
are confidential, not authenticated, until teep verifies the signed ACI
receipt. Phala Cloud requests use the user's API key, so teep can fetch
their receipts (ACI/1 §7.6).

## Supply chain

`phalacloud.SupplyChainPolicy` lists the gateway images
(`aci.GatewayImages`), compose-pinned: the gateway quote's MRConfigID measures
the compose manifest that pins each image by digest. It lists no model-tier
image, so a dstack-format response fails `component_recognition`.

## Factor enforcement

An ACI/1 response selects `ACIDefaultAllowFail`, the list shared with Venice
and NanoGPT. Other formats keep `PhalaCloudDefaultAllowFail`.

## Known limitations

- The machine that runs the model is not attested.
- The live TLS key of the base URL host is not bound to the keyset.
- E2EE v2 defines field paths only for message content. teep refuses a
  request that carries `messages[].tool_calls`, `messages[].function_call`, `messages[].refusal`, `messages[].audio`, `prediction`, `tools`, `functions` and `response_format.json_schema`, and a response with tool calls.
  Not encrypted: the top-level `model`, `messages[].name`, `stop`, `tool_choice` and the top-level `function_call` (which name a function), and the other request parameters, including provider-specific prompt fields, which pass in plaintext.
- E2EE v2 responses are not authenticated against a party on the TLS path;
  teep does not verify ACI receipts yet.

## Test coverage

- `TestVerifyRun_GatewayACI_Fixtures`, `TestGatewayACI_PinsDecideCustody`
  and `TestVerifyRun_ConcurrentACIProviders` in
  [gateway ACI/1 replay tests](../../../internal/integration/gateway_aci_test.go)
  replay a live capture of 2026-10-29 from `tee.redpill.ai`.
- `TestFromConfigGatewayACIProviders` in
  [proxy gateway ACI/1 tests](../../../internal/proxy/gateway_aci_test.go)
  checks the gateway verifier and image policy of `teep serve`.
- `TestParseAttestationResponseACI` and `TestSupplyChainPolicyGatewayImages`
  in [Phala Cloud ACI/1 tests](../../../internal/provider/phalacloud/aci_test.go).
- `TestE2EERoundTrip`, `TestE2EEResponseOfAnotherRequestFails` and
  `TestE2EERejectsRequest` in
  [E2EE v2 encryptor tests](../../../internal/provider/aci/e2ee_test.go)
  check the request against a separate gateway implementation
  ([`aciv2test`](../../../internal/e2ee/aciv2test/gateway.go)).
- `TestACIv2DecryptChunkFailsClosed` and `TestACIv2AADTestVectors` in
  [E2EE v2 session tests](../../../internal/e2ee/aciv2_test.go), the AAD
  against the gateway's byte-exact test vectors.
- `TestTestE2EE_ACIv2` in
  [verify E2EE v2 tests](../../../internal/verify/e2ee_aciv2_test.go) and
  `TestBuildUpstreamBodyACIv2RefusesOtherFormat` in
  [proxy E2EE v2 tests](../../../internal/proxy/aciv2_cache_test.go).
- A live E2EE v2 request on 2026-10-30 (`qwen/qwen3.8-27b`) passed
  `e2ee_usable`: 8 encrypted fields decrypted across 11 chunks.
