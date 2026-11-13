# Phala Cloud Provider Support

Phala Cloud (RedPill) serves its TEE models through the dstack
private-ai-gateway, a TDX CVM that forwards each request to an upstream
inference service. teep verifies the gateway's ACI/1 attestation; it has no
attestation of the machine that runs the model. The shared gateway analysis
is in [ACI/1 Gateway: Attested Gateway, Unattested Inference Host](../../attestation_gaps/aci_gateway.md),
and the limits of the ACI/1 specification are in
[ACI/1 Specification: Assurance Limits and Deployment Requirements](../../attestation_gaps/aci_specification.md).

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
selects the report's `downstream_tls_binding` by the requested host:
`tee.redpill.ai`, `inference.phala.com` and `api.redpill.ai` each receive the
keyset TLS entry for their own hostname (ACI/1 §4.2).

## Attestation evidence and binding

`GET /v1/aci/attestation?nonce=<client nonce>` returns the ACI/1 report of
the gateway (ACI/1 §4.1), the route that ACI/1 verifiers use. The report is
service-scoped: teep does not send the model. teep parses it with
`aci.ParseCanonical`, which requires exactly the members of §4.1 at every
depth; any other format, also the variants of the compatibility route
`/v1/attestation/report`, fails.

- The gateway TDX quote is verified in the gateway tier. Its REPORTDATA is
  sha256 of the ACI/1 §3.2 statement over the workload keyset digest and the
  client nonce, followed by 32 zero bytes (`aci.StatementReportDataVerifier`,
  `gateway_tee_reportdata_binding`, enforced). teep recomputes the keyset
  digest from the keyset, so the quote binds every keyset field: the E2EE,
  receipt and TLS keys and `not_after`.
- The E2EE key is the single keyset entry of the E2EE v2 secp256k1 suite.
- The report echoes no nonce: `nonce_match` and `gateway_nonce_match` fail
  and are allowed. Freshness rests on `gateway_tee_reportdata_binding`.
- `aci_key_custody` verifies the dstack-KMS custody chain of the E2EE key to
  the KMS root and gateway app id that Venice and NanoGPT share
  (`aci.GatewayPins`).
- The report carries no GPU evidence. The GPU factors (`nvidia_signature`,
  `nvidia_nonce_client_bound` and the others) fail and are allowed.
- `aci_backend_named` fails: the report binds no backend for the requested
  model.
- `tls_key_binding` (enforced): the keyset must list exactly one TLS key
  for the base URL host, `downstream_tls_binding` must name the same host
  and key, and the certificate key of the connection that carried the
  report must equal it (`aci.TLSKeyForDomain`). A report fetched over a
  connection of another key, or over plain HTTP, fails.
- Every successful inference response must carry `X-ACI-Keyset-Digest`
  (ACI/1 §5.2); a response without it fails and ends the authorization.
  A response that serves another digest is relayed, because a response in
  flight continues (§5.2), and the authorization ends so that the next
  request verifies again: replicas can serve another member of the same
  renewal family, which keeps continuity, or another keyset, which becomes
  a new authorization (§3.1). An error response is relayed without this
  check.

## TLS and E2EE

teep encrypts Phala Cloud chat requests with E2EE v2 of the gateway, the
secp256k1 suite, to the gateway E2EE key that the gateway quote binds
(`gateway_tee_reportdata_binding`, `aci_key_custody`). E2EE is enabled by
default. The field coverage and the fail-closed rules are in
[API support](../../api_support.md#phala-cloud-and-nanogpt-e2ee-v2-of-the-private-ai-gateway).
A model that answers with another attestation format, and the embeddings
endpoint, fail closed while E2EE is enabled.

Requests go over TLS 1.3 to the base URL host, with WebPKI and Certificate
Transparency enforced. Phala Cloud is a TLS-binding provider: the
authorization holds the report, the gateway E2EE key and the transport
identity (the base URL host and its keyset TLS key) together, and
inference connections are pinned to that key before any request bytes are
sent, with the pool rules of the
[transport reference](../../transport/README.md). The report is
service-scoped, so one authorization identity serves every model of the
host. E2EE v2 responses are confidential, not authenticated, until teep
verifies the signed ACI receipt; the TLS pin keeps a party that holds only
another certificate for the host off the path. Phala Cloud requests use the
operator's API key, so teep can fetch their receipts (ACI/1 §7.6).

## Supply chain

`phalacloud.SupplyChainPolicy` lists the gateway images
(`aci.GatewayImages`), compose-pinned: the gateway quote's MRConfigID measures
the compose manifest that pins each image by digest. It lists no model-tier
image, so a dstack-format response fails `component_recognition`.

## Factor enforcement

The ACI/1 report selects `PhalaCloudACIDefaultAllowFail`: the list shared with
Venice and NanoGPT (`ACIDefaultAllowFail`) without `tls_key_binding`, which
is enforced, and with the GPU signature and nonce factors, because the
report carries no GPU evidence, and `nonce_match` and
`gateway_nonce_match`, because the report echoes no nonce.

## Known limitations

- The machine that runs the model is not attested to the client.
- The report carries no GPU evidence that answers the client nonce.
- E2EE v2 defines field paths only for message content. teep refuses a
  request that carries `messages[].tool_calls`, `messages[].function_call`, `messages[].refusal`, `messages[].audio`, `prediction`, `tools`, `functions` and `response_format.json_schema`, and a response with tool calls.
  Not encrypted: the top-level `model`, `messages[].name`, `stop`, `tool_choice` and the top-level `function_call` (which name a function), and the other request parameters, including provider-specific prompt fields, which pass in plaintext.
- E2EE v2 responses are not authenticated against a party on the TLS path;
  teep does not verify ACI receipts yet.

## Test coverage

- `TestParseCanonical`, `TestParseCanonicalRefusesMalformedReports`,
  `TestStatementReportDataVerifier`, `TestBuildReportCanonicalBody` and
  `TestCheckServedKeysetDigest` in
  [canonical report tests](../../../internal/provider/aci/canonical_test.go)
  use the live report of 2026-10-30 from `tee.redpill.ai`.
- `TestAttester_FetchesCanonicalReport`, `TestAttester_TLSBindingFailures`,
  `TestAttester_RefusesPlainHTTP` and
  `TestParseAttestationResponse_RefusesOtherFormats` in
  [Phala Cloud tests](../../../internal/provider/phalacloud/phalacloud_test.go)
  check the TLS key binding of the attestation connection.
- `TestAuthorizedPhalaCloudACIv2` in
  [pinned Phala Cloud tests](../../../internal/proxy/authorized_phalacloud_test.go),
  `TestCheckAuthorizedKeyset` in
  [pinned keyset tests](../../../internal/proxy/authorized_keyset_test.go) and
  `TestAuthorizationValidatesPhalaCloudKey` in
  [authorization tests](../../../internal/proxy/authorization_internal_test.go)
  check E2EE v2 over the pinned pool and the keyset digest of its responses.
- `TestStandalonePhalaCloudProbe` in
  [standalone probe tests](../../../internal/verify/tls_probe_phalacloud_test.go)
  checks the pinned `teep verify` inference and its capture.
- `TestTestE2EE_ACIv2ServedKeysetDigest` in
  [verify keyset digest tests](../../../internal/verify/e2ee_keyset_digest_test.go).
- `TestFromConfigGatewayACIProviders` in
  [proxy gateway ACI/1 tests](../../../internal/proxy/gateway_aci_test.go)
  checks the gateway verifier and image policy of `teep serve`.
- `TestParseAttestationResponseACI` and `TestSupplyChainPolicyGatewayImages`
  in [Phala Cloud ACI/1 tests](../../../internal/provider/phalacloud/aci_test.go).
- `TestVerifyRun_PhalaCloudCanonical_Fixture` and
  `TestPhalaCloudCanonical_PinsDecideCustody` in
  [canonical report replay tests](../../../internal/integration/phalacloud_canonical_test.go)
  replay a live capture of 2026-10-31 from `tee.redpill.ai`, with the E2EE
  v2 test exchange and its `X-ACI-Keyset-Digest` and `X-Receipt-Id`.
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
