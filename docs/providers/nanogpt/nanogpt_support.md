# NanoGPT Provider Support

NanoGPT serves TEE models from two kinds of backend. Some run on NanoGPT's
own dstack nodes and answer with a dstack attestation of the inference host.
Others go to the dstack private-ai-gateway, a TDX CVM that forwards each
request to an upstream inference service, and answer with the gateway's
ACI/1 attestation. For an ACI/1 model teep verifies the gateway; it has no
attestation of the machine that runs the model. The shared gateway analysis
is in [Venice ACI/1: Attested Gateway, Unattested Inference Host](../../attestation_gaps/venice_aci_gateway.md),
and the limits of the ACI/1 specification are in
[ACI/1 Specification: Gaps That No Deployment Can Close](../../attestation_gaps/aci_specification.md).

## Configuration

```toml
[providers.nanogpt]
base_url = "https://nano-gpt.com/api"
api_key_env = "NANOGPT_API_KEY"
```

`NANOGPT_API_KEY` alone creates the provider with the base URL above.

## Routing

teep sends every request to `nano-gpt.com`. NanoGPT selects the backend for
the requested model; the attestation response shows which kind of backend
answered. `nano-gpt.com` is not a host of the gateway: for an ACI/1 model,
NanoGPT is an unattested hop between teep and the gateway, and its TLS key
is not in the gateway keyset.

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

For an ACI/1 response:

- The gateway TDX quote is verified in the gateway tier against the gateway
  measurement policy shared with Venice and Phala Cloud
  (`aci.GatewayMeasurementPolicy`); its REPORTDATA binds the gateway signing
  key and the client nonce (`gateway_tee_reportdata_binding`, enforced).
- `nonce_match` and `gateway_nonce_match` evaluate the client nonce where the
  evidence binds it: the verified gateway REPORTDATA, and the relayed GPU
  evidence.
- `aci_key_custody` verifies the workload keyset digest and the dstack-KMS
  custody chain to the KMS root and gateway app id that Venice and Phala
  Cloud share (`aci.GatewayPins`).
- `aci_backend_named` fails: the attestation binds no backend for the
  requested model.

## TLS and E2EE

teep has no E2EE for NanoGPT. Requests go over TLS 1.3 to `nano-gpt.com`,
with WebPKI and Certificate Transparency enforced. No attestation binds the
TLS key of `nano-gpt.com`.

## Supply chain

`nanogpt.SupplyChainPolicy` lists the dstack backend images in the model tier
and the gateway images (`aci.GatewayImages`) in the gateway tier, all
compose-pinned: the quote's MRConfigID measures the compose manifest.

## Factor enforcement

An ACI/1 response selects `ACIDefaultAllowFail`, the list shared with Venice
and Phala Cloud. Other formats keep `NanoGPTDefaultAllowFail`.

## Known limitations

- For an ACI/1 model, the machine that runs the model is not attested, and
  NanoGPT is an unattested hop in front of the gateway: it sees the request
  and response in plaintext.
- The TLS key of `nano-gpt.com` is not bound to any attestation.
- `tls_key_binding` reports "provider uses E2EE key exchange", although
  NanoGPT has no E2EE in teep.

## Test coverage

- `TestVerifyRun_GatewayACI_Fixtures`, `TestGatewayACI_PinsDecideCustody`
  and `TestVerifyRun_ConcurrentACIProviders` in
  [gateway ACI/1 replay tests](../../../internal/integration/gateway_aci_test.go)
  replay a live capture of 2026-10-29 from `nano-gpt.com`.
- `TestFromConfigGatewayACIProviders` in
  [proxy gateway ACI/1 tests](../../../internal/proxy/gateway_aci_test.go).
- `TestParseAttestationResponseACI` and `TestSupplyChainPolicyGatewayImages`
  in [NanoGPT ACI/1 tests](../../../internal/provider/nanogpt/aci_test.go).
