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
- Every successful inference response must carry the verified
  `X-ACI-Keyset-Digest` (ACI/1 §5.2). A response without it, or of another
  digest, fails before teep relays it, and the authorization ends so that
  the next request verifies again: replicas can serve another member of
  the same renewal family, which keeps continuity, or another keyset,
  which becomes a new authorization (§3.1). See [Receipts](#receipts) for
  the reason. An error response is relayed without this check.

## Attested sessions

The gateway forwards a request to an upstream that serves the model and
records each upstream that it verified in an attested session (ACI/1 §8).
For qwen/qwen3.8-27b these were Phala's own model CVM (the gateway's
verifier label is `private-ai-verifier/phala-direct/v1`) and Chutes
instances. teep verifies a bounded set of the sessions and pins them on
every request; the gateway then serves the request only through a pinned
session (ACI/1 §5.3, §9.2).

At each full verification of an authorization, the attester lists the
sessions of the model (`GET /v1/aci/sessions?model=`) and fetches session
records (`GET /v1/aci/sessions/{id}`):

- The bundles of the Phala model CVM, at most 4 (one was listed on
  2026-11-01 and two on 2026-11-02, 276 KB each), then Chutes bundles by
  the number of sessions they cover, largest first, while the fetched
  Chutes records stay within 8 MiB (a constant). Sessions that the gateway established from one
  evidence fetch share their evidence; one GET per bundle gives every
  session of the bundle, whose records teep rebuilds and checks against
  their ids (`aci.RebuildSession`).
- A Chutes GET starts only while the rest of the limit holds the largest
  Chutes record fetched so far, because the gateway sends a whole record
  even when teep stops reading.
- Sessions of another verifier are not fetched: teep does not verify their
  evidence.
- Every session request carries the API key, so it goes over a client
  pinned to the TLS key that the report binds, before any request bytes,
  and each response must have come over that key. `teep verify --capture`
  records these requests, and replay checks the recorded TLS key.
- The sessions of one bundle share one decoded evidence, and teep drops
  the parsed records after it rebuilds the bundle.

teep checks each record: its id is `hex(sha256(JCS(record)))`, its
`evidence.data` hashes to `evidence.digest`, and it has every member of
§8.2 at every depth (`aci.ParseSession`). Then `phalacloud.SessionAuditor`
verifies the evidence; every check is enforced, and a session that fails
one is not pinned:

1. The TDX quote: structure, Intel certificate chain, signature, debug off,
   and online a TCB that is UpToDate.
2. MRTD and MRSEAM: the Phala model CVM against the dstack base list, a
   Chutes instance against the Chutes list.
3. REPORTDATA with the session's own nonce: for the Phala model CVM
   sha256(signing_address ‖ tls_cert_fingerprint) and the gateway's request
   nonce, with an ecdsa address that binds the signing key; for Chutes
   sha256(nonce_hex + e2e_pubkey).
4. The channel binding names the TLS key of the Phala model CVM or the
   ML-KEM key of one Chutes instance in the evidence; the identity of the
   Phala model CVM names its signing address.
5. The GPU evidence, verified locally with the session nonce, without NRAS.
6. For the Phala model CVM, the compose binding (MRConfigID) and the
   event-log replay of RTMR0-3.

The parts of a session's evidence must have exactly the members that teep
reads. For a Chutes bundle these include the newer members of the Chutes
evidence response: `excluded_instance_ids`, and for each entry `tee_type`
(`tdx`), `signature` and `attested_body`. teep decodes `attested_body` of
the bound instance and requires that its quote (under `tdx_quote` or
`quote`) is the entry's quote and that its nonce is the nonce of the
evidence request. teep does not verify `signature`: Chutes publishes no
key for it.

`aci_session_verified` (enforced) passes when at least one session passes.
Its detail states what a pinned session proves: genuine TDX and GPU
evidence with an allowed MRTD and MRSEAM. The workload policy of the
upstream (RTMR values, compose content, images) is not checked.
The report and the authorization carry the ids of the passed sessions, and
every Phala Cloud request carries them in `provider.aci_session_ids`; a
request without a verified session is not sent, and a client's own `aci_`
constraint fails. Sessions stay pinned until the authorization is
invalidated or evicted; teep applies no session expiry to requests. A
refusal of the pinned sessions (`session_not_accepted`, HTTP 412) ends the
authorization generation, and teep sends the request at most once more
after a new verification (see
[retry contracts](../../transport/retries.md)).

Observed on 2026-11-01: the gateway served a request pinned to the Phala
model CVM session and two Chutes sessions. Before the October 2026 Chutes
measurements were allowed, only the Phala model CVM session passed, and the
gateway refused a pin with it alone (HTTP 412 `session_not_accepted`); its
error named the Chutes model id `Qwen/Qwen3.8-27B-TEE`.

Observed on 2026-11-03: four models list only Phala as provider
(`qwen/qwen-2.5-7b-instruct`, `phala/gemma-4-26b-a4b-uncensored`,
`phala/qwen3.8-27b-uncensored` and `jaredpalmer/kev-4b`), and each session
list held one Phala model CVM session. For `qwen/qwen-2.5-7b-instruct`, two
lists 76 seconds apart held two different sessions, each established at
the time of its list request. A `teep verify` run audited and pinned the
listed session; the gateway refused the pinned request with HTTP 412
`session_not_accepted` ("pinned sessions may have been superseded by
re-verification"), and it refused the retry after a new verification in
the same way. teep therefore fails closed for that model: no request is
served. The other three models were not sent a request.

## Receipts

`teep serve` requires a signed ACI receipt that verifies for every
successful Phala Cloud response (ACI/1 §7, §9.3), and `teep verify` requires
one for its probe response. teep hashes the response
bytes as they arrive, before decryption. After the response ends, it
fetches `GET /v1/aci/receipts/{X-Receipt-Id}` over the pinned connection
pool with an API key. The gateway can store a receipt after the
response ends, so HTTP 404 gets another attempt: at most 3 attempts, 200 ms
apart. Then `aci.VerifyReceipt` checks:

1. The ed25519 signature over the JCS form of the receipt without
   `signature`, under the `receipt_signing_keys` entry of the verified
   keyset that `key_id` names.
2. `workload_keyset_digest` is the digest of the verified keyset, and
   `served_at` is not past the keyset `not_after`.
3. `endpoint`, `method` and `model` are those of the request.
4. `response.returned.body_hash` is the sha256 of the response bytes that
   teep received.
5. `request.received.body_hash` is the sha256 of the request that the
   gateway restored (E2EE v2 §8), when teep can reproduce it (see below).
6. An `upstream.verified` event with `result: "verified"` and
   `required: true` cites a pinned session whose period, `established_at`
   to `expires_at`, holds `served_at`.

A non-stream response reaches the client only after its receipt verifies.
A stream is relayed to the client before its receipt is checked: teep
checks the receipt after the stream ends. The property is: every response
that delivered content has its receipt checked, and a failure of that check
that the gateway causes ends the authorization generation, so the next
request verifies again. Content that was already streamed cannot be
recalled. The receipt fetch and check run under a context that teep owns,
bounded to 30 seconds, so a client that hangs up does not decide their
result.

When the relay of a stream fails after content went out, teep names the
client only from positive evidence:

- The relay error is the error of the write to the client (except a write
  that failed on teep's own write deadline while the client was still
  connected), or of the client's own request context, which has ended (the
  client hung up; a client timeout shows as a hang-up, because teep serve
  sets no deadline on the incoming request). teep stops writing to the
  client, keeps the upstream request, and reads the rest of the stream to
  its end within a drain bound of 2 minutes and 16 MiB from the client's
  end, then checks the receipt over the whole response. teep did not cancel
  the upstream request, so the gateway sees a complete stream and must
  publish its receipt. A stream that does not end within the bound, and a
  receipt that is not served or does not verify, are the gateway's failure
  and end the generation; an honest gateway keeps it, so that one client
  cannot force a new verification for every client. An abandoned stream is
  read to its end within the bound, which uses upstream tokens, bandwidth
  and a connection.
- Every other relay error is the gateway's: a reset, also after `[DONE]`,
  a cut, a stream that does not parse (an error event, an error object,
  data that is not JSON, a line over 1 MiB, data after `[DONE]`), and
  teep's own deadline for the attempt, also when a write to the client
  fails on it. teep reads the rest of the response under its own bound of
  30 seconds, so a gateway that ended its stream badly but signed what it
  sent still verifies, and checks the receipt against every byte read from
  the gateway; the receipt fetch then has its own bound of 30 seconds. The
  upstream request runs 30 seconds longer than teep's attempt deadline,
  which bounds the relay and the writes, so this read works after teep's
  own deadline too. A stream must end within those 30 seconds after teep's
  attempt deadline (30 minutes for a stream), and within 1 MiB after the
  relay stopped; a longer one is the gateway's failure, also when it is
  honest. The upstream attempt does not
  run on the client's context: teep claims it for this read first, so a
  client that closes when it reads teep's error event does not cut the
  read. A client that left before teep claimed it is the previous item. The receipt covers the whole
  response, so a stream cut before its end does not verify, also when the
  network cut it; that costs one new verification.
- A gateway that sends content and then stops until the client gives up
  runs into the drain bound after the client left: the read ends, the
  receipt does not cover a stream cut before its end, and the generation
  ends.
- A client that leaves before any content reached it cancels the upstream
  request; nothing reached the client, and no receipt is checked.

After a stream that failed or that the client left, the gateway can delay
its receipt until its backend reaches its end, so teep retries an HTTP 404
from the receipt route until the fetch's 30-second bound, with a delay that
starts at 200 ms and doubles up to 2 seconds. After a stream that ended
cleanly, the gateway publishes the receipt with the end of the stream, and
teep makes 3 attempts 200 ms apart.

A failure is logged at error level (`response receipt check failed`, and
`content was relayed before the receipt check failed` for a stream whose
relay failed).

In `teep verify`, the receipt of the probe is the factor
`aci_receipt_verified`. Once the probe response is HTTP 200 with the
verified keyset digest and an event stream, every outcome except a
verified receipt fails it: a missing or malformed receipt id or receipt, a
receipt that the gateway does not serve, a failed check, a failed receipt
request, a reset, a stream without `[DONE]`, and content that does not
decrypt. The receipt is checked over the whole response where teep can
read it, and over the bytes that arrived where it cannot. The gateway
under test cannot choose a failure that skips the check. A network fault
can also fail the receipt request; the detail then says to run again. The
detail of a verified receipt states whether the request hash was checked.
A response that is not HTTP 200, serves another keyset digest or is not an
event stream fails `e2ee_usable`, and the receipt factor is a deferred
skip.

A receipt whose signature, keyset, response hash, cited session or
`served_at` does not verify, a malformed receipt, and a response without
one `X-Receipt-Id` end the authorization generation that the request used.
A response with a 2xx status other than 200 is refused before teep relays
anything, and the generation ends: teep checks the keyset digest, decrypts
and checks the receipt only for 200, and a client takes any 2xx for
success. The gateway passes the status of the model backend through.
For a stream, a receipt that the gateway does not serve (HTTP 404 on 3
attempts, another HTTP status, or a connection failure) ends the
generation too, because the content already went out. For a non-stream
response, which teep holds until its receipt verifies and which the client
does not get otherwise, it fails the request and keeps the generation.

teep checks the service's own statements (signature, keyset,
`served_at`, response hash, cited session) before the statements about the
request, so a receipt for another request cannot stop the check early.
Then:

- A receipt that names another endpoint, method or model ends the
  generation for a stream, whose content went out, and fails a non-stream
  request. The gateway writes them from the request it received, and the
  `model` of the receipt from the `model` that the client sent.
- A receipt whose request hash differs from the request that teep sent
  fails the request and keeps the generation, for a stream too. teep
  builds the gateway's form of the request from the client's request, and
  one client must not end the authorization of the others.

A response of another keyset (a changed `X-ACI-Keyset-Digest`) fails before
teep relays it, and the generation ends. ACI/1 §5.2 lets the gateway finish a response in
flight under the new keyset; that rule describes the gateway. The receipt
of that response is signed under a keyset that teep has not verified, so
teep cannot authenticate the response, and it verifies the new keyset
before the next send.

The request hash: the gateway parses the wire body with serde_json, keeping
the member order, puts the plaintext in place of each ciphertext, and writes
the result with `serde_json::to_vec`. teep writes the same form
(`aci.RestoredRequestHash`). Without E2EE, the gateway hashes the wire body
as received, and so does teep. teep does not check the request hash when
the body has a value on which Go and serde_json can write different bytes:
a number that is not an integer within i64 or u64 or a decimal fraction in
shortest form (magnitude 1e-4 to 1e15, at most 15 significant digits),
U+2028 or U+2029 in a string, or invalid UTF-8. The debug record
`receipt verified` states `request_hash_checked`.

## Point of discussion: one receipt GET per request

Each successful response adds one receipt GET to the gateway, and up to two
more when the receipt is not yet stored. The live receipt of 2026-11-01 was
1340 bytes. A non-stream response waits for the GET before it reaches the
client: one more round trip to the gateway, and 200 ms for each HTTP 404.
The latency on the live gateway is not measured yet.

The alternative is no receipt check: E2EE v2 responses then stay
confidential but not authenticated against a party on the TLS path
(residual exposure 10 of the
[ACI gateway gaps](../../attestation_gaps/aci_gateway.md)).

## Point of discussion: the bounded set of sessions

teep verifies a bounded set of sessions, and the pin narrows routing to
the upstreams of that set. The bound limits the load on the gateway:

- A Phala model CVM session is 276 KB; a Chutes bundle was 3.9 MB on
  2026-10-31 and 4.2 MB on 2026-11-01. On 2026-10-31 the 14 Chutes sessions
  of qwen/qwen3.8-27b shared 10 bundles, so verifying every session would
  fetch about 39 MB for each full verification.
- Under the 8 MiB limit, two 3.9 MB bundles fitted; at 4.2 MB, one bundle
  fits. On 2026-11-01 teep pinned the Phala model CVM session and the two
  Chutes sessions of one bundle.
- Each verified session adds a TDX quote whose Intel PCS collateral teep
  fetches: one full verification on 2026-11-01 made 16 PCS requests for its
  4 quotes.

The alternatives are to verify every session (about 39 MB per full
verification, and the most upstreams to route through) or only the Phala
model CVM sessions (276 KB, but the gateway refused that pin with HTTP 412
`session_not_accepted`, its error naming the Chutes model id, so requests
fail).

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
host. E2EE v2 makes responses confidential; the receipt check
authenticates them (see [Receipts](#receipts)), and the TLS pin keeps a
party that holds only another certificate for the host off the path. Phala
Cloud requests use the user's API key, so teep can fetch their receipts
(ACI/1 §7.6).

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
`aci_session_verified` and `aci_receipt_verified` are enforced.
`aci_receipt_verified` is a deferred skip, which does not block, when there
is no probe receipt to check: in `teep serve`, which checks the receipt of
every response instead, in `teep verify` when the report blocks inference
requests (teep sends no probe then), without an API key, with `--offline`
(an offline run sends no probe), and after a probe whose
stream failed.

## Known limitations

- For a model whose gateway session is replaced at each re-verification,
  the pin is refused and teep serves no request (observed on 2026-11-03;
  see [Attested sessions](#attested-sessions)).
- The client nonce does not reach the upstream: a session is a snapshot of
  the gateway's verification at `established_at`, with the gateway's own
  nonce. teep pins sessions that a verification passed until the
  authorization ends.
- teep has no policy for the RTMR values, the compose content and the images
  of the Phala model CVM, and checks only MRTD, MRSEAM, RTMR1 and RTMR2 of a
  Chutes instance. It sends no Sigstore, Proof of Cloud or NRAS request for a
  session.
- The bounded set narrows routing to the pinned upstreams (see the point of
  discussion).
- E2EE v2 defines field paths only for message content. teep refuses a
  request that carries `messages[].tool_calls`, `messages[].function_call`, `messages[].refusal`, `messages[].audio`, `prediction`, `tools`, `functions` and `response_format.json_schema`, and a response with tool calls.
  Not encrypted: the top-level `model`, `messages[].name`, `stop`, `tool_choice` and the top-level `function_call` (which name a function), and the other request parameters, including provider-specific prompt fields, which pass in plaintext.
- A stream is relayed before teep checks its receipt. A failed or missing
  check is reported after delivery: it is logged and ends the authorization
  generation. It does not withdraw the content that the client has.
- teep does not check the request hash of a request with a value that
  serde_json can write in another form (see [Receipts](#receipts)).
- `teep verify --reverify` does not check the recorded receipt again. A
  recorded receipt failure stays a failure. A recorded pass becomes a
  deferred skip that quotes the recorded verdict, because a factor does not
  pass on a check that did not run, so a replayed report differs from the
  live one in that line and in the score. Checking the receipt again needs
  the restored request and the pinned sessions, which a capture does not
  hold yet.

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
  replay a live capture of 2026-11-01 from `tee.redpill.ai` (4.8 MB): the
  report, the sessions, and the pinned E2EE v2 test exchange with its
  `X-ACI-Keyset-Digest` and `X-Receipt-Id`.
- `TestParseSessionFixtures`, `TestRebuildSession`,
  `TestParseSessionRejectsMalformedRecords` and
  `TestEvidencePartsRejectsMalformedBundles` in
  [session tests](../../../internal/provider/aci/session_test.go), and
  `TestPinSessions` and `TestPinSessionsRefuses` in
  [pin tests](../../../internal/provider/aci/pin_test.go).
- `TestSessionAuditPhalaModelCVM`, `TestSessionAuditChutes` and
  `TestSessionAuditRefuses` in
  [session audit tests](../../../internal/provider/phalacloud/session_audit_test.go);
  `TestFetchSessionsSelectsBoundedBundles` and `TestSelectBundles` in
  [session fetch tests](../../../internal/provider/phalacloud/sessions_test.go).
- `TestAuthorizedPhalaCloudRequiresPinnedSessions`, and the
  `sessions refused` case of `TestAuthorizedPhalaCloudACIv2`.
- `TestVerifyReceiptLive`, `TestVerifyReceiptRefuses`,
  `TestVerifyReceiptWithoutRequestHash` and
  `TestParseReceiptRefusesMalformed` in
  [receipt tests](../../../internal/provider/aci/receipt_test.go) check the
  live receipt of 2026-11-01 against the replayed capture.
  `TestRestoredRequestHashLive`, `TestRestoredForm`,
  `TestEncryptRequestRestoredHash` and
  `TestEncryptRequestRestoredHashNotReproducible` in
  [restored request tests](../../../internal/provider/aci/restored_test.go),
  and `TestFetchReceipt`, `TestFetchReceiptStopsAtDeadline` and
  `TestReceiptID` in
  [receipt fetch tests](../../../internal/provider/aci/receipt_fetch_test.go).
- The receipt cases of `TestAuthorizedPhalaCloudACIv2` check the proxy:
  a non-stream response held until its receipt verifies, which failures
  end the generation, a stream reset after `[DONE]` or after its first
  chunk, five endings that do not parse, a receipt for another model or
  another request, a 2xx status other than 200, a comment line then a
  reset, and a client that hangs up, whose deadline passes or
  whose connection breaks (the generation stays). `TestEndedByClient`
  checks who a relay failure names, teep's own deadline included, and
  `TestVerifyReceiptChecksServiceStatementsFirst` the order of the receipt
  check. `TestStandalonePhalaCloudProbe` checks the receipt of the
  `teep verify` probe and its capture, the same two resets, a reset
  without a receipt id, a stream without `[DONE]` and a chunk that does
  not decrypt included, and
  `TestTestE2EE_ACIv2ServedKeysetDigest` the failure of a response of
  another keyset. `TestResponseHash` is in
  [response hash tests](../../../internal/provider/aci/response_hash_test.go).
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
