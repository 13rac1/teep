# Plan: NEAR AI HTTP/2 Connection Reuse and Multiplexing

This plan records the migration design and phase structure. The implementation
is complete; the [transport reference](../transport/README.md) defines the
maintained behavior, and [API support](../api_support.md) defines endpoint
support. The pre-implementation survey below is historical. Phase file lists
and test inventories describe the migration, not a requirement to retain old
helpers or duplicate tests.

## Objective

Move `nearcloud` and `neardirect` from their manual HTTP/1.1
`PinnedHandler` path to the SPKI-pinned `net/http` transport path that
`tinfoil_v3_cloud` and `tinfoil_v3_direct` use.

As part of the consolidation, move `tinfoil_v3_direct` to the same immutable
`ResolvedRoute` contract as `neardirect`. This removes its independent cache,
attestation, supply-chain-repository, and inference resolution calls. Do not
replace tinfoil's pooled SPKI transport architecture or change its sticky-domain
selection, evidence policy, or EHBP protocol. Shared transport settings and the
bounded recovery policy below apply to tinfoil as well as NEAR.

The new atomic authorization cache applies only to providers that use the
pooled HTTP transport with `UsesTLSBinding == true`. At present, those are
`nearcloud`, `neardirect`, `tinfoil_v3_cloud`, and `tinfoil_v3_direct`.
Providers without TLS binding keep their current report, signing-key, and
per-request material paths.

TLS and E2EE keys for these providers are created during image boot and bound
to that booted image by attestation. A repository or discovery metadata change
does not revoke a valid authorization for the same attested keys. The
repository is a verification input on an authorization miss, not a continuing
transport identity and not an independent reason to expire or revalidate a
cached authorization. Use an expiration only when authenticated attestation
evidence supplies one. Otherwise, treat the authorization as valid for its
attested key until a trust failure, explicit invalidation, capacity eviction,
or process exit.

The completed change must:

- negotiate HTTP/2 for NEAR AI attestation and inference when the server
  supports it;
- reuse authenticated TLS connections and multiplex concurrent inference
  requests on them;
- never set `Connection: close` or `Connection: keep-alive`;
- verify WebPKI, TLS 1.3, Certificate Transparency, and the attested SPKI before
  any inference request bytes are sent on each new TLS connection;
- keep each connection pool within its provider, authority, and attested SPKI
  scope;
- re-attest and replace the selectable pool when an attested key changes;
- reject redirects in every teep-controlled outbound HTTP client;
- make `teep verify` use the same resolved route, SPKI-pinned transport, and
  HTTP/2-capable inference path as `teep serve` for TLS-binding providers;
- publish and invalidate reports, signing keys, routes, and transport identities
  as one immutable authorization generation;
- preserve all current fail-closed attestation and E2EE behavior for every
  supported NEAR AI endpoint; and
- remain safe when many clients send concurrent requests to multiple models and
  providers.

This work includes a transport migration and an explicit authorization-lifetime
change: TLS-binding authorizations stop using the local one-hour cache TTL.
Review and test the lifetime change separately. Do not change measurement
policy, factor enforcement, endpoint support, encryption algorithms, or response
schemas. Global redirect enforcement is a separate implementation phase because
it also affects discovery, release retrieval, and collateral clients.

## Pre-implementation Behavior (Historical)

### `nearcloud`

`internal/provider/nearcloud/pinned.go` implements the complete request on a
manually managed `tlsct.Conn`:

1. Open a new TLS connection to `cloud-api.near.ai` for every inference
   request.
2. Check WebPKI, TLS 1.3, and Certificate Transparency.
3. On an SPKI-cache miss, send
   `GET /v1/attestation/report` as HTTP/1.1 on that connection and verify the
   gateway and model evidence.
4. Send the inference request as HTTP/1.1 on the same connection.
5. Set `Connection: close` on the inference request.
6. Wrap the response in `neardirect.ConnClosingReader`, which closes the socket
   when the response body closes.

The attestation request sets `Connection: keep-alive`, but the connection is
never available to a pool after the inference response. Concurrent requests
therefore open independent TCP and TLS connections and cannot use HTTP/2
multiplexing.

The gateway attestation contains two TLS identities with different scopes:

- `GatewayTLSFingerprint` identifies the `cloud-api.near.ai` TLS peer and is
  the value that must authorize the inference transport.
- `RawAttestation.TLSFingerprint` identifies the selected model backend behind
  the gateway. It must remain in the verification report, but it must not pin
  the client-to-gateway connection.

### `neardirect`

`internal/provider/neardirect/pinned.go` uses the same manual HTTP/1.1 design.
It resolves the model through `EndpointResolver`, opens a new TLS connection to
the resolved `*.completions.near.ai` authority, performs attestation on a cache
miss, sends one inference request with `Connection: close`, and closes the
connection with the response body.

The direct provider's `RawAttestation.TLSFingerprint` identifies the same
authority that receives inference traffic. The model-to-authority mapping has a
five-minute cache and can change independently of the one-hour attestation
cache.

### Existing tinfoil v3 reference path

The reusable path is split across these files:

- `internal/provider/tinfoil/attester.go` calls
  `provider.FetchAttestationWithTLS`, compares the live attestation-connection
  SPKI with the attested TLS fingerprint, and returns the verified transport
  identity with the raw evidence.
- `internal/config/config.go:NewAttestationClient` provides a reusable
  attestation client, but its custom TLS transport does not currently set
  `ForceAttemptHTTP2`. Add that setting as part of this work so NEAR
  attestation fetches can negotiate HTTP/2. This also makes tinfoil attestation
  fetch behavior consistent with its inference transport.
- `internal/proxy/proxy.go` stores the attested fingerprint in
  `VerificationReport.TLSKeyFP`, gets it on both report-cache hits and misses,
  and routes inference through `sendUpstreamRequest`.
- `internal/proxy/pinned_upstream.go` owns one selectable `http.Client` and
  `http.Transport` per provider and authority. It replaces the entry when the
  expected fingerprint changes and closes idle connections in the old entry.
- `internal/tlsct/pinned.go` installs a constant-time SPKI comparison in
  `tls.Config.VerifyConnection`. A mismatch stops the TLS handshake before the
  HTTP transport can read the inference body or send request bytes.
- `internal/proxy/proxy.go:verifyUpstreamTLSBinding` currently compares the
  response TLS peer with the attested fingerprint again. This work removes that
  duplicate post-send check: pool selection and `VerifyConnection` must enforce
  provider, authority, and fingerprint before request bytes are sent.
- `newUpstreamTransport` sets `ForceAttemptHTTP2: true`,
  `MaxIdleConnsPerHost: 10`, and `IdleConnTimeout: 90s`. The pinned TLS config
  disables session resumption so a resumed session cannot bypass the
  attestation-bound identity check.
- `setUpstreamConnectionHeaders` does not set `Connection`; `net/http` owns
  connection lifetime and HTTP framing.

This path permits authenticated connections to remain in the pool. HTTP/2 can
then carry concurrent streams on one connection. The response body must still
be read to EOF and closed for reuse.

Tinfoil direct currently resolves its dynamic domain independently for the
cache suffix, attestation fetch, supply-chain repository, and inference URL.
This plan migrates those calls to one request-scoped route snapshot before the
shared authorization cache becomes authoritative.

## Live Investigation Results

Tests were run on 2026-09-04 with `NEARAI_API_KEY` loaded from `.env`. No
inference request content was sent and the key was not printed.

- `https://completions.near.ai/endpoints` returned HTTP 200 over HTTP/1.1.
  Discovery does not need HTTP/2 and must continue to work over HTTP/1.1.
- A direct attestation request to
  `glm-5-1.completions.near.ai/v1/attestation/report` returned HTTP 200 over
  HTTP/2.
- A cloud attestation request to
  `cloud-api.near.ai/v1/attestation/report` returned HTTP 200 over HTTP/2.
- Two sequential `/v1/models` requests in one client process used HTTP/2 for
  both providers. The first request opened one connection; the second opened
  zero new connections and used the same connection ID.
- A fresh TLS handshake to the direct authority produced the same SPKI as the
  model attestation's `tls_cert_fingerprint`.
- A fresh TLS handshake to `cloud-api.near.ai` produced the same SPKI as the
  gateway attestation's `tls_cert_fingerprint`.

These results show that the current services support the proposed transport
model. They do not replace automated tests because endpoint configuration and
server behavior can change.

## Security and Concurrency Invariants

The implementation is complete only if all of these invariants hold.

1. **No request before authentication.** A new inference TLS connection must
   complete system WebPKI, TLS 1.3, Certificate Transparency, and constant-time
   SPKI verification before its request headers or body are sent.
2. **Attestation fetch binding.** The TLS peer that returns attestation must
   match the TLS fingerprint in that response. This comparison is an early
   consistency check; the later quote and REPORTDATA verification authenticates
   the fingerprint itself. A TLS-binding report cannot pass
   `tls_key_binding`, and an authorization entry cannot be published, unless
   both derived transport-identity fields were populated after this comparison.
3. **Correct fingerprint scope.** `neardirect` uses the selected model
   authority's fingerprint. `nearcloud` uses the gateway fingerprint for the
   client transport and never substitutes the model backend fingerprint.
4. **Pool isolation.** A transport pool is selectable only for its provider,
   normalized HTTPS authority, and expected SPKI. Do not share a transport
   between `nearcloud`, `neardirect`, or tinfoil, even if hostnames or keys
   happen to match.
5. **Authority is part of the authenticated transport identity.** Cache the
   normalized authority observed during the attestation fetch with the SPKI.
   Before inference, require it to equal the request's resolved authority. An
   SPKI shared by two authorities must not make their evidence interchangeable.
6. **No mixed authorization state.** A report, E2EE key, transport authority,
   and transport fingerprint form one immutable authorization entry with one
   opaque generation identifier. Publish and read them atomically. Use the
   generation only for equality in conditional report updates and deletion; it
   does not order TLS keys and does not implement newest-key-wins revocation. A
   changed SPKI replaces the selectable pool and closes idle connections in the
   old pool. In-flight requests that already acquired the old client may finish
   or fail naturally.
7. **Collapsed re-attestation.** A cache miss initiates or joins one full
   re-attestation keyed by provider and route-scoped model. Caller cancellation
   must not cancel verification for other joiners, and the shared operation
   must have a fixed timeout. Recheck the positive and negative caches inside
   the singleflight callback before starting network work. A server-wide
   semaphore must bound active full verification across distinct keys. The
   callback must acquire it without waiting: if it is full, return a typed
   overload error. This bounds detached work without a keyed admission queue,
   waiter-counting scheduler, or queued operation that can outlive its caller.
8. **No TLS session resumption.** SPKI-scoped pools keep
   `ClientSessionCache == nil` and perform a full verified handshake for every
   new connection.
9. **Fail closed on missing state.** A TLS-binding provider with an empty,
   malformed, mismatched, or expired transport identity fails before
   publication and before inference I/O. Expired means past an expiration that
   authenticated evidence explicitly supplies; do not derive one from fetch
   time. This is an authorization-construction error, not a factor failure that
   `allow_fail` can bypass.
10. **One route per request.** `neardirect` and `tinfoil_v3_direct` must use the
   same resolved authority for their authorization-cache key, attestation URL,
   supply-chain repository selection, pinned pool, and inference URL.
   A discovery refresh must not mix evidence from one authority with traffic to
   another.
11. **No redirects.** Every teep-controlled outbound HTTP client must return
    3xx responses without following them. Fetch clients must treat the returned
    3xx as an error. Inference must convert it to a fail-closed proxy error and
    must not forward the redirect status or `Location` header to the downstream
    client. A redirect must not move credentials, encrypted request data, route
    data, or authorization state to another URL.
12. **Independent E2EE state.** Each multiplexed request gets its own ephemeral
   E2EE session. Never store a session, request body, response body, or nonce in
   the transport pool.
13. **Body ownership.** Every response path reads the body to EOF when safe and
    closes the original HTTP response body exactly once. A decryption reader
    has separate cleanup ownership; closing it must not replace closing the
    HTTP body. A rejection parser that closes the original body must replace
    it before returning, including on errors. Error paths close bodies and zero
    ephemeral key material. A bounded error-body read may cause `net/http` to discard a
    connection; it must never justify an unbounded read.
14. **Protocol correctness.** Do not send HTTP/1.1 connection headers or force
    `Transfer-Encoding: chunked` on HTTP/2. Let `net/http` use DATA frames and
    END_STREAM for bodies with unknown length.
15. **Bounded connection and verification use.** Each inference and attestation
   transport must have a finite active connection limit greater than one.
   Requests that wait for a connection must remain subject to the applicable
   context deadline. Verification admission does not wait; it returns a typed
   overload error when the server-wide limit is full. Per-host connection limits
   do not replace that cross-authority active-verification limit. Do not add
   cross-generation connection accounting: active connections already acquired
   from an old pool remain authenticated to that pool's key and are bounded by
   request deadlines and the server's incoming connection limit.
16. **No ambiguous NEAR discovery data.** Keep neardirect discovery validation
   limited to properties used for deterministic, safe routing: a bounded
   response, the top-level unknown and missing field checks that
   `jsonstrict.UnmarshalWarn` currently supports, a non-empty bounded mapping,
   one non-empty bounded model identifier per mapping, no duplicate model, and
   a valid provider-owned authority. Keep semantic validation for nested
   endpoint values, but do not add a custom recursive or duplicate-JSON-key
   parser for this change. Reject the complete refresh on malformed or
   ambiguous data; do not silently skip an invalid element and publish a
   partial routing map. Do not add overlapping per-array limits when one total
   mapping limit and the body limit suffice.
17. **Uniform SPKI per authority.** The design assumes that all concurrently
   reachable TLS endpoints for one authority present the same SPKI and that a
   rotation is uniform. DNS round-robin and load balancing do not change this
   assumption. If an endpoint violates it, any connection with a different SPKI
   must fail closed before request bytes are sent; do not add multi-key fallback
   behavior.

## Lifetime Model and Intentional Simplifications

These decisions are part of the security model. Do not reintroduce the removed
state or checks during implementation or review without identifying a different
provider lifecycle or threat model.

### Boot-bound authorization, not metadata-bound authorization

TLS and E2EE keys are created during image boot. Attestation binds those keys to
the booted image. If authenticated evidence has an explicit expiration, the
earliest applicable expiration bounds how long teep accepts that evidence. If
it has no explicit expiration, do not invent a local TTL: the authorization
remains key-bound until a trust failure, explicit invalidation, capacity
eviction, or process exit. Supply-chain repositories and discovery documents
help teep verify or locate the boot; they are not additional per-request
credentials.

Consequences:

- select the effective supply-chain repository from the same discovery snapshot
  as the authority when a new authorization is built;
- do not put the repository, discovery refresh time, or resolver generation in
  the authorization cache key;
- do not expire or reverify an authorization only because discovery metadata
  changed while its attested keys remain valid;
  and
- keep the report, E2EE key, authority, and SPKI in one entry because those are
  the materials that authorize and protect traffic.

If a backend restarts while a gateway TLS key remains unchanged, a request that
uses the old boot's E2EE key fails to decrypt at the backend or fails response
decryption at teep. Conditionally delete the authorization generation used by
the failed request.
A recognized pre-inference key rejection can invoke full re-attestation and one
retry under the retry policy below. A response-decryption failure or ambiguous
failure ends the logical request; the next request performs fresh attestation.
Never use plaintext fallback. No separate persistent failure marker or E2EE-key
expiry timer is required.

### Evidence expiration contract

Only verification outputs with an explicit authenticated validity bound may
contribute an expiration. Do not parse cached raw evidence a second time to
recover dates. Have the verifier return a validated optional bound with its
successful result, then take the minimum once during authorization construction.

| Evidence or state | Contribution to authorization expiration | Required implementation behavior |
| --- | --- | --- |
| TDX or SEV-SNP quote/report and REPORTDATA key binding | No separate expiration field in the quote/report itself | Preserve quote, nonce, measurement, and key-binding verification; do not manufacture an age limit from fetch time. |
| Intel online collateral used to pass enforced checks | Authenticated `nextUpdate`/valid-until bounds and the current-time certificate validity required by that verification | Extend the verified result to expose the earliest bound actually used by successful verification; do not copy an unchecked parsed field. Include gateway and model evidence when both apply. |
| NVIDIA NRAS overall JWT | Verified `exp`, when present | Require successful signature and claims validation. `NvidiaVerifyResult.ExpiresAt` is also populated on partial failure today, so its presence alone is insufficient. Per-GPU diagnostic JWTs are not independently verified by the current extraction path and supply no bound. |
| Local NVIDIA SPDM/EAT certificate verification | Verified certificate validity bounds required at verification time | Return the applicable bound from the successful verifier; do not infer a boot-key expiration from unrelated metadata. |
| Proof of Cloud JWT | No independently signature-verified expiration is exposed by the current implementation | `verifyPoCJWTClaimsAt` validates decoded claims without checking the JWT signature, and `PoCResult` has no validated expiration. Do not label its parsed `exp` an independently authenticated JWT bound or add signature verification in this transport change. Document this limitation. A future signature-verification change must return its validated bound explicitly. |
| Sigstore/Fulcio signing certificates and timestamped release evidence | No current authorization expiration solely from historical signer-certificate `NotAfter` | Preserve verification at the authenticated signing time. A historical signing certificate expiring now does not expire a correctly verified release. |
| Inference TLS certificate | No authorization-cache expiration | WebPKI checks its validity on every new handshake. Do not use its lifetime as a boot-key TTL. |
| Discovery, repository metadata, cache age, idle timeout, JWKS cache refresh | None | These are routing, verification-input, or resource-management state, not authorization validity bounds. |

A contributing verifier must distinguish absent, authenticated, and invalid
bounds. Absent is permitted only when the evidence format permits omission.
Malformed, unauthenticated, or already-expired evidence must retain the existing
factor failure behavior; never turn it into a successful result with no expiry.
An explicitly allowed factor failure supplies no trusted bound. Preserve its
failed/allowed report status. Do not derive bounds from diagnostics.

Check `now >= expiresAt` at publication and attempt acquisition. A verified
result that expires while other factors are running cannot be published. Report
promotion preserves the original bound. Test absent and zero timestamps,
malformed bounds, failed signatures with populated dates, multiple contributing
bounds, offline/inapplicable/allowed factors, and historical Sigstore validity.

### Request acquisition and invalidation

Define attempt acquisition as one cache operation immediately before preparing
an inference attempt. Under the cache lock, require that the candidate generation
is still the current entry and is unexpired, then return the immutable snapshot.
Receiving a singleflight result is not attempt acquisition: a delayed waiter must
acquire through this operation, so a result invalidated before delivery cannot
be used directly. If the entry is absent or expired, initiate or join full
verification; if replaced, acquire the current valid entry. All preparation and
network work occurs after releasing the lock.

Deletion prevents subsequent acquisitions. Attempts already acquired may finish
or fail naturally; deletion does not cancel other authorized streams. This is an
explicit concurrency boundary, not newest-key-wins revocation. Capacity eviction
has the same acquisition behavior. No lease, reference count, tombstone, or pool
epoch is needed. Unconditional explicit invalidation must also prevent an
already-running verification from publishing afterward: cancel that key's active verification
and condition publication on its active operation identity under the same state
lock. Retain that identity only while verification is active; do not retain
per-key invalidation history. Do not use `singleflight.Forget` to create competing
publishers. Generation-conditional failure deletion must not cancel a newer
verification operation: a late failure of A cannot interrupt construction of B.
This is internal lifecycle behavior; do not add an administrative API.

Each attempt's context deadline is the minimum of the logical request deadline
and its authenticated evidence expiration, when present. This bounds connection
waits, buffered response processing, and downstream writes without an independent
E2EE timer. Response writers must support `SetWriteDeadline`, directly or through
`Unwrap`; fail if the deadline cannot be applied. An expired attempt cannot
promote the report to E2EE success. Do not renew this
deadline on retries or report promotion. Check context cancellation before
invoking the transport; expiry during a wait cancels the attempt. Ordinary cache
deletion after acquisition does not introduce a second per-request validity
poll or repeat cryptographic verification.

### Generation equality, not key ordering

An authorization generation prevents a late result from request A from deleting
or mutating replacement authorization B. Equality is sufficient for that
purpose. A larger generation does not prove that its TLS key revokes a smaller
generation's key.

Consequences:

- use generation equality for conditional report updates and deletion;
- do not compare generations to select a TLS fingerprint;
- do not retain authority high-water marks or tombstones after a pool is
  removed; and
- let a valid authorization recreate its own pinned pool after
  capacity eviction. If its boot is gone, the SPKI-pinned handshake fails before
  request bytes are sent.

### One preventive TLS check

The attestation fetch first binds the returned evidence to its live TLS peer.
The inference transport then checks the authorized SPKI in
`tls.Config.VerifyConnection` before it sends request bytes. A response-time
comparison repeats the same property after disclosure and is not an independent
preventive control.

Consequences:

- validate the derived transport identity once with shared validation logic;
- check provider, canonical authority, and expected fingerprint during pool
  selection;
- enforce the SPKI in every new inference handshake; and
- do not add a response-time SPKI check, pool lease, or failure tombstone as a
  substitute for correct pre-send pool selection.

### Bounded verification admission

Singleflight collapses work only for the same key. A fail-fast semaphore also
bounds detached work across distinct keys without introducing a queue or a
second scheduler.

Consequences:

- collapse same-key misses with singleflight;
- recheck both caches inside the shared callback;
- acquire one server-wide verification semaphore without waiting and return a
  typed overload error when it is full;
- let canceled callers stop waiting without canceling work used by other
  joiners; and
- do not add a separate bounded keyed scheduler, waiter reference counts,
  queued detached operations, or new expiry rules.

### Redirects are protocol failures

Teep does not use redirects for outbound requests. This rule is broader than
attestation because discovery, model listing, collateral, and supply-chain
fetches can also carry credentials or influence authorization.

Consequences:

- install the policy in common teep HTTP-client construction;
- require every fetch caller to treat a returned 3xx as an error;
- convert an inference 3xx to a proxy error without forwarding `Location`; and
- add no same-authority exception.

### Review standard for additional state or checks

The omitted mechanisms are not deferred hardening tasks. A future change that
adds a cache-key dimension, independent expiry timer, key-order rule, retained
failure state, pool lease, retry, or repeated validation must first document:

- the provider lifecycle or client threat that differs from the assumptions in
  this plan;
- the security property that the existing attestation lifetime, generation
  equality, request deadline, semaphore, route snapshot, or pre-send TLS check
  does not enforce;
- why the new mechanism is independent defense in depth rather than a second
  enforcement of the same property; and
- its failure, cleanup, concurrency, and bounded-retention behavior, with a
  regression test for the identified threat.

Operational caution or a general preference for more validation is not enough
to add this state. If the assumptions remain true, preserve the simpler model.

## Proposed Design

Use the existing tinfoil v3 path rather than add a second provider-owned HTTP/2
implementation.

### Represent the inference transport identity explicitly

Add `TransportTLSFingerprint string` and `TransportTLSAuthority string` to
`attestation.RawAttestation`. Together they identify the authenticated TLS
origin that receives the inference request. The authority is the canonical
HTTPS authority whose WebPKI identity was checked during the attestation
fetch. The fingerprint is:

- tinfoil v3: the endorsed tinfoil TLS key;
- neardirect: `TLSFingerprint`;
- nearcloud: `GatewayTLSFingerprint`.

Populate both fields only after the attester has obtained a non-empty live peer
SPKI, compared it with the correct response field, and normalized the
attestation request authority. Keep the provider-native fields because factor
evaluation and report metadata still need them.

Change `attestation.BuildReport` to copy the two fields into
`VerificationReport.TLSKeyFP` and a new internal
`VerificationReport.TLSAuthority`. Remove its current tinfoil-only fingerprint
selection from `RawAttestation.TinfoilTLSKeyFP`. Update the tinfoil attesters to
set both new fields after their existing live-SPKI comparison. This makes the
transport contract provider-independent and prevents nearcloud from
accidentally using the model backend fingerprint.

Change `evalTLSKeyBinding` at the same time. When
`ProviderUsesTLSBinding == true`, it must evaluate the derived transport
identity, not the mere presence of a provider-native `TLSFingerprint`. Both
derived fields must be present and valid. Do not compare the derived fingerprint
with the provider-native field again: the attester already selected the correct
field and compared it with the live peer before it populated the derived
identity. Do not make `BuildReport` guess fingerprint scope from the provider
name.

Document the scope in the factor implementation and report field comments:
for `nearcloud`, `tls_key_binding` evaluates the attested gateway transport key
because that is the TLS peer teep contacts. The model backend fingerprint stays
authenticated through the model evidence and REPORTDATA checks, but it is not
the client-to-gateway TLS binding. For `neardirect`, the model endpoint and
transport peer are the same authority and key.

Use one shared derived-identity validator for factor evaluation and
authorization construction so validation rules are not duplicated. The
authorization constructor must receive a successful validation result for a
canonical authority and a 32-byte fingerprint before publication. This is an
internal authorization invariant and is not subject to `allow_fail` or
`--force`. A blocked report can still be returned to the current caller for
diagnostics, but missing or malformed transport identity can never become
authorization state.

Do not infer either transport-identity field inside `BuildReport` from the
provider name or from the first non-empty TLS field. The attester knows which
TLS peer and authority it contacted and must select the correct scope. Cache
only the minimum derived authorization material; do not store
`RawAttestation`, its raw response body, challenge nonce, or provider-specific
per-request state in the authorization entry.

### Bind each NEAR attestation response to its live TLS peer

Change both NEAR attesters from `FetchAttestationJSON` to
`FetchAttestationWithTLS`.

For `neardirect.Attester.FetchAttestation`:

1. Receive the already resolved route explicitly. Proxy and standalone
   orchestration each resolve once before this call; standalone verification
   retains the same route for its inference exercise.
2. Fetch and parse the attestation over the configured TLS client.
3. Require a non-empty peer SPKI and a non-empty
   `RawAttestation.TLSFingerprint`.
4. Decode and compare them with a shared constant-time fingerprint helper.
   Reject malformed hex and wrong lengths explicitly.
5. Set `raw.TransportTLSFingerprint = raw.TLSFingerprint` and
   `raw.TransportTLSAuthority = route.Authority` only after the comparison
   passes.

For `nearcloud.Attester.FetchAttestation`:

1. Fetch and parse the combined gateway and model response.
2. Require a non-empty peer SPKI and non-empty
   `GatewayRaw.TLSCertFingerprint`.
3. Compare those two values in constant time.
4. Copy all existing gateway evidence into `RawAttestation`.
5. Set `raw.TransportTLSFingerprint = gwRaw.TLSCertFingerprint` and
   `raw.TransportTLSAuthority` to the normalized gateway authority.
6. Do not compare the live gateway peer with `raw.TLSFingerprint`; that value
   describes the model backend behind the gateway.

Use one shared helper in `internal/tlsct` for validated, constant-time
fingerprint comparison. Extend the existing decoder or return an error-bearing
comparison result so malformed fingerprints are distinguishable from valid
non-matches. Do not keep `neardirect.ConstantTimeHexEqual` in a provider file
after the manual pinned path is removed.

The capture/replay transport already reconstructs `http.Response.TLS` from
`peer_spki_der_base64`. Keep fixture tests on the same binding path. A fixture
that lacks TLS peer data must fail closed and be recaptured; do not add a replay
exception to production attesters.

Install one shared client policy that returns `http.ErrUseLastResponse` for
every redirect in the common teep HTTP-client constructors. Do not accept a
redirect to the same authority: an unexpected path change is still a provider
protocol change and must fail closed. Apply the policy to every teep-controlled
outbound client, including attestation, route discovery, inference, model
listing, Sigstore, Rekor, collateral, and online verification clients. Audit
clients owned internally by dependencies separately; do not mutate
`http.DefaultClient` or other process-global HTTP state.

### Route TLS-binding inference through one resolved route

In `proxy.fromConfig`:

- set `UsesTLSBinding = true` for `nearcloud` and `neardirect`;
- leave each provider's existing `Attester`, `Encryptor`, `Preparer`, report
  verifier, policies, endpoint paths, and model lister in place;
- stop constructing either NEAR `PinnedHandler`;
- for nearcloud, use `https://cloud-api.near.ai` as the inference base URL;
- construct one `EndpointResolver` and inject that exact instance into the
  proxy-mode neardirect attester and the route resolver;
- for neardirect, resolve `https://` plus the selected authority into one typed
  request route, from which all cache keys and upstream URLs are derived;
- construct one tinfoil `DirectResolver` and use it only through the tinfoil
  direct route resolver in proxy mode; and
- preserve the original client model name in request JSON rewriting while the
  request route selects the authority.

Resolve dynamic TLS-binding routing once per incoming request. Add an immutable
`provider.ResolvedRoute` with an absolute HTTPS `BaseURL` and canonical
`Authority`. It can also carry an immutable `SupplyChainRepo` selected from the
same discovery snapshot for tinfoil direct. Add a typed authorization key that
combines provider, model, and route authority.

Add `Provider.ResolveRoute`, called by the proxy after it extracts the model and
before the first cache lookup. The proxy must validate that the returned URL is
an origin-only absolute HTTPS URL without userinfo, path, raw path, query,
fragment, opaque data, percent-escaped host bytes, or an IPv6 zone. Normalize
case, a trailing DNS dot, default port, and IPv6 form once. Construct `BaseURL`
with `url.URL`, not string concatenation. Keep validated route and transport
identity fields private, expose values or defensive copies, and store the
validated fingerprint as a fixed 32-byte value. Do not expose a mutable URL
pointer, key slice, or report map. Validate and decode at construction; downstream
code compares typed values instead of reparsing URLs or decoding fingerprints.
Construct the typed authorization key
directly from provider, model, and `route.Authority`; do not accept an
independently supplied cache suffix. Give that type one private, unambiguous
serialization for the `singleflight.Group` key instead of reconstructing it at
call sites. Static TLS-binding providers receive a validated route derived once
from their configured base URL.

The cache identity intentionally excludes `SupplyChainRepo`. TLS and E2EE keys
are created during image boot and attestation binds them to that booted image.
The effective repository is selected once from the same discovery snapshot and
used only while building a new authorization. A later repository mapping change
does not invalidate a valid authorization for the same attested keys and
must not trigger independent revalidation.

Pass the typed route and authorization key explicitly through cache lookup,
negative-cache lookup, verification, invalidation, supply-chain verification,
and `authorizedRoundtrip`. Do not make those operations recover security state
from `context.Context`, and do not silently fall back to a bare model key. If an
existing provider interface cannot receive a route directly, use one narrow
adapter at the attester call boundary; absence there is an internal error. For
tinfoil direct,
`ResolveRoute` must preserve the existing `prompt_cache_key` sticky-domain
selection and copy the repository from the same `ModelMapping` snapshot into
`SupplyChainRepo`; verification must not resolve the repository again.

Remove the dynamic `BaseURLForModel`, `CacheKeySuffix`,
`SPKIDomainForModel`, and `SigstoreRepoForModel` callbacks for neardirect and
tinfoil direct after their behavior moves to `ResolveRoute`. Static callbacks
can remain where they do not perform discovery. Do not call either resolver
independently for the cache key, attestation, repository, SPKI scope, and
inference URL. This avoids an expiry-boundary race where a discovery refresh
changes the mapping between those operations.

Put route setup in one proxy helper and call it from every entry path that can
fetch, cache, invalidate, or use authorization state. This includes
`handleEndpoint`, `handleExploreAttest`, explore report lookup, standalone
verification, and internal inference helpers. Each helper receives the returned
route and authorization key explicitly. Extract a shared internal inference
operation that accepts the
resolved route and authorization key and returns the report/generation actually
used, including attempt-local E2EE promotion. The main HTTP handler and
`loopbackInfer` both call it. Explore must not call `ServeHTTP` and then recover
security state through context or a second cache lookup. A replacement report
for the same route is not necessarily the report used by the completed request.
Do not leave an entry path that uses the bare model key or resolves again.

Apply focused fail-closed validation to neardirect endpoint discovery before it
becomes a routing input. Enforce the 1 MiB decoded-body limit by reading at most
limit plus one byte and rejecting any larger result; a valid 1 MiB prefix must
not make an oversized body acceptable. Add one named total mapping limit and
bound model identifiers. Decode with `jsonstrict.UnmarshalWarn` and reject the
top-level unknown and missing fields that it currently reports. Do not add a
custom recursive strict decoder or duplicate-JSON-key scanner in this work.
Require a non-empty endpoint set, non-empty model identifiers, and exactly one
mapping for each model. Reject duplicate model mappings, control characters,
Unicode or punycode hostnames, IP literals, IPv6 zones, invalid DNS labels, and
invalid ports. Production NEAR discovery authorities must remain under
`near.ai`. Reject the complete refresh; do not skip invalid elements or use
last-value-wins selection. Do not add separate endpoint,
models-per-endpoint, DNS-name, and authority-length limits when the body limit,
one total mapping limit, and canonical authority validation already bound those
values.

A discovery change means that a refreshed model mapping selects a different
authority, or for tinfoil also a different repository or eligible domain set.
It does not mean that an attested key changed. Keep discovery behavior
fail-closed and distinct from authorization lifetime: when a required stale
refresh fails, return an error and do not route with the old map, but do not
delete an existing authorization merely because the refresh failed. If refresh
maps the model to a new authority, use the new route key and attest it. The old
route authorization can remain until capacity eviction or another key-specific
invalidation. A repository-only change affects the next authorization
construction; it does not reverify an already valid exact-route authorization.
Concurrent callers continue to join one bounded refresh.

Do not expand this phase into a general rewrite of tinfoil discovery. The
tinfoil direct route must still validate its selected origin through the shared
route validator and must use one `ModelMapping` snapshot for domain and effective
repository selection. Broader response-policy changes for that existing
resolver are separate work.

After the authorization load succeeds, the flow provides the immutable
authorization snapshot to `authorizedAttempt`. Authorization construction
compares the snapshot's `TLSAuthority` with the route authority. Then
`pinnedClientForIdentity` obtains the provider-and-authority pool and performs the
SPKI check in every new TLS handshake. Remove the response-time SPKI comparison:
it repeats the same fingerprint check after request bytes have already been sent
and adds no preventive protection. Pool lookup must compare the selected entry's
provider, authority, and fingerprint before it returns the client.

Do not add `Connection` headers. Keep `ForceAttemptHTTP2: true` on every
SPKI-pinned base transport. Also set it on the reusable transport created by
`config.NewAttestationClient`; installing a custom `TLSClientConfig` disables
Go's automatic HTTP/2 setup unless this field is explicit. HTTP/1.1 remains an
acceptable negotiated protocol if an endpoint does not advertise HTTP/2, but
it must still use persistent connections and all the same TLS checks. Keep the
AMD KDS TLS 1.2 transport separate. It is exempt from the HTTP/2 requirement if
the service does not advertise HTTP/2; preserve its finite connection limits,
redirect policy, and context cancellation.

Set a finite `MaxConnsPerHost` on the reusable attestation transport as well as
on inference transports. Use a value greater than one so unrelated model
attestations can progress. The authorization verification semaphore separately
bounds aggregate work across different authorities and the CPU- and
network-intensive factor checks. Neither limit may be held while waiting on a
cache mutex or pool-registry mutex.

Use one shared transport-construction helper for proxy inference and standalone
verification, with an attestation variant that does not install an inference
pin. It owns protocol selection, TLS/CT composition, redirects, connection
limits, environment proxy selection (`HTTPS_PROXY` and `NO_PROXY`), and
connection-establishment budgets. Preserve `http.ProxyFromEnvironment` when
constructing a transport. Test proxy selection in a fresh process because Go
caches environment proxy configuration. Do not duplicate these settings in
`internal/verify`. Keep the AMD KDS TLS-version exception explicit.

Use five-minute TCP dial and five-minute TLS handshake budgets, including the
separate KDS transport. These are long resource-cleanup budgets, not key expiry
or per-stream timeouts. A future SOCKS/Tor dialer must apply the dial budget to
the complete connection setup, including proxy negotiation. A roughly one-minute
Tor connection attempt fits inside this budget. Go can continue dialing after
a requesting caller is canceled, so the finite dial and handshake budgets are
necessary even with request deadlines. Tests inject short budgets and prove
stalled connections eventually release their slots; do not wait five minutes.

Existing shorter request, discovery, or attestation deadlines can still end an
operation earlier. In particular, the current attestation client timeout is
30 seconds. This change prevents permanent slot occupation; it does not claim
complete Tor support. When Tor is enabled, its request/verification budgets must
also allow slow connection setup and verification. Keep those budgets injectable
and avoid introducing another short transport timeout.

Use named initial limits of 16 active connections per attestation host, 16
active connections per inference pool, 16 concurrent full TLS-binding
verification operations per server, and a two-minute fixed timeout for each
shared full verification operation. Tests must use injected smaller limits and
timeouts instead of waiting on production values. Changing these limits later
is a capacity decision; zero must never mean unbounded on these transports or
the verification semaphore.

Reject redirects in each SPKI-pinned `http.Client`. The client must not issue a
second request. Convert a returned inference 3xx to a fail-closed proxy error and
do not forward its `Location` header to the downstream client. Do not depend on
the default header-copy rules to protect credentials.

### Publish one TLS-binding authorization entry per route

Replace the independently updated report and signing-key entries on the
HTTP/2-capable TLS-binding path with one immutable authorization entry keyed by
provider and route-scoped model. Do not migrate providers with
`UsesTLSBinding == false` to this cache. The entry contains:

- the verification report;
- the minimum REPORTDATA-verified E2EE public key, when applicable;
- the normalized transport authority and fingerprint;
- a server-owned opaque authorization generation assigned when the entry is
  published and used only for equality checks; and
- the earliest explicit expiration authenticated by applicable evidence, when
  such an expiration exists.

The entry must not contain `RawAttestation`, a raw response body, an attestation
challenge nonce, an E2EE session, or request-specific material. A singleflight
result returns only this immutable entry. Every joined caller creates its own
E2EE session from the cached verified public key. The repository used during
supply-chain verification is not continuing authorization material and is not
stored for per-request comparison.

The generation prevents a result from an old request from updating or deleting
a replacement authorization. It is not a key freshness value, is not compared
with `<` or `>`, and must not be used by the pool to implement newest-key-wins
selection. A server-owned counter is acceptable if code treats its values as
opaque equality tokens. Store it on `Server`; do not add writable package
state.

Read and publish this entry atomically. The cache owns the report and never
returns a mutable cached pointer: return a deep immutable snapshot, or keep all
report mutation behind cache compare-and-swap methods. Publish only an
authorization whose enforced factors pass, whose derived transport identity
passes the non-bypassable constructor checks, and whose protocol-required E2EE
public key is present, valid, and authenticated by REPORTDATA. Validate these
construction properties once; a partial authorization is never a cache hit.
A blocked report can be returned
to each joined caller for diagnostics, but it must not be retained in a new
unbounded diagnostic cache or become authorization state unless the debug-only
`--force` option explicitly bypasses its enforced factor failures. `--force`
does not bypass malformed or missing transport identity. Reuse the existing
cache capacity. Do not use the existing locally chosen attestation-cache TTL for
this TLS-binding authorization. Use only an expiration authenticated by the
applicable evidence, and use the earliest one when several authenticated
evidence objects expire. If no applicable evidence has an expiration, store no
wall-clock expiration. Do not introduce independent expiry conditions for
derived identity, repository metadata, connection idle time, or E2EE key
material that belongs to the same boot-bound authorization.

Use generation-conditional operations:

- report-only promotion clones the current report and replaces it
  under the cache lock only if the authorization generation still matches;
- a TLS/SPKI, authority-consistency, or E2EE trust failure deletes
  authorization only if the immutable generation matches; a discovery refresh
  failure or repository-only change does not delete it;
- no operation from an old generation can update or delete a replacement; and
- do not add a separate persistent E2EE-failure marker when conditional
  deletion already forces the next request to perform fresh attestation. Any
  negative-cache record created after authorization acquisition must be tied to
  the same generation or omitted if it would block a replacement generation.

Refactor the cache-miss operation so it does not write to an
`http.ResponseWriter`. It must return a typed result or error that each caller
can render independently. Put the full fetch, cryptographic verification,
factor enforcement, and atomic publication inside a `singleflight.Group`
operation keyed by provider and route-scoped model. Use `DoChan`, a detached
context derived from the server lifecycle, and a fixed verification timeout so
canceled callers return promptly without canceling the shared operation.
Server shutdown cancels detached verification, prevents later publication, and
closes idle pools; do not detach from server shutdown. Inside the singleflight
callback,
recheck the positive and negative caches, then try to acquire one bounded
server-wide verification semaphore without waiting. Return a typed overload
error if it is full. Hold the semaphore only around the full network and
cryptographic operation and always release it. Same-key callers still join one
operation; distinct excess keys do not create queued detached work. Do not put
the overload result in the negative cache. The HTTP handler maps it to 503 and
may send a fixed `Retry-After`; it must not expose internal key or capacity
details. Do not add waiter accounting or cancellation ownership to singleflight.
Do not share
`RawAttestation`, request E2EE sessions, or any one-use material; joiners share
only immutable verified authorization material.

Providers without TLS binding, including providers that require specialized
per-request E2EE material, remain on their existing cache and material paths.
Do not route them through the TLS-binding authorization singleflight as part of
this change.

Move tinfoil and NEAR to the TLS-binding authorization cache in separate phases.
Keep the old report and signing-key caches for non-TLS-binding providers and for
any TLS-binding provider not yet migrated in that phase. Remove only state that
became unused; do not remove caches that non-TLS-binding providers still
require. This temporary phase boundary keeps every commit buildable without
retaining a final compatibility path for TLS-binding providers.

Do not enable neardirect's production `ResolveRoute` while its old
`PinnedHandler` still resolves independently. An earlier phase can construct and
test the resolver and proxy-mode attester contract, but the NEAR migration phase
must enable the route, authorization cache, and standard transport dispatch
together. This avoids a
buildable intermediate commit that appears route-bound while the active handler
still selects its own authority.

### Preserve NEAR E2EE headers on the standard path

The manual handlers currently add all of these headers for a
`NearCloudSession`:

- `X-Signing-Algo: ed25519`
- `X-Client-Pub-Key: <per-request public key>`
- `X-Encryption-Version: 2`
- `X-Encrypt-All-Fields: true`

The standard `prepareUpstreamHeaders` path currently constructs the first
three, while `neardirect.Preparer` ignores the supplied E2EE headers. Before
switching dispatch paths:

1. Add `X-Encrypt-All-Fields: true` to the shared `NearCloudSession` header
   construction.
2. Change `neardirect.Preparer.PrepareRequest` to copy only the four recognized
   NEAR E2EE headers with `Header.Set` after it sets provider authorization.
3. Validate that the internal session produced all four exact protocol headers
   before constructing the upstream request. Downstream client headers are not
   copied into this internal header set, so do not add a second client-conflict
   rejection path.
4. Keep one header-building implementation for nearcloud and neardirect.
5. Preserve the current behavior that omits `X-Model-Pub-Key`; adding it can
   bind traffic to an unavailable instance after backend restart or scaling.

Refactor `buildUpstreamBody` to consume the signing key from the immutable
authorization snapshot. On an authorization hit, it must not read a second key
cache. A snapshot cannot lack required key material after validated construction.
Treat such a state as an internal invariant failure, not a reason for a second
attestation lookup in the body builder. Do not publish partial entries or create
a loop that repeatedly retrieves the same incomplete cache hit.

### Make standalone verification use the same TLS-binding contract

Update `internal/verify/factory.go:providerUsesTLSBinding` to include
`nearcloud` and `neardirect`. In `internal/verify/e2ee.go`, resolve a dynamic
route once before attestation and retain that immutable value through E2EE
verification. Remove the second direct resolver calls for NEAR and tinfoil.

For every TLS-binding provider, build the verifier's inference client from the
report's validated transport fingerprint and the retained route authority. Call
the shared transport constructor for the same WebPKI, TLS 1.3, CT,
disabled-session-resumption, redirect, finite connection-limit, dial/handshake
budget, and `ForceAttemptHTTP2` settings as the proxy transport. The
standalone command does not need the server's reusable pool registry, but it
must exercise the same pre-send SPKI check and negotiate HTTP/2 when the peer
offers it. Nearcloud uses the gateway fingerprint for this client. Do not add a
post-response duplicate SPKI check.

If current authenticated provider evidence does not expose a verified
expiration, the authorization expiration field is absent. Do not synthesize it
from report creation time, attestation fetch time, a discovery refresh time, a
TLS certificate lifetime, or a transport idle timeout.

### Remove the manual HTTP/1.1 path

After both providers use the standard path, remove code that exists only for
manual NEAR connections:

- delete `internal/provider/nearcloud/pinned.go` and its obsolete tests;
- delete `internal/provider/neardirect/pinned.go` and its obsolete tests;
- remove `WriteHTTPRequest`, `ConnClosingReader`, manual read deadlines,
  per-request TLS dial hooks, provider-local SPKI singleflight logic, and all
  explicit `Connection` header code only after the shared authorization
  singleflight has replacement coverage;
- remove `PinnedHandler`, `PinnedRequest`, and `PinnedResponse` from
  `internal/provider/provider.go` if no provider remains on that interface;
- remove `Provider.PinnedHandler` and pinned-only proxy dispatch,
  `handlePinnedChat`, `handlePinnedNonChat`, `pinnedPreDispatchE2EE`, and
  `pinnedPostDispatchE2EE` if they have no callers;
- remove `SPKICache`, `SPKIDomainForModel`, and dashboard SPKI-cache counters if
  they become unused. The `pinnedUpstreamPools` registry is different state and
  must remain; it contains reusable handshake-pinned transports;
- simplify `fromConfig` parameters that existed only to construct NEAR pinned
  handlers; and
- update package comments and user-visible status labels that still describe
  NEAR as a same-socket or connection-pinned provider.

Do not retain unused compatibility wrappers. Preserve independently useful TLS
helpers and their behavior coverage. TLS-binding inference uses only the
authorized path and selects its pool from the acquired transport identity.
Remove the generic send path's TLS-binding branch, independent pin lookup, and
invalidation helpers. Consolidate duplicate tests on the authorized path while
retaining coverage for non-TLS-binding dispatch.

### Pool lifecycle and connection reuse

Retain the tinfoil pool behavior as the initial policy:

- registry key: provider plus normalized HTTPS authority;
- selected entry: one expected SPKI, client, and transport;
- same fingerprint: return the same client and pool;
- changed fingerprint: publish a new pool atomically, then close idle
  connections in the old pool;
- registry bound: 1,000 entries with oldest-entry eviction;
- transport settings: `ForceAttemptHTTP2: true`,
  `MaxIdleConnsPerHost: 10`, `MaxConnsPerHost: 16`,
  `IdleConnTimeout: 90s`, and default keep-alive behavior;
- no per-request `CloseIdleConnections`; and
- no `Connection` header.

A request that already acquired an old client before a replacement can finish
or fail naturally. The connection remains cryptographically bound to the key
authenticated during its handshake; it cannot become a connection to the new
boot. If the old boot no longer exists, a new connection pinned to its old key
fails before request bytes are sent. If the old boot remains reachable and its
authorization is valid, observing a second key does not by itself prove
that the old boot was revoked.

Do not add authorization-epoch ordering, pool leases, high-water marks, or
tombstones. Those mechanisms implement an unstated newest-key-wins revocation
policy and require complex retention rules for cached and in-progress
authorizations. Attestation establishes whether a boot and its keys are
authorized; it does not establish that the latest observed key revokes every
earlier valid key. The handshake pin provides
the required fail-closed boundary for an unavailable or replaced boot.

Pool eviction is capacity cleanup, not a trust event. A valid
authorization can recreate a pool for its own expected fingerprint after LRU
eviction. The new handshake must still pass WebPKI, TLS 1.3, CT, and the SPKI
pin before request bytes are sent.

Document that `MaxIdleConnsPerHost` affects idle HTTP/1.1 connections. HTTP/2
normally uses one connection per authority and multiplexes streams up to the
peer's advertised limit. Do not set `MaxConnsPerHost` to one: that can reduce
availability when the peer reaches its concurrent-stream limit or sends
GOAWAY. The finite limit lets the Go transport open additional fully verified
connections when needed. When a new dial cannot acquire a physical socket
permit, reject it with an explicit capacity error; do not wait for socket
closure when an existing HTTP/2 stream can finish without closing its socket.
Inference returns HTTP 503 without replay or authorization invalidation.
HTTP/1.1 connection waits remain bounded by the request context deadline.
Do not enable `StrictMaxConcurrentRequests`: Go 1.26.8 and 1.27.1 can deadlock
because stream admission counts reservations queued behind the holder of
`reqHeaderMu`. See the maintained [transport reference](../transport/README.md).

On a TLS handshake SPKI mismatch, keep fail-closed behavior: conditionally
delete only the authorization generation used by the request and require fresh
attestation for the next logical request. The failed handshake does not add a
connection to the pool, so do not add separate pool-retirement or persistent
failure-marker state. Do not perform an application-level inference retry; the
body may be non-idempotent and its E2EE session is single-request state.

Assume one uniform SPKI per authority, including authorities reached through
DNS round-robin or a load balancer, and assume rotations are uniform. A staged
or non-uniform rotation can cause temporary unavailability. That result is
acceptable: the mismatch must block, conditionally delete the authorization
generation used by the request, and require re-attestation. Do not accept a set
of keys for one authorization,
try a second key during one logical request, or route around the mismatch.

### Retry classification and ownership

Teep should retry recoverable failures when it can establish that inference was
not processed. Transience alone is insufficient: a timeout or HTTP/2 reset after
a write can occur after inference started. Use one bounded attempt loop for the
TLS-binding path shared by proxy and standalone inference, with at most two
application attempts total (one retry), under one logical request deadline.
Do not nest provider-specific retry loops or alter non-TLS-binding retry behavior.

| Failure | Retry action | Authorization action |
| --- | --- | --- |
| Typed temporary or timed-out DNS error, or a dial error, before any connection was assigned to the attempt | Teep may retry once if the caller is active and the deadline permits | Retain authorization and pool; reacquire a valid snapshot for the retry. |
| Stale connection or HTTP/2 stream error after connection assignment, including `REFUSED_STREAM` and GOAWAY | No application retry; encrypted requests have no `GetBody` replay source | Retain authorization. Do not infer non-processing from a reset or EOF. |
| Recognized pre-inference E2EE key rejection described below | Conditionally invalidate, initiate or join full attestation, then retry once with a new session | Use the replacement/current verified authorization, never a key from an error response. |
| SPKI, authority, WebPKI, CT, attestation, or required factor failure | No retry of the logical inference request | Preserve fail-closed handling; conditionally invalidate the applicable generation for a trust failure. |
| Ambiguous write/read failure, peer `PROTOCOL_ERROR`, generic 4xx/5xx, redirect, malformed error, or response-decryption failure | No retry | Only a demonstrated trust/key failure invalidates; ordinary input, auth, rate-limit, and service errors retain valid keys. |
| Caller cancellation, logical deadline, or authenticated evidence deadline | No retry | Cancellation and ordinary I/O failures retain the authorization. Expired evidence requires new authorization for subsequent requests. |

Use a typed decryption failure for response authentication failures, including
EHBP AEAD failures. Do not classify every relay error as a key failure: client
cancellation, upstream I/O failures, and downstream write failures do not revoke
shared authorization. Test that another client can use the same authorization
after a canceled stream.

Recognize pre-inference key rejection only in a plaintext error envelope. An
EHBP response-nonce header prevents plaintext rejection parsing, even for HTTP
422 and `application/problem+json`. Authenticate encrypted error bodies through
the ordinary decryption path. A corrupt encrypted error invalidates the used
generation without replay; an authenticated error retains it.

Classify typed errors at the connection boundary and retain per-attempt phase
state. A failed `net.Error` or absent `WroteRequest` callback alone is not proof
that nothing was processed. Conservatively stop classifying a failure as
pre-connection once `httptrace.GotConn` has fired, even if a later callback did
not run. Trace callbacks can run concurrently; protect the per-attempt phase
flag and never reset it during an internal transport retry. This state must not
live on the shared transport or provider. Do not inspect
error strings to reconstruct Go's private HTTP/2 errors.

Set inference `Request.GetBody = nil` after constructing each request. The
current buffered NEAR body otherwise enables replay on Go 1.26 after a peer
`PROTOCOL_ERROR`, which does not prove non-processing. Go 1.27 differs; test the
minimum supported Go version as well as the development toolchain. See
[Go 1.26 HTTP/2 retry implementation](https://github.com/golang/go/blob/go1.26.0/src/net/http/h2_bundle.go#L7530).
Do not add idempotency headers to manufacture replay permission. When stdlib
hides a retry-safe HTTP/2 condition behind an untyped error, return that error;
do not introduce a custom HTTP/2 implementation solely to recover that case.
Safe internal retries which do not require body replay may still occur.

For an application retry, close the previous response if any, zero the previous
session, reacquire authorization, and rebuild encryption from the retained,
bounded normalized request body with fresh ephemeral state. Reuse the resolved
route; never resolve another backend to make a failed request succeed. Do not
reset timeouts or render any downstream response before deciding to retry.
A generic failure after a response, or after any downstream output, ends the
request. Log only the classified failure, provider, and attempt number.

### Provider key-rejection contracts

Reference implementations inspected on 2026-09-05 establish these protocol
signals. They inform teep's classifier; they are not instructions to copy their
fallbacks, logging, parsing, or mutable client state.

| Provider/protocol | Recognized rejection | Meaning and handling |
| --- | --- | --- |
| NEAR direct | HTTP 400 JSON with `error.type = "bad_request"` and exact `error.message = "Decryption failed"` | `inference-proxy/src/encryption.rs:decrypt_string` returns this failure while decrypting request fields, before inference dispatch. Invalidate the used generation. A retry requires this exact pre-inference contract for the endpoint. |
| NEAR cloud | HTTP 400 JSON with `error.type = "invalid_request_error"` and exact `error.message = "Decryption failed"` for chat | The cloud extracts the backend message, maps HTTP 400 to `InvalidParams`, and converts that to this envelope. Invalidate the used generation and retry once after full attestation. Verify the envelope and pre-inference propagation separately for other supported endpoints. Do not match an arbitrary substring in a provider message. |
| Tinfoil cloud/direct EHBP | HTTP 422, media type `application/problem+json`, and exact `type = "urn:ietf:params:ehbp:error:key-config"` | EHBP middleware probes decryption before calling the inference handler and returns this problem on key mismatch. Conditionally invalidate, perform full attestation, and retry once. Generic 422 responses do not identify key rejection. |

NEAR source references: `reference_impls/nearai/inference-proxy/src/encryption.rs`,
`src/error.rs`, and `src/routes/chat.rs`; cloud propagation is in
`reference_impls/nearai/cloud-api/crates/inference_providers/src/attested/nearai/mod.rs`,
`crates/inference_providers/src/lib.rs:extract_error_message`,
`crates/services/src/completions/mod.rs:map_provider_error`, and `crates/api/src/conversions.rs` plus `crates/api/src/routes/common.rs`.
Other NEAR endpoints must have equivalent propagation coverage;
a chat-only assertion is insufficient.

Tinfoil source references:
`reference_impls/tinfoil/encrypted-http-body-protocol/protocol/protocol.go`,
`identity/middleware.go`, and `client/client.go:isKeyConfigMismatchResponse`.
`reference_impls/tinfoil/tinfoil-go/ehbp_transport.go:RoundTrip` already performs
one re-attestation/retry for that rejection. Teep must use its own atomic cache
and full factor policy instead of copying the reference client's mutable state.

Inspect candidate non-200 errors before the generic status-forwarding branch.
Read at most 64 KiB plus one byte and reject oversized or malformed candidates;
use `internal/jsonstrict` with explicit protocol schemas. Ignore free-form titles
for classification and never log error bodies. These errors are received through
the attested TLS transport, but are not successful E2EE responses: they cannot
promote `e2ee_usable` or supply keys. Preserve bounded body ownership for ordinary
errors so classification does not consume a body that another branch expects.

An encrypted error response that fails authenticated decryption invalidates its
generation regardless of status, but does not justify replay. A generic plaintext
error status does not prove key expiry. Test wrong/missing types, near-matching
messages, ordinary 400/401/403/422/429/5xx, repeated rejection, and concurrent
rejections after another request has installed a replacement generation.

## Implementation Phases

Use one commit per phase. Run `make check` before each commit and stage only the
files changed in that phase.

### Phase 1: Transport identity and common transport construction

Files:

- `internal/attestation/attestation.go`
- `internal/attestation/report.go`
- `internal/attestation/report_test.go`
- `internal/provider/tinfoil/attester.go`
- `internal/provider/tinfoil/attester_test.go`
- `internal/config/config.go`
- `internal/config/config_test.go`
- `internal/tlsct/pinned.go`
- `internal/tlsct/pinned_test.go`

Work:

1. Add `RawAttestation.TransportTLSFingerprint` and
   `RawAttestation.TransportTLSAuthority` with precise scope comments.
2. Make `BuildReport` source `VerificationReport.TLSKeyFP` and
   `VerificationReport.TLSAuthority` only from those fields.
3. Add one shared derived-identity validator. Make the TLS-binding factor use
   its result; do not compare the derived value with the provider-native field
   again.
4. Set both fields in the tinfoil attesters after their existing live-peer
   comparison so tinfoil behavior does not change.
5. Add the shared validated constant-time comparison helper.
6. Enable HTTP/2 attempts and a finite active-connection limit on the shared
   attestation client. Test the transport settings, connection wait
   cancellation, and negotiated protocol. Keep the AMD KDS TLS 1.2 client
   exempt from the HTTP/2 requirement if its service does not support HTTP/2.
7. Consolidate proxy and standalone transport settings, including the
   five-minute dial and handshake budgets. Test stalled handshake cleanup and
   successful slow setup with injected values, including KDS.
8. Add tests for direct, gateway, empty, malformed, and mismatched identities.

Commit purpose: introduce provider-independent identity and transport
construction without changing NEAR dispatch or global redirect behavior.

### Phase 2: Global redirect enforcement

Files: common HTTP-client constructors, fetch/inference status handlers, and
focused tests for discovery, model listing, release retrieval, collateral,
Sigstore, Rekor, and online verification.

1. Install the shared reject-redirect policy in every teep-controlled client.
   Audit dependency-owned clients without changing global HTTP state.
2. Reject fetch 3xx responses and convert inference 3xx to a proxy error without
   forwarding `Location`.
3. Test direct successful responses as well as same-authority and cross-authority
   redirects through representative production constructors. Record any provider
   dependency on redirects as a compatibility finding; do not silently weaken
   the policy to make live checks pass.

Commit purpose: make the broader outbound-client behavior change independently
reviewable from NEAR pooling and authorization lifetime.

### Phase 3: Bind NEAR attestation fetches to live TLS

Files:

- `internal/provider/neardirect/nearai.go`
- `internal/provider/neardirect/nearai_test.go`
- `internal/provider/nearcloud/nearcloud.go`
- `internal/provider/nearcloud/nearcloud_test.go`
- capture fixtures only if existing ones do not contain usable TLS peer SPKI
  metadata

Work:

1. Use `FetchAttestationWithTLS` in both attesters.
2. Apply the correct direct or gateway fingerprint selection.
3. Set both transport-identity fields only after a successful comparison.
4. Add TLS test-server coverage for success and every fail-closed case.
5. Test that a same-authority or cross-authority redirect is not followed.
6. Run fixture verification to prove replay exercises the same code.

Commit purpose: authenticate the transport identity before any provider uses
it for pooled inference.

### Phase 4: Add immutable request routes

Files:

- `internal/provider/provider.go`
- `internal/provider/neardirect/nearai.go`
- `internal/provider/neardirect/endpoints.go`
- `internal/provider/tinfoil/attester.go`
- `internal/provider/tinfoil/resolver.go`
- `internal/proxy/proxy.go`
- `internal/proxy/explore.go`
- focused NEAR and tinfoil route, discovery, and explore tests

Work:

1. Add `ResolvedRoute`, a typed route-scoped authorization key, strict origin
   validation, and one request-scoped resolution function. Pass the route and
   key explicitly after resolution; permit a narrow context adapter only at an
   unchanged provider interface boundary.
2. Add and test the single-resolver construction for each dynamic provider.
   The new attester adapter requires a supplied route, but do not activate this
   adapter for production callers still using independent resolution.
3. Preserve tinfoil sticky-domain and supply-chain repository selection in one
   tinfoil direct route snapshot. Compute the effective repository, including
   the existing empty-value fallback, once during route resolution.
4. Add the key derivation and shared internal inference interfaces. Test explicit
   route/report handoff for proxy and explore. Do not switch production cache,
   dashboard, failure, or invalidation paths before the new cache is available.
5. Apply the focused NEAR discovery validation: an exact hard body limit, a
   total mapping bound, the top-level unknown and missing field reporting that
   `jsonstrict.UnmarshalWarn` supports, unique models, canonical
   provider-owned authorities, and no partial-map publication. Do not add a
   separate duplicate-key or recursive strict decoder.
6. Test that a discovery refresh cannot mix route fields within one request and
   that repository metadata does not alter the route cache key.

Commit purpose: add and test the route contract without activating a partial
migration. Production resolver/callback/cache activation occurs atomically per
provider in phases 6 and 7.

### Phase 5: Add the atomic TLS-binding authorization cache

Files:

- `internal/proxy/proxy.go`
- proxy cache files selected for the TLS-binding authorization entry
- dashboard files that read report or signing-key cache state
- focused authorization and concurrency tests

Work:

1. Add the immutable authorization entry with report, minimum verified E2EE
   public key, transport identity, opaque generation, and the earliest explicit
   authenticated evidence expiration when one exists.
2. Reuse validated identity and required REPORTDATA-authenticated E2EE key
   values in the non-bypassable constructor; reject incomplete entries.
3. Add generation-conditional report updates and deletion. Do not add revision
   counters, key ordering, failure tombstones, or a separate diagnostic cache.
4. Put full verification and atomic publication inside singleflight with a
   caller-independent, server-lifecycle context and fixed timeout. Recheck both
   caches and use fail-fast verification admission. Add attempt acquisition and
   cancellation-safe publication for invalidation/shutdown without a scheduler
   or retained invalidation history.
5. Keep existing cache capacity. Use authenticated evidence expiration when it
   exists and otherwise use no wall-clock authorization expiry. Do not reuse the
   local attestation-cache TTL or add repository, transport, connection-idle,
   E2EE-key, or diagnostic expiry timers.
6. Add deterministic tests for atomic publication, delayed singleflight delivery,
   invalidation before acquisition, expiry during connection waits, shutdown,
   stale-generation updates, and verification concurrency limits. Implement and
   test the evidence expiration table, including verified-result propagation.
7. Leave all providers on their current dispatch path in this phase.

Commit purpose: make one immutable generation the atomic unit of TLS-binding
authorization without changing transport dispatch.

### Phase 6: Move tinfoil to immutable routes and authorization

Files:

- `internal/provider/tinfoil/attester.go`
- `internal/provider/tinfoil/resolver.go`
- `internal/proxy/proxy.go`
- `internal/proxy/explore.go`
- `internal/verify/factory.go` and `internal/verify/e2ee.go`
- shared transport/retry helpers and focused tinfoil route, authorization,
  EHBP, and supply-chain tests

Work:

1. Activate tinfoil cloud/direct routes, route-aware attesters, authorization
   cache, and every cache consumer together. Remove independent callbacks in
   this same phase. Include proxy, explore, dashboard, invalidation, and
   standalone verification; return the report actually used by inference.
2. Remove tinfoil direct's independent dynamic callbacks only after route-based
   attestation, effective repository selection, cache keys, and inference URLs
   have replacement coverage.
3. Preserve sticky-domain selection and prove one `ModelMapping` snapshot
   supplies both the selected authority and effective repository on a miss.
4. Prove a cache hit uses the already verified authorization without rechecking
   discovery repository metadata.
5. Preserve EHBP key use and report promotion. Add the shared bounded retry
   loop, typed connection-failure classification, and EHBP key-config rejection
   handling with generation-conditional invalidation and fresh sessions.
6. Count cache hits and misses at the initial acquisition in the authorization
   loader. Do not acquire and clone a report solely to count a lookup.
7. Return the actual request outcome and accumulated phase durations, including
   retries, to the common HTTP handler. Count per-model errors once. Use the
   resolved authority in request, error, verification, and throughput metric
   keys. Test concurrent requests across providers and models.

Commit purpose: validate the shared route and authorization contracts on the
existing pooled TLS-binding providers before moving NEAR.

### Phase 7: Move NEAR providers to the standard HTTP transport path

Files:

- `internal/provider/provider.go`
- `internal/provider/neardirect/nearai.go`
- `internal/proxy/proxy.go`
- `internal/proxy/pinned_upstream.go`
- `internal/verify/factory.go`
- `internal/verify/e2ee.go`
- `internal/proxy/tls_binding_internal_test.go`
- focused standalone verifier tests
- related proxy unit tests

Work:

1. Activate `UsesTLSBinding`, routes, authorization cache, standard dispatch,
   and all cache consumers together for NEAR. Classify both NEAR providers in
   proxy and standalone construction; no active pinned handler may resolve
   independently while other consumers use the new route contract.
2. Keep the pool keyed by provider and canonical authority. Reuse it for the
   same fingerprint and atomically replace it for a changed fingerprint. Do not
   add pool epochs, leases, high-water marks, or tombstones.
3. Stop constructing NEAR pinned handlers.
4. Copy only the required E2EE headers through `neardirect.Preparer` and reject
   an incomplete internally generated protocol header set. Do not add redundant
   conflict checks for downstream headers that are not copied there.
5. Parameterize generic TLS-binding tests so tinfoil, neardirect, and
   nearcloud fingerprint scopes are covered.
6. Verify every NEAR endpoint now reaches `authorizedRoundtrip`.
7. Add HTTP/2 negotiation, sequential reuse, concurrent multiplexing,
   connection-limit, SPKI rotation, and authority-isolation tests in this
   phase.
8. Test redirect rejection, typed transient connection failures, permitted and
   prohibited retries, and exact NEAR key-rejection envelopes across endpoints.
   Prove re-attestation collapse and a fresh E2EE session for the one retry.
9. Remove the second neardirect resolution in `teep verify`; retain coverage for
   tinfoil's route contract activated in phase 6. Use the exact attestation route
   to construct the SPKI-pinned
   inference client, and prove that its inference exercise negotiates HTTP/2
   when the TLS test server advertises it.

10. Share request preparation between proxy and standalone inference: invoke
    the same provider encryptor, apply the same protocol and authentication
    headers, and let net/http select body framing. Use one helper for
    evidence-bounded attempt contexts and one session cleanup function. Keep
    report and retry orchestration in their respective callers.

Commit purpose: enable HTTP/2 pooling while the old implementation still
exists but has no production callers.

### Phase 8: Remove obsolete pinned-handler code and migrate tests

Files:

- remove both provider `pinned.go` and `pinned_test.go` files
- `internal/provider/provider.go`
- `internal/proxy/proxy.go`
- `internal/proxy/proxy_test.go`
- `internal/proxy/proxy_internal_test.go`
- `internal/proxy/relay_internal_test.go`
- `internal/proxy/mock_near_pinned_test.go`
- `internal/proxy/integration_neardirect_test.go`
- `internal/proxy/integration_nearcloud_test.go`
- dashboard files if pinned-only state is removed

Work:

1. Make a test-migration inventory that maps every test in the two removed
   `pinned_test.go` files to a replacement test or an explicitly obsolete
   behavior.
2. Remove the manual interface and dispatch code.
3. Replace pinned-handler mocks with TLS test upstreams, stub attesters, and
   real provider E2EE implementations.
4. Preserve endpoint routing, negative-cache, authorization-cache, E2EE
   failure, factor enforcement, recovery, and
   response-header tests on the standard path.
5. Remove obsolete connection-close assertions and add no-`Connection` and
   HTTP/2 assertions.
6. Remove unused SPKI-cache state only after `rg` confirms no callers.

Commit purpose: leave one transport implementation and no HTTP/1.1 connection
writer in the NEAR providers.

### Phase 9: Integration and documentation

Files:

- `internal/proxy/tls_binding_internal_test.go`
- NEAR proxy integration tests
- `internal/integration/nearcloud_test.go`
- `internal/integration/neardirect_test.go`
- tinfoil direct route and integration tests
- `docs/providers/tinfoil/tinfoil_support.md`
- other comments or documentation found by the searches below

Work:

1. Run the HTTP/2 reuse, multiplexing, SPKI rotation, authorization-generation,
   connection bound, verification bound, and concurrent transition tests added
   in the implementation phases.
2. Run fixture and live NEAR and tinfoil tests.
3. Update the stale tinfoil text that still says TLS-binding providers send
   `Connection: close`.
4. Update all NEAR documentation to describe attestation-bound pooled
   transports and state that nearcloud `tls_key_binding` applies to the gateway
   transport key, while the model backend fingerprint remains a separately
   authenticated evidence field.

Commit purpose: prove the required behavior and align documentation with the
code.

## Detailed Test Plan

### Attester tests

Use `testtls.RunWithFallbackRoot` and `authority.NewTLSServer`. Keep production
WebPKI code active; do not set custom roots or `InsecureSkipVerify` on a
production transport.

For each NEAR provider, test:

- live peer SPKI equals the correct attested fingerprint: fetch succeeds and
  both transport-identity fields are set;
- peer differs from the attested fingerprint: fetch fails;
- response fingerprint is absent: fetch fails;
- peer TLS state is absent: fetch fails;
- fingerprint is malformed hex or has a decoded length other than 32 bytes:
  fetch fails;
- nonce, model selection, and the existing provider JSON validation still run;
- nearcloud ignores the model backend fingerprint for transport selection and
  fails if only that value matches the gateway peer;
- neardirect binds the canonical authority returned by discovery;
- an authority mismatch between route and cached report fails;
- the proxy-mode neardirect attester fails when the route is absent;
- the standalone verifier resolves once and the attester and inference exercise
  receive that exact route;
- same-authority and cross-authority redirects make the fetch fail on the 3xx
  response and the redirect target sees zero requests; and
- captured fixtures reproduce the stored TLS peer SPKI and pass the same
  comparison.

Add a regression test that the mismatch occurs before a raw attestation can be
cached or an E2EE key can be used. Add a report-construction test for every
TLS-binding provider in which its provider-native fingerprint is populated but
the derived identity is absent; the TLS-binding factor must fail and the
authorization constructor must reject the entry.

For tinfoil direct, also test that proxy mode requires the supplied route,
uses its authority for attestation, and uses its `SupplyChainRepo` without a
second resolver call. Standalone verification must resolve one mapping
and use the domain and repository from that same snapshot for attestation and
the SPKI-pinned inference exercise.

### Redirect-policy tests

Test the common no-redirect policy through representative clients for
attestation, NEAR and tinfoil route discovery, model listing, Sigstore or
release retrieval, collateral or online verification, and inference. For each
client, test direct successful retrieval as well as same-authority and
cross-authority redirects, and assert that redirect targets receive zero requests.
Fetch callers must return an error for every 3xx.
Inference must return a proxy error and must not copy `Location` to the
downstream response. Audit any dependency-owned client that cannot use the
common constructor and record its behavior explicitly; do not change global
`http.DefaultClient` state for a local exception.

### Transport and pool tests

Extend the current tinfoil TLS-binding tests with NEAR cases:

- `newUpstreamTransport().ForceAttemptHTTP2` is true.
- `newUpstreamTransport().MaxConnsPerHost` equals the finite configured limit.
- The pinned client keeps `ClientSessionCache` nil.
- A wrong SPKI fails during the TLS handshake. The server sees zero HTTP
  requests and a counting body sees zero reads.
- A matching connection uses HTTP/2 and two sequential fully read responses
  use one remote address.
- A server that does not advertise HTTP/2 uses persistent HTTP/1.1 and reuses a
  fully consumed connection without a `Connection` header.
- No request contains a `Connection` header.
- An unchanged SPKI returns the same pool/client.
- A changed SPKI replaces the pool and closes old idle connections.
- A valid authorization can recreate a pool for its fingerprint after LRU
  eviction; no tombstone or key-order comparison blocks it.
- Two valid authorizations for one authority and different fingerprints can
  each select a pool in request order; the pool does not compare their opaque
  generations or reject one only because the other was observed later. Every
  newly opened connection must still match the fingerprint selected for that
  request.
- A delayed request using an old authorization cannot delete or mutate a newer
  authorization generation, but its already acquired authenticated connection
  may finish or fail naturally.
- Different providers on one authority do not share a pool.
- Different neardirect authorities do not share a pool.
- Different nearcloud models with one gateway SPKI do share the gateway pool.
- A malformed or empty expected SPKI creates no client and performs no
  network I/O.
- A handshake SPKI mismatch conditionally deletes only the authorization
  generation used by that request and creates no persistent failure marker.
- After GOAWAY or an idle connection closes, subsequent requests establish a
  new connection whose handshake repeats SPKI and CT verification. This does
  not authorize replay of an in-flight encrypted request.
- A 301, 302, 303, 307, or 308 response does not cause a request to a second
  URL, including when the target has the same SPKI.
- Retry tests count both protocol-layer attempts and inference handler calls.
  A recognized key rejection reaches its protocol handler but no inference
  handler; the recovered request invokes inference exactly once.
- A consumed POST followed by peer `PROTOCOL_ERROR` is not replayed, including
  on the minimum supported Go version. `GetBody` is nil for buffered NEAR and
  EHBP requests; no idempotency header enables hidden replay.
- A typed transient pre-connection failure retries once; cancellation, trust
  failure, or any ambiguous failure after connection assignment does not.
- Retry attempts keep the original route and logical deadline, reacquire valid
  authorization, and use distinct sessions. Two failures exhaust the attempt
  budget; no provider-specific loop adds more attempts.
- A stalled TCP/TLS setup eventually releases its connection slot after the
  injected establishment budget, even after its original caller has canceled.
  A slow setup below that budget succeeds. Cover the KDS transport as well.
- A persistent HTTP/1.1 peer supports sequential reuse and the same TLS pin,
  WebPKI, and CT checks. Production constructors reject invalid WebPKI and CT;
  offline tests do not substitute for positive online enforcement coverage.
- An HTTP/1.1 request waiting at the active-connection limit stops when its
  context deadline expires. HTTP/2 socket exhaustion returns a capacity error.
- The attestation transport has a finite `MaxConnsPerHost`, and a request
  waiting at that limit stops when its fixed verification context expires.
- The separate AMD KDS client still works with its TLS 1.2 exception and does
  not require HTTP/2 when the test server omits it.

For multiplexing, configure a test HTTP/2 server with an explicit concurrent
stream limit of at least 32. Warm one connection first, then start at least 32
goroutines with a barrier. Give both the client and server barriers fixed
deadlines. Assign connection IDs through the server's connection context or an
equivalent connection hook; do not infer identity only from remote-address
strings. Hold the handlers open until every request has arrived. Assert:

- all handlers observe `r.ProtoMajor == 2`;
- all overlapping requests use one connection ID;
- every request body and response maps to the correct goroutine;
- stream and non-stream responses can overlap;
- each E2EE request has a distinct client public key and decryptor;
- there are no data races under `go test -race`; and
- closing one response body does not close the connection or cancel another
  stream.

Use a separate server with an advertised concurrent-stream limit of two.
Assert that additional connections never exceed `MaxConnsPerHost`, every
additional connection passes the handshake pin before its first request, and
excess work receives a capacity error without an unbounded dial burst. After
active streams finish, subsequent requests reuse the existing connections.

### Cache and rotation tests

Test authorization, route, and pool state together:

- authorization-cache hit uses the report fingerprint and authority and does
  not fetch a new attestation;
- authorization-cache miss performs full attestation before inference;
- 32 concurrent misses perform one full attestation and all joiners receive
  the same immutable authorization generation without a
  shared `RawAttestation`;
- the singleflight callback rechecks positive and negative caches so a value
  published between the outer lookup and callback execution prevents duplicate
  verification;
- one failed shared verification creates at most one applicable negative-cache
  record, not one per joiner;
- a cached E2EE key still creates a new per-request E2EE session;
- concurrent joined NEAR and tinfoil requests use distinct E2EE sessions and
  never share request bodies, response bodies, decryptors, or attestation
  challenge nonces;
- explicit evidence expiration rejects publication if verification finishes too
  late, requires fresh authorization at acquisition, and cancels an attempt
  waiting for a connection at the boundary; the unchanged SPKI retains its pool;
- a delayed singleflight waiter cannot acquire a generation deleted before it
  receives the result; an attempt acquired before deletion follows the stated
  in-flight rule without canceling another stream;
- explicit invalidation and shutdown prevent late verification publication;
  shutdown cancels detached work and releases verification capacity;
- the expiration table distinguishes absent dates, invalid/failed-signature
  dates, zero timestamps, applicable factors, historical signing validity, and
  the earliest authenticated bound; no cache reparses raw evidence;
- evidence without an authenticated expiration receives no locally invented
  wall-clock expiry;
- changed gateway or direct SPKI selects a replacement pool;
- a handshake SPKI mismatch sends no request bytes and compare-and-deletes only
  the exact authorization generation used by the request;
- a neardirect model moving from authority A to B cannot use A's report, key,
  negative-cache entry, or pool;
- interleaved A and B verification cannot publish report B with signing key A;
- a stale report clone cannot overwrite a newer report while marking
  `e2ee_usable`;
- report promotion does not change the authorization's explicit expiration or
  add one when it is absent;
- a trust or E2EE failure for generation A cannot delete or mutate replacement
  generation B;
- a blocked report is returned to joined callers but is never returned by an
  authorization lookup or retained in a new diagnostic cache;
- a repository mapping change with the same model, authority, and attested keys
  does not expire or reverify the cached authorization;
- requests for many distinct route keys never exceed the configured full
  active-verification concurrency limit, excess distinct keys receive the
  typed overload error without queuing or negative caching, the handler maps it
  to 503, same-key joiners still share one admitted operation, and canceled
  callers return promptly;
- concurrent cache hits, expiry, re-attestation, cancellation, and SPKI
  mismatch do not race or cross authorization generations; and
- concurrent nearcloud requests for different models keep model signing keys
  separate while sharing only the gateway transport.

Do not test successful use of expired evidence or a stale route after a required
refresh fails. All refresh and mismatch errors must block. A valid
authorization does not become stale solely because another fingerprint or new
repository metadata was observed for the same logical service.

### Route and discovery tests

Test route construction and discovery independently of transport behavior:

- the route accepts only an origin-only absolute HTTPS URL;
- userinfo, path, raw path, query, fragment, opaque URLs, percent-escaped host
  bytes, invalid ports, IPv6 zones, Unicode hostnames, and empty authorities
  fail;
- case, trailing DNS dots, default ports, and IPv6 forms have one canonical
  representation;
- the cache key is derived from the validated authority and cannot differ from
  it;
- every proxy and standalone verifier entry path passes the same route and
  authorization key before its first cache access;
- invalid discovery entries, an empty endpoint set, duplicate model mappings,
  top-level unknown or missing fields reported by `jsonstrict`, overlong models,
  punycode, IP literals, invalid DNS labels, and a total mapping count over the
  configured limit reject the complete refresh;
- nested values receive the required semantic checks without a new recursive
  strict-JSON or duplicate-key implementation;
- a decoded response body at exactly 1 MiB succeeds when otherwise valid, and
  a body of 1 MiB plus one byte fails even when its first 1 MiB is valid JSON;
- the body limit applies to decoded content when the HTTP transport decompresses
  a response;
- the total mapping and model-length bounds accept the exact limit and reject
  limit plus one;
- a failed required refresh does not return a stale route; and
- concurrent refresh callers join one bounded discovery request while a
  canceled caller returns promptly.

For tinfoil direct, test that one route resolution fixes the sticky domain,
authority, cache key, attestation URL, repository, pool, and inference URL even
when discovery expires or a concurrent refresh publishes a different mapping.
Test both an empty and a non-empty `prompt_cache_key`.

Test that explore reports the actual attempt's authorization even if another
request replaces the cache entry before explore renders its result. Assert one
route resolution and no post-response report lookup. Mutation of returned route,
report, or key values must not change cached authorization.

### E2EE and endpoint regression tests

Replace `mockNearPinnedHandler` with a TLS upstream that implements the real
Near E2EE protocol used by the existing tests. Cover both nearcloud and
neardirect for:

- chat completions, streaming and non-streaming;
- embeddings;
- images for nearcloud and neardirect;
- audio transcription for neardirect with E2EE disabled, protected by attested
  TLS; reject multipart audio when E2EE is enabled. Nearcloud has no configured
  audio endpoint;
- rerank and score;
- correct provider authorization;
- all four E2EE request headers and omission of `X-Model-Pub-Key`;
- rejection of a missing or malformed internally generated E2EE protocol
  header set, without a redundant downstream-header conflict check;
- response decryption and `e2ee_usable` promotion;
- decrypt failure conditionally deletes only the authorization generation used
  by that request, performs no plaintext fallback or application-level retry,
  retains no failure marker, and causes the next logical request to perform
  fresh attestation;
- exact NEAR cloud/direct key-rejection responses are classified
  before generic non-200 handling, conditionally invalidate, join full
  re-attestation, and retry once without publishing error-supplied keys;
- simultaneous key rejections cannot delete a replacement generation and share
  one re-attestation; ordinary 400/401/403/422/429/5xx errors retain valid keys;
- malformed, oversized, wrong-type, or near-matching rejection bodies do not
  enable retry; encrypted error-body authentication failure invalidates without
  replay; all body reads remain bounded;
- non-200 response handling;
- request cancellation and stream timeout; and
- bounded response reads.

Assert the upstream receives the rewritten unprefixed model and the request's
resolved authority matches the attested and cached authority.

Retain focused regression tests for tinfoil cloud and direct on the new
TLS-binding authorization cache, including EHBP key use, route authority,
sticky-domain selection, supply-chain repository selection, report promotion,
TLS invalidation, and the EHBP key-config rejection/re-attestation/retry
contract. Add dispatch tests proving Venice, Chutes, NanoGPT, and
PhalaCloud still use their existing non-TLS-binding cache and per-request E2EE
material paths.

Before deleting either `pinned_test.go`, account for its behavior coverage in a
migration table. Multiple old tests may map to one replacement when they check
the same contract. The replacement suite must retain tests for blocked
reports, online/offline factor applicability, attestation query parameters,
timeouts, malformed responses, recovery, signing-key publication, gateway and
model tier independence, and concurrent verification collapse. Only manual
HTTP writer, explicit connection-close, manual dial-hook, and socket-closing
reader tests are obsolete by design.

### Live tests

Use current models from discovery rather than hard-coding a model that may have
been removed. Load credentials without printing them:

```sh
set -a
source .env
set +a
test -n "$NEARAI_API_KEY"
```

Run:

```sh
make integration-neardirect
make integration-nearcloud
make report-neardirect
make report-nearcloud
```

Add live integration assertions using an internal test-only transport hook, not
new production response metadata or logs, that:

- attestation and inference negotiate HTTP/2 when the live authority supports
  it;
- two sequential requests reuse the same connection;
- concurrent requests complete while at least two streams overlap;
- E2EE succeeds for streaming and non-streaming traffic; and
- the report's transport fingerprint matches the inference response TLS peer;
  and
- the report's transport authority matches the resolved inference authority.

Open multiple fresh TLS connections, including concurrent connections, as an
operational check that each authority presents one uniform SPKI. If DNS
round-robin or a load balancer exposes a different SPKI, a positive-path live
test can fail because the production request must fail closed. Treat that as a
provider deployment issue; do not add alternate-key acceptance or retry around
the mismatch.

Never log API keys, prompts, encrypted request bodies, decrypted responses, or
full nonces. A live provider verification failure is a valid security result;
do not weaken `allow_fail` to make the test pass.

## Validation Sequence

Run focused tests during implementation:

```sh
go test -race ./internal/tlsct
go test -race ./internal/provider/tinfoil
go test -race ./internal/provider/neardirect
go test -race ./internal/provider/nearcloud
go test -race ./internal/proxy
go test -race ./internal/integration -run 'Near(Cloud|Direct)|Tinfoil'
```

Search for obsolete behavior before final validation:

```sh
rg -n 'Connection.*(close|keep-alive)|ConnClosingReader|WriteHTTPRequest|PinnedHandler' internal docs
rg -n 'DisableKeepAlives|ForceAttemptHTTP2|MaxConnsPerHost|ClientSessionCache|CloseIdleConnections' internal
rg -n 'TransportTLS(Fingerprint|Authority)|TLS(KeyFP|Authority)|GatewayTLSFingerprint|TLSFingerprint' internal
rg -n 'CheckRedirect|ErrUseLastResponse|GetBody|authorizationGeneration|singleflight' internal
rg -n 'verifyUpstreamTLSBinding|response-time SPKI|tombstone|high-water' internal
rg -n 'CacheKeySuffix|BaseURLForModel|ResolveRoute|ResolvedRoute' internal
```

The first search must have no NEAR transport implementation matches. Any
remaining historical documentation match must be corrected or clearly marked
as historical.

Follow the repository checks for every phase and for the completed change:

```sh
make check
set -a
source .env
set +a
make integration
make reports
git diff --check
```

All tests run with the race detector through repository targets. If an
enforced attestation factor fails during live integration or report generation,
stop and investigate or ask for direction. Do not bypass it.

## Acceptance Criteria

The work is complete when:

- nearcloud and neardirect production providers have no `PinnedHandler` and use
  `authorizedRoundtrip` with `UsesTLSBinding == true`;
- neither provider writes HTTP/1.1 requests manually or sets a `Connection`
  header;
- automated tests prove HTTP/2 negotiation, sequential reuse, and concurrent
  multiplexing;
- every new inference connection rejects a wrong SPKI before request bytes are
  sent;
- nearcloud pins the gateway fingerprint and neardirect pins the selected
  direct authority fingerprint;
- `providerUsesTLSBinding` classifies both NEAR providers accordingly, and
  `teep verify` exercises inference through the same one-shot resolved route and
  HTTP/2-capable SPKI-pinned transport as the proxy;
- each TLS-binding authorization atomically contains a report, minimum E2EE
  public key, transport authority, fingerprint, opaque generation, and optional
  authenticated evidence expiration, but no locally invented TTL,
  `RawAttestation`, or request-specific state;
- the TLS-binding factor and authorization constructor reject a missing or
  malformed derived transport identity even when a provider-native fingerprint
  is present;
- neardirect and tinfoil direct resolve once per request, and every
  authorization lookup, negative-cache lookup, pool selection, and metric key
  uses that route's authority; repository selection uses the same route snapshot
  only when a new authorization is verified;
- tinfoil direct preserves sticky-domain selection and uses the repository from
  the same discovery snapshot on an authorization miss, without making later
  repository metadata changes an independent expiry condition;
- concurrent same-key cache misses join one verification operation, while an
  aggregate fail-fast limit bounds active verification across distinct keys and
  does not create a detached queue;
- a result from an old authorization generation cannot delete or mutate its
  replacement;
- SPKI rotation replaces the selected pool, and a handshake mismatch
  conditionally deletes the authorization used by the request and forces
  re-attestation without application-level inference replay;
- all teep-controlled outbound clients reject every redirect without issuing a
  request to its target, and inference never forwards a redirect or `Location`;
- active connections per inference and attestation host are finite, dial and
  TLS handshake budgets release stalled slots, connection waits honor attempt
  deadlines, and verification overload fails without waiting;
- typed recoverable pre-connection failures and recognized pre-inference key
  rejections use at most one application retry with fresh E2EE state; ambiguous
  failures never replay, including on the minimum supported Go version;
- acquisition rejects invalidated/expired generations, explicit invalidation
  and shutdown prevent late publication, and explore returns the report used;
- the shared transport constructor governs both proxy and standalone behavior;
- neardirect endpoint discovery rejects malformed, ambiguous, or over-limit
  data without constructing a partial routing map, using only the strict-JSON
  field reporting that the current `jsonstrict` wrapper supports;
- all NEAR E2EE headers and endpoint behaviors remain correct;
- non-TLS-binding providers retain their existing cache and per-request E2EE
  material behavior;
- `make check`, `make integration`, `make reports`, and `git diff --check`
  pass without new exemptions; and
- documentation no longer states that TLS-binding providers use
  `Connection: close`.

## Risks and Decisions to Keep Explicit

- **Gateway and model fingerprints are not interchangeable.** This is the
  highest-risk nearcloud mistake because both values are present in one
  response.
- **HTTP/2 support is negotiated, not assumed.** The transport should prefer
  HTTP/2 and retain secure persistent HTTP/1.1 behavior when ALPN selects it.
- **A pooled connection does not extend authorization validity.** A valid
  authorization entry and current E2EE key are required for every request even
  when the TLS connection remains open.
- **Authority and fingerprint are one identity.** The attestation connection,
  cache entry, selected pool, and inference URL must use the same canonical
  authority even when two authorities share an SPKI.
- **All dynamic TLS-binding routes use one snapshot.** Neardirect and tinfoil
  direct must not resolve the cache key, attestation URL, effective repository,
  or inference URL independently during authorization construction. A cache hit
  does not revalidate repository discovery metadata.
- **Authorization state has one opaque generation.** Report and key publication,
  invalidation, and post-E2EE report updates must not cross generations. Use the
  generation only for equality; do not use it to order keys or create
  newest-key-wins behavior.
- **A cache miss joins verification.** Concurrent callers must not multiply
  expensive attestation work or publish competing report and key pairs.
- **Do not close a connection on each response.** Closing a response body
  returns a fully consumed HTTP/1.1 connection to the pool and closes only the
  HTTP/2 stream. It must not close the underlying shared HTTP/2 connection.
- **Retry only proven unprocessed inference.** Use the shared classification
  table and at most one application retry. Recognized pre-inference key rejection
  requires full attestation and a fresh session. Ambiguous failures, trust
  failures, and response-decryption failures end the logical request. Redirects
  become proxy errors without forwarding `Location`.
- **Bound active connections.** HTTP/2 multiplexing reduces connection count,
  but an HTTP/1.1 peer or a low concurrent-stream limit must not cause an
  unbounded dial burst. Bound attestation connections and aggregate detached
  active verification as well. Do not add cross-generation connection
  accounting or a hostile-client keyed admission scheduler under the local
  client threat model.
- **One SPKI is reachable per authority.** DNS round-robin and load-balanced
  endpoints are assumed to rotate their SPKI uniformly. Non-uniform rotation
  can reduce availability, but every mismatch must fail closed; do not add a
  multi-key fallback.
- **A newly observed key does not revoke an older valid authorization.** TLS
  and E2EE keys are boot-bound. If the old boot is gone, its pinned handshake
  fails before request bytes are sent. Do not add epoch high-water marks or
  tombstones to impose an unstated revocation order.
- **Repository metadata does not independently expire a boot-bound
  authorization.** Use the effective repository from the route snapshot on a
  miss, then rely on the attested keys and an explicit authenticated evidence
  expiration when one exists. Do not add a repository comparison on cache hits
  or invent an authorization TTL.
- **Do not use one global pool.** Provider and authority isolation must remain
  visible in the registry key and in tests.
- **Do not preserve the old SPKI cache as a second authority source.** The
  verified report and the SPKI-scoped transport registry must have clear and
  separate ownership.
