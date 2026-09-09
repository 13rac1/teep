# Plan: stable NEAR backend selection

Investigation date: 2026-09-09. This document is the historical implementation
design. The maintained contracts are [NEAR routing and attestation](../providers/near/near_attestation.md)
and the [transport reference](../transport/README.md). The implementation instructions
and investigation results below describe the original design context.
Read [AGENTS.md](../../AGENTS.md), the [transport reference](../transport/README.md),
the [retry contract](../transport/retries.md), and
[transport testing](../transport/testing.md) before implementation. Those
security requirements remain in force. This plan repairs the shared NEAR
binding between public key and signing address, changes routing, and adds one admission
requirement: NearCloud TLS-only operation must authenticate the
retained model routing key through successful REPORTDATA binding, even when
`allow_fail` permits that factor to fail. Other attestation admission rules and
authorization lifetimes remain unchanged.

## Objective and decisions

For NearDirect, select one random healthy backend index for each provider
instance and model route. Keep that selection across requests from all clients,
HTTP/2 streams, new TLS connections, attestation cache misses, and backend
count or membership changes. Discover the route and count only to establish
an initial selection; established routes never require discovery refresh.
Distribute initial selections
across independent instances and models. Do not rotate per request, prompt,
client, connection, elapsed time, or authorization generation. A backend key
change or failure must not trigger index rediscovery or invalidate unrelated
authorizations, connections, or HTTP/2 streams.

For NearCloud, retain the gateway as the TLS authority and use the acquired
model signing key as the gateway routing hint. Cache the gateway and model
authorization together as today. The gateway selects physical model backends;
its public attestation API does not expose an index selector. Generic image
HTTP errors fail the request without replay or authorization invalidation.
Image key retirement has no distinct supported error contract, so automatic
recovery from a generic image error is outside this change.
Do not promise
client-controlled random or fixed physical-backend selection through this API.

The implementation must not attest every backend, pre-warm every index,
rebalance healthy established selections, or introduce an authorization TTL.
This balances initial placement across a population of Teep instances while
minimizing attestation within each instance. It does not distribute one busy
instance's requests for one model across the whole fleet. A later change to
that scope requires an explicit design decision.

## Investigation and evidence

Reviewed revisions:

| Repository | Revision |
| --- | --- |
| teep | `16650b860ab88e2fa138a11f776a1679b6fe28a8` |
| nearai/cloud-api | `1c8057f3620a77d0aef9f3a16c5711fd2e6ee21c` |
| nearai/inference-proxy | `c59ea60e658f33c3b4d63ccd615de9395013559e` |
| nearai/cvm-ingress | `c785c6ed8d4ec0bb0ec4bcb45ef7afe3de48b24e` |

The local source is in `reference_impls/nearai/`. That directory is untracked;
the pinned upstream links below let another agent locate the same evidence.
Recheck the contracts if the reference revisions change.

### NearDirect reproduction

The existing `TestIntegration_NearDirect/NonStream` failed after successful
attestation, when its separate inference connection presented a different
SPKI. The attestation fetch itself passed its peer/report SPKI comparison in
[`fetchAttestationForRoute`](../../internal/provider/neardirect/nearai.go).
The inference handshake correctly blocked request transmission.

The public count endpoint returned:

```json
{"domain":"glm-5-3-flash.completions.near.ai","requested_domain":"glm-5-3-flash.completions.near.ai","healthy":2,"total":2}
```

Fresh attestation connections to each indexed hostname returned consistent,
distinct SPKIs, each matching the TLS peer. The same existing non-streaming
scenario passed against each indexed hostname with its existing offline
factor policy. These tests did not establish full online or E2EE suite success.
Temporary diagnostic tests were removed after the investigation.

| Authority | Observed SPKI prefix |
| --- | --- |
| `glm-5-3-flash-i0.completions.near.ai` | `375ce9c3129cc9fd` |
| `glm-5-3-flash-i1.completions.near.ai` | `4066aed3031802c9` |

Do not put these observations into an allowlist. They are diagnostic evidence,
not trusted configuration or stable identifiers.

### Routing hints supplied by NEAR

1. **Canonical model discovery:** `GET https://completions.near.ai/endpoints`
   returns model-to-domain mappings. Teep already consumes this API in
   [`endpoints.go`](../../internal/provider/neardirect/endpoints.go).
2. **Healthy count:** `GET https://completions.near.ai/backends/count?domain=<canonical-host>`
   supplies `healthy` and `total`; the live response also contains `domain`
   and `requested_domain`. Use the canonical host, not an indexed host. An
   indexed-domain count query returned HTTP 404 during this investigation.
3. **Index SNI:** `https://<canonical-label>-i<N>.completions.near.ai`
   routes a fresh TCP connection to backend `N % healthy_count`. This bypasses
   the ordinary least-connections selection. See
   [rotation.rs](https://github.com/nearai/cloud-api/blob/1c8057f3620a77d0aef9f3a16c5711fd2e6ee21c/crates/inference_providers/src/rotation.rs).
   Index routing was present in May; cloud-api adopted per-index inference
   clients in June, commit `818727f6`. The GLM deployment-change date is unknown.
4. **Index stability limit:** the physical mapping is stable only while the
   healthy count and membership remain unchanged. Same-count replacement can
   remap an index too. See
   [Fleet](https://github.com/nearai/cloud-api/blob/1c8057f3620a77d0aef9f3a16c5711fd2e6ee21c/crates/inference_providers/src/attested/nearai/fleet.rs),
   especially `acquire_index`, `store_backend_count`, and its stability comments.
5. **Gateway key affinity:** `X-Model-Pub-Key` filters providers by model key in
   cloud-api. For chat, that pin reaches `Fleet::acquire_index`; backend-index
   restrictions depend on enabled affinity and an available matching key group.
   Disabled affinity, an empty backend-key map, or an unknown key group permits
   unrestricted backend selection in the reviewed source. Replicas may have
   different keys because they use different dstack KMS roots. This behavior was updated in
   commit `07798f89` on September 1. See
   [provider pool](https://github.com/nearai/cloud-api/blob/1c8057f3620a77d0aef9f3a16c5711fd2e6ee21c/crates/services/src/inference_provider_pool/mod.rs),
   `reinsert_pubkey_pin`, `retry_with_fallback_caps`, and both chat methods.
6. **Gateway attestation selectors:** `model`, `signing_algo`, `nonce`,
   `signing_address`, `include_tls_fingerprint`, and `provider=near|chutes`.
   There is no backend-index selector in
   [AttestationQuery](https://github.com/nearai/cloud-api/blob/1c8057f3620a77d0aef9f3a16c5711fd2e6ee21c/crates/api/src/routes/attestation/report.rs).
   `signing_address` is a report filter, not a reliable physical-backend route:
   the NEAR provider forwards it through its general client and a nonmatching
   server returns 404. The pool returns the first successful provider report.

No public per-index weight, queue-depth, recommended-index field, or client
backend-index HTTP header was found in the checked sources or count response.
Cloud-api's prefix/conversation affinity, live-request counts, and TTFT moving
averages are internal scheduling inputs, not discovery hints for Teep.
Do not copy its per-request scheduling, eager verification, or generic 5xx
retry behavior. Those conflict with this plan's reuse and replay contracts.
The model-proxy repository was absent locally and its public GitHub API lookup
returned 404; its implementation was not inspected. Index semantics are
supported by cloud-api source and the live indexed-host tests, not a complete
review of the load balancer.

### NearCloud findings and boundaries

[`nearcloud.Attester`](../../internal/provider/nearcloud/nearcloud.go) correctly
checks the gateway report's SPKI against the gateway TLS peer. The model SPKI
is separate evidence and must never become the gateway transport pin.

Teep currently gives both NEAR providers `neardirect.NewPreparer` and
[`PrepareInferenceHeaders`](../../internal/provider/inference.go) supplies four
NEAR encryption headers but no `X-Model-Pub-Key`. Thus the gateway can choose a
backend that does not hold the key Teep just authenticated. Correct AEAD
enforcement blocks that failure, but repeated attestation does not fix the
missing routing hint.

The focused live tests `TestIntegration_NearCloud/NonStream` and
`TestIntegration_NearCloud/E2EENonStream` both passed on September 9 with
`-count=1 -race`. The first uses the suite's offline policy; the second uses
online verification. Thus this investigation did not reproduce a cloud SPKI
or decryption failure. The missing hint is a source-confirmed gap whose
failure depends on backend selection and key differences, not proof of a
current failure on every cloud request.

The current upstream endpoint behavior differs:

| Endpoint | Gateway key selection in reviewed source | Required plan treatment |
| --- | --- | --- |
| Chat, streaming and non-streaming | Filters providers by key; backend-index restrictions are conditional on enabled affinity and a matching populated key group | Add the authenticated key hint; test both honored and ignored hints in mixed-key fleets. |
| Images | Filters providers by key, but does not preserve the pin for backend-index selection | Do not claim physical-backend affinity. Retain encryption and failure enforcement. |
| Embeddings, rerank, score | Pool selection passes no model-key filter; downstream header preparation does not select an index | Document the upstream limitation; do not claim this change fixes mixed-key fleets for these endpoints. |

See `get_attestation_report`, `image_generation_with_attribution`, `embeddings`,
`rerank`, and `score` in the provider pool, and `prepare_encryption_headers` in
the [NEAR provider](https://github.com/nearai/cloud-api/blob/1c8057f3620a77d0aef9f3a16c5711fd2e6ee21c/crates/inference_providers/src/attested/nearai/mod.rs).
In the pinned [Fleet implementation](https://github.com/nearai/cloud-api/blob/1c8057f3620a77d0aef9f3a16c5711fd2e6ee21c/crates/inference_providers/src/attested/nearai/fleet.rs),
`resolve_key_group` returns unrestricted routing when
`E2EE_BACKEND_KEY_AFFINITY=0` (or `false`/`FALSE`) disables affinity.
`key_group` also returns unrestricted routing for an empty backend-key map.
An unknown group, including one whose indices are all outside the current
count, causes `acquire_index` to warn and route without the key restriction.
Provider-level key filtering and backend-index selection are separate steps:
the former can succeed while the latter ignores the hint. Teep cannot infer
the deployed flag or current map state from a successful attestation response.

The header therefore provides conditional routing affinity, not enforcement
that Teep can independently verify. Test disabled affinity, empty maps, and
unknown groups explicitly. An E2EE request routed to a backend without the
authenticated key must not expose encrypted fields or accept unauthenticated
fields that require E2EE response protection. Apply only the documented exact pre-inference rejection
retry; a response authentication failure still fails without replay. In
TLS-only mode, a successful response does not prove that the selected backend
holds the retained routing key. Do not report that key as independently
verified backend selection or E2EE success.

The gateway can route among multiple machines sharing the same key. Key
affinity is not proof that every such machine has the same measured software.
Retain the documented delegated gateway trust boundary; do not turn this
routing hint into an independent attestation factor or broaden authorization
to unverified keys. In TLS-only mode, model routing is delegated to the
attested gateway, without a client-to-model encrypted channel.

### Prompt and conversation affinity

The reviewed cloud-api chat routing code does not consume `prompt_cache_key`
for backend selection. Its presence in Responses API types does not establish
that contract. The pinned
[prefix router](https://github.com/nearai/cloud-api/blob/1c8057f3620a77d0aef9f3a16c5711fd2e6ee21c/crates/inference_providers/src/attested/nearai/prefix_router.rs)
hashes the first message for initial requests and the first two messages once
assistant or tool history is present. Fleet load and latency can also change
placement. The NEAR chat provider strips message `cache_control` markers before
routing; they do not provide a backend selector.

Teep encrypts message content with fresh session material before the gateway
routes it. From these code paths, repeated plaintext prefixes produce changing
ciphertext routing inputs. This is a source-based inference, not a measurement
of deployed cache behavior. Do not promise gateway prefix or conversation
affinity for E2EE requests, or expose plaintext or reuse encryption material to
obtain it. Backend-local prefix caching can still work after decryption when
requests reach the same backend; stable placement does not guarantee cache
retention. `X-Model-Pub-Key` remains a conditional key-group hint, separate from
prompt affinity.

Keep this change's one-selection-per-instance/model NearDirect default. Retain
the existing `prompt_cache_key` domain selection in the
[Tinfoil direct resolver](../../internal/provider/tinfoil/resolver.go); this
plan does not generalize or replace that behavior. A future NearCloud opaque
affinity token would require an upstream routing contract that preserves the
authenticated key restriction. Sending an otherwise unused field does not
establish such a contract.

### Assessment: requiring NearDirect E2EE

Using E2EE for NearDirect adds application-layer authentication and encryption
for the protocol's supported fields with the REPORTDATA-authenticated model
key. This is useful protection if routing behind an authorized TLS endpoint
reaches a backend without that model key. It does not change index selection,
make a stale index stable, or repair a TLS identity mismatch. NearDirect's
SPKI check already rejects a different TLS identity before sending request
bytes, with or without E2EE; retain that check in both modes.

Requiring NearDirect E2EE does not fix the NearCloud affinity limitation:
NearDirect bypasses cloud-api's provider and backend scheduler. For NearCloud,
E2EE protects the encrypted fields when a routing hint is ignored and the
chosen backend lacks the authenticated key; it does not make that backend
able to serve the request. Neither provider's E2EE proves physical-machine
uniqueness or distinguishes machines that share the same key.

Keep E2EE enabled for supported confidential workloads. Environment-based NEAR
configuration already enables it. Do not make it mandatory for NearDirect in
this routing change: the current field protocol does not support multipart
audio transcription, which requires explicit TLS-only operation. It also does
not encrypt every field or authenticate every response field at the model
layer; score responses are a documented example. See the maintained
[NEAR endpoint and field coverage](../api_support.md#neardirect),
[production encryptor](../../internal/provider/neardirect/e2ee.go), and
[configuration defaults](../../internal/config/config.go).

A future mandatory-E2EE policy must reject disabled E2EE configuration at
startup, explicitly remove unsupported endpoint use, and retain all TLS
checks. It must not silently override configuration, imply full-body coverage,
or use TLS-only fallback on encryption failure. This plan retains both modes
and tests their distinct guarantees, including the NearCloud TLS-only stale-key
invalidation described below.

## NearDirect design

### Discovery and selection ownership

Extend the long-lived NearDirect resolver/attester, not global state or a
mutable shared provider endpoint. Separate bounded metadata fetching, strict
parsing, authority construction, and selection publication into named helpers.
Keep each function below the repository's complexity limit.

Maintain synchronized metadata and established route records within the provider
instance. Each model has one established canonical authority and indexed route;
an explicitly indexed route retains its initial discovery validation. A route
record contains no attestation, fingerprint, encryption key, evidence expiry,
or independent authorization. All clients of one model share it. Models that
share a canonical authority may select independently and share count fetches.

Resolve an established route directly from this state before consulting any
metadata. Retain it for the provider instance's lifetime, including after
metadata expiry, mapping removal or replacement in later discovery, backend
failure, and authorization eviction. A new model may require discovery, but
its discovery must not modify previously established routes. Configuration
changes take effect through a new provider instance. A retired hostname can
require configuration changes or restart; do not search for another hostname
in response to ordinary request failures.

For initial selection, use `crypto/rand.Int` with bound `healthy` for an
unbiased index in `[0, healthy)`. Fail on entropy errors. Use an injected
selector for deterministic unit tests, never a mutable package global.
Concurrent callers establish one route with one draw. There is no subsequent
out-of-range reselection: upstream modulo routing handles an index above the
current count, subject to the same TLS and E2EE authentication requirements.
Do not substitute an arbitrary large random index for initial count discovery.

Endpoint-list and count snapshots may be reused for five minutes when resolving
another model for the first time. Only initial resolution can fetch or refresh
metadata; expiry causes no work by itself. Failed initial resolution can retry
under the bounded failure-delay rules below. Established-route requests,
re-attestation, authorization eviction, connection creation, and report reads
must make zero discovery requests, regardless of snapshot age. This replaces
the existing resolver's recurring endpoint refresh for established models and
prevents count lookup from becoming a recurring inference dependency.

Reuse the discovery client's production TLS, redirect, timeout, capture, retry,
and cleanup behavior. Do not use the inference transport for metadata. Bound
the count response to 64 KiB. Decode counts losslessly as unsigned 64-bit
integers and require `0 <= healthy <= total`; initial selection also requires
`healthy > 0`. There is no 256-backend deployment limit. The upstream 256
constant limits its per-backend fan-out, which this design does not perform.
Use `big.Int.SetUint64` for the random bound and retain a `uint64` index through
selection, hostname formatting, and capture/replay; do not narrow it to `int`.
An index of zero is valid. Validate DNS label length after formatting.
Decode the four observed fields strictly with `internal/jsonstrict`; reject
unknown, missing, duplicate, null, fractional, negative, overflowing,
inconsistent, or oversized input. Counts must use integer JSON tokens; reject
exponent or decimal notation as well as values outside uint64. Return field
names from parsers to callers.
Verify both domain fields match the requested canonical authority; do not
follow an asserted alternate domain. Zero healthy backends blocks initial
selection loudly, without using the general host. Do not clamp counts.

Validate the upstream model identifier before any resolver lookup, reservation,
worker creation, or diagnostic that could include its value. Share the endpoint
parser's identifier rule: nonempty, at most 256 bytes, and no control characters
below U+0020 or U+007F. Apply it after the existing provider-prefix separation,
without truncating or otherwise rewriting the identifier. Use the same validator
for discovered mappings, normal inference, Explore, and standalone resolution,
including configured indexed and static routes. Invalid identifiers produce a
typed input error without retaining the name or starting metadata work; HTTP
handlers return 400 without retry advice. Diagnostics name the violated rule,
not the supplied value. Check an already-canceled caller before admitting work.

Bound established route records to 4,096 models, independently of the current
4,096-model endpoint list. Bound retained count records to 4,096 authorities,
including pending work. Reserve initial route capacity before work begins;
pending model resolutions count toward the route bound. Reclaim unsuccessful
or canceled operation reservations, but do not evict established routes to make space.
Reject capacity exhaustion rather than grow without limit or change placement.
Static routes need no random selection records. Authorization LRU eviction
retains its separate 1,000-entry bound: a miss fully verifies the same established
route without another draw or discovery request. Zero additional attestation
applies only while authorization remains resident and valid.

Limit active count fetches to 16 per provider instance, each with a 30-second
server-owned deadline. This limit is separate from authorization verification
admission. Callers for the same authority join its existing operation; a new
authority that cannot acquire a slot fails immediately with a non-secret
capacity diagnostic. Do not start a detached goroutine or an unbounded queue
for each rejected authority. Singleflight per authority alone does not bound
work across different authorities. Endpoint-list refresh remains one shared
operation with its own 30-second bound.

For both count fetches and endpoint-list refreshes, use one operation record
with one shared `done` channel and a result that is immutable after completion.
Create or join the operation under the state lock. Only its owner starts a
worker. The worker stores its result before closing `done` exactly once;
callers wait on that same channel or their own context cancellation. Do not
register callers in the operation or allocate a result channel or worker for
each waiter. Replace the resolver's `singleflight.DoChan` usage: it retains
each caller's result channel until completion, including canceled callers.
Resolver-owned operation state must remain independent of the number of
current or canceled waiters. Completion notification does not replace the
operation ownership, snapshot freshness, and lifecycle checks required for route publication.

Implement this as one internal metadata-operation mechanism shared by count
and endpoint-list fetching. Share completion notification, cancellation,
operation ownership, and failure-delay handling; keep each metadata type's
validation and publication rules explicit. Do not create a general cache
framework or duplicate these lifecycle rules in two implementations.

Reserve capacity before starting work. Count pending and completed count
records together toward the 4,096-record bound. When a new authority needs a
record at capacity, evict the least recently used eligible completed record.
Active fetches and failed records whose one-second failure delay has not expired
are ineligible. If no record is eligible, reject admission without queued work.
Protecting an unexpired failure delay prevents eviction from bypassing backoff.
Update count-record recency only when an initial resolution uses that record.
Use a bounded scan or an existing LRU helper; do not add a general cache framework.

Do not track references from discovery mappings or initial selections to cache
records. A pending initial selection retains only a copy of its acquired mapping
and count snapshot, not the entire endpoint list or a cache reservation after
count completion. Eviction cannot change that snapshot or its original fetch
time. Mapping changes do not cancel active count work. Eviction can cause an
additional count fetch for a later initial selection; established routes still
perform zero discovery. Expired completed records need no background cleanup.

Release count-fetch admission slots exactly once at completion. Operation
identity prevents late completion from overwriting replacement state. Shutdown
prevents new admission and publication, cancels active work, and joins cleanup
before releasing owned resources. Count-record eviction never removes a route
or authorization.

If initial resolution needs metadata and its fetch or required refresh fails,
fail that initial resolution. Retry only on a later initial-resolution request
under bounded shared work and the failure delay below. Do not establish a route
from expired or invalid metadata. Other models' established routes continue
without consulting that metadata or its failure state; their requests still
require valid authorization and the normal transport authentication.

After a failed endpoint-list fetch or count fetch, including invalid data or
zero healthy backends, retain a non-secret error and a retry-after time one
second after completion. Store these on the existing endpoint-list state or
count record, subject to operation ownership and resolver lifecycle checks. A late failure must not overwrite replacement state.
Requests that need that metadata during the delay fail immediately without
starting a fetch or extending the delay. The first request after the delay
starts the normal shared fetch; success clears the failure. Caller cancellation,
local capacity rejection, and shared operation cancellation do not create a
failure delay. This needs no timer, background retry, exponential backoff,
configuration option, or separate failure cache. Failed count records become
eligible for normal completed-record eviction once their delay expires.

An unresolved model absent from a fresh endpoint list fails as unknown without
refreshing the list. Retry its discovery only after the list's five-minute TTL
expires and another initial-resolution request arrives; do not
retain a failure record for each unknown model. Thus repeated unknown names
cannot trigger repeated discovery or grow resolver state.

Define typed metadata errors and one response mapping used by normal inference
and Explore. Do not leave the current unconditional route-error HTTP 502 mapping
in place for local overload. Preserve underlying errors through wrapping; do
not classify them by message text.

| Resolution outcome | HTTP response and retry advice |
| --- | --- |
| Active count-fetch slots, non-evictable count-record capacity, or route capacity exhausted | 503 with `Retry-After: 1`; no queued work, failure delay, or authorization invalidation. Established-route capacity exhaustion can require configuration changes or restart; the delay is advice, not a recovery guarantee. |
| Invalid model identifier | 400 with an input-error classification; no retry advice, retained model state, metadata work, or diagnostic containing the supplied value. |
| Upstream discovery/count retrieval or validation fails | 502 with a non-secret metadata error classification; install the fixed failure delay when eligible. |
| Request arrives during the fixed metadata failure delay | 503 with `Retry-After: 1` and a distinct metadata-delay classification; retain the original diagnostic, without another fetch or extending the delay. |
| Model absent from a fresh endpoint list | 400 with an unknown-model classification; no retry advice, fetch, or retained per-name failure record. |
| Initial operation's acquired metadata expires before route publication | 503 with `Retry-After: 1`; no internal retry loop or metadata failure delay. A later request can acquire fresh snapshots. |

Reject statically detectable invalid configured origins and applicable index
syntax at startup, using the precedence table below. Discovery-dependent
model/domain mismatches fail resolution with a
configuration-mismatch diagnostic and HTTP 502, without selecting another
authority. Preserve existing caller-cancellation and deadline handling. Test
the response mapping at the HTTP handlers, including wrapped errors and the
absence of inference bytes, rather than testing only resolver return values.

Operator documentation must distinguish transient metadata/socket overload
from retained-route capacity exhaustion and retired image keys that can require
restart or configuration changes. `Retry-After: 1` is not a recovery guarantee;
advise bounded client retries and retain a diagnostic that identifies the
condition. Document these limits beside configuration and endpoint use.

Shared discovery must have a server-owned cancellation context and bounded
timeout, with caller cancellation only stopping that caller's wait. Wire
resolver shutdown into `Server.Close` and standalone operation cleanup. The
current resolver detaches caller cancellation; retain that property while
making shutdown ownership explicit for new shared count/selection work.

### Atomic selection publication

After identifier and caller-context validation, create or join one
initial-selection operation per model under the resolver lock. Its owner reserves
route capacity and starts one worker with a server-owned 60-second deadline covering metadata acquisition and selection.
All callers share its completion channel; cancellation stops only that caller's
wait. Do not keep waiter registrations or count waiters. If all callers cancel,
the admitted operation still completes within its own deadline. On success it
converts the pending reservation into one established route; on failure,
deadline, or shutdown it releases the reservation exactly once. No authorization
or inference is initiated by a selection worker.

The owner acquires an immutable model/authority mapping with its fetch time,
then a validated count snapshot for that authority with its fetch time. Later
endpoint refreshes, mapping removal or replacement (including A-to-B-to-A), and
new count publications do not supersede these acquired snapshots. Both must
still be within their five-minute lifetime when the route is published. This
is sufficient because metadata selects a candidate authority; full attestation
and transport authentication independently authorize every inference attempt.
Do not add mapping-incarnation tokens, count generations, or a latest-metadata
publication requirement. Metadata changes cannot rewrite established routes.

Only the operation owner draws an index. Perform network I/O and the random
draw outside the resolver lock. Check the operation context before and after
the draw; do not detach another worker to wait for entropy. The injected test
selector must accept context cancellation for controlled blocking tests. Do
not promise that an operating-system entropy call can be interrupted by Go
context cancellation; it must never hold a shared lock or publish after timeout.
Construct and validate the complete candidate route before taking the lock.
Under the lock, recheck operation identity, lifecycle, deadline, and the two
acquired snapshots' freshness, then publish the route and operation result
atomically. Close the shared completion channel once after storing the result.
On failure, do not redraw, acquire newer snapshots, or internally restart;
a later request may create a new operation. Explicit indexed routes use the
same ownership rules without count acquisition or a random draw.

An established route bypasses all metadata freshness checks. Tests must block
one model's selector while established routes and another model continue,
cancel every waiter before selection finishes, and race shutdown or snapshot
expiry with publication. Verify one draw per successful operation, bounded
reservations, completion for remaining waiters, and no publication after
shutdown or timeout. A test selector released after cancellation must not
recreate state. Already returned routes remain immutable request snapshots.

### Route resolution and configured URLs

For default `api.near.ai` or `completions.near.ai` configuration at the standard
HTTPS port:

1. Return the established route if present, without discovery or a random draw.
2. Otherwise resolve the canonical model authority through `/endpoints` and
   acquire count metadata for that authority under the initial-resolution rules.
3. Select an index once, construct and validate the indexed HTTPS origin, and
   atomically establish an immutable `provider.ResolvedRoute` for the model.
4. Use that exact route for attestation, authorization acquisition, encryption,
   inference, reporting, and any already-permitted retry.

Normalize and validate the configured origin first. This table describes
initial resolution; later requests reuse the established route without either
metadata lookup.
The standard HTTPS port includes an explicit port 443 after normalization.
Non-default ports take precedence over automatic discovery. Recognized model
names below have one label under `completions.near.ai`.

| Configured origin | Endpoint-list requirement | Count requirement | Result |
| --- | --- | --- | --- |
| Any valid HTTPS origin with a non-default port, including NEAR names | None | None | Exact static origin; do not interpret or append an index suffix. Model identity must still pass attestation checks. |
| `api.near.ai` or `completions.near.ai` at the standard port | Required | Required for the discovered canonical authority | Selected indexed origin. |
| Explicit canonical NEAR model name at the standard port | Required to match the requested model and disambiguate the name | Required for that canonical authority | Selected indexed origin. |
| Explicit indexed NEAR model name at the standard port | Required to validate its canonical model mapping and rule out ambiguity | None | Exact configured indexed origin. |
| Other valid explicit HTTPS origin | None | None | Exact static origin. |

Automatic index construction requires a single canonical label under
`completions.near.ai`. Validate the final DNS label and origin after appending
the suffix. An explicit index must use canonical unsigned decimal syntax and
fit `uint64`, matching the reviewed upstream index URL builder: `0` or a
nonzero digit followed by digits, without signs or leading zeros. Reject
integer overflow and invalid DNS label length; do not impose a fleet-size cap.
An explicit index need not be below the current count and does not query count.
Compare recognized names with discovery before deciding whether an index-like
suffix belongs to a canonical name or an explicit index; reject ambiguous
interpretations and model mismatches. Never query count with an indexed name.
An explicit index fixes the SNI name, not a physical machine: upstream modulo
routing still applies when that index exceeds the current healthy count.

Required endpoint-list lookup failures block initial resolution of explicit
canonical and indexed routes too; they cannot block established routes. Static
routes do not depend on that service and need no random selection records. Test every table row with discovery unavailable, including
explicit port 443, non-default ports, invalid suffixes, and DNS length limits.

Use the indexed authority for URL host, HTTP authority/Host, TLS SNI, certificate
hostname validation, and authorization identity. Do not dial an IP with a
different Host/SNI, rewrite certificate names, install custom roots, or disable
WebPKI/CT. Live probes established normal certificate validation for GLM's two
indexed names; other models must independently satisfy it.

### Topology changes, admission, and retries

| Event | Selection and authorization behavior |
| --- | --- |
| Metadata TTL expires | Established routes perform no discovery and retain selection and authorization. A new model's initial resolution may fetch fresh metadata. |
| Count grows or shrinks, including below the selected index | Preserve the hostname and index without rediscovery or reselection; fresh connections use upstream modulo routing and must pass identity authentication. Initial placement balance can change. |
| Discovery for a new model removes or replaces an established model's canonical mapping | Preserve that established route and authorization. Only initial operations that have not acquired a mapping use the updated mapping. |
| Count is zero, discovery fails, or metadata is invalid during initial resolution | Block that initial resolution. Do not alter established routes or their authorizations. |
| Same index now reaches another SPKI, including same-count replacement | Fail the current inference handshake without replay; conditionally invalidate only the used authorization generation. The next request fully verifies on a miss using the same route and a fresh attestation connection, without discovery. |
| One backend goes down; ordinary dial/I/O failure, socket-capacity rejection, 429, or generic 5xx | Preserve selection and authorization. Apply only the existing retry/backoff contract on the same route. No backend search, index rediscovery, or fleet-wide connection invalidation. |
| Exact supported encryption-key rejection | At most one authorized retry with fresh session material, same immutable route, and generation-conditional invalidation as required by the retry contract. No discovery. |
| Evidence expires, all connections close, or an HTTP/2 pool expands | Preserve selection and authorization; new handshakes must authenticate the cached identity. |


Count is an availability hint, not authentication. A count change alone is not
authorization withdrawal. A retained HTTP/2 connection can still reach its old
authorized backend even if new connections with the same SNI would be routed
elsewhere. Allow acquired attempts to complete within their deadlines. Do not
cancel unrelated streams or flush all NEAR pools. For a new trust failure,
preserve the existing authorization-generation checks and pool identity checks.
Do not weaken these checks to accommodate a remapping race. An established
route's identity failure can retire only the affected authorization generation
and pools whose trust depends on it. A model-key change with unchanged gateway
SPKI preserves gateway connections. Discovery must never be used to invalidate
all existing connections after one backend failure or key change.

In Phase 4, document initial-only discovery and lifetime route reuse in
[the transport reference](../transport/README.md) and its [retry](../transport/retries.md)
and [testing](../transport/testing.md) documents. State explicitly that elapsed
time, re-attestation, cache eviction, a backend outage, or a key change must
not cause recurring discovery or fleet-wide invalidation. Include the tradeoff
that physical placement and load balance can change under upstream modulo
routing, and a retired hostname may need operator configuration or restart.
Link the regression tests that assert zero discovery on established routes.

### Attestation connections after index remapping

Re-attestation through an existing pooled connection can still reach backend A
after fresh connections for that index reach backend B. Repeatedly fetching
A's evidence and rejecting B's inference SPKI can sustain an outage. Closing
only inference connections or waiting for the attestation idle timeout does
not establish recovery.

For NearDirect, start each full verification's attestation fetch with a fresh
TLS connection to its immutable route. Use an operation-owned transport for
that fetch and close its owned resources when the fetch finishes. This avoids
a retained attestation-pool generation registry and does not add handshakes or
attestation to requests that reuse authorization. Keep metadata and collateral
clients pooled. Do not close shared clients or unrelated inference pools.

Construct the fetch transport with the production TLS, WebPKI, CT, proxy,
redirect, timeout, retry, and socket-limit rules. Preserve capture/replay and
test injection through a client/transport factory that creates an independent
pool; copying an HTTP client while retaining its shared transport is not
sufficient. Update ownership and cleanup together. Shared authorization
admission bounds this work, and its server-owned context bounds setup and body
reads. Standalone verification owns the equivalent bounded operation and
cleanup. Do not use per-request `Connection: close` or disable HTTP/2.

Connection pools are operation-owned; the socket budget is not. Inject one
server-owned attestation socket-budget group into the shared attestation client
and every fresh NearDirect fetch transport derived from it. Preserve the common
transport's physical-socket accounting and per-dial-address limit, using
`tlsct.MaxConnectionsPerHost` as the production limit. All those pools consume
the same allowance for an address, including concurrent models, retries,
pending dials, and sockets awaiting closure. Do not allocate a new budget per
factory call or use only each transport's `MaxConnsPerHost` as the bound.
Keep inference's budget separate. Give metadata its own pooled client and
budget: the current NearDirect `SetClient` also assigns the attestation client
to discovery, so this separation requires an explicit construction change.
The shared attestation client and fresh fetch factory use the same budget,
including nested transports such as the AMD KDS transport. Pass the budget
through constructors; do not discover it by inspecting transport wrappers.
Preserve capture, counting, and logging wrappers on each client. The server
owns the pooled clients; each fetch owns only its fresh pool. Standalone owns
the equivalent clients and budget group for its invocation;
there is no mutable package-level budget. Reuse the existing connection-budget
mechanism through explicit injection, without adding another scheduling queue.

Each socket retains its permit until physical close; failed dials release their
reservation. Fetch cleanup closes only its owned pool and does not reset the
shared budget. Exhaustion returns the existing typed capacity error, without
retry, negative caching, or authorization invalidation. Verification admission
and socket admission remain separate limits. Test with a small injected shared
limit across factories and the pooled attestation client, including concurrent
models, HTTP/2, retries, failed handshakes, cancellation, and shutdown. Assert
aggregate live-socket and pending-dial bounds, permit release exactly once, and
that ending one fetch does not close another fetch's sockets.

Reserve capacity for fresh fetches within that same aggregate allowance. For
an address with limit L, the long-lived pooled attestation client may hold at
most L-1 permits, counting pending dials and idle sockets. Fresh fetch pools
may use any remaining aggregate permits. Production L remains 16; injected
limits for this shared arrangement must be at least 2. Acquire the aggregate
permit and, for a pooled dial, its pooled-share permit atomically. Release both
only on physical close or a failed dial. This is fixed admission accounting,
not another queue or a new per-factory budget. Pooled-share exhaustion has the
same typed capacity behavior as aggregate exhaustion.

This leaves at least one slot available to a fresh fetch when only pooled
connections occupy the address. Concurrent fresh fetches can still exhaust the
aggregate limit and fail immediately; do not promise fairness or a slot for
every caller. Do not close an active stream or a shared pool to obtain capacity.
Keep this reservation local to the shared attestation budget; inference and
metadata pools retain their existing limits.

This reservation guarantees progress for a fresh evidence fetch, not for full
verification. A subsequent collateral cache miss can still encounter a full
pooled share at the same forward-proxy address. Return the typed capacity error
without retry, cooldown, or authorization publication. A later request can
proceed after pooled sockets physically close, normally through idle timeout.
Document this recovery delay; do not add a queue, another reserved share, or
automatic shared-pool closure to eliminate it in this change.

Test an HTTPS forward proxy with several origins sharing its dial address.
Fill the pooled share with idle connections and prove it cannot consume the
reserved slot. A fresh NearDirect fetch must then succeed before idle timeout,
without closing pooled connections, changing authorization, or exceeding the
aggregate bound. Also fill the remaining capacity with an active fresh fetch:
another new dial fails immediately, then a later fetch succeeds after physical
close releases the permit. Cover active pooled HTTP/2 streams, failed dials,
cancellation, and shutdown, including release of both counters exactly once.
Also require collateral from an origin without a pooled connection after the
fresh evidence fetch. With the pooled share full, assert capacity failure and
no publication or negative entry. After the fixture closes an idle pooled
socket, a later operation must complete. Exercise the nested AMD KDS transport
against the same aggregate budget, and verify metadata uses its separate
budget. Use controlled closure rather than waiting for the idle timeout.

The fresh connection does not prevent membership from changing again between
attestation and inference. Such a mismatch still blocks without replay. Test
recovery when topology settles: keep a connection to A available in the test's
shared client to detect accidental transport reuse, route fresh connections
to B, fail the first inference attempt, then verify B on the next
request and reuse B's authorization across later requests. Assert separate
attestation/inference connection identities, verification counts, cleanup,
unchanged selected index, and zero inference bytes on failed handshakes. Add
concurrent late-A failures and unaffected other-authority streams. Do not
replace this test with an attester mock that always returns the newest key.

## NearCloud design

1. Keep `cloud-api.near.ai` as the gateway route. Do not construct gateway
   `-iN` names or substitute a direct backend as the NearCloud TLS peer.
2. Request `provider=near` when fetching gateway/model attestation. Teep's
   NearCloud evidence and encryption implementation is for that serving tier;
   do not let the first successful report silently select Chutes. Continue
   using a fresh client nonce and `signing_algo=ed25519` with TLS binding.
3. Add a dedicated `nearcloud.NewPreparer`. Reuse NEAR encryption-header logic,
   but add `X-Model-Pub-Key` from the acquired authorization's validated
   Ed25519 signing key, not its X25519 conversion, the client's ephemeral key,
   a request header/body, or a separate cache. Encode the authenticated 32 key
   bytes as exactly 64 lowercase hexadecimal characters without a prefix.
   Mathematical key validation accepts uppercase hex, but the reviewed gateway
   uses the header text as a case-sensitive public-key map lookup. Do not copy
   the evidence's original text representation into the header. Keep byte
   authentication in the shared binding verifier and canonical wire encoding
   in the NearCloud preparer. Do not log the key.
4. Extend the existing request-preparer input with immutable authenticated
   preparation data, sourced from `InferenceInput.SigningKey` by
   `provider.PrepareInference`. Use the existing `RequestPreparer` dispatch;
   do not add an optional second interface or runtime capability assertion for
   mandatory NearCloud behavior. Update all implementations and call sites in
   the same phase, preserving other providers' behavior. Keep the input type
   in the shared provider package and retain no per-request state on preparers.
   NearCloud requires its acquired authenticated key and sets exactly one
   validated header. Use this for TLS-only requests as well as E2EE; add
   encryption headers only when an encryption session exists.
   `newAuthorization` currently clears `signingKey` for TLS-only operation:
   explicitly retain and validate the REPORTDATA-authenticated Ed25519 key
   for NearCloud routing in that case. Require successful key binding before
   publishing it, just as for an encryption key. Do not populate a routing
   hint from a key whose binding factor merely had an allowance. This adds a
   mandatory admission requirement for NearCloud TLS-only operation. Test that
   failed or missing binding blocks publication and sends zero inference bytes
   even with `allow_fail` for that factor, in proxy and standalone paths. Keep
   other TLS-only providers' key-retention behavior unchanged. Retaining a routing
   key must not mark an E2EE test successful or enable encryption implicitly;
   update key-count assertions and diagnostics to describe the retained key.
5. Update both proxy construction and `verify.testStandaloneInference`, which
   currently selects the NearDirect preparer for both providers. Every retry
   must obtain its key and header from the same acquired authorization as its
   fresh session. After rejection it may join a replacement already published
   by another request; it must not require another redundant verification.
6. Do not re-fetch evidence to choose another key while a valid cached key is
   usable. Keep model-specific authorization and gateway-SPKI pool scoping.
   Replacing a model key with an unchanged gateway identity must not require
   closing unrelated gateway connections.
7. Apply the header consistently to supported NearCloud request preparation,
   but document the endpoint limitations above. Do not bypass AEAD failures,
   route cloud requests through the direct API, disable encryption, or claim
   non-chat backend affinity. No extra per-request attestation can repair an
   upstream endpoint that ignores the routing hint. Image requests retain the
   ordinary error policy and the key-retirement recovery limitation below.

### Standalone inference mode and reporting

The production standalone entry point continues to send its existing streaming
chat probe to `/v1/chat/completions`. This change adds no image, embedding,
rerank, score, or audio probe and no endpoint-selection interface. Models that
cannot serve chat have no successful standalone inference validation from this
probe; preserve a visible failure if the attempted chat request fails. An
otherwise skipped probe establishes no inference success. Exercise non-chat
endpoint behavior through the production proxy entry points and endpoint tests,
not through a test-only standalone request builder.

For NEAR standalone inference, use the configured E2EE mode explicitly. The
current `verify.testStandaloneInference` constructs a provider with `E2EE: true`,
and `completeTLSInference` records its outcome as an E2EE test. Changing the
preparer alone does not implement or test TLS-only operation. Update request
preparation, response processing, rejection handling, and completion reporting
together. Do not run an implicit encrypted probe when NEAR E2EE is disabled.
Keep other providers' standalone mode behavior unchanged.

Before a NearCloud TLS-only attempt, require successful REPORTDATA binding and
validate the retained Ed25519 routing key under the same admission rules as
the proxy. Send its routing header over the attested gateway transport, without
an encryption session or encryption headers. Process the response as TLS-only;
neither successful inference nor key retention can promote `e2ee_usable`.
An exact chat 421 rejection ends that standalone attempt without replay or
automatic re-attestation. A later standalone invocation obtains new evidence;
standalone verification does not retain the proxy's shared authorization cache.

Represent TLS-only inference success and failure separately from E2EE outcomes
in standalone output and capture metadata. Use a standalone `tls_inference`
operational result; it is not a configurable factor allowance. Preserve the
existing requirement that TLS-only configuration explicitly allows
`e2ee_usable` to fail. A configured allowlist replaces provider defaults, so
TLS-only validation must retain those defaults and add only `e2ee_usable`. A TLS-only inference failure must
remain a visible failed verification outcome, not become success because no
E2EE result exists. Update capture writers, replay readers, and schema tests
with this reporting change. Preserve existing offline, replay, and credential
conditions for whether live inference runs; skipped inference establishes
neither TLS-only inference success nor E2EE success.
Record the configured E2EE mode even when inference was skipped. Replay must
check it against the current configuration before verification, as specified
in the capture contract; absence of an inference result does not identify the mode.

### Explicit stale-key rejection

The new hint can make the gateway return a different pre-inference rejection.
For chat, the reviewed `retry_with_fallback_caps` returns `NoPubKeyProvider`
before calling the provider closure when the pinned key is absent. The
[completion service](https://github.com/nearai/cloud-api/blob/1c8057f3620a77d0aef9f3a16c5711fd2e6ee21c/crates/services/src/completions/mod.rs)
maps it to HTTP 421 with this exact message:

```text
The encryption key is no longer valid. Please refresh your attestation report and retry.
```

The [API conversion](https://github.com/nearai/cloud-api/blob/1c8057f3620a77d0aef9f3a16c5711fd2e6ee21c/crates/api/src/conversions.rs)
uses `error.type=provider_error`; `routes/common.rs::map_domain_error_to_status`
preserves the service's HTTP 421 status. Optional `param` and `code` are null
in the current envelope. For this new 421 contract, accept each of `param`
and `code` only when absent or null. Reject every non-null value, including
strings, numbers, booleans, arrays, and objects; do not inherit the existing
400 parser's unrestricted `any` fields. Keep the 400 contract unchanged.
Extend recognition only for NearCloud
`/v1/chat/completions`, HTTP 421, `application/json`, that type and exact
message, received through the attested gateway transport after sending the
acquired authorization's routing key. Separate recognition and authorization
invalidation from replay permission:

- E2EE attempt: conditionally remove the used generation and permit at most
  one retry with newly acquired authorization and fresh session material.
- TLS-only attempt: conditionally remove the used generation, return the
  rejection, and do not replay the request. The next request must acquire a
  replacement authorization, fully verifying on a miss. Preserve gateway
  connections whose transport identity remains valid.

Without TLS-only invalidation, the cached routing key could remain selected
indefinitely after the gateway removes it: authorization has no TTL, and an
unchanged gateway SPKI would not trigger renewal. A late rejection must never
remove a replacement generation. Exact stale-key invalidation does not create
a decryption-failure cooldown. Generic TLS-only chat errors and generic image
errors retain authorization.

Preserve strict envelope parsing, duplicate field checks, the 64 KiB bound,
encrypted-error exclusions, one-retry maximum, generation-conditional removal,
fresh session creation for E2EE, and the caller deadline.
Update the retry reference in the same implementation commit. Do not recognize
generic 421, approximate messages, non-chat errors, TLS failures, or HTTP 5xx as
key rejection. TLS-only errors retain their existing non-replay behavior.
Image errors have no additional invalidation or replay contract.
Existing 400 decryption-rejection contracts remain E2EE-only.

### Image errors and recovery limits

The reviewed
[`image_generation_with_attribution`](https://github.com/nearai/cloud-api/blob/1c8057f3620a77d0aef9f3a16c5711fd2e6ee21c/crates/services/src/inference_provider_pool/mod.rs)
filters providers by the supplied model key, but converts a missing-key failure
into `ImageGenerationError::GenerationError`. The pinned
[image API conversion](https://github.com/nearai/cloud-api/blob/1c8057f3620a77d0aef9f3a16c5711fd2e6ee21c/crates/api/src/routes/completions.rs)
maps that error to HTTP 404 when its message contains `not found` or
`does not exist`, and HTTP 500 otherwise. Those statuses can also describe
request-specific failures with an unchanged valid key. They establish neither
key retirement nor rejection before inference.

For `/v1/images/generations`, retain authorization on generic HTTP errors,
including 404 and 500, in both E2EE and TLS-only modes. Return the failed
attempt without replay, a new cooldown, or automatic re-attestation. Retain
existing body bounds, redirect handling, and the separate invalidation rules
for independently classified origin trust or response-authentication failures.
Do not extend chat rejection recognition to images through status codes or
nested error text.

This avoids letting one client's request-specific error remove usable shared
authorization or impose a cooldown on other clients and endpoints. Tests must
exercise repeated 404/500 responses with an unchanged key alongside valid
same-model traffic, another endpoint sharing its authorization, and another
model. Assert unchanged generations and gateway pools, no negative-cache entry,
no additional verification, and no replay. Cover malformed and oversized error
bodies, body read failures, and caller cancellation without promoting any
failure to success. Independent authentication failures must still invalidate
under their existing generation-conditional contract.

Automatic image key-retirement recovery remains unsupported. If a retired key
produces only generic errors and no independent authentication failure, requests
can continue to fail until authorization is otherwise evicted or the process
restarts. Do not add an authorization TTL or instruct clients to provoke eviction.
Document this limitation beside NearCloud image use. Standalone verification
only probes chat; it does not provide an image recovery operation.

A future image recovery policy requires an upstream error contract that
reliably distinguishes key retirement from request-specific failure. Replay
also requires proof of rejection before inference. Keep that work separate
from this routing change. In Phase 5, update API support, transport retry/testing
documents, and the provider documentation with the limitation, pinned evidence,
and linked regression tests. Generic HTTP errors must not create shared
availability failures as a substitute for an unavailable recovery contract.

## Shared NEAR attestation validation

The model-key binding repair is Phase 1. Representation parsing is Phase 2 and
must preserve the repaired binding checks. Both phases retain existing routing
and inference modes; NearCloud TLS-only key admission changes in Phase 5.

### Representation parsing

Tighten the shared attestation parser without changing routing or inference
modes. Require the requested model, reject ambiguous multiple matching entries,
and validate the entire response structure before selecting an entry. Do not
choose the first entry or drop malformed alternatives to obtain a matching
fingerprint. The direct live format repeats its one report at the top level
and in `all_attestations`; preserve its defined representation without
conflating that with an array containing several candidate machines.

Use a provider-specific typed outer envelope and shared typed model-entry decoder.
Choose the envelope from the configured provider before parsing; do not infer
the provider from response fields or retry another parser after an error.
Support the forms demonstrated by the checked captures under
`internal/integration/testdata/neardirect_*` and `nearcloud_*` and the pinned
inference-proxy `AttestationResponse` and cloud-api gateway response:

| Provider and representations | Required treatment |
| --- | --- |
| NearDirect: complete flat report plus `all_attestations` | Require exactly one array entry, matching the flat report and requested model in every supported report field. |
| NearCloud: `gateway_attestation` plus `model_attestations`, without flat model fields or `all_attestations` | Validate gateway evidence and every model entry; require a nonempty bounded array with exactly one requested-model entry and no duplicate models. |
| Flat-only, array-only direct response, both arrays, cloud flat/array mixtures, partial flat report, null/empty required array, null entry, or malformed alternative | Reject the response. Do not select a usable subset or try another envelope. |

Use presence-aware decoding to reject forbidden fields even when null or empty.
Retain each supported envelope's documented auxiliary fields with their own
validation. Do not implement cross-array set comparison or speculative formats
for previous or future provider APIs. Adding a format requires pinned protocol
evidence, a representative fixture, and an explicit contract update. Existing
synthetic tests using unsupported shapes must become negative tests or migrate
to a supported envelope without changing their intended security assertion.

Equality of supported fields includes model name, signing algorithm, signing
address, public key, TLS fingerprint, request nonce, Intel quote, NVIDIA payload,
all supported `info` fields
(including nested TCB information), and the ordered event log. Compare typed
structures rather than JSON formatting or object member order. Compare decoded
cryptographic values with constant-time operations; supported equivalent hex
case must not cause disagreement. Preserve exact evidence bytes where no
protocol-defined normalization exists. Validate each representation before
comparison, including missing and unknown fields under the existing parser
policy. Unknown additions are returned as field diagnostics and are not used
as verification inputs or compared as authenticated report fields. They may
be accepted under the caller's existing `response_schema` policy; this change
does not make every unknown field an unconditional parsing error. Keep all
supported fields in the typed comparison.
Gateway and auxiliary attestations are distinct evidence types, not repeated
model reports. Validate their object boundaries and retain their separate bounds;
do not apply model-report equality or model-key binding to the gateway. These comparisons do
not authenticate provider assertions or replace quote and binding verification.
Tests must cover every matrix row and disagreement in each field group,
including non-selected entries and equivalent cryptographic text encodings.

Strictness must apply at every object boundary. The current `jsonstrict`
dependency reports unknown and missing fields only for the object passed to it;
a single outer decode does not validate nested objects. Decode model entries,
`info`, `tcb_info`, and structured event-log entries through named strict helpers.
Use typed nested fields with custom `UnmarshalJSON` methods that validate their
input through `internal/jsonstrict` before assigning decoded values. Retain
presence and schema diagnostics on each decoded value, including array entries,
then collect field paths at the provider envelope. Do not retain `json.RawMessage`
fields, use raw-byte aliases to avoid lint checks, or add teeplint exemptions.
Transient decoder input bytes are sufficient for nested validation; retained
raw nested representations are not required. Return field paths
to the caller for its policy decision without logging or deduplicating them in
low-level parsers. Reject malformed, duplicate, null, and incomplete required
structures before report selection or comparison.

Replace `tcbInfo.UnmarshalJSON`'s ordinary decoder. Validate duplicate object
members, including equivalent escaped names, in the outer JSON document before
decoding. For a supported JSON-encoded `tcb_info` string, unwrap that one defined
layer and validate duplicate members and strict fields again on the decoded
object. The outer duplicate check cannot inspect JSON inside a string. Preserve
the bounded input and reject invalid or extra encoding layers. Do not compare
partially decoded structures that have silently discarded supported fields.

Apply the same strictness explicitly to `nearcloud.gatewayAttestation`, its
nested `info`, and its separate `tcbInfo.UnmarshalJSON`. The gateway `event_log`
is also a JSON-encoded string: unwrap its defined layer, validate duplicates in
the decoded document, bound the entry count, and strictly decode each entry.
An outer duplicate check cannot validate that string. Reject malformed, null,
and missing structurally required nested fields before returning gateway
evidence. Return unknown-field diagnostics to the caller under the same schema
policy as model evidence.

Share TCB decoding and event-entry decoding between direct and gateway parsers
where the schemas agree. Keep envelope decoding, array versus JSON-string
representation, and gateway/model binding rules explicit. Do not create a
general recursive decoding framework or duplicate the same strict helpers.

Use deterministic table-driven tests for unknown, missing, duplicate,
escaped-duplicate, and null fields inside model and gateway `info`, `tcb_info`,
and event logs, including decoded strings and non-selected model reports.
Check returned field paths and rejection under the applicable parser policy.
Cover acceptance of unknown additions with an explicit schema allowance,
without treating the added fields as authenticated inputs. Duplicate members,
malformed structures, and failed cryptographic checks retain their own rules.
Equivalent supported object and string TCB forms must compare by their complete
decoded structure. Test only evidence-supported forms as positive cases.

Captures describe the provider revision at capture time and can become stale.
The current Go structs also omit fields present in existing captures. Check
representative captures and pinned source when defining supported fields;
record unavailable current evidence as a validation limitation. Keep schema
definitions in code and fixtures rather than reproducing them in this plan.

### Model-key binding repair

Repair the shared NEAR REPORTDATA verifier. Its current success
authenticates `SigningAddress` and the TLS fingerprint, but does not establish
that `SigningKey` corresponds to that address. Mathematical Ed25519 key
validation and agreement between repeated response representations do not
establish that relationship either.

For the requested Ed25519 protocol, require `signing_algo=ed25519`, decode and
validate the public key, require a 32-byte signing address, and compare the
decoded key and address with `subtle.ConstantTimeCompare` before declaring
REPORTDATA binding successful. The pinned upstream
[Ed25519 signing implementation](https://github.com/nearai/inference-proxy/blob/c59ea60e658f33c3b4d63ccd615de9395013559e/src/signing.rs)
sets the address to the public-key bytes themselves, not their hash. Correct
the local verifier's misleading address comment. Reject algorithm substitution,
20-byte ECDSA addresses in this model-key path, missing fields, malformed keys,
and key/address disagreement. Keep the gateway's distinct signing-address
scheme separate; do not apply this model-key rule to the gateway verifier.

Own the key/address relationship in the shared model REPORTDATA verifier,
rather than repeating it in preparers or authorization constructors. Their
binding-success requirement must then refer to this complete check. E2EE
admission for both providers must reject a failed binding even with an
allowance; Phase 5 applies that same requirement to NearCloud TLS-only routing.
Do not change NearDirect TLS-only factor-allowance semantics in this repair.

## Capture configuration and route records

For NEAR captures, record the effective HTTPS origin and configured
E2EE boolean independently of the inference outcome, including skipped inference.
For NearDirect, normalize the configured origin. For NearCloud, record the
fixed `https://cloud-api.near.ai` gateway used for attestation and inference;
its unused `base_url` setting must not change capture or replay. Before
replay verification, require both values to match the current provider
effective configuration; otherwise return a clear configuration-mismatch error. Do not
override configuration, infer missing values, or add equivalence rules between
different origins. This compares two settings, not a saved copy of the full
configuration; current verification policy remains in force.

Migrate affected fixtures or obtain new captures under normal enforcement;
do not add format fallback code. Do not relabel a previous encrypted self-test
as TLS-only merely because its configuration had E2EE disabled. Test matching
settings and each setting changed independently for TLS-only, E2EE, and
skipped-inference captures. Mismatches fail before verification, and replay
makes zero live inference requests.

Use a typed route record in `capture.Manifest` with canonical authority,
selected index, final authority, and selection mode (discovered or explicit).
Selection mode describes how the index was obtained: an explicitly configured
canonical URL that undergoes count-based selection is discovered mode; an
explicit indexed URL is explicit mode. Static authorities require an explicit
representation without an invented index. Validate these field combinations.
After the configuration comparison implemented in Phase 4, replay must use the
recorded selection without another random draw. Validate that selection against
captured canonical discovery/count data. Verify that the recorded attestation
URL/peer and final report agree with the route; manifest metadata itself is not
attestation. Explicit indexed captures require canonical endpoint-list
validation but no count response. Static captures require neither endpoint-list
nor count discovery, in accordance with the configured-origin decision table.

Obtain new indexed captures when required metadata is absent;
do not add old-format fallbacks or synthesize successful trust checks. Add
negative replay tests for tampered route fields, invalid mode combinations,
missing required metadata, and attestation URL/peer/report disagreement. Reject
invalid captures without network access, a new random selection, or an alternate
route. Matching replay makes no fresh random selection or live inference request.

## Report lookup

For NEAR providers, `GET /v1/tee/report` reads cached diagnostic state. It must
not call ordinary route resolution or acquire authorization. An explicit
`authority` selects that exact cached authorization as today. Without `authority`, read the
resolver's established default selection under its state lock and copy the
immutable route. Static origins and explicitly indexed configured routes can
use their normalized authority without discovery. Do not allocate a selection
record for a report lookup.

If lookup would need discovery to determine an authority, or no report is
cached for the determined authority, return HTTP 404. Metadata TTL expiry or discovery unavailability
does not prevent reading an existing cached report. If ordinary resolution
has established a route, metadata changes do not remove or replace it. Lookup
must not search another authority. Concurrent authorization replacement or
eviction may occur after the route is copied: lookup still reads only that
captured authority and returns its cached report or 404.

Neither lookup form fetches metadata, draws an index, refreshes attestation,
updates authorization recency or generation, or changes selection. A report
is diagnostic evidence, not permission to forward a new request. Completed
request metrics continue to use that request's immutable route snapshot.

## Phases for the implementation agent

Each phase builds on completed earlier phases and must be independently
reviewable and testable at its own commit. It must not require files, fixtures,
report formats, or behavior from a later phase to pass. Use one commit per
phase and stage only the files changed in that phase. Do not commit reference
repositories, credentials, or unrelated untracked files.

Include production changes, their regression tests, affected capture readers
and writers, fixture migration, and maintained documentation in the same phase.
Do not defer feature coverage or documentation to a final integration phase.
Do not add unused production helpers, temporary compatibility paths, feature
flags, disabled tests, or weaker checks to make a phase pass. If a dependency
is discovered, move the dependent work into the same phase or an earlier one
before implementation; do not leave a commit that depends on a later repair.

Run `make check` before every phase commit. Run the affected signed-evidence
replay tests in every phase that changes their parser or format. Phase 3
requires `make integration`, including the affected transport and capture tests.
Phases 4–5
also require `make integration` and `make reports`, with relevant live NEAR
suites run with `-count=1`. Record actual results and unavailable prerequisites;
a skipped or blocked live test is not successful validation. Follow AGENTS.md
if a validation failure prevents progress. Each phase's commit description must
state its implemented behavior, tests run, and remaining external validation.
Do not record implementation status or validation logs in this plan. Do not
report required validation as complete while it remains unexecuted.

The design sections own behavior. The [requirement-to-test checklist](#requirement-to-test-checklist)
owns acceptance assertions and phase assignments. Use the phase table for
implementation order and affected entry points; do not maintain a second copy
of the test requirements in phase prose.

| Phase | Implementation and documentation scope |
| --- | --- |
| 1 | Implement the [model-key binding repair](#model-key-binding-repair), its key-substitution and admission regression tests, signed-evidence validation, and binding documentation. Preserve existing representation selection, routing, and inference modes. Ship this cryptographic repair independently of the parser rewrite. |
| 2 | Implement [representation parsing](#representation-parsing), including strict nested decoding, complete comparisons, parser consumers, signed-evidence fixtures, and parser-contract documentation. Retain Phase 1 binding enforcement. Preserve existing routing and inference modes. |
| 3 | Extract explicit shared attestation socket-budget injection and a client/transport factory that preserves production TLS, proxy, retry, capture, and cleanup behavior. Connect existing production client construction to the factory and shared budget, including nested attestation transports; separate metadata client ownership and its budget. Exercise independent pools through production factory tests. Preserve the pooled client's full allowance, current routing, attestation connection reuse, standalone modes, and capture formats. Update transport documentation and ownership tests. Phase 4 activates operation-owned NearDirect fetch pools and their reserved capacity together. |
| 4 | Implement complete NearDirect routing and NEAR standalone mode/reporting support together: the [NearDirect design](#neardirect-design), [standalone modes](#standalone-inference-mode-and-reporting), all [capture configuration and route records](#capture-configuration-and-route-records), and [read-only report lookup](#report-lookup). Connect proxy, Explore, shared verification, and standalone to the same resolver and exact route snapshot. Keep the existing route type and authorization key unless an invariant requires a change. Update output, capture writers/readers, self-checks, fixtures, and documentation together. Retain the existing standalone NearCloud binding requirement; gateway routing headers and recovery belong to Phase 5. Cover every supported direct endpoint. |
| 5 | Implement the [NearCloud design](#nearcloud-design), including its preparer, mandatory TLS-only binding, attestation query, rejection handling, and both standalone modes. Update all preparer implementations and callers, factories, authorization-key handling, and affected captures together. Complete cloud and concurrent multi-provider coverage. |

Phase 3 must use the extracted factory in existing production client
construction, so it adds no unused production abstraction. Its tests must prove
shared admission, transport settings, and capture/cleanup
ownership without requiring indexed routing or a new report schema. Phase 4
retains those tests and activates fresh fetches and the pooled-share limit
together with selected routes. It adds the reserved-capacity progress and
collateral-capacity recovery tests; Phase 3 does not reduce pooled capacity
before fresh fetches use the reservation.

For Phase 4, extend `endpoints_test.go`, `discovery_validation_test.go`,
`discovery_diagnostics_test.go`, `refresh_generation_test.go`, and
`client_ownership_test.go`; add focused count and selection tests. Preserve
capture injection for metadata and the selected authority in attestation and
report identity. Routing, standalone modes, and capture changes form one
Phase 4 unit so its integration tests and reports use indexed authorities from
the start. There is no earlier standalone phase that requires the unresolved
direct routing failure to pass. Phase 5 must retain all Phase 4 coverage.

Phases 4 and 5 each create the corresponding maintained provider document under
`docs/providers/`, following the Tinfoil document's structure. Update affected
transport, retry/testing, README/README_ADVANCED, API support, measurement and
attestation-gap references, and examples in the same phase. Phase 4 links the
historical NEAR HTTP/2 plan to the maintained routing contract. Phase 5 includes
the image recovery limitation and evidence required for a future contract beside
image use, in `docs/api_support.md`, and in the transport documents. Phase 4
explicitly documents the prohibition on recurring discovery for established
routes and on fleet-wide invalidation after individual backend failures.

Finish implementation only when all checklist requirements and validation
finish. Record completion in the phase commits. Review documentation consistency
and link the completed design to maintained references.

## Requirement-to-test checklist

Use deterministic table-driven parser tests, injected clocks, and channel
barriers for concurrency schedules. Parser fuzzing is optional, not a completion
requirement or a substitute for deterministic cases. Do not add probabilistic
placement assertions, sleep-based race tests, or heap/goroutine-count thresholds.

Tests must check attestation call counts and authorization generations, not
only successful inference or HTTP/2 negotiation. Use real TLS test servers and
the production crypto/transport path. Use `testtls.RunWithFallbackRoot` and
`authority.NewTLSServer` when production clients retain system trust. Model
SNI selection in a test listener with distinguishable certificates/backends;
do not use a plaintext stand-in for trust behavior.

Use these test layers with explicit responsibilities:

- **Deterministic unit tests:** Extend
  [the NEAR HTTP/2 tests](../../internal/proxy/near_http2_test.go) for controlled
  SNI remapping, mixed keys, ignored hints, cancellation, and generation races.
  Generated server and encryption keys exercise production TLS and NEAR
  encryption. Synthetic authorization reports are permitted only to isolate
  those behaviors; they do not establish successful attestation. Describe
  counters at this layer as acquisition or verification-invocation counts,
  not completed full verifications.
- **Live admission integration tests:** Extend
  [NEAR HTTP/2 integration](../../internal/proxy/integration_near_http2_test.go)
  and [key recovery integration](../../internal/proxy/integration_key_recovery_test.go).
  Use live provider evidence and production admission, with normal and offline
  policy tested separately. Observe the real attester without replacing its
  result; assert successful authorization publication as well as fetch counts
  and generations. These tests establish full verification on a miss and reuse
  on subsequent requests. Do not require control over live fleet membership or
  key rotation; deterministic unit tests cover those transitions and cache reuse
  after evidence expiry. Replay uses its recorded verification time for initial
  admission; do not change signed evidence or introduce an admission exception
  to simulate expiry.
- **Signed-evidence replay integration tests:** Use unmodified NEAR captures
  from production verification for parser, binding, route, and capture checks.
  Obtain new indexed captures when existing fixtures lack required metadata.
  Captured public keys do not provide private keys for local TLS or encryption
  servers. Do not combine captured quotes with generated keys or synthetic
  passing reports to claim full admission. Replay does not prove new live
  inference succeeded.

The checklist below spans these layers; it does not require a deterministic local
server to produce hardware attestation for generated keys. Assertions of full
verification require real signed evidence and the production admission path.
Record unavailable live credentials, evidence, or provider prerequisites as
unexecuted or blocked coverage; do not substitute unit-test success. Each row
maps a design requirement to its required assertions and implementation phase.
Replace the unchecked marker only after recording the actual test names and
results. A row assigned to multiple phases remains unchecked until all its
applicable phase coverage is complete.

| Requirement | Phase | Required assertions |
| --- | --- | --- |
| [Random placement](#discovery-and-selection-ownership) | 4 | Exhaust all indices for small counts; test zero and the last index for counts 256, 257, above 32-bit range, and the uint64 maximum without statistical assertions or enumerating large ranges. Accept total above 256 with a smaller healthy count. Reject negative, fractional, overflowing, inconsistent, and zero-healthy counts; reject negative or overflowing explicit indices while accepting index zero. Preserve exact integers in capture/replay and enforce DNS label length. One initial draw per scope, concurrent first callers agree, entropy failure blocks. Test separate provider instances/models without flaky statistical thresholds. |
| [Model identifier admission](#discovery-and-selection-ownership) | 4 | Test empty, 256-byte, 257-byte, multibyte, control-character, and large distinct identifiers after provider-prefix separation across normal inference, Explore, and standalone, including static/indexed routes. With discovery blocked, submit concurrent invalid names and cancel callers; assert 400 where applicable, zero reservations/workers/metadata calls/draws/retained names, and no supplied values in diagnostics. Already-canceled valid callers admit no new work. Valid canceled waiters retain only the bounded shared operation. |
| [Strict metadata](#discovery-and-selection-ownership) | 4 | Full invalid-input matrix above, body/count/state bounds, domain mismatch, redirects, 404, zero healthy, unknown model, duplicate model mapping, no fallback to canonical LB. |
| [Metadata reuse](#discovery-and-selection-ownership) | 4 | Concurrent initial count/discovery misses join one fetch. Advance time across multiple five-minute intervals and repeatedly use established routes: zero endpoint-list/count requests, including when discovery is unavailable or returns zero healthy. New models may refresh metadata; their refreshes cannot modify established routes. Failed required initial discovery blocks only the unresolved model. |
| [Metadata failure delay](#discovery-and-selection-ownership) | 4 | Use an injected clock. Repeated initial resolutions during the one-second delay return errors without another fetch or extending the delay; concurrent callers after it expires share one fetch. Cover endpoint-list errors, count errors, zero healthy, and successful initial recovery. Capacity rejection, caller cancellation, and shared operation cancellation must not install a delay. Repeated unknown models against a fresh list cause no fetch or retained per-name errors; only a later initial-resolution request after TTL expiry can refresh. Established routes never consult the delay. |
| [Metadata HTTP responses](#discovery-and-selection-ownership) | 4 | Exercise normal inference and Explore handlers. Wrapped capacity errors return 503 with `Retry-After: 1`; initial upstream metadata failures return 502; delayed requests return a distinct 503 with retry advice and no new work; unknown models return 400 without retry advice; acquired-snapshot expiry returns 503 without an internal retry or failure delay. Cover configuration mismatch, cancellation, and deadlines. Assert no inference bytes, authorization invalidation, or accidental per-name failure records. |
| [Metadata admission and cleanup](#discovery-and-selection-ownership) | 4 | At most 16 active count fetches across distinct authorities; an additional initial miss fails without queued work, while same-authority callers join. Pending records and initial route reservations count toward their bounds. Block each metadata fetch, repeatedly join and cancel callers, and assert one operation/completion channel with no retained waiter registrations or per-waiter workers. A remaining caller receives the single fetch result. Inspect operation state, not heap or global goroutine-count thresholds. Count-cache pressure evicts eligible completed records without changing acquired snapshots, active work, established routes, or authorizations. Active fetches and unexpired failure delays cannot be evicted; expired failures can. With a small injected capacity, cover LRU order, capacity rejection when all records are protected, additional count fetches only for later initial selections, and no reference tracking across discovery churn. All-waiter cancellation leaves one bounded owner operation; success converts its reservation to a route, while failure or timeout releases it once. Slots release exactly once. Shutdown rejects admission/publication and joins cleanup. Full retained-route capacity rejects new models without evicting established selections. |
| [Selection publication](#atomic-selection-publication) | 4 | Channel-controlled races cover discovery mapping removal, replacement, A-to-B-to-A, and newer count publication while initial selection holds fresh acquired snapshots: publication uses those snapshots and succeeds after full route validation. Expired snapshots, operation timeout, and shutdown prevent publication without internal retry. Block the injected selector outside the resolver lock and prove established routes and another model progress. Cancel all waiters, then finish the owner operation and verify one draw and one established route; failure releases the reservation. Release a canceled selector late and prove no state is recreated or replacement operation overwritten. Once established, a route survives all later discovery mapping/count changes without another draw. New-model discovery cannot replace an established route for another model. Already returned snapshots remain immutable. |
| [Count changes](#topology-changes-admission-and-retries) | 4 | Model growth, shrink below the selected index, zero backends then recovery, canonical mapping changes, and same-count replacement without rediscovery for established routes. Exercise upstream modulo routing in the TLS fixture: retain the SNI/index, authenticate every fresh peer, and re-attest only under the existing trust/key failure contracts. Placement need not remain balanced. Discovery changes encountered while adding a new model leave existing routes intact. |
| [Admission minimization](#topology-changes-admission-and-retries) | 4 direct; 5 cloud | Concurrent first wave fully verifies once per provider/model/index scope; later waves perform zero additional full attestations while authorization remains resident and valid. Repeat after metadata expiry, discovery refresh for a new model, evidence expiry, all idle connections closing, and new concurrent connections. Established direct routes make zero discovery requests throughout. Test normal and offline admission separately. |
| [Authorization eviction](#discovery-and-selection-ownership) | 4 | Use a small injected authorization capacity and establish more direct selections than it can retain. After eviction, concurrent requests retain the index with no random draw or discovery, despite expired metadata, and share one verification on the miss. Assert a new authorization generation, no reacquisition of the evicted generation, and unchanged other selections. Already acquired attempts keep their completion contract. Distinguish verification-invocation counts from full admission. |
| [Trust failure](#topology-changes-admission-and-retries) | 4 direct; 5 cloud | Different SPKI on the same indexed authority sends zero inference bytes, fails without retry, and conditionally removes only the used generation. Next request verifies fully; late failures cannot remove its replacement. |
| [Shared socket-budget progress](#attestation-connections-after-index-remapping) | 3 ownership/accounting; 4 reservation/recovery | Phase 3 tests production factory use, nested transport accounting, separate metadata budgets, and unchanged pooled capacity. Phase 4 tests the reservation and collateral recovery. Use a small shared limit of at least 2 through an HTTPS forward proxy with several origins. Fill the long-lived pooled share with idle sockets; it cannot consume the reserved fresh slot. A fresh pool completes a fetch before idle timeout without closing pooled sockets or active HTTP/2 streams. Count pooled-share and aggregate live sockets plus pending dials. Active fresh fetches can exhaust the aggregate limit; excess work fails immediately and a later fetch succeeds after physical close. Failed dials, cancellation, and shutdown release all acquired counters exactly once. Assert capture injection, unchanged production trust settings, and no retry, cooldown, or authorization invalidation on capacity rejection. After evidence retrieval, a required collateral cache miss with a full pooled share fails without authorization publication or negative caching; after controlled physical closure of an idle pooled socket, a later operation completes. |
| [Attestation-connection recovery](#attestation-connections-after-index-remapping) | 4 | Retain a connection to backend A while fresh connections for the same index reach B. After inference SPKI failure, the next full verification fetches through a fresh attestation connection to B on the same indexed route; later requests reuse B. Count production transport/parser verification calls and connections. Assert zero discovery, unchanged selection, cleanup, no replay, and zero inference bytes on failed handshakes. Late-A failures cannot remove B or affect other-authority streams. Test factory capture/replay injection and cancellation cleanup. Across fresh factories and the shared attestation client, use a small injected per-address socket budget; concurrent models, HTTP/2, retries, failed handshakes, cancellation, and shutdown cannot multiply the aggregate allowance. Count live sockets and pending dials, assert permit release exactly once, and preserve another operation's sockets when one fetch closes. |
| [Ordinary failures](#topology-changes-admission-and-retries) | 4 direct; 5 cloud | Direct dial retry stays on its snapshot. Cancellation, capacity exhaustion, I/O, 429, and generic 5xx do not change direct selection, trigger discovery, or cause full attestation. One backend outage cannot invalidate another authority or cancel unrelated HTTP/2 streams. No background fleet attestation. NearCloud generic image errors also retain authorization and create no cooldown or automatic verification. |
| [HTTP/2](#topology-changes-admission-and-retries) | 4 direct; 5 cloud | Multiple clients/models/providers retain identity isolation and multiplexing; closing one stream does not close peers; physical socket limits, caller deadlines, and shutdown remain effective. |
| [Configured routes](#route-resolution-and-configured-urls) | 4 | Exercise each configured-origin table row with initial discovery available and unavailable, including explicit port 443, non-default ports, static origins, invalid/ambiguous index syntax, model mismatch, and DNS label limits. Explicit indexed routes validate endpoint discovery once and never query count; static routes need neither. Reuse established configured routes after metadata expiry/outage without discovery. Proxy, standalone, and replay agree. |
| [Attestation representation](#representation-parsing) | 2 | Exercise both supported provider envelopes and reject every unsupported matrix row, including forbidden null/empty representations. Direct flat and single-array reports must agree in every field group; cloud validates every model entry and rejects duplicate models. Preserve byte equality for supported cryptographic encodings. Deterministic cases cover unknown, missing, duplicate, escaped-duplicate, and null nested fields in model and gateway info, TCB forms, and event entries. Validate duplicates inside decoded gateway event-log and both TCB strings, field paths, bounds, and complete typed comparisons. Test unknown-field acceptance under an explicit schema allowance, with diagnostics retained and additions excluded from verification inputs. Test production parser dispatch and signed-evidence fixtures; note capture staleness when current evidence is unavailable. |
| [Model-key binding](#model-key-binding-repair) | 1 E2EE; regress in 2; 5 cloud TLS-only | Replace the public key with another valid Ed25519 key in every repeated representation while retaining the signed quote, address, fingerprint, and nonce. Both providers reject binding; representation agreement does not make the substituted key authentic. Cover missing/invalid algorithms, 20-byte addresses, malformed keys, and key/address disagreement. E2EE admission rejects with factor allowances in Phase 1; NearCloud TLS-only proxy and standalone admission do so in Phase 5, with no authorization publication or inference bytes. Keep the gateway address scheme separate. |
| [Cloud preparation](#nearcloud-design) | 5 | Exactly one pin contains the acquired Ed25519 key as 64 lowercase hex characters. Uppercase evidence key text still passes byte binding and produces the same lowercase header; a substituted key still fails binding. Exercise a case-sensitive gateway key map and assert no false 421 or additional verification; arbitrary inbound pins cannot override it. TLS-only and encrypted requests, both chat modes, all supported preparation paths, and standalone use the same rule. NearCloud TLS-only admission rejects missing or failed REPORTDATA binding even with a factor allowance, publishes no authorization, and sends zero inference bytes. Successful binding retains the key without enabling encryption or reporting E2EE success. Direct requests do not acquire a gateway-specific pin. |
| [Mixed cloud keys](#nearcloud-findings-and-boundaries) | 5 | With affinity enabled and a matching populated group, attest A, send its pin, select A, and use real NEAR encryption successfully without re-attesting cached requests. With disabled affinity, empty maps, or unknown groups, model ignored hints and selection of B: B cannot decrypt A's protected fields, and an unauthenticated response fails closed without replay. Only exact supported pre-inference rejection permits retry. TLS-only success must not claim independently verified backend-key selection or E2EE success. Replacement key/header/session come from one generation while gateway pool reuse remains possible. |
| [Cloud 421](#explicit-stale-key-rejection) | 5 | Exact supported E2EE rejection retries once with full verification on a miss and a new session; repeated rejection stops. TLS-only exact rejection invalidates only the used generation without replay; the next request recovers through full verification on a miss. Concurrent late rejections cannot remove a replacement. Wrong status/type/message/path, duplicate/unknown/missing fields, oversize, and encrypted envelopes authorize neither new 421 invalidation nor replay. Generic TLS-only chat errors and existing chat 400 behavior remain unchanged. Generic image errors authorize neither invalidation nor replay. |
| [Cloud 421 optional fields](#explicit-stale-key-rejection) | 5 | Independently accept absent or null `param` and `code`. Reject non-null strings, numbers, booleans, arrays, and objects in either field, with no invalidation or replay in either encryption mode. Preserve existing 400 parsing tests. |
| [Standalone NEAR modes](#standalone-inference-mode-and-reporting) | 4 modes; 5 cloud routing/rejection | Exercise the production standalone streaming-chat entry point and confirm it sends no non-chat probe. An image-only model cannot acquire a successful inference result from a failed chat probe. Exercise the entry point with E2EE enabled and disabled. NearCloud TLS-only mode sends the authenticated routing header with no encryption headers or session; missing or failed binding blocks before inference even with an allowance. Success does not promote `e2ee_usable`; failures remain visible failed verification outcomes. Exact TLS-only chat 421 produces one attempt without replay or automatic re-attestation; a later invocation fetches new evidence. Output and capture/replay round trips preserve distinct TLS-only and E2EE success, failure, and skipped outcomes. |
| [Image errors and recovery limits](#image-errors-and-recovery-limits) | 5 | Through production proxy image handlers, repeat generic 404/500 errors with an unchanged valid key in both modes while other clients send valid same-model requests, another supported endpoint sharing authorization, and another model. Assert retained generations/pools, no cooldown, no additional verification, no replay, and continued valid traffic. Cover other generic statuses, malformed/oversized error bodies, read failures, and cancellation. Independently classified authentication failures still use existing invalidation/cooldown rules. Retire A while offering B and return only generic errors: failures remain visible and do not claim automatic recovery or select B. After an explicit test eviction, the next acquisition fully verifies before using B. Standalone remains chat-only; do not simulate a nonexistent production image probe. |
| [Direct E2EE boundaries](#assessment-requiring-neardirect-e2ee) | 4 | E2EE and TLS-only direct requests both block a changed SPKI before sending request bytes. Under an authorized TLS identity, an E2EE request to a backend without the authenticated model key cannot expose protected fields or accept unauthenticated encrypted-field responses. Audio remains rejected with E2EE enabled and requires attested TLS-only operation. Do not infer full-body or score-response E2EE coverage from the enabled flag. |
| [Capture/reports](#capture-configuration-and-route-records) | 4 direct; 5 cloud | Selected random route is reproducible from captured metadata; no fresh network/discovery/random choice on replay. Tampered route fields, invalid mode combinations, missing required metadata, and attestation URL/peer/report disagreement fail. Explicit canonical, indexed, and static captures exercise their distinct metadata requirements. Final retry evidence and nonce match the final report. |
| [Read-only report lookup](#report-lookup) | 4; regress in 5 | Test explicit and authority-free reads, cold lookup, selected route without a cached report, expired metadata, discovery outage, and topology changes. Cold lookup returns 404 without a route record. Existing cached reports remain readable without refresh, and later discovery cannot remove established routes. Concurrent authorization replacement/eviction does not change the copied lookup authority. Assert zero discovery, attestation, random draws, and authorization acquisitions; no selection, recency, or generation mutations. Cover discovered, explicit indexed, and static routes. |
| [Replay configuration](#capture-configuration-and-route-records) | 4; regress in 5 | Matching normalized configured origin and E2EE mode permit recorded-route validation. Changing either setting independently rejects before verification; missing settings are invalid. Cover TLS-only, E2EE, and skipped-inference captures, including an E2EE-mode mismatch when inference was skipped. Assert zero live inference and zero fresh random selection. Current verification policy still applies. |
| [Document discovery and image recovery limits](#phases-for-the-implementation-agent) | 4 discovery; 5 images | Transport README, retries, and testing docs prohibit recurring discovery for established routes and fleet-wide invalidation after an individual backend failure or key change, with linked tests. API support and provider/transport docs describe generic image errors retaining authorization, no replay or new cooldown, the remaining key-retirement recovery limitation, and the distinct upstream evidence required for a future recovery contract. Document standalone chat-only probe coverage. Prefer links to maintained explanations over duplicate policy text. |

Required final commands: `make check`, `make integration`, and `make reports`.
During development run the relevant packages with `go test -race`; retain the
repository's supported Go-version matrix. Live NEAR suites require API keys
and must use `-count=1`. Verify streaming/non-streaming E2EE and TLS-only direct
traffic, cloud chat with the hint, supported non-chat endpoints, and concurrent
multi-provider reuse. Do not weaken factors or declare a blocked suite passing.
Record provider-side failures and follow AGENTS.md if they prevent development.

## Deliberate limits and future work

- This change does not implement prompt/client affinity, throughput-driven
  reselection, per-request latency probes, or automatic cross-backend failover.
- Conversation affinity, including stateless rendezvous hashing, requires a
  separate design and implementation decision. It is not an acceptance
  requirement for this plan; existing Tinfoil affinity remains unchanged.
- A healthy count does not identify members or revoke approval; SPKI and E2EE
  checks remain authoritative for the connection and key used.
- NearCloud supplies conditional key-group affinity, not a stable physical
  index or independently enforced backend-key selection exposed to Teep.
  Controlled random physical placement there would need a supported
  gateway selector, or a separately designed combination of gateway and direct
  evidence. Do not invent that API or add extra direct attestations in this work.
- Non-chat cloud backend-index affinity needs upstream support. Existing
  encryption and failure behavior remain mandatory; document the limitation
  instead of assuming that sending a header makes those endpoints honor it.
- Do not copy cloud-api's permissive handling of unknown key groups, bootstrap
  fingerprints, fallback providers, or broad request retries into Teep.
