# HTTP and TLS transport

This reference defines the transport requirements for provider implementations
and changes to shared HTTP clients. Read it with the security rules in
[AGENTS.md](../../AGENTS.md) and the
[attestation architecture](../../README_ADVANCED.md).

- [Retry contracts](retries.md): when the client may repeat an inference request.
- [Redirect policy](redirects.md): outbound clients and response handling.
- [Transport testing](testing.md): provider migrations and Go upgrades.

## Reuse goals

Reducing attestation overhead is a main goal of HTTP/2 support and the shared
authorization store. Reuse valid attestation results across requests and
preserve authenticated connections so concurrent clients can share them.
HTTP/2 multiplexing reduces connection setup and repeated TLS, certificate,
and CT checks. Authorization caching avoids repeated full attestation;
HTTP/2 alone does not change when attestation is required. Per-request
authorization checks and encryption remain required.

Connection lifetime and authorization lifetime are independent. One valid
authorization can cover multiple connections. A preserved connection can
serve successive authorizations when its attested transport identity remains
the same. Neither form of reuse requires new attestation while the authorized identity and required keys remain usable.

## Shared requirements

Every inference request must use a currently valid attestation for its
provider, model or route, cryptographic identity, and key epoch. On a cache
miss, the request handler must start or join verification. Failed enforced
factors block transmission. The existing explicit policy controls remain the
only exceptions; a transport change must not introduce an additional
exception.

Every inference TLS handshake requires TLS 1.3, system WebPKI validation, and
Certificate Transparency (CT) validation before the client sends request
bytes. For TLS-SPKI binding, the client must also compare the peer's SPKI with
the attested fingerprint during the handshake. A comparison after receiving
the response is too late to protect request data. SPKI comparisons use
constant-time operations. TLS-SPKI pools disable session resumption to ensure
that each handshake checks the attested peer identity.

For E2EE routes, every logical request must acquire a valid authorization that
binds the backend encryption key through attestation, including requests that
reuse relay TLS connections. A cached authorization satisfies this requirement;
the request does not need to perform full attestation again while it is valid.
Relay connection reuse does not extend the lifetime of a backend
authorization. NEAR cloud also attests its gateway: the gateway SPKI
identifies the TLS peer; the model backend fingerprint is separate evidence.

## Routes and authorizations

Resolve an immutable request route before verification or encryption. Do not
change a shared provider's endpoint while another request can use it.
Discovery must reject ambiguous model mappings. Authorization identity
includes provider, model, and route authority. Tinfoil cloud is the exception:
its evidence authenticates a model-independent router, so models share one
provider-and-authority authorization generation. Transport identity includes
the canonical HTTPS authority and attested SPKI.

Discovery refreshes share bounded work. A delayed caller rechecks whether a
fresh mapping was published after its initial lookup before starting another
refresh. A failed required refresh does not authorize use of a stale mapping.

The shared authorization store publishes the report, authenticated encryption
key, and transport identity together. Fully verify an uncached authorization.
Reuse it while its attested identity and required encryption keys remain usable,
until explicit invalidation, eviction, or process exit. Evidence expiration alone
does not trigger renewal. Do not maintain independent pin or key caches with
different lifetimes. This policy applies to TLS-binding providers in both normal
and `--offline` operation; other provider caches retain their existing behavior.

Fresh client nonce binding and all enforced verification factors remain admission
requirements. TDX uses the pinned upstream `github.com/google/go-tdx-guest` module.
TDX, SEV-SNP, and NVIDIA certificate verification retain their supported admission
checks, including certificate and online collateral validity. These dates do not
become cached authorization deadlines. The SEV retrieval path supplies VCEK
evidence only; missing VLEK material or a trusted ASVK fails closed.

Online NRAS JWT verification requires a valid signature and expiration claim,
with 10 seconds of clock skew for applicable time claims. Recheck successfully
verified NRAS time eligibility immediately before initial authorization
publication. Discard this transient admission metadata after publication; cache
hits and E2EE report promotion do not recheck it. Diagnostic expiration fields
retain the signed `exp`. Offline mode skips online verification under its existing
factor policy; it does not substitute a local TTL for those checks.

Concurrent requests for the same authorization join shared verification.
Tinfoil cloud shares verification, negative caching, and conditional
invalidation across models on the same router. Returned reports name the
requested model; successful E2EE outcomes remain specific to that model.
The store retains at most 1,000 model report views per router. Evicting a view
discards its diagnostic E2EE outcome without discarding router authorization
or triggering attestation.

The server owns the context for shared verification and limits its duration.
Cancellation of one waiting client does not cancel work needed by other
clients. Recheck NRAS admission time eligibility and invalidation before initial
publication. A stale
request may remove or update only the generation it used, never a replacement
published by another request. Tinfoil trusted-root metadata and target
downloads inherit the verification context, including response body reads.

The caller deadline limits each inference attempt.
This bound also applies while waiting for a connection, processing buffered
response data, and writing to the client. Response writers must support
`SetWriteDeadline`, either directly or through an `Unwrap` method that exposes
the HTTP server writer. A response that reaches its deadline cannot promote
the authorization report to E2EE success. Eviction prevents later acquisition
of the evicted authorization. Retire
only pools whose trust depends on the affected identity. Client cancellation
and ordinary I/O errors do not invalidate shared authorization; origin or
response authentication failures do. See
[the decision table](retries.md#retry-and-invalidation-decisions).

Implementation: [routes](../../internal/provider/route.go),
[authorization store](../../internal/proxy/authorization.go),
[route verification](../../internal/proxy/authorized_route.go), and
[transport identity](../../internal/tlsct/identity.go).

### Cached report selection

Report reads do not change authorization recency or the set of models observed
during inference.

`GET /v1/tee/report` requires `provider` and `model`. For a TLS-bound provider,
add `authority` with a host and optional port to select that exact cached
scope, for example `authority=backend.example:8443`. This lookup performs no
discovery or attestation and returns 404 when the authorization is absent,
evicted, or invalidated. Each parameter accepts one value; URLs, paths, and
credentials are invalid authority values.

Without `authority`, the proxy resolves the default route. Tinfoil direct
inference can select another backend from `prompt_cache_key`; use that
request's resolved authority to retrieve its report. The default lookup does
not identify which backend a previous sticky request selected.

### Response completion

Non-streaming HTTP 200 responses accept at most 10 MiB. NEAR chat reassembly
also bounds the encrypted SSE input to 32 MiB, including comments and framing.
This bounds accumulated content and tool arguments before final JSON encoding.
The relay reads one extra byte to distinguish an exact-limit response from truncation at the limit,
and fails
before reporting success if the response exceeds the bound or a required
frame cannot be authenticated. Oversize alone does not invalidate shared
authorization. Fully decrypted EHBP responses retain the upstream media type,
including audio responses.

### When full attestation repeats

For a stable provider, model, and authority, concurrent clients share a cached
authorization within one proxy server. Tinfoil cloud also shares it across
models on the same router authority. After the initial verification,
successful requests do not renew its lifetime or require full attestation.

Avoid full attestation when an existing authorization still covers the request.
At capacity, the cache evicts the least recently used authorization. Cache age
and evidence expiration do not cause eviction or background refresh.

| Event | Effect on attestation reuse |
|---|---|
| Previously verified evidence expires | Retain authorization. Certificate, collateral, and NRAS JWT expiration alone do not cause renewal, including after all connections close. |
| Routing selects an authority without a cached authorization | Full verification is required for that authority. A single model can use multiple authorities; Tinfoil direct can select different backends for different `prompt_cache_key` values. Discovery refresh with the same authority does not force renewal. |
| An origin TLS trust failure, recognized encryption-key rejection, or response authentication failure invalidates authorization | A subsequent attempt requires full verification. Invalidation applies only to the generation used by the failed request; retry eligibility follows the [retry contract](retries.md#retry-and-invalidation-decisions). |
| An HTTPS forward-proxy handshake fails | Fail the request without retry and retain origin authorization. No origin handshake occurred, so full origin attestation cannot repair the proxy failure. |
| Authorization is evicted, or a new proxy server starts | Full verification is required on a cache miss. Authorization caches are not shared across server instances. |
| Shared verification fails | After eligible collateral retries finish, a terminal verification failure can start the negative-cache delay. Intermediate retrieval failures must not start that delay. Cancellation of shared verification and local capacity errors do not create negative entries. |

Opening another connection for concurrency, reconnecting after idle timeout
or server closure, and closing or evicting a connection pool do not themselves
require full attestation. Each new TLS connection must pass the handshake
checks against the currently authorized identity. Ordinary network errors,
client cancellation, and local connection-capacity rejection retain valid
authorization. See the retry contract for error classification.

### Approval withdrawal

Cached authorization records approval at admission. Later vendor revocation or
expiration does not withdraw that approval automatically. A provider retaining
its keys, or an attacker holding those keys, can retain the old approval subject
to the remaining TLS and encryption checks. External supply-chain audits do not
by themselves invalidate running instances.

Maintainers publish an advisory when approval must be withdrawn. Operators,
package managers, or a future teep updater must deliver the corrected package or
policy and restart every affected instance. Restart clears cached authorizations;
the updated admission policy must reject the withdrawn state. Restart alone can
approve the same state again. Instances that do not receive the update and restart
can retain approval indefinitely. Teep currently has no advisory feed, updater,
live policy reload, or administrative authorization-withdrawal API.

## Connection reuse and resource limits

Prefer HTTP/2 multiplexing. HTTP/1.1 peers may reuse connections sequentially
under the same trust constraints. Do not set `Connection: close` per request;
HTTP/2 forbids the header. Closing one response stream must not terminate
other requests on its connection.

The pool registry selects pinned pools by provider, authority, and attested
SPKI. Models may share a pool only when that transport identity is the same;
each request still needs its own applicable authorization. A pool identified
only by hostname cannot distinguish attestation epochs. Keep mutable TLS
configuration separate for each provider.

Use the common transport and client constructors. The client constructors
install TLS, CT, and redirect policy; `NewPooledTransport` alone is not a
fully authenticated client. Environment proxy selection (`HTTPS_PROXY` and
`NO_PROXY`) remains enabled. A pinned client selects the proxy once for its
attested origin. For HTTPS proxies, a separate TLS configuration authenticates
the proxy with TLS 1.3, system WebPKI, and CT before CONNECT is sent. Go then
performs CONNECT and the origin TLS handshake, including the attested SPKI
check. Each TLS handshake has its own setup budget. Origin HTTP/2 pooling and
physical socket limits also apply through a proxy.

An outer proxy handshake failure retains origin authorization. Origin TLS
trust failures still conditionally invalidate the generation used by the
request. Neither failure permits inference replay.

The common transport separately bounds physical sockets because Go's HTTP/2
accounting can stop counting a live connection against `MaxConnsPerHost` when
the connection reaches its stream limit. Each socket holds its permit until
close. This is a resource bound, separate from authorization and stream
concurrency. A dial that cannot acquire a socket permit returns
`tlsct.ErrConnectionCapacity` immediately. Inference reports HTTP 503 with `Retry-After: 1`, retains
its authorization, and does not retry. Attestation clients also return this
local capacity error without retry. When an attestation fetch or a collateral
request exhausts socket capacity and prevents authorization, acquisition
preserves that error and returns the
same 503/backoff response without negative caching it. Intel PCS and AMD KDS
getters use the shared client's retry policy; they do not add another retry
loop. Online verification preserves fetch error causes that the certificate
libraries otherwise convert to text. Explicit factor
allowances and force mode retain their enforcement semantics. A later request
can attempt full verification as soon as capacity is available. Existing streams continue;
subsequent requests can reuse their connections when stream capacity becomes
available.
The one-second delay is backoff advice, not a prediction of available capacity.
Clients should respect it and use increasing delays with jitter for repeated
overload responses. [HTTP 503](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.6.4)
describes shared service capacity; [HTTP 429](https://www.rfc-editor.org/rfc/rfc6585.html#section-4)
would describe a client rate limit, which this transport does not impose.
HTTP/1.1 requests can still wait in Go's connection queue under their deadlines.

Do not enable `http.HTTP2Config.StrictMaxConcurrentRequests` as a substitute
for this overload handling. A local regression reproduced a reservation-count
deadlock in Go 1.26.0, 1.26.8, 1.27.0, and 1.27.1. In strict mode, queued
requests reserve a connection. The first waiter holds `reqHeaderMu` while
`awaitOpenSlotForStreamLocked` counts the other reservations as occupied
streams. Those requests cannot advance past that lock to release their
reservations, even after active streams finish. Non-strict mode permits
connection expansion; rejecting exhausted socket permits avoids a second wait
that stream completion cannot release. No Go or HTTP/2 dependency patch is
required. Reassess strict mode only with regression coverage for queued
requests resuming after active streams finish.

Each pool currently permits 16 physical connections per dial address and 10
idle connections per host. The idle timeout is 90 seconds. TCP dialing and TLS
handshakes each have a separate five-minute time limit. Shared full
verification admits 16 concurrent operations. These values are implementation
settings, not cryptographic guarantees or a global provider connection limit.
Earlier caller deadlines still apply. Change limits with the
corresponding concurrency tests. If a peer advertises 128 streams per connection,
16 connections provide a nominal 2,048 simultaneous streams per pool. This is
not an admission guarantee: retiring sockets, pending dials, and peer settings
can cause exhaustion earlier. Models sharing a pool share its capacity.
The inbound `max_conns` setting does not change these outbound limits.

Implementation: [common transport](../../internal/tlsct/pooled.go),
[physical socket limits](../../internal/tlsct/connection_budget.go),
[TLS clients](../../internal/tlsct/transport.go),
[pinned TLS checks](../../internal/tlsct/pinned.go),
[HTTPS proxy authentication](../../internal/tlsct/pinned_proxy.go), and
[pool management](../../internal/proxy/pinned_upstream.go).

## Request and response ownership

Proxy and standalone verification share request encryption, headers, framing,
caller deadlines, and session cleanup. Use
[`PrepareInference`](../../internal/provider/inference.go),
[`InferenceAttempt.Context`](../../internal/tlsct/inference_retry.go), and
[`ZeroSessions`](../../internal/e2ee/session.go) for each provider. Each retry
creates a fresh encryption session. Encrypted inference requests have
`GetBody == nil` to prevent transparent transport replay.

The attempt owner closes the original HTTP response body exactly once and
clears ephemeral session material on every exit path. A decryption reader has
its own cleanup; it must not replace the owned HTTP body. A parser that
consumes and closes a response body must install the replacement body before
returning, including on errors. Authenticate encrypted error responses before
interpreting their content. Never log request bodies, response bodies, or
encryption keys.

EHBP response EOF is valid only at a frame boundary after at least one
authenticated frame. Empty encrypted responses and partial frame headers fail
the request and cannot promote E2EE success. Transport read failures retain
authorization, including during NEAR non-streaming response reassembly;
cryptographic failures conditionally invalidate the generation used.
An SSE `[DONE]` marker does not establish EHBP frame completion. Streaming
relay, SSE reassembly, and standalone NEAR and EHBP verification read the remaining
stream through the same scanner before accepting completion. Only bounded
empty lines and comments may follow `[DONE]`. The 64 KiB budget counts each
scanned line plus two bytes for its possible CRLF terminator. This conservative
accounting also applies to LF, CR, and unterminated lines.
Trailing data, partial frames, authentication failures, and read failures
fail the request. The relay does not send `[DONE]` or promote E2EE success
until completion succeeds. The caller deadline also bounds this final read;
admission evidence timestamps do not limit an authorized response.

NEAR chat SSE requires `[DONE]`; clean HTTP EOF alone does not indicate a
complete response, even when a choice supplied `finish_reason`. A completed
response may omit `finish_reason`; non-stream reassembly retains its `stop`
default and preserves explicit reasons such as `length` and `tool_calls`.
Provider error events fail response processing even if valid encrypted content
preceded them and `[DONE]` follows them. Reassembly must not drop the error and
return a successful partial response. These protocol and provider failures do
not authorize replay or invalidate attestation; the next request can reuse the
same valid authorization. This NEAR marker requirement does not add a marker
requirement to EHBP or other protocols.

Metrics and reports must describe the route and authorization the request
used. Explore uses the same endpoint handler for request normalization, guards,
request counters, and active request gauges. Accumulate phase durations across
attempts and include the resolved authority in model metrics. Do not perform another discovery or authorization
lookup solely to label the completed request.

Callers that embed the proxy in another HTTP server must call `Server.Close`
to cancel shared verification and close idle inference, attestation, model
discovery, endpoint discovery, and nonce-fetch connections. Provider components
forward cleanup to their owned clients and resolvers, including wrapped model
listers. Active inference streams may finish under their existing deadlines.
Configure injected clients before concurrent use or cleanup.

Transport wrappers, including retry and capture wrappers, must forward
`CloseIdleConnections` to their underlying pools so client cleanup remains
effective. Standalone verification closes clients it creates; callers retain
ownership of injected clients. Per-operation Sigstore clients also close
idle connections when verification ends.
NEAR direct attestation and endpoint discovery share the injected client, so
standalone client cleanup also closes idle discovery connections. Discovery
requests use that client's transport wrappers, including capture and replay.

Standalone capture retains the original route-discovery responses and the
final attestation attempt, with its nonce and inference test outcome. A
retry after key rejection uses a new client nonce and replaces the recorded evidence;
it does not resolve the route again. Replay therefore cannot select evidence
from the rejected key's attempt, including collateral fetched at the same URL.
Capture self-check verifies the saved final report, including inference errors.
Capture collection takes synchronized snapshots of completed exchanges. A
canceled discovery caller can collect a partial capture while detached
discovery finishes; that operation must not race with capture collection.

## Current provider coverage

| Providers | Channel binding | Authorization and inference path |
| --- | --- | --- |
| NEAR direct | Attested TLS SPKI and NEAR request encryption | Immutable route, atomic authorization, shared pinned HTTP transport |
| NEAR cloud | Attested gateway TLS SPKI plus backend encryption key | Immutable gateway route, gateway and backend verification, atomic authorization, shared pinned HTTP transport |
| Tinfoil direct and cloud | Attested TLS SPKI and EHBP encryption key | Immutable route, atomic authorization, shared pinned HTTP transport |
| Other providers | Provider-specific attestation and E2EE mechanisms | Existing generic verification and cache path; does not use the atomic authorization implementation above |

EHBP request and response handling belongs to the authorized inference path;
the generic path rejects streaming request encryption.

TLS-binding providers use the authorized inference path, which selects a pinned
pool from the acquired authorization's transport identity. The generic send
path serves providers without TLS binding and has no separate pin lookup or
TLS-binding invalidation path. The handshake authenticates the SPKI; response
handling does not repeat that check after transmission.

All providers must satisfy the shared requirements. For a provider migration,
identify its TLS peer, backend key, route scope, and admission checks first.
Reuse the shared implementation where those contracts apply. Add a
provider-specific behavior only with an explicit contract and regression
coverage. Update these documents and their linked tests in the same change as
any transport behavior change.
