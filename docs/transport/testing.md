# Transport verification and provider migrations

Transport tests must establish authentication before transmission, isolation
between concurrent clients, and bounded resource use. Use TLS test servers and
the production encryption and decryption paths. When production clients retain
system WebPKI roots, use `testtls.RunWithFallbackRoot` and
`authority.NewTLSServer`; do not weaken production trust configuration for
tests.

## Required scenarios

| Behavior to preserve | Representative coverage |
| --- | --- |
| Concurrent KDS retrieval uses TLS 1.3/HTTP2 and verifies signed evidence; retrieval failures are terminal | `TestTinfoilKDS`, `TestTinfoilKDSEmbeddedChains` in [Tinfoil KDS tests](../../internal/provider/tinfoil/kds_test.go) |
| Canceled discovery and capture collection do not race | `TestCanceledDiscoveryCapture` in [capture cancellation tests](../../internal/verify/capture_cancellation_test.go) |
| Standalone EHBP rejects encrypted provider error events and malformed data without exposing response content | `TestStandaloneEHBPStreamCompletion` in [EHBP completion tests](../../internal/verify/ehbp_completion_test.go) |
| Tinfoil report tests use separate model and authority parameters; explicit authority avoids discovery | `TestTinfoilIntegrationReportLookup` in [report lookup tests](../../internal/proxy/tinfoil_report_lookup_test.go) |
| Reject SPKI mismatch before sending request bytes; enforce CT and WebPKI | `TestSPKIPinnedClientRejectsBeforeSendingRequest`, `TestSPKIPinnedClientRejectsModifiedTrust` in [pinned tests](../../internal/tlsct/pinned_test.go) |
| HTTP/2 physical bounds, concurrent overload rejection, and recovery after stream completion | `TestHTTP2ConcurrentStreamConnectionBound` in [connection tests](../../internal/tlsct/http2_limits_test.go) |
| Independent pools share socket admission and capture; metadata retains an independent full allowance | `TestAttestationFactorySharedBudget`, `TestAttestationFactoryFullPooledAllowance` in [factory tests](../../internal/config/attestation_client_test.go) |
| Nested TLS transports consume the same socket allowance and release permits on cleanup | `TestNestedAttestationTransportSharesSocketBudget` in [shared budget tests](../../internal/tlsct/shared_budget_test.go) |
| HTTP/1.1 sequential reuse; closing one HTTP/2 stream preserves another | [Stream lifetime tests](../../internal/tlsct/stream_lifetime_test.go) |
| Provider, authority, and SPKI pool isolation | `TestAttestedPoolsRespectProviderAuthorityAndKey` in [pool tests](../../internal/proxy/tls_binding_internal_test.go) |
| Shared verification for the same authorization key, replacement generations, invalidation during verification, age-independent reuse, eviction, and blocked reports | [Authorization tests](../../internal/proxy/authorization_internal_test.go) |
| Caller deadlines stop waiting for a connection, buffered response processing, and downstream writes | [Authorization wait tests](../../internal/proxy/authorization_wait_test.go), [response lifetime tests](../../internal/proxy/response_lifetime_test.go) |
| Exact rejection recognition, duplicate-member rejection, bounded parsing, body ownership, and unsupported endpoints | [Rejection tests](../../internal/provider/key_rejection_test.go), [duplicate-member tests](../../internal/provider/key_rejection_duplicates_test.go) |
| Protocol failures do not cause replay after the transport consumes an encrypted POST body | `TestAuthorizedProtocolErrorNeverReplays` in [protocol tests](../../internal/proxy/http2_protocol_test.go) |
| Independent clients share HTTP/2 safely; a stale rejection cannot remove replacement authorization | [Authorized inference tests](../../internal/proxy/authorized_inference_test.go) |
| Cancellation retains authorization; the client authenticates encrypted errors; bodies close once; metrics remain separate for concurrent providers and models | [Failure and concurrency tests](../../internal/proxy/authorized_failure_test.go) |
| NEAR non-streaming read failures retain authorization; empty EHBP responses and partial frame headers fail without promoting E2EE success | [Response read failure tests](../../internal/proxy/authorized_read_failure_test.go) |
| Concurrent NEAR model misses retain distinct keys; old requests cannot delete or promote replacement generations | [NEAR authorization key tests](../../internal/proxy/authorization_near_keys_test.go) |
| Proxy and standalone request preparation and error authentication agree | [Preparation tests](../../internal/provider/inference_test.go), [standalone tests](../../internal/verify/e2ee_test.go) |
| Redirect targets receive zero requests; proxy omits `Location` | [Client redirect tests](../../internal/tlsct/redirect_test.go), [proxy redirect tests](../../internal/proxy/redirect_internal_test.go) |
| Environment proxy selection and connection setup budgets remain effective | [Common transport tests](../../internal/tlsct/pooled_test.go) |
| HTTPS proxies authenticate before CONNECT; origin pins reject before request transmission; HTTP/2 multiplexing and handshake budgets remain effective | [HTTPS proxy tests](../../internal/tlsct/pinned_proxy_test.go) |
| Explore uses common endpoint guards and accounting, isolates reports across concurrent providers/models, and does not claim E2EE when request encryption is disabled | [Explore authorization test](../../internal/proxy/explore_authorization_test.go) |
| The generic inference path rejects EHBP | [Generic encryption test](../../internal/proxy/generic_encryption_test.go) |
| NEAR completion rejects missing markers, provider errors, trailing data, and read failures while retaining missing finish reasons | `TestNearSSECompletion`, `TestStandaloneNearSSECompletion`, `TestAuthorizedNearCompletionRetainsAuthorization` |
| NRAS JWT validity allows exactly 10 seconds of leeway and failed claims do not refetch JWKS | `TestNVIDIAJWTLeeway` |
| SSE completion consumes trailing EHBP frames before reporting success | `TestAuthorizedEHBPStreamCompletion`, `TestStandaloneEHBPStreamCompletion`, and `TestReassembleSSECompletion` |
| SSE trailing-line limits account for CRLF, with conservative bounds for LF, CR, and unterminated lines | `TestFinishSSETrailingByteLimit` in [SSE completion tests](../../internal/e2ee/sse_completion_test.go) |
| Standalone capture retains discovery and final attempt evidence; successful and failed inference outcomes replay with signed Tinfoil evidence | `TestVerificationCaptureKeepsFinalEvidence`, `TestVerificationCaptureFinalOutcomeReplay` in [capture tests](../../internal/verify/capture_attempt_test.go) |
| Server cleanup closes provider clients; retry and capture wrappers forward cleanup | `TestServerCloseProviderConnections` and `TestAttestationClientCloseIdleConnections` |
| Concurrent report acquisition and promotion preserve ownership | `TestAuthorizationConcurrentReportOwnership` |
| Client cleanup reaches each wrapped connection pool | `TestWrappedClientClosesIdleConnections` in [transport tests](../../internal/tlsct/transport_test.go) |
| Concurrent NEAR clients and models use distinct backend keys and request content, separate provider pools, and fresh encryption sessions | [NEAR multiplexing tests](../../internal/proxy/near_http2_test.go) |
| Live NEAR attestation and inference use HTTP/2, the attested identity, sequential reuse, and overlapping encrypted requests | [NEAR HTTP/2 integration tests](../../internal/proxy/integration_near_http2_test.go) |
| Eviction uses recency, not authorization age; concurrent callers retain a recently used generation without re-attestation | `TestAuthorizationEvictionUsesRecency` in [eviction tests](../../internal/proxy/authorization_eviction_test.go) |
| HTTPS forward-proxy WebPKI and CT failures block requests without retry or origin authorization invalidation, including concurrent models and replacement generations | `TestAuthorizedHTTPSProxyFailureRetainsAuthorization` in [proxy failure tests](../../internal/proxy/authorized_proxy_failure_test.go), `TestPinnedHTTPSProxyRejectsTrustFailures`, and `TestOriginTrustFailureClassification` |
| Serve and verify share collateral retry policy; negative caching starts only after exhaustion of one shared verification's retries | `TestAuthorizationCollateralRetryPolicy`, `TestAuthorizationNegativeCacheAfterCollateralRetries` in [collateral retry tests](../../internal/proxy/collateral_retry_test.go) |
| Cold concurrent clients verify independent provider/model scopes concurrently; warm clients reuse them without extra attestation | `TestIntegration_ConcurrentProviders` in [concurrent provider integration](../../internal/proxy/integration_concurrent_providers_test.go) |

| Additional regression | Tests |
| --- | --- |
| TUF verification cancellation reaches headers, body reads, and subsequent downloads without canceling other operations | `TestTrustedRootVerificationCancellation` |
| Captured backend and gateway SEV evidence passes production verification | `TestVerifyRun_Tinfoil_Fixture` |
| Tinfoil delayed discovery callers reuse a newly published mapping | `TestDiscoveryDelayedRefresh` in Tinfoil |
| Established NEAR routes never refresh metadata; caller cancellation cannot cancel shared selection | `TestEstablishedSelectionSurvivesMetadataExpiry`, `TestSelectionWaiterCancellationAndShutdown` |
| Metadata failures delay new work without extending the delay; concurrent recovery shares one fetch; cancellation and capacity failures create no delay | `TestMetadataFailureDelayRecovery`, `TestMetadataCanceledAndCapacityFetchesDoNotDelayRecovery`, `TestMetadataOwnerCancellationDoesNotInstallDelay` |
| Inference and Explore preserve route error classifications, retry advice, and cached authorization under concurrent use | `TestRouteErrorResponsesPreserveAuthorization` |
| Standalone TLS-only probes retry only eligible connection-establishment failures, at most once | `TestStandaloneTLSOnlyConnectionRetry` |
| Fresh NEAR fetches use independent connections within reserved aggregate capacity | `TestDirectFetchOwnsFreshConnections`, `TestAttestationFactoryReservesFreshCapacity`, `TestReservedBudgetAcrossHTTPSProxyOrigins` |
| Concurrent key rejections run one shared full online re-attestation, create fresh retry sessions, and preserve replacement authorization against a delayed rejection | `TestIntegration_NearDirectKeyRecovery`, `TestIntegration_NearCloudKeyRecovery`, `TestIntegration_TinfoilKeyRecovery` |
| Router verification is shared across models while report outcomes remain separate and bounded | `TestAuthorizationRouterSharesVerificationAcrossModels`, `TestAuthorizationRouterModelViewsBounded` |
| Ordinary TLS-only key-error envelopes (excluding the exact NearCloud 421) retain authorization without retry under concurrent use | `TestAuthorizedTLSOnlyKeyErrorsRetainAuthorization` |
| Ambiguous rejection envelopes fail concurrent requests without replay or authorization invalidation | `TestAuthorizedDuplicateRejectionRetainsAuthorization` |
| NEAR discovery uses the injected client's transport and releases idle connections with owner cleanup | `TestAttesterDiscoveryUsesOwnedClient` |
| SEV report and certificate signature failures reject admission under concurrent verification | `TestSEVOnlineRequiresAuthenticatedEvidence` |
| Attestation and collateral socket overload returns 503/backoff without negative caching and permits subsequent verification | `TestAuthorizationAttestationCapacityRecovery`, `TestAuthorizationCollateralCapacityRecovery`, `TestAllowedCollateralCapacityFailure`, `TestCollateralCapacityNoRetry`, `TestSEVVerificationPreservesCapacityCause`, `TestTDXVerificationPreservesCapacityCause` |
| NEAR non-streaming reassembly bounds aggregate input and final content/tool-call output | `TestReassemblyInputLimit`, `TestReassemblyResponseLimit` |
| Non-streaming EHBP rejects oversize and bad trailing frames; speech keeps its media type | `TestAuthorizedEHBPResponseBoundary` |
| Explicit report authority selects only that cached scope without discovery | `TestAuthorizedReportLookup` |
| Malformed SSE retains authorization while authentication failures invalidate the used generation | `TestAuthorizedSSEFailureClassification` |
| Reassembly decrypts tool-call fields once through production NEAR cryptography | `TestReassemblyDecryptsToolCallsOnce` |

For each provider migration, add provider-specific coverage for route
discovery, the live attestation peer, separation of backend and gateway
identities where applicable, and supported endpoints. A shared transport test
does not prove that a provider supplies the correct identity or encryption
key. Positive integration cases must use the same factor policy as
`teep serve` and `teep verify`.

The shared proxy test server registers cleanup for both its inbound listener
and the proxy's owned outbound clients. NEAR E2EE endpoint integration tests
use online verification. Offline configurations in plaintext endpoint tests
exercise that explicit policy and do not establish online E2EE coverage.
Each main NEAR chat suite shares one proxy per policy across its subtests, so
successful requests can reuse authorization. The report subtest performs and
checks its own inference request even when a report is already cached. Cold
concurrent-provider and key-recovery tests retain separate proxy instances.

The concurrent provider live test starts with an empty authorization cache and
uses two discovered chat models per provider and independent streaming and
non-streaming clients. It checks one full verification per NEAR model scope
and one shared verification for the Tinfoil cloud router, then checks that a
second request wave retains each generation. The verification start barrier
also detects unintended serialization across independent scopes. These
assertions measure attestation reuse, not only inference success.

## Validation workflow

`make integration-concurrent-providers` runs the combined online test for
`nearcloud`, `neardirect`, and `tinfoil_v3_cloud`. It requires both
`NEARAI_API_KEY` and `TINFOIL_API_KEY`. Discovered models must pass current
factor enforcement; a provider-side attestation failure fails the test.

Run `make check` before committing. Transport and concurrency changes also
require `make integration`; major changes require `make reports`. Captured
fixtures provide deterministic provider verification, while live suites check
the deployed protocol. Live tests require their configured opt-in or API keys.
Live Makefile targets use `go test -count=1` so each invocation contacts the
provider; cached Go test successes must not stand in for live validation. Use
`-count=1` for direct live `go test` invocations too.
Do not weaken policy to make a provider pass. Record external failures and any
excluded suites in the PR rather than treating an incomplete run as success.

Run the transport, authorization, request preparation, and standalone tests
with the race detector on the minimum supported Go version and the other
versions in [CI](../../.github/workflows/ci.yml). The CI matrix is the
maintained version list. The same matrix checks upstream TDX certificate-time
rejection in [TDX admission tests](../../internal/attestation/tdx_admission_test.go)
and NRAS time claims in `TestNVIDIAJWTLeeway`.
`TestAuthorizationNRASAdmissionAndReuse` verifies publication-time rejection and
concurrent reuse after evidence expiration. Collateral-capacity tests retain
fail-closed error propagation.

For Go upgrades, explicitly retain tests of consumed POST errors, HTTP/2
stream saturation, physical socket accounting, connection waiting, and
cancellation. These protect assumptions about transport behavior that a
successful handshake or a single request cannot establish.

Update this reference when renaming or replacing tests. Keep assertions about
the required behavior. Remove checks for obsolete implementation details, such
as manual HTTP/1.1 writing or an independent SPKI cache.

`TestAuthorizedConnectionCapacityRetainsAuthorization` checks concurrent HTTP 503
responses without sending inference or invalidating shared authorization.
`TestRetryTransportRejectsCapacityWithoutRetry` and
`TestInferenceRetryClassification` exclude local capacity errors from retries.

## Recorded TLS evidence

Capture replay reconstructs `resp.TLS` from recorded peer SPKI data. A replayed
TLS-binding PASS tests consistency between that data and the signed evidence;
it does not prove a current handshake, WebPKI validation, CT validation, or
possession of the peer private key. Live TLS tests provide those checks. Missing
recorded peer data fails closed through the ordinary verifier.

`TestAuthorizedEHBPConcurrentHTTP2` exercises 64 simultaneous encrypted requests
on one HTTP/2 connection. `TestAuthorizedEncryptedErrors` checks authenticated errors and concurrent
acquisition during a failure cooldown. `TestAuthorizedEHBPPlaintextStatus`
checks non-2xx diagnostic status and bounded body passthrough without retry,
invalidation, or E2EE promotion, and rejects nonce-free 2xx responses.
`TestResponseFailureCooldownGeneration` checks that concurrent and late response
failures cannot extend a cooldown or remove replacement authorization.

`TestReportLookupDoesNotObserveModels` verifies that concurrent report queries
leave authorization recency and observed inference models unchanged, and return
independent report snapshots.

## NearCloud routing and stale keys

- `TestNearModelKeyConcurrentSessionReuse` checks that two models share their own immutable conversions across concurrent requests while session keys remain fresh and cross-model decryption fails.
- [Preparer tests](../../internal/provider/nearcloud/preparer_test.go) cover concurrent authenticated headers, canonical encoding, TLS-only preparation, and production encryption.
- [Admission tests](../../internal/proxy/authorization_near_keys_test.go) and [signed replay tests](../../internal/verify/near_capture_test.go) reject unbound TLS-only routing keys even with a factor allowance.
- [Stale-key tests](../../internal/proxy/nearcloud_stale_key_test.go) cover TLS-only invalidation without replay, late-generation isolation, and encrypted retries using an already-published replacement and fresh session.
- [Image policy tests](../../internal/proxy/nearcloud_image_policy_test.go) retain authorization and gateway connections across generic failures.
- [Mixed-key gateway tests](../../internal/proxy/nearcloud_affinity_test.go) exercise honored hints, disabled affinity, empty maps, and unknown groups with concurrent streaming and non-streaming clients. The production encryption path blocks decryption by the wrong backend key; unauthenticated responses fail without replay. TLS-only success does not establish E2EE success.
- `TestIntegration_NearCloudKeyRecovery` exercises the exact 421 envelope with full online verification and real encrypted recovery.

NearCloud positive replay uses the capture from 2026-09-10, whose recorded TLS
peer matches the reported fingerprint. The earlier capture from 2026-09-09 at
20:40:25 records a mismatch and is retained for
`TestReverifyRejectsCapturedGatewaySPKIMismatch` in
[reverify TLS tests](../../cmd/teep/reverify_tls_test.go). Production replay must
reject that evidence before inference; fixture tests do not waive TLS binding.
