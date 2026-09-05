# Outbound redirect policy

Teep HTTP clients return 3xx responses without requesting the redirect target.
The policy includes redirects to the same authority. Fetch callers reject
these responses. Proxy inference returns HTTP 502 without copying the upstream
`Location` header. A redirect does not authorize inference replay.

Redirect following belongs to the client constructor; status handling belongs
to the caller. These are different responsibilities: stopping the client from
following a redirect must not expose that redirect to an API consumer.

## Policy ownership

| Client | Construction or policy owner | Response handling |
| --- | --- | --- |
| Attestation, discovery, model listing, NRAS, JWKS, Proof of Cloud, Rekor, GitHub releases | `tlsct.NewHTTPClient` or `tlsct.NewHTTPClientWithTransport` | Fetch callers reject non-success statuses |
| Pinned inference | `tlsct.NewSPKIPinnedHTTPClientWithTransport`, through the common constructor | Authorized attempt closes rejected responses; proxy returns an error |
| Ordinary inference | Common Teep client constructor | Proxy rejects redirects before copying response headers |
| CT log list retrieval | `tlsct.NewChecker` | Fetch requires HTTP 200 |
| Capture replay | `verify.Replay` client | Same redirect policy as network clients |
| AMD KDS | Attestation client's separate TLS 1.2 transport | SEV getter rejects statuses of 300 or greater |

AMD KDS is a collateral retrieval exception to the common TLS version setting;
it is not an inference transport exception.

## Clients created by dependencies

`sigstore-go` uses the `go-tuf` fetcher to retrieve its trusted root. Teep
supplies a separate Teep client that enforces CT through `WithFetcher`. TUF
retrieval remains independent of attestation capture and replay. Teep does not
modify a global HTTP client.

The Google TDX and SEV verification packages expose default HTTP getters, but
Teep supplies its own collateral and certificate getters. They use the
supplied Teep client and reject redirects. NVIDIA JWKS retrieval also uses the
supplied client; the keyfunc dependency receives already retrieved keys.

When adding a dependency that performs network requests, inspect its client
construction and supply a client that enforces the Teep policy. Configuring
only the provider's main client is insufficient when the dependency creates
another client internally.

Implementation: [redirect helpers](../../internal/tlsct/redirect.go),
[client constructors](../../internal/tlsct/transport.go), and
[authorized inference](../../internal/proxy/authorized_inference.go). Tests:
[outbound clients](../../internal/tlsct/redirect_test.go) and
[inference responses](../../internal/proxy/redirect_internal_test.go).
