# Section 02 — Attestation Fetch, Parsing & Nonce Freshness

## Scope

Audit attestation retrieval, response parsing, model entry selection, and nonce freshness/replay resistance.

Upon connection to the model server, the attestation API of this model server MUST be queried and fully validated before any inference request is sent to the model server.

Certificate Transparency MUST be consulted for the TLS certificate of this model endpoint. This CT log report SHOULD be cached.

The attestation information is provided by an API endpoint as a JSON object that includes the Intel TEE attestation, NVIDIA TEE attestation, and auxiliary information such as docker compose contents and event log metadata.

## Primary Files

- [`internal/provider/nearai/nearai.go`](../../../internal/provider/nearai/nearai.go)
- [`internal/attestation/attestation.go`](../../../internal/attestation/attestation.go)
- [`internal/jsonstrict/unmarshal.go`](../../../internal/jsonstrict/unmarshal.go)

## Secondary Context Files

- [`internal/provider/venice/venice.go`](../../../internal/provider/venice/venice.go)
- [`internal/tlsct/checker.go`](../../../internal/tlsct/checker.go)

## Required Checks

Verify and report:
- attestation response body size bounds,
- strict JSON unmarshalling behavior for unknown fields,
- unknown-field warning behavior (dedup/rate-limit vs noisy logging),
- support for polymorphic formats (flat object vs arrays),
- explicit bounds checks on array lengths (e.g., model/all attestations),
- model selection logic when multiple attestation entries exist,
- failure behavior when no model match is found,
- malformed nested element handling (fail-whole-response vs element drop),
- whether provider-asserted "verified" booleans are ignored unless independently verified,
- endpoint CT checks for attestation endpoint certificates and any caching behavior.

For nonce handling, verify:
- fresh cryptographic 32-byte nonce generation per attempt,
- fail-closed behavior if randomness source fails (the recommended behavior is to panic or abort — never fall back to a weaker entropy source),
- constant-time nonce equality checks,
- that the nonce is transmitted to the attestation endpoint by the proxy, not delegated to the server — the nonce MUST originate solely from the client and not be sourced from or influenced by the server response.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. parse-path and nonce-check classification by enforcement mode,
3. clear replay-resistance conclusion,
4. include at least one concrete positive control and one concrete negative/residual-risk observation,
5. source citations for all claims.
