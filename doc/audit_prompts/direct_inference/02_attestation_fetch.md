# Section 02 — Attestation Fetch, Parsing & Nonce Freshness

## Scope

Audit attestation retrieval, response parsing, model entry selection, and nonce freshness/replay resistance.

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
- fail-closed behavior if randomness source fails,
- constant-time nonce equality checks,
- nonce origin is exclusively client/proxy-generated and not server-influenced.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. parse-path and nonce-check classification by enforcement mode,
3. clear replay-resistance conclusion,
4. include at least one concrete positive control and one concrete negative/residual-risk observation,
5. source citations for all claims.
