# Section 12 — Proof-of-Cloud Verification

## Scope

Audit Proof-of-Cloud (PoC) identity verification flow and its enforcement semantics.

Ensure that the code verifies that the machine ID from the model backend's attestation is covered in proof-of-cloud. The PoC protocol binds a hardware identity (derived from the TDX attestation's PCK certificate PPID) to a registry of known cloud machines, providing an independent signal that the attesting hardware is deployed by a legitimate cloud provider rather than an attacker-controlled machine.

The audit MUST also document whether Proof-of-Cloud is checked for the gateway CVM, or only for the model backend CVM, and whether a missing gateway PoC check is a residual risk.

## Primary Files

- [`internal/attestation/poc.go`](../../../internal/attestation/poc.go) — `PoCClient`, stage-1/stage-2 multisig protocol, `CheckQuote()`

## Secondary Context Files

- [`internal/attestation/report.go`](../../../internal/attestation/report.go) — `cpu_id_registry` factor evaluation
- [`internal/attestation/poc_test.go`](../../../internal/attestation/poc_test.go) — PoC protocol test cases
- [`internal/attestation/tdx.go`](../../../internal/attestation/tdx.go) — PPID extraction from PCK certificate chain

## Required Checks

### PoC Enforcement Factor

The PoC result is reported via the `cpu_id_registry` verification factor. Verify:
- `cpu_id_registry` IS in `NearcloudDefaultAllowFail` — PoC failure does not block traffic by default,
- this means PoC is currently **informational-only** (computed but non-blocking),
- document the rationale: PoC depends on external trust servers that may be unavailable,
- verify whether PoC can be promoted to enforced via the `[policy] enforce` TOML configuration.

### Machine Identity Derivation

Verify and report:
- the machine identity input is the **PPID** extracted from the PCK certificate in the TDX quote's certificate chain,
- PPID extraction occurs during TDX quote parsing — verify the PPID is passed from the TDX verification result into the PoC flow,
- the PPID uniquely identifies a physical Intel platform (not a VM or container),
- the full hex-encoded TDX quote is sent to the trust servers,
- when TDX parsing fails or PPID is unavailable, the `cpu_id_registry` factor reports `Skip`.

### Multi-Stage Protocol (Stage-1 and Stage-2)

#### Stage 1 — Nonce Collection

- The client POSTs `{"quote": hexQuote}` to each trust server's `/get_jwt` endpoint,
- Each trust server responds with `machineId`, `moniker`, and `nonce`,
- Nonces are collected from exactly `PoCQuorum` (3) peers,
- **HTTP 403** response is treated as "not whitelisted" — returns `Registered: false`,
- Missing `moniker` or `nonce` triggers an error.

Verify:
- that all 3 peers must respond successfully before proceeding,
- that the loop breaks after collecting quorum nonces,
- that the `moniker` → `nonce` mapping is correctly built.

#### Stage 2 — Chained Partial Signatures

- The client re-POSTs to each peer in order with accumulated `partial_sigs`,
- Final response contains the signed JWT,
- Intermediate responses contain partial signatures.

Verify:
- partial signatures are accumulated and forwarded in sequence,
- protocol fails if any peer returns an error (no partial-success),
- ordering is deterministic (same order as `PoCPeers` list),
- missing final JWT after all peers is treated as error.

### Trust Server Configuration

Verify:
- peer URLs are **not configurable** at runtime (hardcoded),
- quorum is 3-of-3 (not a threshold subset),
- trust servers operated by independent alliance members,
- TLS certificate verification for trust server connections uses the system trust store — assess sufficiency.

### Gateway PoC Gap

The audit MUST document:
- whether PoC is checked for the gateway CVM's PPID in addition to the model backend's,
- if PoC is NOT checked for the gateway, flag this as a residual risk and document its severity,
- whether the gateway and model backend could run on different physical machines (and therefore have different PPIDs),
- whether a compromised gateway running on attacker-controlled hardware would be detected by PoC if the model backend PoC passes.

### Behavior When PoC Backend is Unavailable

Verify:
- network errors return `PoCResult{Err: ...}` (not `Registered: false`),
- `cpu_id_registry` factor distinguishes between errors (`Skip`) and negative results (`Fail`),
- since PoC is non-enforced by default, failure does not block traffic — this is fail-open for PoC,
- document the residual risk.

### PoC JWT Verification

Verify:
- whether the JWT signature is cryptographically verified by the client, or accepted at face value,
- if verified, what public key or JWKS is used,
- if **not** verified, document as residual risk.

### Caching and Response Limits

Verify:
- whether PoC results are cached (per machine/PPID, per attestation, or not at all),
- response body size limits (`io.LimitReader` with 1 MiB),
- HTTP context propagation for cancellation.

### Future Expansion Items (Out of Scope)

Track separately — do NOT treat as present controls:
- DCEA integration,
- TPM quote integration,
- PoC v2 protocol changes.

## Best-Practice Audit Points

### Go (Golang) Best Practices

- **Context propagation**: `CheckQuote()` accepts `context.Context` and propagates through all HTTP calls.
- **Error wrapping**: Consistent `%w` wrapping with per-stage error messages.
- **JSON unmarshalling safety**: Malformed JSON from compromised trust server cannot cause panics.
- **Sequential HTTP calls**: No parallelization that could introduce races on `partialSigs`.

### Cryptography Best Practices

- **Threshold signature scheme**: 3-of-3 multisig with chained partial signatures. Verify order-dependence.
- **EdDSA JWT**: Assess whether client verifies the JWT's Ed25519 signature.
- **Nonce freshness**: Each trust server provides its own nonce in stage 1 for replay prevention.

### General Security Audit Practices

- **Trust server authentication**: HTTPS with standard TLS — assess whether pinning would strengthen.
- **Fail-open semantics**: Document as known trade-off between availability and security.
- **Trust server compromise**: Single compromised server can deny service; all 3 must cooperate for success.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. PoC flow summary with protocol description and trust assumptions,
3. enforcement classification for `cpu_id_registry` factor,
4. gateway PoC gap assessment (checked vs not checked for gateway CVM),
5. PoC JWT verification assessment,
6. trust server compromise impact analysis,
7. include at least one concrete positive control and one concrete negative/residual-risk observation,
8. source citations for all claims.
