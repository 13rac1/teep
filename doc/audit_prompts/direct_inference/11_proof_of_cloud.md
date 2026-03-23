# Section 11 — Proof-of-Cloud Verification

## Scope

Audit Proof-of-Cloud (PoC) identity verification flow and its enforcement semantics.

Ensure that the code verifies that the machine ID from the attestation is covered in proof-of-cloud. The PoC protocol binds a hardware identity (derived from the TDX attestation's PCK certificate PPID) to a registry of known cloud machines, providing an independent signal that the attesting hardware is deployed by a legitimate cloud provider rather than an attacker-controlled machine.

## Primary Files

- [`internal/attestation/poc.go`](../../../internal/attestation/poc.go) — `PoCClient`, stage-1/stage-2 multisig protocol, `CheckQuote()`

## Secondary Context Files

- [`internal/attestation/report.go`](../../../internal/attestation/report.go) — `cpu_id_registry` factor evaluation (lines 522–545)
- [`internal/attestation/poc_test.go`](../../../internal/attestation/poc_test.go) — PoC protocol test cases
- [`internal/attestation/tdx.go`](../../../internal/attestation/tdx.go) — PPID extraction from PCK certificate chain

## Required Checks

### PoC Enforcement Factor

The PoC result is reported via the [`cpu_id_registry`](../../../internal/attestation/report.go:522) verification factor. Verify:
- `cpu_id_registry` is **not** in [`DefaultEnforced`](../../../internal/attestation/report.go:76) — PoC failure does not block traffic by default,
- this means PoC is currently **informational-only** (computed but non-blocking),
- document the rationale: PoC depends on external trust servers that may be unavailable — making it enforced would cause outages when trust servers are down,
- verify whether PoC can be promoted to enforced via the `[policy] enforce` TOML configuration.

### Machine Identity Derivation

Verify and report:
- the machine identity input is the **PPID** (Platform Provisioning ID) extracted from the PCK (Provisioning Certification Key) certificate in the TDX quote's certificate chain,
- PPID extraction occurs during TDX quote parsing — verify the PPID is passed from the TDX verification result into the PoC flow,
- the PPID uniquely identifies a physical Intel platform (not a VM or container),
- the full hex-encoded TDX quote (`hexQuote`) is sent to the trust servers — verify this is the raw Intel quote, not a processed/trimmed version,
- when TDX parsing fails or PPID is unavailable, the `cpu_id_registry` factor reports `Skip` with the PPID status.

### Multi-Stage Protocol (Stage-1 and Stage-2)

The PoC protocol is a two-stage threshold multisig operation implemented in [`CheckQuote()`](../../../internal/attestation/poc.go:67):

#### Stage 1 — Nonce Collection

- The client POSTs `{"quote": hexQuote}` to each trust server's `/get_jwt` endpoint,
- Each trust server responds with a [`stage1Response`](../../../internal/attestation/poc.go:51) containing `machineId`, `moniker`, and `nonce`,
- Nonces are collected from exactly [`PoCQuorum`](../../../internal/attestation/poc.go:25) (3) peers,
- **HTTP 403** response is treated as "not whitelisted" — returns `Registered: false` immediately,
- Missing `moniker` or `nonce` in the response triggers an error return.

Verify:
- that all 3 peers must respond successfully before proceeding (not best-effort quorum),
- that the loop breaks after collecting `quorum` nonces (potential issue if fewer peers are available),
- that the `moniker` → `nonce` mapping is correctly built from collected responses.

#### Stage 2 — Chained Partial Signatures

- The client re-POSTs to each peer in order, including the full `nonces` map and accumulated `partial_sigs`,
- Each peer returns either partial signatures (intermediate signers) or the final JWT (last signer),
- The final response contains [`stage2Response`](../../../internal/attestation/poc.go:58) with `machineId`, `label`, and the signed `jwt`,
- Intermediate responses are a flat `map[string]string` of `moniker → partial_sig`.

Verify:
- that partial signatures from each peer are accumulated and forwarded to the next peer in sequence,
- that the protocol fails if any peer returns an error during stage 2 (no partial-success mode),
- that the ordering of peers in the chain is deterministic (same order as `PoCPeers` list),
- that a missing final JWT after all peers have been queried is treated as an error.

### Trust Server Configuration

The trust server peer list is hardcoded in [`PoCPeers`](../../../internal/attestation/poc.go:18):
```
https://trust-server.scrtlabs.com
https://trust-server.nillion.network
https://trust-server.iex.ec
```

Verify:
- these URLs are **not configurable** at runtime (no TOML or env var override),
- the quorum requirement is [`PoCQuorum = 3`](../../../internal/attestation/poc.go:25) (3-of-3, not a threshold subset),
- the trust servers are operated by independent alliance members (Secret Network, Nillion, iExec),
- TLS certificate verification for trust server connections uses the system trust store (standard Go `http.Client` behavior) — assess whether this is sufficient or whether trust server TLS should be pinned.

### Behavior When PoC Backend is Unavailable

Verify:
- network errors during stage 1 or stage 2 return `PoCResult{Err: ...}` (not `Registered: false`),
- the [`cpu_id_registry`](../../../internal/attestation/report.go:525) factor distinguishes between errors (`Skip` with error detail) and negative results (`Fail` with registration guidance),
- since `cpu_id_registry` is non-enforced by default, PoC failure does not block traffic — this is a **fail-open** posture for PoC,
- document the residual risk: when trust servers are down, PoC provides no assurance, and traffic proceeds without hardware identity verification.

### Caching Behavior for PoC Results

Verify and report:
- whether PoC results are cached (per machine/PPID, per attestation, or not at all),
- under what conditions PoC is re-queried (every attestation, only on PPID change, or periodic refresh),
- if uncached, note the latency impact of 3 sequential HTTP round-trips per attestation.

### PoC JWT Verification

The final trust server returns a signed EdDSA JWT. Verify:
- whether the JWT signature is cryptographically verified by the client, or simply accepted at face value,
- if verified, what public key or JWKS is used,
- if **not** verified, document this as a residual risk — the JWT could be forged by any intermediary,
- the JWT is stored in [`PoCResult.JWT`](../../../internal/attestation/poc.go:34) — verify whether it is logged, persisted, or only used transiently.

### Relationship to Overall Attestation Chain

The PoC verification provides a complementary signal to the TDX attestation:
- **TDX attestation** proves the software is running in a genuine TEE with specific measurements,
- **PoC** proves the physical hardware is registered with known cloud providers,
- Together, they establish that the attesting machine is both genuine Intel TEE hardware AND deployed in a recognized cloud environment,
- **Without PoC**, an attacker could set up their own TDX-capable hardware (e.g., purchased Intel server) and present a valid TDX attestation — PoC mitigates this threat.

### Response Size and Resource Limits

Verify:
- [`postJSON()`](../../../internal/attestation/poc.go:175) uses [`io.LimitReader(resp.Body, 1<<20)`](../../../internal/attestation/poc.go:194) (1 MiB max) for response body reading,
- this applies to both stage-1 and stage-2 responses,
- verify that the limit is appropriate for expected response sizes.

### Future Expansion Items (Out of Scope)

Track separately — do NOT treat as present controls:
- DCEA (Data Center Enclave Attestation) integration,
- TPM quote integration,
- PoC v2 protocol changes,
- additional cloud provider registries.

## Best-Practice Audit Points

### Go (Golang) Best Practices

- **Context propagation**: [`CheckQuote()`](../../../internal/attestation/poc.go:67) accepts a `context.Context` and passes it to [`postJSON()`](../../../internal/attestation/poc.go:175) via `http.NewRequestWithContext`. Verify that caller-supplied deadlines and cancellation signals propagate correctly through all 3+ HTTP calls in the protocol.
- **Error wrapping**: PoC errors use `fmt.Errorf("stage 1 POST to %s: %w", peer, err)` with `%w` wrapping. Verify this is consistent and enables callers to distinguish network errors from protocol errors.
- **JSON unmarshalling on untrusted input**: Stage-1 and stage-2 responses are parsed with `json.Unmarshal` from trust server responses. Verify that malformed JSON from a compromised trust server cannot cause panics or excessive memory allocation.
- **Sequential HTTP calls**: The protocol makes 3 stage-1 calls followed by 3 stage-2 calls (6 total). Verify there is no parallelization that could introduce race conditions on the `partialSigs` accumulator.

### Cryptography Best Practices

- **Threshold signature scheme**: The protocol uses a 3-of-3 multisig with chained partial signatures. Verify that the partial signature accumulation is order-dependent (signer 1 → signer 2 → signer 3) and that a replay of partial signatures from a different quote is not possible.
- **EdDSA JWT from final signer**: Assess whether the client verifies the JWT's Ed25519 signature or trusts it based on transport security (TLS) alone. If not verified, any MITM on the final trust server connection could forge the JWT.
- **Nonce freshness**: Each trust server provides its own nonce in stage 1. Verify these nonces are used to prevent replay of the PoC registration check — a stale PoC result should not be re-presentable.

### General Security Audit Practices

- **Trust server authentication**: The client connects to trust servers via HTTPS with standard TLS. Assess whether certificate pinning for trust server endpoints would strengthen the protocol (currently, a CA-level compromise could MITM the PoC flow).
- **Fail-open semantics**: PoC is non-enforced by default, meaning trust server outages silently degrade security. Document this as a known trade-off between availability and security assurance.
- **Input validation on hex quote**: The `hexQuote` string sent to trust servers originates from the TDX quote. Verify it is properly hex-encoded and bounded in length before being embedded in JSON and posted to external servers.
- **Trust server compromise**: If one or more trust servers are compromised, assess the impact:
  - A single compromised server can withhold its nonce (denial of service) or provide a malicious partial signature (protocol failure),
  - All 3 must cooperate for a successful registration result — this is a strength of the 3-of-3 scheme (but also a liveness weakness).

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. PoC flow summary with stage-1/stage-2 protocol description and trust assumptions,
3. enforcement classification for `cpu_id_registry` factor (expected: non-enforced/informational),
4. PoC JWT verification assessment (verified vs trust-on-TLS),
5. trust server compromise impact analysis,
6. include at least one concrete positive control and one concrete negative/residual-risk observation,
7. source citations for all claims.
