# Proof of Cloud Registry: JWT Expiration Missing

**Date:** 2026-04-06
**Updated:** 2026-04-10
**Status:** Partially mitigated — teep validates `timestamp` freshness; PoC `exp` enhancement pending

The Proof of Cloud (PoC) hardware identity registry — teep's primary defense-in-depth layer against [TEE.fail](https://tee.fail/) attestation key extraction attacks — is functional for hardware identity verification. This report documents a remaining gap in the PoC protocol: the trust-server JWTs do not include an `exp` (expiration) claim. Teep works around this by enforcing a ±10 minute freshness window on the JWT's `timestamp` claim, but this is a workaround with significant operational consequences. The proper fix is for the PoC alliance to add `exp` to their JWT payloads.

## The Problem

Proof of Cloud is a vendor-neutral alliance that maintains a registry mapping hardware IDs to verified physical data centers. Teep queries this registry to confirm that the hardware running an inference workload is located in a known, secured facility. This check is the primary mitigation for [TEE.fail](https://tee.fail/) attacks, where an attacker extracts TEE attestation signing keys via DDR5 memory bus interposition and forges attestation quotes on unauthorized hardware.

The registry check uses a three-party multisig protocol: teep contacts three independent trust servers, each operated by a different alliance member, and they collaboratively produce a signed JWT confirming the hardware's registration status. All three servers must participate — there is no threshold or fallback.

**The gap:** The PoC trust-server JWTs do not include an `exp` (expiration) claim. Without it, teep cannot cache verified JWTs — the PoC quorum never commits to how long a registration token should be trusted. Teep works around this by treating the JWT's `timestamp` claim (the time the quote was processed) as a freshness bound, rejecting tokens more than 10 minutes old. This closes the replay window but forces a full 3-server multisig round trip on every request, amplifying the protocol's 3-of-3 fragility.

## Impact

### Compensating controls present

Before assessing the security impact, it is important to document the mechanisms that DO provide freshness in the current protocol:

- **Stage 1 whitelist check (HTTP 403):** When hardware is sold, decommissioned, or unenrolled from the PoC registry, the trust servers will return HTTP 403 at Stage 1, before any JWT is issued. Teep reports `Fail` (`Registered: false`). This correctly handles the "machine changes hands" scenario — an attacker cannot replay an old JWT for hardware that has been decommissioned, because no JWT will be issued for that hardware in the first place.
- **`timestamp` freshness (teep-side workaround):** Teep enforces a ±10 minute window on the JWT's `timestamp` claim. An attacker who captures a valid JWT cannot replay it more than 10 minutes later. This closes the active replay window for currently-enrolled hardware.
- **`quote_hash` binding:** The JWT includes a hash of the submitted TDX quote. A captured JWT cannot be presented alongside a different quote.

### Security impact

Given the above compensating controls, the security impact of missing `exp` is narrower than it first appears:

- **The primary gap is a missing protocol commitment, not an exploitable replay vulnerability.** Teep's `timestamp` workaround is unilateral — the signed JWT payload contains no expiry assertion from the quorum. If a future teep version removes the workaround, or a consumer verifies the JWT without it, there is no protocol-level defense.
- **Signing key rotation is unknown.** If the PoC alliance rotates its signing keys on a published schedule (e.g., monthly), any captured JWT becomes invalid at the next rotation regardless of `exp`. If keys are never rotated, a captured JWT — absent the `timestamp` workaround — would be valid indefinitely. The alliance has not published a key rotation policy.
- **The Stage 1 nonce does not appear in the final JWT.** It is used to bind partial signatures during Stage 2 chaining but is not validated by teep in the final JWT payload, so it does not contribute to freshness.

### Operational impact (primary consequence)

- **JWTs cannot be cached.** Because there is no `exp` in the JWT, teep must complete the full 3-server multisig protocol on every attested request. A single peer being unavailable causes the entire check to fail for that request.
- **The 3-of-3 quorum is a per-request dependency.** Without caching, any transient unavailability of a trust server fails every incoming request until the server recovers.
- **Both factors are in `DefaultAllowFail`.** `cpu_id_registry` and `gateway_cpu_id_registry` are non-enforced, so this does not block inference requests — but the PoC check is degraded to a best-effort operation rather than a reliable control.

## Current Status

| Teep factor | Status | Detail |
|---|---|---|
| `cpu_id_registry` | **Pass** for registered hardware; **Fail** for unregistered | Registered: "Proof of Cloud: registered (label)". Unregistered: Stage 1 HTTP 403 / `Registered: false`. |
| `gateway_cpu_id_registry` | **Pass** for registered gateway hardware | Same (NearCloud gateway only) |

Teep accepts PoC JWTs without `exp` and logs at DEBUG. When `exp` is present, teep enforces it.

---

## Technical Background

### Proof of Cloud protocol

The PoC registry check uses a two-stage multisig protocol with three hardcoded trust servers:

| Peer | Operator | URL |
|---|---|---|
| 1 | iExec | `https://trust-server.iex.ec` |
| 2 | Nillion | `https://trust-server.nillion.network` |
| 3 | Secret Network | `https://trust-server.scrtlabs.com` |

**Quorum:** 3-of-3 (all must cooperate). There is no threshold — a single peer failure kills the entire check.

**Stage 1 — Nonce collection (parallel):** Teep sends the raw TDX quote to all three peers simultaneously. Each peer responds with a `machineId`, `moniker`, and `nonce`. If any peer returns HTTP 403, the hardware is not whitelisted and the check ends immediately with `Registered: false`.

**Stage 2 — Chained partial signatures (sequential):** Teep visits peers in **sorted URL order** (iex.ec → nillion.network → scrtlabs.com), forwarding accumulated partial signatures at each step. The final peer (scrtlabs.com, always last alphabetically) returns the completed JWT.

### Freshness mechanisms in the PoC protocol

| Mechanism | Present? | Notes |
|---|---|---|
| `exp` claim in JWT | **No** | Absent from trust-server payload construction |
| `timestamp` claim | Yes (teep workaround) | Teep enforces ±10 min; not a quorum commitment |
| `quote_hash` binding | Yes | Binds JWT to a specific TDX quote, not to time |
| Stage 1 nonce | Yes (partial) | Used to bind chained partial signatures in Stage 2; not validated in the final JWT payload by teep |
| Signing key rotation | **Unknown** | PoC alliance has not published a key rotation schedule or policy |
| Stage 1 whitelist (HTTP 403) | Yes | Handles decommissioned/unenrolled hardware before JWT issuance |

The Stage 1 whitelist check is the primary freshness control for the "machine changes hands" threat model — it prevents a JWT from being issued for hardware that is no longer registered. The `timestamp` workaround prevents replay of captured JWTs within the current 10-minute window.

### JWT validation

Teep validates the final JWT before accepting it ([`poc.go:verifyPoCJWTClaims`](../../internal/attestation/poc.go)):

1. JWT must have exactly 3 dot-separated parts (header.payload.signature)
2. `quote_hash` claim must equal `hex(sha256(binary_quote))` — binds the JWT to the specific TDX quote (fail closed if absent)
3. `timestamp` claim must be within ±10 minutes of now — freshness workaround for missing `exp` (fail closed if absent)
4. If `exp` claim is present, it must not be expired (absent `exp` is logged at DEBUG)
5. `machine_id` claim must match across all stage-1 peer responses (constant-time comparison)
6. Stage-2 wrapper `machineId`/`label` fields must match the JWT claims (fail closed on mismatch)

Channel integrity is provided by TLS with Certificate Transparency enforcement via `tlsct.NewHTTPClient`. The JWT cryptographic signature is not verified — the trust-server's EdDSA multisig guarantees authenticity at the protocol level, and the TLS+CT channel prevents tampering in transit.

### Why `timestamp` is not a substitute for `exp`

The PoC JWT payload includes a `timestamp` field recording when the trust server processed the quote. Teep uses this as a freshness bound (±10 minutes), which prevents replay of a captured token within a short window. However, `timestamp` and `exp` serve fundamentally different purposes:

**`timestamp` is a receipt. `exp` is a commitment.**

- `timestamp` records when the signing happened. It is set unilaterally by the server constructing the JWT payload — it does not represent an agreement among all quorum members about how long the token should be trusted.
- `exp` is a forward-looking claim in the signed payload: the entire quorum commits that the token is valid until a specific time. Any consumer — teep or otherwise — can apply standard JWT expiry semantics without out-of-band knowledge of teep's validation logic.
- Because teep's `timestamp` window is only 10 minutes, JWTs **cannot be cached**. Every inference request that requires a PoC check must complete the full 3-server multisig round trip. This means the 3-of-3 fragility is not just a per-attestation cost — it is a per-request cost.
- With a reasonable `exp` (e.g., 24 hours), teep could cache a validated JWT for its full duration and only re-query the trust servers on expiry or first attestation. This would reduce the frequency of 3-of-3 round trips by orders of magnitude, dramatically improving resilience against transient peer unavailability.
- When hardware is decommissioned from the PoC registry, the trust servers will begin returning 403. With caching enabled by `exp`, teep would serve cached results until expiry, then detect the 403 on renewal. Without `exp`, there is no mechanism for the PoC alliance to signal "this token should only be trusted for N days" — the validity window is entirely controlled by teep's workaround.

In short: the `timestamp` workaround closes the immediate replay gap but forces teep to re-query the trust servers on every request, converting a per-attestation 3-of-3 dependency into a per-request one.

### Root cause: trust-server source code

The omission is in the shared trust-server codebase ([`src/services.js:246-251`](https://github.com/proofofcloud/trust-server/blob/b252aab3e84bdb22c18b509069a7007410eb9f9c/src/services.js#L246-L251)). The JWT payload object never includes an `exp` claim:

```javascript
const payload = {
  quote_hash: quoteHash,
  machine_id: machineId,
  label: validNode.label,
  timestamp: timestamp,
};
```

This affects **both** JWT generation paths:

**Multisig mode** (production, `services.js:255-308`): The payload is manually base64url-encoded and signed via the `sss-tool` Shamir Secret Sharing binary. Since `exp` is not in the payload object, it never appears in the JWT. There is no library call that could inject it automatically — the JWT is assembled by hand from `header.payload.signature`.

**Single-signer mode** (`services.js:330-333`): Uses the `jsonwebtoken` library's `jwt.sign()`, but does not pass the `expiresIn` option:

```javascript
jwt_token = jwt.sign(payload, state.privateKey, {
  algorithm: "RS256",
  header: { kid: state.keyId },
});
```

Without `expiresIn`, the library does not add `exp`. The omission exists in both modes because the payload construction is shared.

### Protocol fragility: 3-of-3 quorum

The 3-of-3 requirement means:
- **Any single peer failure → total failure.** Network errors, server bugs, or downtime at any one of the three trust servers makes the entire PoC check fail.
- **No degraded mode.** There is no 2-of-3 threshold that would tolerate one server being down or misconfigured.
- **Fixed peer list.** The trust server URLs are hardcoded in teep ([`poc.go:25-29`](../../internal/attestation/poc.go#L25-L29)). Adding, removing, or replacing a peer requires a code change.

Without JWT caching (which requires `exp`), this fragility applies to every request rather than just attestation events.

---

## Remediation

### PoC enhancement request: add `exp` claim

To enable JWT caching and full replay protection, the PoC alliance should add an `exp` claim to the JWT payload in [`src/services.js:246-251`](https://github.com/proofofcloud/trust-server/blob/b252aab3e84bdb22c18b509069a7007410eb9f9c/src/services.js#L246-L251):

```javascript
const payload = {
  quote_hash: quoteHash,
  machine_id: machineId,
  label: validNode.label,
  timestamp: timestamp,
  exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60, // 7 days
};
```

This fixes both multisig and single-signer paths since they share the same payload object. The TTL should be chosen by the alliance — 7 days is a reasonable default that balances freshness against re-verification frequency. Once `exp` is present, teep will enforce it automatically and can safely cache validated JWTs for their full duration.

- **Source:** [proofofcloud/trust-server](https://github.com/proofofcloud/trust-server)
- **Action:** File an issue or submit a PR to add `exp` to JWT generation

### Design consideration: quorum threshold

The 3-of-3 quorum requirement makes the PoC check fragile. A 2-of-3 threshold would tolerate one peer being down or misconfigured while still requiring multi-party agreement. This is a protocol-level design decision for the Proof of Cloud alliance, not a teep change — but combined with JWT caching enabled by `exp`, it would significantly improve the reliability of the registry check.

## References

- [Proof of Cloud alliance](https://proofofcloud.org/) — vendor-neutral hardware registry
- [proofofcloud/trust-server](https://github.com/proofofcloud/trust-server) — trust server source code
- [TEE.fail](https://tee.fail/) — DDR5 memory bus interposition attack on Intel TDX/SGX attestation
- [gpu_cpu_binding.md](gpu_cpu_binding.md) — teep attestation gap report covering PoC as TEE.fail mitigation (Stage 1)
- [RFC 7519 §4.1.4](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4) — JWT `exp` claim specification
