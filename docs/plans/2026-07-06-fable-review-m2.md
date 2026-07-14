# Plan: Fable review M2 — response decryption not bound to the attested model key (Venice, NearCloud)

Source: `docs/2026-07-02-fable-review.md`, finding M2. Verified still present
on main @ 4152307.

## Current state

- Venice: `DecryptVenice` (`internal/e2ee/venice.go:144-172`) parses the
  wire ephemeral pubkey (:159) and ECDHs with the client session private
  key (:164). The attested model key is on the session (`modelKeyHex`/
  `modelPubKey`, `venice.go:22-23`, set via `SetModelKey` :52-70) but is
  never consulted on the decrypt path.
- NearCloud: `DecryptXChaCha20` (`internal/e2ee/nearcloud.go:207-244`) —
  same shape; attested key fields (`modelEd25519Hex`/`modelX25519`,
  :28-35) unused on decrypt.
- Chutes does **not** have this problem: the client's response key travels
  encrypted inside the request body, so only the attested enclave learns
  it.

Impact: response-AEAD key = `ECDH(client_priv, wire_ephemeral_pub)` where
the wire ephemeral is attacker-choosable ciphertext. Anyone who knows the
client's session public key can forge "model output." For Venice — whose
API infrastructure terminates TLS and reads the client pubkey from the
`X-Venice-TEE-Client-Pub-Key` header — that means the non-attested gateway
can fabricate responses. Confidentiality holds; response **authenticity**
does not. NearCloud's pinned transport reduces this to a
malicious-but-attested gateway.

## Analysis — why this is not a one-line pin

In an ECIES-style scheme the wire key is a fresh per-message server
ephemeral; there is genuinely nothing to equality-check it against. The
review's open question ("is the wire pub the attested model key or a fresh
ephemeral?") is the fork in the road:

- If the server actually sends its **static attested key** as the wire key:
  add `subtle.ConstantTimeCompare(wirePub, attestedModelPub)` before ECDH
  in both decrypt paths and the finding closes cheaply.
- If it is a fresh ephemeral (likely): true response-origin authentication
  requires the upstream protocol to bind the response to the attested key —
  a provider-side change. Options in order of preference:
  1. **Chutes-style client response key:** carry a client-chosen response
     public key *inside the encrypted request* so only the enclave can
     learn it. Requires provider protocol support.
  2. **Sign-then-encrypt:** enclave signs the response (or a transcript
     hash) with the attested signing key; teep verifies with the key it
     already holds on the session.
  3. Static-key ECDH contribution: derive the response key from
     `ECDH(client_priv, wire_ephemeral) || ECDH(client_priv, attested_static)`
     so forgery requires the attested private key. Also provider-side.

## Plan

### Phase 1 — Determine ground truth (no code risk)

Instrument a live verification run (`TEEP_LIVE_TESTS`) to compare the wire
ephemeral against the session's attested key for Venice and NearCloud over
multiple responses. Constant across responses and equal to attested key →
Phase 2a; varying → Phase 2b.

### Phase 2a — Equality pin (if wire key is the attested key)

- `DecryptVenice`/`DecryptXChaCha20`: fail closed with a distinct error if
  the wire key ≠ session attested key (constant-time compare). The session
  accessors (`ModelPubKey()`, `modelX25519`) already exist.
- Regression tests: forged wire key → decrypt error; matching key → OK.

### Phase 2b — Document + upstream protocol work (if fresh ephemeral)

- Immediately: document in `docs/attestation_gaps/` that Venice E2EE
  provides confidentiality but **not response-origin authentication**, and
  surface it in the report metadata (a non-factor informational line, or a
  new allow-fail-by-default factor `e2ee_response_origin` that is Pass for
  Chutes, Fail-with-detail for Venice/NearCloud — making the gap visible
  per "fail loudly" instead of silent).
- Open provider conversations for option 1 or 2 above; implement teep-side
  verification once a provider ships it. NearCloud first (single gateway
  operator, pinned transport already); Venice is the higher-risk one but
  needs Venice-side changes.
- Interlock with L3 (empty AAD): if a protocol rev happens, add positional
  AAD in the same rev — one provider-coordinated change instead of two.

## Files

- `internal/e2ee/venice.go`, `internal/e2ee/nearcloud.go` — pin (2a) or
  factor plumbing (2b).
- `internal/attestation/report.go` — `e2ee_response_origin` factor (2b).
- `docs/attestation_gaps/e2ee_response_origin.md` (new) — the analysis
  above, provider matrix (Chutes ✓, Venice ✗, NearCloud partial).

## Tests

- 2a: table tests with matching/mismatched wire keys, constant-time compare
  asserted by code review; concurrent decrypt test (sessions are
  per-request but the race detector should cover accessor use).
- 2b: factor rendering tests per provider; report metadata visible in
  golden `report.txt`.

## Verification

- `make check`; `go test -race ./internal/e2ee/...`; `make integration`;
  live phase-1 probe behind `TEEP_LIVE_TESTS`.

## Constraints (AGENTS.md)

- Cryptographic comparisons constant-time; authenticated encryption only —
  no weakening of the existing paths while adding checks.
- Fail loudly: if 2b, the gap becomes a visible report line, not a doc
  footnote only.
