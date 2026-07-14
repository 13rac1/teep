# Plan: Fable review low-severity findings (L1–L15)

Source: `docs/2026-07-02-fable-review.md`. All 15 verified still present on
main @ 4152307 (only line numbers drifted). Grouped by theme; each entry has
the verified location, the fix, and a test note. High-value picks to do
first: **L15** (NEAR E2EE key not bound into REPORTDATA), **L1/L2**
(transparency/PoC signatures unverified), **L8** (signer recognition without
inclusion), **L12** (no https enforcement on base_url).

---

## Transparency & signature verification gaps

### L1 — Rekor inclusion proof root not bound to a signed checkpoint
- Location: `internal/attestation/rekor.go:835-889` (`verifyInclusionProof`);
  `ip.RootHash` (decoded :870) used directly; `ip.Checkpoint`
  (struct :56-57, populated :545) never verified.
- Fix: verify the inclusion proof against the **signed checkpoint** — check
  the checkpoint signature (pinned Rekor log key, same key material used by
  `verifySET`), parse its root hash, and require it to equal the root the
  proof is verified against. Reject if the checkpoint signature is absent or
  the roots differ. If that binding is not implemented, drop the claim that
  inclusion is independently proven (docs) rather than imply a guarantee we
  don't provide.
- Mitigation today: SET signature (pinned production key) still anchors
  authenticity, so this weakens rather than breaks the transparency claim.
- Test: tampered `RootHash` with a valid-but-unrelated checkpoint → reject;
  matching signed checkpoint → accept.

### L2 — Proof-of-Cloud multisig JWT signature never verified
- Location: `internal/attestation/poc.go:76-147` — decodes payload, checks
  `quote_hash`/timestamp/`exp`/`machine_id`, but never verifies the EdDSA
  signature (comment :84-85 admits reliance on TLS+CT).
- Fix: verify the JWT/aggregate multisig signature against the signers'
  published public keys; require a quorum. Until then, relabel the verdict
  shown to users as "transport-trust only" so the "registered" status isn't
  presented as cryptographically sound.
- Bounded impact: `cpu_id_registry` is allow-fail + `OnlineFactor`, cannot
  block — this is a truthfulness fix, not an enforcement hole.
- Test: JWT with bad signature → factor not "registered"; valid quorum →
  registered.

### L8 — Signer-recognition factors don't require log inclusion; NoDSSE skip
- Location: `report.go:1939-1948` / `evalComposeProviderSignerRecognition`
  (:1975-2018, sig check :2008); `evalComponentSignatureRecognition`
  (:2020-2030, compose path :2056+). Neither checks
  `SETVerified`/`InclusionVerified`. `NoDSSE` bypass at `verifyFulcioEntry`
  :1824 (`if r.SignatureErr != nil && !img.NoDSSE`).
- Fix: require `SETVerified` (and inclusion per L1) for any trust-bearing
  signer/signature factor, or document explicitly that
  `build_transparency_log` (which does check them, :1773-1810) is the sole
  carrier and both are per-provider allow-failable. Disallow `NoDSSE` on
  trust-bearing factors — a component with no DSSE signature cannot satisfy
  signer recognition. Coordinate with issue #118 (mandatory policy) where
  `NoDSSE` lives on `ImageProvenance`.
- Test: entry with valid Fulcio cert but no SET → signer recognition Fail;
  `NoDSSE` component → cannot pass signer recognition.

---

## E2EE / AEAD hardening

### L15 — NEAR E2EE key not bound to attested signing_address
- Location: `internal/provider/neardirect/reportdata.go:24-68` (REPORTDATA =
  `sha256(signing_address || tls_fingerprint)`, :53) and
  `internal/provider/nearcloud/reportdata.go:34-80` — neither checks that
  the E2EE model key (`raw.SigningKey`) derives to `signing_address`.
  Contrast `internal/provider/venice/reportdata.go:22-69` which re-derives
  the address from `SigningKey` (:36-44) and cross-checks (:51-59).
- Fix: if the NEAR enclave derives `signing_address` deterministically from
  the Ed25519 `signing_key` (sha256/keccak of the pubkey — **confirm the
  exact derivation from NEAR server behavior**), re-derive and
  constant-time-compare against the attested `signing_address`, matching
  Venice. This makes the key binding independent of gateway/TLS trust
  (currently neardirect leans on pinned TLS, nearcloud on the attested
  gateway).
- Test: mismatched `SigningKey` vs `signing_address` → reportdata factor
  Fail; matching → Pass. Add once the derivation is confirmed.

### L3 — Field ciphertexts use empty AAD (no positional binding)
- Location: `venice.go:220`, `nearcloud.go:194`, `chutes.go:273` — all
  `Seal(nil, nonce, pt, nil)`.
- Fix: bind the JSON field path/array index as AAD so a ciphertext can't be
  relocated/duplicated to another field/index and still decrypt.
  **Constraint:** AAD must match the TEE-server implementation exactly — this
  is a provider-coordinated protocol change, not a unilateral edit. Batch
  with any M2 protocol rev.
- Test: relocate a valid ciphertext to a different index → Open fails.

### L4 — Up to 8 plaintext chars can reach logs on a tamper path
- Location: `internal/e2ee/relay.go:537` — `SafePrefix(s, 8)` of an
  expected-encrypted-but-plaintext field embedded in a returned error
  (`SafePrefix` at `sse.go:49`).
- Fix: log/return length and/or a hash only; never a content prefix. Low
  sensitivity (8 chars, tamper-only) but trivial to close.
- Test: tamper path error message contains no field content.

### L5 — EHBP chunked stream has no authenticated end-of-stream marker
- Location: `internal/e2ee/ehbp.go:78-122` — framing is `[len][ciphertext]`
  per chunk (:106-109); stream end is only EOF (`r.done` :117-119).
- Fix: add an authenticated final-chunk / total-length marker so truncation
  after a whole chunk is detectable at the framing layer (not only via the
  SSE `[DONE]` sentinel).
- Test: truncate the byte stream after a complete chunk → reader errors.

### L6 — EHBP seals a zero-length chunk on a `(0, nil)` read
- Location: `internal/e2ee/ehbp.go:92-100` — guard only handles
  `n==0 && err!=nil`; a legal `(0, nil)` falls through to
  `Seal(nil, plaintext[:0])`.
- Fix: `if n > 0` before sealing; loop/continue on `(0, nil)`. Not a
  nonce-reuse bug (HPKE counter still advances), just wasteful/pathological.
- Test: reader returning `(0, nil)` then data → no empty chunk emitted.

### L7 — Derived AEAD keys not zeroized
- Location: `venice.go:195-208` (`deriveKeyVenice`), `nearcloud.go:863-870`
  (`deriveKeyEd25519`), `chutes.go:240+` (`deriveKeyMLKEM`) — returned keys
  never cleared; the `Zero()` methods only nil the long-term keys. EHBP is
  the model (`ehbp.go:147,156,162` `defer clear(...)`).
- Fix: `defer clear(key)` after each derived symmetric key's last use.
- Test: not directly assertable in Go; enforce by code review + a comment.

---

## Capture safety

### L9 — Capture can persist single-use Chutes E2EE nonces
- Location: `internal/capture/capture.go:114-130` records full response
  bodies (`Body: body`, ≤10 MiB) including the Chutes
  `/e2e/instances/{chute}` body whose nonce pool `chutes/noncepool.go`
  refuses to log.
- Fix: redact/skip the nonce-pool body in capture, matching the noncepool
  policy (match on URL path or body shape). Opt-in feature, 0600 files —
  low but should mirror the existing redaction contract.
- Test: capture a chutes instance exchange → stored body has the nonce pool
  redacted.

### L10 — Provider name not slugified in capture path
- Location: `internal/capture/capture.go:249-251` — `slugify(m.Model)` but
  `m.Provider` inserted raw into the directory name.
- Fix: `slugify(m.Provider)` too (a `/` or `..` would escape the capture
  dir). Local-trusted input, so low, but trivial.
- Test: provider name with `/` → path stays within the capture dir.

---

## Config / transport hardening

### L11 — Fail-open config warnings + comment/code mismatch
- Location: `internal/config/config.go` — world/group-readable config →
  `slog.Warn` and proceed (:297-299 via `checkFilePermissions` :640-650);
  non-loopback listen addr → warn only (`warnNonLoopback` :652-667). Comment
  at :639 says `0o044` but code checks `mode&0o066` (:646) and the error
  says "0600".
- Fix: consider hard-failing on world-readable files containing inline
  secrets and on non-loopback listen addresses unless an explicit override
  flag is set (interlock with M4's `--allow-non-loopback`). Fix the
  comment/error to match the `0o066` check.
- Test: world-readable config with inline `api_key` → error (or warn if
  override set); comment/code consistency.

### L12 — No https enforcement on base_url
- Location: `internal/config/config.go` — `resolveProvider` (:562-576)
  copies `pc.BaseURL` verbatim; only phalacloud checks absolute-ness
  (`proxy.go:778-790`), only Tinfoil fails closed on plain HTTP
  (`provider/fetch.go`). CT-layer https check (`tlsct/checker.go:149`) does
  not cover config.
- Fix: require `https://` for any `base_url` that carries an API key or
  prompts; reject `http://` at config load (fail closed). Pinned-transport
  providers (near*) ignore base_url for transport but still validate for
  consistency.
- Test: `base_url = "http://…"` → startup error.

### L13 — Sigstore latest-release resolution allows signed-but-old downgrade
- Location: `internal/provider/tinfoil/sigstore.go:57-95` — `fetchLatestTag`
  trusts the releases endpoint's `latest` tag; no version floor/monotonicity.
- Fix: add a configurable minimum-version floor (and/or monotonic
  "never accept a tag older than last-seen" pin, stored like measurement
  pins). DSSE prevents forgery but not a rollback to an old vulnerable-but-
  signed build.
- Test: releases endpoint returns an older signed tag than the floor →
  rejected.

### L14 — Incomplete hop-by-hop header stripping
- Location: `internal/proxy/proxy.go:2173-2178` and :3174-3178 — strip only
  `Transfer-Encoding`/`Content-Encoding`/`Content-Length`/`Connection`.
- Fix: strip the full RFC 7230 hop-by-hop set (`Keep-Alive`,
  `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Upgrade`)
  plus any header named in the response `Connection` token list. Factor into
  a shared helper used by both sites.
- Test: upstream response with `Connection: X-Foo` and hop-by-hop headers →
  all stripped before returning to the client.

---

## Sequencing

- **Independent, cheap, do first:** L4, L6, L7, L10, L14 (self-contained,
  no provider coordination).
- **Verification-strengthening:** L1, L2, L8 (transparency/signature) — land
  together; L8 interlocks with issue #118.
- **Config policy:** L11, L12, L13 — land with M4 (listen-address policy)
  and the measurement-pin infrastructure.
- **Provider-coordinated (slowest):** L3, L15 — need confirmation of
  server-side behavior; batch with M2's protocol work.
- **Capture:** L9 (redaction contract), L10 (path) — together.

## Constraints (AGENTS.md)

- Every fix gets regression test coverage (line 139).
- Constant-time compares for L15's address comparison and any
  fingerprint/hash work (line 87).
- Fail closed: L11/L12/L13 move from warn/accept toward reject.
- Provider-coordinated changes (L3, L15) must match server behavior exactly
  — confirm before implementing, no unilateral protocol edits.
