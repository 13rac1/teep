# Security Code Review — 2026-07-02

Reviewer: Claude Fable 5 (four parallel deep passes: E2EE crypto, attestation
verification, proxy/TLS layer, config/providers/capture) plus build and
dependency check.

## Scope

- `internal/e2ee/` — encryption sessions and relay logic
- `internal/attestation/` — TDX/SEV/NVIDIA quote verification, sigstore, Rekor, measurement policy
- `internal/verify/` — multi-factor orchestration
- `internal/proxy/`, `internal/tlsct/`, `internal/reqid/`, `cmd/teep/` — HTTP handler, TLS, dashboard
- `internal/provider/`, `internal/config/`, `internal/capture/`, `internal/multi/`, `internal/defaults/`, `internal/formatdetect/`, `internal/jsonstrict/`

Build is clean (`go build ./...`). Dependency choices are sound: Google
`go-tdx-guest`/`go-sev-guest` for quote verification, `sigstore-go` for
supply-chain, `certificate-transparency-go` for CT — no hand-rolled quote parsing.

## Overall assessment

The cryptographic primitives and the mechanical fail-closed machinery are
strong: constant-time comparisons on every binding check, pinned trust roots
(Intel, NVIDIA, Rekor), real offline TDX signature verification, per-message
ephemeral keys that make nonce reuse structurally impossible, size-bounded reads
everywhere, strict TOML/JSON parsing, API keys and plaintext kept out of logs
and capture files, and an inverted "enforce-by-default" factor model.

**The concentrated risk is the per-provider policy data on top of those
mechanisms, not the mechanisms themselves.** The default `allow_fail` lists
quietly exempt exactly the factors that make attestation meaningful for several
providers. The "FAIL CLOSED" invariant holds mechanically while the effective
guarantee for those providers degrades toward "TLS plus warnings." Two
independent review passes converged on the same top finding (#1), which is the
strongest signal in this review.

---

## Findings checklist

Severity legend: 🔴 High · 🟠 Medium · 🟡 Low/Info

### 🔴 High

- [ ] **H1 — `tinfoil_v3_cloud` exempts the TEE quote signature and cert chain by default.**
  - Location: `internal/attestation/report.go:408-420` (`TinfoilCloudDefaultAllowFail` includes `FactorTEECertChain`, `FactorTEEQuoteSignature`); selected via `internal/config/config.go:57-65`, applied at `config.go:456`.
  - Defect: The two factors that cryptographically authenticate the hardware quote are warn-only by default. Every other enforced factor (`tee_measurement`, `tee_boot_config`, `tee_reportdata_binding`) derives its values from that same unverified quote (`report.go:973-1120`, `1149-1185`), so exempting the signature removes the only thing that makes those values trustworthy.
  - Failure scenario: A compromised Tinfoil router — or any party holding a CA-valid, CT-logged cert for `inference.tinfoil.sh` — serves a fabricated TDX quote with attacker-chosen MRTD/RTMR and a REPORTDATA that binds the attacker's own key. Signature = Fail but ALLOWED; Sigstore `CodeMatch`/`HWMatch` and `tee_reportdata_binding` all PASS against the forged values; `Blocked()` returns false; E2EE proceeds to the attacker's key. Hardware attestation collapses to ordinary TLS trust.
  - Why the stated rationale doesn't hold: The in-code justification is AMD KDS (`kdsintf.amd.com`) flakiness (`report.go:390-407`). That is a SEV-SNP concern; TDX cert-chain + signature verification is fully offline against the embedded Intel root (`tdx.go:300-310`), so there is no availability reason to exempt TDX.
  - Suggested resolution: Split the TDX path from the SEV/KDS rationale. Make `tee_quote_signature` and `tee_cert_chain` **non-exemptible** for any TEE-backed provider (reject these entries if present in a provider's allow-fail list, or hard-enforce regardless). If a genuine SEV/KDS availability problem exists, scope the exemption to SEV cert-chain fetch only, and surface it per-request rather than silently.
  - Open question: Does Tinfoil cloud actually attest with SEV-SNP, TDX, or both? If TDX-only, there is no KDS dependency at all and the exemption should simply be removed. Confirm with the provider's deployment before choosing scope.

### 🟠 Medium

- [ ] **M1 — `nanogpt` / `phalacloud` defaults disable freshness and identity binding.**
  - Location: `internal/attestation/report.go:320-368` (`NanoGPTDefaultAllowFail`, `PhalaCloudDefaultAllowFail`).
  - Defect: Both exempt `nonce_match` and `tee_measurement`; nanogpt additionally exempts `tee_reportdata_binding`. A genuine-but-stale or foreign TDX quote (valid Intel signature, arbitrary machine, replayed indefinitely) passes with no replay protection, no enforced measurement allowlist, and — for nanogpt — no proof the enclave key is bound into the quote.
  - Compounding issue: `teep verify nanogpt --update-config` refuses only when `Blocked()` (`cmd/teep/main.go:431`), so a replayed quote's measurements get pinned into the user's allowlist via `internal/config/update.go`.
  - Suggested resolution: Reclassify `nonce_match` and the binding factors as blocking for these providers. If genuine hardware limitations prevent full attestation, keep them as separate provider tiers but (a) require an explicit opt-in flag to enable a weak-tier provider, and (b) refuse `--update-config` pinning for any report that only passed because of tier exemptions.
  - Open question: Are these providers expected to reach full attestation parity, or are they permanently limited? That decides whether this is a temporary waiver or a permanent tiering design.

- [ ] **M2 — Response decryption is not bound to the attested model key (Venice, NearCloud).**
  - Location: `internal/e2ee/venice.go:144-172` (`DecryptVenice`), `internal/e2ee/nearcloud.go:207-244` (`DecryptXChaCha20`); attested key retained but unused at `venice.go:83-84`, `nearcloud.go:88-89`.
  - Defect: Response AEAD key = `ECDH(client_session_private, ephemeral_pub_from_wire)`, where the ephemeral public key comes entirely from attacker-controllable ciphertext. A successful decrypt proves only "someone who knew the client's public key produced this," not "the attested enclave produced this."
  - Failure scenario (Venice): Venice is not TLS-pinned; its API infrastructure terminates client TLS and reads `X-Venice-TEE-Client-Pub-Key` (`verify/e2ee.go:98`). That infrastructure can choose any ephemeral key, compute the shared secret with the client pubkey, seal arbitrary text, and return it as `choices[].delta.content`. The client accepts forged "model output." Confidentiality holds; response authenticity does not. NearCloud has the same shape but its pinned transport reduces the threat to a malicious-but-attested gateway.
  - Note: Chutes does **not** have this problem — the client's response public key travels encrypted inside the request body (`chutes.go:119-141`), so only the attested enclave learns it.
  - Suggested resolution: Where the response is encrypted with the model's static/attested key, pin `wire_pub == attested model key` (the key is already in the session). Where the upstream protocol genuinely uses a fresh server ephemeral not bound to attestation, document explicitly that Venice provides confidentiality but not response-origin authentication, and consider carrying a client-chosen response key inside the encrypted request as Chutes does.
  - Open question: For Venice/NEAR, is the wire "ephemeral_pub" actually the attested model key, or a fresh per-response server ephemeral? This determines whether an equality pin is possible or whether a protocol change is required. Needs confirmation against the provider server behavior.

- [ ] **M3 — SPKI re-pinning is silently skipped on attestation cache hits.**
  - Location: `internal/proxy/proxy.go:2833-2840` (guard `raw != nil && raw.TinfoilTLSKeyFP != ""`); misleading comment at `proxy.go:2668-2683`; root cause `attestAndCache` returns `Raw == nil` on cache hits (`proxy.go:2245-2259`, `2284-2289`).
  - Defect: The comment claims per-response SPKI verification keeps a reused connection bound to the attested enclave, but `verifyUpstreamTLSBinding` runs only when `raw != nil`. On a cache hit `raw` is nil, so the check never runs and `Connection: close` is also not set — pooled TLS reuse without re-pinning, for up to the 1-hour `AttestationCacheTTL`. Affects `tinfoil_v3_cloud`/`tinfoil_v3_direct` (`UsesTLSBinding = true`).
  - Failure scenario: After the first request caches attestation, later requests within the hour reach the enclave domain over a connection whose leaf SPKI is never compared against the attested `TinfoilTLSKeyFP`. A mis-issued but CA-valid, CT-logged cert for the domain is not caught on the cache-hit path.
  - Suggested resolution: Thread the attested fingerprint (or a cached copy) into the cache-hit path so `verifyUpstreamTLSBinding` runs on every upstream response for TLS-binding providers; or set `Connection: close` regardless. Fix the comment to match actual behavior.

- [ ] **M4 — DNS-rebinding against the localhost API and dashboard.**
  - Location: `internal/proxy/proxy.go:514-531` (no Host guard on any route); corroborated by `internal/config/config.go:655-667`.
  - Defect: Every endpoint (`/`, `/events`, `/metrics`, `/explore`, `/explore/attest`, `/explore/infer`, `/v1/*`) is served with no Host-header allowlist and no CSP / `X-Frame-Options`. Access control rests entirely on loopback binding, which DNS rebinding defeats.
  - Failure scenario: An operator visits a malicious page. The attacker rebinds their domain to `127.0.0.1`, becoming same-origin with `http://attacker.com:8337`, defeating CORS and the JSON-preflight barrier. The page drives the proxy with the operator's configured provider API keys: enumerate models, trigger attestation fetches, run inference (reading responses and burning paid credits), and scrape dashboard/`/metrics` for provider config.
  - Suggested resolution: Reject requests whose `Host` is not an allowlisted loopback authority (`127.0.0.1:PORT`, `[::1]:PORT`, `localhost:PORT`). Add `Content-Security-Policy` and `X-Frame-Options: DENY` to dashboard responses.

- [ ] **M5 — `esc()` does not escape quotes → attribute-injection XSS from provider-controlled data.**
  - Location: `internal/proxy/templates/_base_js.html:10` (the `esc` helper); sinks in `internal/proxy/templates/explore.html:196-210` and `dashboard.html:373-383`.
  - Defect: `esc()` sets `textContent` then reads `innerHTML`, escaping `&`, `<`, `>` but not `"` or `'`. Output is interpolated into double-quoted HTML attributes whose values (model IDs and metadata) come verbatim from each provider's `/v1/models` response; `prefixModelID` (`proxy.go:3221-3298`) rewrites only the id prefix. No CSP to contain injected handlers.
  - Failure scenario: A malicious/compromised provider (or MITM of the non-attested model-listing endpoint) returns a model id such as `venice:x" autofocus onfocus="fetch('/explore/infer',...)`. The unescaped `"` breaks out of `data-attest="…"` and injects an event handler that executes attacker JS in the dashboard origin — which then chains into M4's actions.
  - Suggested resolution: Escape `"` and `'` in `esc`, or build DOM nodes via `setAttribute`/`createElement` instead of string-concatenated `innerHTML`. Add CSP as defense-in-depth.

- [ ] **M6 — `--update-config` silently erases an explicitly-empty `allow_fail = []`.**
  - Location: `internal/config/update.go:83`, `:92` (`AllowFail []string \`toml:"allow_fail,omitempty"\``) vs. `internal/config/config.go:330-334`, `358-370` (`meta.IsDefined` treats `allow_fail = []` as "enforce ALL factors").
  - Defect: The update path round-trips config through structs whose `omitempty` tag erases an explicitly-empty allow-fail list. A user who hardens config with `allow_fail = []` then runs `teep verify X --update-config` gets that list dropped; on next load `MergedAllowFail` falls back to the weaker Go defaults (H1/M1 lists) — a silent security downgrade from a maintenance command.
  - Related: `update.go:48` uses non-strict `toml.Decode` (no `meta.Undecoded()` check), so unknown/future keys and comments are silently dropped on rewrite; the `.bak` at `update.go:52` is the only mitigation.
  - Suggested resolution: Distinguish "absent" from "present but empty" — drop `omitempty` and use a pointer/`*[]string` or a sentinel, so an explicit `allow_fail = []` survives the round-trip. Consider preserving comments/unknown keys, or at minimum warn loudly that `--update-config` rewrites and strips them.

### 🟡 Low / Info

- [ ] **L1 — Rekor inclusion proof root hash not bound to a signed checkpoint.** `internal/attestation/rekor.go:839-889`. The proof recomputes `leaf → RootHash`, but `ip.RootHash` comes from the same untrusted API response and `ip.Checkpoint` (signed tree head) is ignored, so an attacker-controlled response can supply a self-consistent triple. Authenticity is still anchored by the SET signature (`verifySET`, `rekor.go:795-833`, pinned production key), so this weakens rather than breaks the transparency guarantee. Resolution: verify the inclusion proof against the signed checkpoint root, or drop the claim that inclusion is independently proven.

- [ ] **L2 — Proof-of-Cloud multisig JWT is never cryptographically verified.** `internal/attestation/poc.go:76-147`. The final signer's EdDSA JWT is base64-decoded but its signature is never checked; the aggregate multisig is decorative and trust reduces to TLS to the peer URLs. Bounded impact: `cpu_id_registry` is allow-fail and an `OnlineFactor`, so it cannot block — but the "registered" verdict shown to users is not cryptographically sound. Resolution: verify the JWT/aggregate signature against the signers' public keys, or relabel the verdict as transport-trust only.

- [ ] **L3 — Field ciphertexts use empty AAD (no positional binding).** `internal/e2ee/venice.go:220`, `nearcloud.go:194`, `chutes.go:273` (all `Seal(nil, nonce, pt, nil)`). An intermediary can relocate/duplicate a valid ciphertext to a different field or array index and it decrypts cleanly (e.g., swap encrypted `content` between `messages[0]`/`messages[1]` or `choices[0]`/`choices[1]`). On the response side this compounds M2. Resolution: bind the JSON field path/index as AAD.

- [ ] **L4 — Up to 8 plaintext chars can reach logs on a policy-violation path.** `internal/e2ee/relay.go:520` — `SafePrefix(s, 8)` of an expected-encrypted-but-plaintext field is put into an error emitted via `slog.ErrorContext` (`relay.go:1321`). Only 8 chars and only on a tamper event, but it is decrypted-domain content in logs. Resolution: log length/hash only.

- [ ] **L5 — EHBP chunked stream has no authenticated end-of-stream marker.** `internal/e2ee/ehbp.go:207-269`. Each chunk is authenticated but stream completion is not, so cutting the byte stream after a whole chunk yields a shorter but valid plaintext (truncation). Mitigated because the SSE consumer expects a `[DONE]` sentinel. Resolution: add an authenticated final-chunk/length marker.

- [ ] **L6 — `ehbpRequestReader` seals an empty chunk on a `(0, nil)` read.** `internal/e2ee/ehbp.go:90-100`. A legal `(0, nil)` read skips the `n==0 && err!=nil` guard and seals a zero-length chunk (advancing the HPKE nonce). Not a nonce-reuse bug; wasteful and could loop on a pathological reader. Resolution: guard `n>0` before sealing.

- [ ] **L7 — Derived AEAD keys not zeroized on some paths.** `internal/e2ee/venice.go:195`, `nearcloud.go:863`, `chutes.go:242` never zero the derived key after use, unlike the EHBP path (`ehbp.go:147,156,162` `defer clear(...)`). Session `Zero()` methods can only nil references (stdlib crypto types expose no in-place wipe) and document this. Low impact in a memory-safe runtime. Resolution: `defer clear(key)` for consistency.

- [ ] **L8 — Provider/component signer recognition trusts the Fulcio cert without requiring log inclusion.** `internal/attestation/report.go:1823-1855`, `2106-2133`. These factors validate OIDC issuer/identity/repo and DSSE signature from the Rekor entry but never check `SETVerified`/`InclusionVerified`. Mitigated by TLS+CT to rekor.sigstore.dev and the DSSE check — except when `img.NoDSSE` is set (`report.go:1824`), which skips even the DSSE signature. Resolution: require SET/inclusion verification, and disallow `NoDSSE` for trust-bearing factors.

- [ ] **L9 — Capture mode can persist single-use Chutes E2EE nonces to disk.** `internal/capture/capture.go:115-131`, `248-304` record full attestation response bodies, including the Chutes `/e2e/instances/{chute}` body whose pools of unconsumed single-use nonces `chutes/noncepool.go:188-190` explicitly refuses to log. Opt-in only, files 0600/dirs 0750, request Authorization never recorded, proxy data path never captures — so prompts and API keys are not written. Resolution: redact/skip the nonce-pool body in capture, matching the noncepool policy.

- [ ] **L10 — `capture.Save` does not sanitize the provider name in the directory path.** `internal/capture/capture.go:250-251`. `m.Provider` (arbitrary TOML key / CLI arg) is not slugified, unlike `m.Model`; a `/` or `..` escapes the capture dir. Local-trusted input. Resolution: `slugify(m.Provider)`.

- [ ] **L11 — Fail-open warnings on config load.** `internal/config/config.go:296-299` (group/world-readable config with inline `api_key` → `slog.Warn`, startup proceeds); `config.go:655-666` (non-loopback/unparseable `TEEP_LISTEN_ADDR` → warn only, so a typo can expose the proxy). Also a comment/code mismatch at `config.go:638-640` ("0o044" comment vs. `0o066` checked — code is stricter). Resolution: consider hard-failing on world-readable secrets and on non-loopback listen addresses unless an explicit override flag is set; fix the comment.

- [ ] **L12 — No `https` scheme enforcement on `base_url`.** `internal/config/config.go:86-93`, `562-576`. A `base_url = "http://..."` typo sends `Authorization: Bearer <key>` and (for non-E2EE providers) plaintext prompts unencrypted. Only Tinfoil fails closed on plain HTTP (`provider/fetch.go:60-67`). Pinned-handler providers (near*) ignore base_url for transport. Resolution: require `https://` for any `base_url` that carries keys/prompts.

- [ ] **L13 — Sigstore "latest release" resolution permits a signed-but-old downgrade.** `internal/provider/tinfoil/sigstore.go:28`, `77-92`. Expected measurements resolve via `github-proxy.tinfoil.sh` → latest release tag → `tinfoil.hash`. DSSE verification prevents forgery, but the proxy can serve an older validly-signed release matching an old (possibly vulnerable) enclave build. No version floor/monotonicity check. Resolution: add a configurable minimum-version floor or monotonicity check.

- [ ] **L14 — Incomplete hop-by-hop header stripping.** `internal/proxy/proxy.go:2134-2142`, `3134-3142` strip only `Transfer-Encoding`/`Content-Encoding`/`Content-Length`/`Connection`; `Keep-Alive`/`Trailer`/`Upgrade`/`Proxy-Authenticate`/`TE` pass through. Response splitting mitigated by Go stdlib header sanitization. Resolution: strip the full RFC 7230 hop-by-hop set plus any listed in the response `Connection` header.

- [ ] **L15 — NEAR E2EE key not verified to derive from the attested `signing_address`.** `internal/provider/neardirect/reportdata.go:53`, `nearcloud/reportdata.go:72` bind `sha256(signing_address ‖ tls_fingerprint)`, but E2EE encrypts to `raw.SigningKey` with no check that it derives to the attested `signing_address`. Contrast Venice (`provider/venice/reportdata.go:36-58`), which re-derives and compares — strictly stronger. Covered today for neardirect by pinned TLS to the attested enclave; for nearcloud the model-key trust rests on the attested gateway. Resolution: if the NEAR enclave derives `signing_address` deterministically from `signing_key`, add the equality check so the binding is independent of gateway/TLS trust. Open question: is `signing_address` a function of `signing_key`? Needs confirmation against NEAR server behavior.

---

## Verified correct (no action)

- No nonce/IV reuse on any encrypt path: fresh ephemeral key + fresh `crypto/rand` nonce per message (Venice/NearCloud), fresh KEM secret + random nonce per request (Chutes), stateful HPKE counter (EHBP request), deterministic base-XOR-counter with overflow guard (EHBP response).
- No shared mutable session state across concurrent requests; `sseScannerBufPool` cleared on return.
- Nonce/REPORTDATA comparisons use `subtle.ConstantTimeCompare` and fail closed on absence (`report.go:837-848`, `nvidia_eat.go:86-89`, `:268`).
- TDX offline path performs real cert-chain + signature verification against the embedded Intel SGX root (`tdx.go:300-310`).
- Offline SEV correctly returns Skip for signature/cert-chain, which — being enforced and non-deferred — is promoted to Fail and blocks (`report.go:734-739`, `936-946`).
- NVIDIA root CA pinned by SHA-256 with constant-time compare; SPDM signature verified over the reconstructed message (`nvidia_eat.go:112-132`, `209-217`, `:333`).
- Rekor front-running mitigated by preferring Fulcio entries over raw-key entries; DSSE verified via correct PAE construction (`rekor.go:222-348`, `686-763`); SET verified against the pinned production key.
- Missing REPORTDATA verifier becomes a factor **Fail**, not a silent pass (`report.go:1171`) — fail closed.
- No `InsecureSkipVerify` anywhere; TLS dials pin `MinVersion: TLS13`; the TLS 1.2 fallback is scoped to AMD KDS with `MaxVersion` pinned; CT checker fails closed on private-log/missing-SCT.
- API keys never logged, captured, or embedded in errors; keys sent via `Authorization` header only; NEAR/Tinfoil endpoint discovery restricted to `*.near.ai` / `*.tinfoil.sh` domains; Go's default redirect policy strips `Authorization` cross-host.
- Strict config parsing: unknown TOML keys, unknown factor names, and malformed measurement values all rejected; inverted allow-fail model enforces new factors by default.
- Size-bounded reads throughout with overflow detection (10 MiB relay/gunzip, 16 MiB EHBP chunk, 50 MiB inference, 4 KiB explore, 1 MiB loopback); error messages exclude query strings (nonce-safe).
- No remote config download — `--update-config` is local TOFU pinning that refuses on `Blocked()` reports and backs up the original.

---

## Prioritized recommendations

1. **H1** — Make `tee_quote_signature`/`tee_cert_chain` non-exemptible for any TEE-backed provider; split the TDX path from the SEV/KDS rationale.
2. **M6** — Preserve explicitly-empty `allow_fail = []` across `--update-config`.
3. **M3** — Run SPKI re-pinning on attestation cache hits (or force `Connection: close`).
4. **M4 + M5** — Add Host-header allowlist + CSP, and escape quotes in the dashboard `esc()` helper.
5. **M1** — Reclassify freshness/binding exemptions for nanogpt/phalacloud as blocking, gated behind explicit weak-tier opt-in.
6. Add a user-facing **"effective enforcement" summary** at startup and per verification, so weakened per-provider defaults cannot hide in log-warning noise.

## Open questions for maintainers

- Does `tinfoil_v3_cloud` attest with SEV-SNP, TDX, or both? (Scopes H1's fix.)
- Are nanogpt/phalacloud expected to reach full attestation parity, or are they permanently limited tiers? (M1 waiver vs. permanent tiering.)
- For Venice/NEAR, is the wire response "ephemeral_pub" the attested model key or a fresh server ephemeral? (Determines whether M2 is a one-line pin or a protocol change.)
- Is the NEAR `signing_address` a deterministic function of `signing_key`? (Enables L15's equality check.)
