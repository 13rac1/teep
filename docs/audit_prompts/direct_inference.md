# Direct Inference Provider Audit

This repository implements a proxy that ensures private LLM inference by performing attestation-bound TLS pinning to model servers, validating that the remote machine runs genuine TEE hardware with verifiable software, and preventing man-in-the-middle attacks through cryptographic binding of the TLS channel to the attestation report.

Please verify every stage of attestation for the requested provider, following this audit guide to produce a detailed report.

This audit applies to direct inference providers, where the API endpoint is running the inference directly on the same machine, meaning that there will only be one layer of attestation to verify.

The report MUST cite the source code locations relevant to BOTH positive AND negative audit findings, using relative markdown links to the source locations, for human validation of audit claims.

The report MUST also distinguish between:
- checks that are computed but do not block traffic, and
- checks that are enforced fail-closed (request rejected on failure).

---

## Part 1 — Repository Security Rules

This is **critical infrastructure security software**. Protecting confidential traffic is more important than providing service. Failing closed is a feature, not a bug.

The auditor MUST evaluate every code path against these rules. Any violation is a finding.

### Fail-Closed Policy (highest priority)

Every validation check MUST block the request on failure. Flag any code that:

- Returns a nil error, default value, or falls through on a validation failure.
- Catches an error and continues instead of aborting (error fallback).
- Uses a fallback, default, or degraded mode when a security check fails.
- Introduces a "best-effort", "soft-fail", or "skip-on-error" code path.
- Adds backwards-compatible shims that weaken validation.
- Silently drops malformed elements instead of rejecting the whole input.
- Allows an unattested or partially-attested request to be forwarded.
- Serves stale or cached data when re-validation fails, without blocking.

If an error path does anything other than return/propagate an error, it is a defect.

There are **NO** acceptable workarounds, fallbacks, or error recoveries for security validation.

### Cryptographic Safety

- All comparisons of secrets, keys, fingerprints, nonces, or hashes MUST use `subtle.ConstantTimeCompare`. Flag any use of `==`, `!=`, `bytes.Equal`, or `strings.EqualFold` on security-sensitive values.
- Encryption MUST be authenticated (AES-GCM, not AES-CTR/CBC alone).
- Encryption keys MUST be bound to TEE attestation.
- Nonce generation MUST use `crypto/rand`. If randomness fails, the code MUST panic or return an error — never use a weak source.

### Sensitive Data Handling

- NEVER log or print API keys, inference request bodies, or response bodies.
- API keys in logs must be redacted (first few characters only).
- Ephemeral key material should be zeroed after use (with acknowledgment of GC limitations).
- Config files containing secrets should have permission checks.
- Attestation nonces MUST NOT be reused across requests.

### Error Handling and Configuration

- Error returns MUST block the request — no silent swallowing.
- Unknown or misspelled config values MUST be rejected at startup (not silently ignored).
- JSON unmarshalling SHOULD use strict mode (reject unknown fields).
- Malformed attestation data MUST fail the entire response, not skip elements.

### Input Bounds

- All reads from untrusted sources (HTTP bodies, JSON arrays, external API responses) MUST be bounded.
- Unbounded reads from untrusted sources represent a denial-of-service vector and MUST be flagged.

---

## Part 2 — Quality Bar and Deliverables

Future direct-provider audits MUST meet the following quality bar:
- include an executive summary with severity counts and a one-paragraph overall risk statement,
- present findings first (ordered by severity) before narrative walkthrough,
- include at least one concrete positive control and one concrete negative/residual-risk observation for every major section,
- classify every security check as one of: `enforced fail-closed`, `computed but non-blocking`, or `skipped/advisory`,
- separate implementation fact from recommendation (no implicit policy assumptions),
- quantify residual risk when a control is informational-only,
- cite source locations for every substantive claim (positive and negative).

The final report MUST include all of the following artifacts:
- findings summary table (severity, location, impact),
- verification-factor matrix with pass/fail/skip and enforcement status,
- cache-layer table (keys, TTL, bounds, eviction, stale behavior),
- offline-mode matrix (active checks vs skipped checks),
- explicit "open questions / assumptions" section when behavior cannot be proven from code.

---

## Part 3 — Attestation Architecture Reference

This section provides background for auditors on the TDX attestation model used by direct inference providers. This is reference material — the audit checklist follows in Part 4.

### What Each TDX Register Measures

Understanding the security semantics of each register is critical for assessing attestation completeness. The following describes the trust-chain role of each register, based on Intel TDX architecture and the dstack CVM implementation used by inference providers:

**MRSEAM** — Measurement of the TDX module (SEAM firmware). This 48-byte hash represents the identity and integrity of the Intel TDX module running in Secure Arbitration Mode. Intel signs and guarantees TDX module integrity; the MRSEAM value should correspond to a known Intel-released TDX module version. Verification of MRSEAM ensures the TDX firmware has not been tampered with and is a recognised, trusted version. Without MRSEAM verification, an attacker who compromises the hypervisor could potentially load a modified TDX module that subverts TD isolation guarantees.

**MRTD** — Measurement Register for Trust Domain. This 48-byte hash captures the initial memory contents and configuration of the TD at creation time, specifically the virtual firmware (OVMF/TDVF) measurement. MRTD is measured by the TDX module in SEAM mode before any guest code executes, making it the root-of-trust anchor for the entire guest boot chain. In dstack's architecture, MRTD corresponds to TPM PCR[0] (FirmwareCode). MRTD can be pre-calculated from the built dstack OS image. Without MRTD verification, an attacker could substitute a different virtual firmware (e.g., one that leaks secrets or skips subsequent measured boot steps) while preserving the correct compose hash and RTMR3 values.

**RTMR0** — Runtime firmware configuration measurement. RTMR0 records the CVM's virtual hardware setup as measured by OVMF, including CPU count, memory size, device configuration, secure boot policy variables (PK, KEK, db, dbx), boot variables, and TdHob/CFV data provided by the VMM. Corresponds to TPM PCR[1,7]. While dstack uses fixed devices, CPU and memory specifications can vary, so RTMR0 can be computed from the dstack image given specific CPU and RAM parameters. Without RTMR0 verification, a malicious VMM could alter the virtual hardware configuration (e.g., inject rogue devices or disable secure boot) without detection.

**RTMR1** — Runtime OS loader measurement. RTMR1 records the Linux kernel measurement as extended by OVMF, along with the GPT partition table and boot loader (shim/grub) code. Corresponds to TPM PCR[2,3,4,5]. RTMR1 can be pre-calculated from the built dstack OS image. Without RTMR1 verification, a modified kernel could be loaded that bypasses security controls while leaving application-level measurements intact.

**RTMR2** — Runtime OS component measurement. RTMR2 records the kernel command line (including the rootfs hash), initrd binary, and grub configuration/modules as measured by the boot loader. Corresponds to TPM PCR[8-15]. RTMR2 can be pre-calculated from the built dstack OS image. Without RTMR2 verification, the kernel command line could be altered (e.g., to disable security features or change the root filesystem hash) without detection.

**RTMR3** — Application-specific runtime measurement. In dstack's implementation, RTMR3 records application-level details including the compose hash, instance ID, app ID, and key provider. Unlike RTMR0-2, RTMR3 cannot be pre-calculated from the image alone because it contains runtime information. It is verified by replaying the event log: if replayed RTMR3 matches the quoted RTMR3, the event log content is authentic, and the compose hash, key provider, and other details can be extracted and verified from the event log entries. The existing compose binding check (MRConfigID) partially overlaps with RTMR3 for compose hash verification.

### How Thorough Verification Should Work

For complete attestation of a dstack-based CVM, the verification process should:

1. **Obtain golden values**: The inference provider MUST publish reference values for MRTD, RTMR0, RTMR1, and RTMR2 corresponding to each released CVM image version. These values can be computed using reproducible build tooling (e.g., dstack's `dstack-mr` tool) from the source-built image given the specific CPU and RAM configuration of the deployment.

2. **Verify MRSEAM against Intel's published values**: MRSEAM should match a known Intel TDX module release. Intel publishes TDX module versions; the expected MRSEAM value can be derived from the specific TDX module version running on the platform.

3. **Verify MRTD, RTMR0, RTMR1, RTMR2 against golden values**: These four registers, taken together, attest that the firmware, kernel, initrd, rootfs, and boot configuration all match the expected dstack OS image for the provider's declared CPU/RAM configuration. This is the only way to establish that the base operating environment is the expected one.

4. **Verify RTMR3 via event log replay**: RTMR3 contains runtime-specific measurements that cannot be pre-calculated. Replay the event log, compare the replayed RTMR3 against the quoted value, and then inspect the event log entries for expected compose hash, app ID, and key provider values.

5. **Verify MRSEAM + MRTD + RTMR0-2 as a set**: These five values together form a complete chain-of-trust from the TDX module through firmware, kernel, and OS components. Verifying only a subset (e.g., only compose binding via MRConfigID + RTMR3 event log replay) leaves significant gaps where the base system could be substituted.

### Current Stopgaps and Residual Gaps

The code supports an allowlist-based `MeasurementPolicy` for MRTD, MRSEAM, and RTMR0-3. The direct inference provider (neardirect / NEAR AI) does not publish authenticated measurement baselines in-band, but teep now provides Go-coded stopgap defaults and operator tooling to partially close this gap:

**MRSEAM — Go-coded defaults from Intel releases.** `DstackBaseMeasurementPolicy()` in `internal/attestation/dstack_defaults.go` ships an allowlist of four Intel-published MRSEAM values corresponding to TDX module versions 1.5.08, 1.5.16, 2.0.08, and 2.0.02. These are sourced from Intel's official `confidential-computing.tdx.tdx-module` release notes. The `tdx_mrseam_mrtd` factor is enforced by default for neardirect (it is NOT in `NeardirectDefaultAllowFail`).

**MRTD — Go-coded defaults from dstack reproducible builds.** The same base policy ships two MRTD values corresponding to dstack-nvidia image versions 0.5.4.1 and 0.5.5, derived from reproducible build artifacts. MRTD is deterministic for a given dstack OS image version (it measures only the virtual firmware binary). The `tdx_mrseam_mrtd` factor covers MRTD enforcement.

**RTMR0, RTMR1, RTMR2 — Per-provider observed-value defaults.** Each provider's `DefaultMeasurementPolicy()` in `internal/provider/neardirect/policy.go` ships observed RTMR values pinned from captured attestation data. These serve as drift-detection baselines. The `tdx_hardware_config` (RTMR0) and `tdx_boot_config` (RTMR1/RTMR2) factors are in `NeardirectDefaultAllowFail` — meaning they are computed and reported but do not block traffic by default. Operators can enforce them by removing these factors from their `allow_fail` configuration.

**Measurement policy merge.** Policies are resolved via a three-tier precedence: per-provider TOML config → global TOML config → Go-coded defaults. This allows operators to override or extend the built-in baselines. See `MergedMeasurementPolicy()` in `internal/config/config.go`.

**Operator bootstrapping.** The `teep verify <provider> --model <model> --update-config` command (`internal/config/update.go`) runs a full attestation verification and appends any newly observed MRSEAM, MRTD, and RTMR0-2 values to the per-provider policy section in the operator's config file. RTMR3 is deliberately excluded because it varies per instance and is verified via event log replay. The `buildMetadata()` function in `internal/attestation/report.go` emits full hex values for all measurement registers in every verification report's metadata section, making it straightforward to extract values for manual cross-checking.

**Residual risk.** Despite these stopgaps, the provider still does not publish authenticated measurement baselines in-band:
- MRSEAM and MRTD defaults are sourced from Intel and dstack reproducible builds, which are independently verifiable — these are the strongest stopgaps.
- RTMR0-2 defaults are pinned from observed attestation data, which means they cannot distinguish a legitimate provider infrastructure change from a compromised lower stack. They detect drift but do not independently verify correctness.
- No signed, versioned measurement manifest exists that teep can fetch and verify automatically. Allowlist updates require operator intervention via `--update-config` or manual config edits.

**The audit MUST flag the remaining residual risk**: RTMR0-2 observed-value pins are not independently verifiable without provider-published hardware configurations and reproducible build references. An attacker with hypervisor-level access could substitute firmware/kernel/initrd components while preserving compose binding, and the observed-value pins would only detect this if the resulting RTMR values differ from those previously captured. However, MRSEAM and MRTD enforcement (when defaults are active) significantly reduces this risk by preventing TDX module substitution and firmware replacement.

**The audit MUST recommend** that the inference provider publish:
1. The specific dstack OS version and TDX module version used in their deployments,
2. Reproducible build instructions or source references for their CVM image,
3. Pre-computed golden values for MRTD, RTMR0, RTMR1, and RTMR2 for each supported CPU/RAM configuration,
4. A versioned, signed measurement manifest (ideally Sigstore-signed and Rekor-recorded) that teep can consume automatically,
5. Advance notice of infrastructure changes that alter measurement values, so operators can pre-configure new allowlist entries.

See `docs/attestation_gaps/dstack_integrity.md` for a detailed analysis of this gap and the recommended in-band publication model.

---

## Part 4 — Verification Stage Audit Checklist

Each subsection below is an audit stage. For every stage, the auditor MUST classify each check as `enforced fail-closed`, `computed but non-blocking`, or `skipped/advisory`, and verify that enforcement matches the fail-closed policy from Part 1.

### 4.1 Model Routing

In this direct inference model, the attestation covers a single model server. There is a model mapping routing API that the teep proxy consults to determine the destination host for a particular model identity string.

Certificate Transparency MUST be consulted for the TLS certificate of this model router endpoint. This CT log report SHOULD be cached.

The audit MUST verify model routing safety controls, including:
- model-to-domain mapping cache TTL and refresh behavior,
- rejection of malformed endpoint domains (scheme/path/whitespace injection),
- rejection of domains without a dot (non-qualified hostnames),
- rejection of domains that do not end in the same subdomain as the API endpoint (eg completions.near.ai),
- exact model selection behavior when multiple endpoint entries map different models to different domains (last-wins, first-wins, or explicit conflict handling),
- behavior when duplicate model entries map to different domains in a single refresh (and whether this emits operator-visible warning),
- concurrency behavior for refreshes (singleflight or equivalent anti-stampede control),
- behavior when the discovery endpoint is unreachable (stale-on-error vs hard failure — per fail-closed policy, first-use MUST hard-fail when no stale mapping exists),
- whether IDN/punycode domains are normalized or accepted as-is, and residual homograph risk,
- CT cache keying and TTL behavior for discovery endpoint checks,
- maximum response size limits to prevent memory exhaustion from a malicious discovery response.

> NOTE: Even with all of these checks, ultimately nothing strongly authenticates this list of hostnames as belonging to the inference provider. This is a gap that can only be mitigated by ensuring that the docker images are those expected to be used by the inference provider (see CVM Image Component Verification below).

### 4.2 Attestation Fetch and Response Parsing

Upon connection to the model server, the attestation API of this model server MUST be queried and fully validated before any inference request is sent to the model server.

Certificate Transparency MUST be consulted for the TLS certificate of this model endpoint. This CT log report SHOULD be cached.

The attestation information is provided by an API endpoint as a JSON object that includes the Intel TEE attestation, NVIDIA TEE attestation, and auxiliary information such as docker compose contents and event log metadata.

The audit MUST verify the attestation response parsing path, including:
- maximum response body size limit (to prevent memory exhaustion — per Part 1 input bounds rules),
- JSON strict unmarshalling behavior (unknown fields rejection or warning — per Part 1 error handling rules),
- whether unknown-field warnings are rate-limited/deduplicated,
- handling of polymorphic response formats (array vs flat object),
- bounds checking on array lengths (model_attestations, all_attestations) to cap iteration,
- model selection logic when the response contains multiple attestation entries (exact match, prefix, or fuzzy), and whether failure to find a matching model is a hard error,
- malformed-element behavior for event-log or nested arrays (fail-whole-response vs silently drop element — per fail-closed policy, dropping is a defect),
- that no provider-asserted "verified" field is trusted without independent verification.

### 4.3 Nonce Freshness and Replay Resistance

The verifier MUST generate a fresh 32-byte cryptographic nonce per attestation attempt.

The code MUST verify nonce equality using constant-time comparison (`subtle.ConstantTimeCompare`) and fail closed on mismatch.

If cryptographic randomness fails, nonce generation MUST fail closed (no weak fallback mode). The recommended behavior is to panic or abort — never fall back to a weaker entropy source. Per Part 1 cryptographic safety rules, `crypto/rand` is the only acceptable source.

The nonce MUST be transmitted to the attestation endpoint by the proxy, not delegated to the server. The auditor must verify that the nonce originates solely from the client and is not sourced from or influenced by the server response.

### 4.4 TDX Quote Verification

Signatures over the Intel TEE attestation MUST be verified for the entire certificate chain, including:
- quote structure parsing (supported quote versions),
- PCK chain validation back to Intel trust roots,
- quote signature verification,
- debug bit check (debug enclaves rejected for production trust),
- TCB collateral and currency classification when online.

Document how trust roots are obtained (embedded/provisioned), and how third-party verification libraries are called and interpreted.

The audit MUST explicitly describe the two-pass verification architecture if present (offline first, online collateral second), and whether a Pass-1-only result (no collateral) is still treated as blocking or advisory.

### 4.5 TDX Measurement Fields and Policy

The audit MUST explicitly cover the following TDX fields from the parsed quote body:
- MRTD,
- RTMR0, RTMR1, RTMR2, RTMR3,
- MRSEAM,
- MRSIGNERSEAM,
- MROWNER,
- MROWNERCONFIG,
- MRCONFIGID,
- REPORTDATA.

For each field, the report MUST distinguish between:
- extraction/visibility only (field parsed and logged),
- structural integrity checks (length/format/consistency), and
- policy enforcement (allowlist/denylist or expected value matching).

#### Current direct-provider expectation summary

- MRCONFIGID is expected to be cryptographically checked via compose binding,
- RTMR fields are expected to be consistency-checked via event log replay when event logs are present,
- REPORTDATA is expected to be cryptographically verified via the provider-specific binding scheme,
- MRSEAM and MRTD are enforced by default via Go-coded allowlists sourced from Intel TDX module releases and dstack reproducible builds — the `tdx_mrseam_mrtd` factor is enforced (not in `NeardirectDefaultAllowFail`),
- RTMR0 is checked via `tdx_hardware_config` against per-provider observed values — allowed to fail by default (in `NeardirectDefaultAllowFail`), but operators can enforce it,
- RTMR1 and RTMR2 are checked via `tdx_boot_config` against per-provider observed values — allowed to fail by default, but operators can enforce them,
- MRSIGNERSEAM, MROWNER, MROWNERCONFIG are expected to be all-zeros for standard dstack deployments and should be documented as informational-only.

The audit MUST verify:
- how MRTD/MRSEAM/RTMR allowlists are configured (Go-coded defaults in `DstackBaseMeasurementPolicy()` and provider-specific `DefaultMeasurementPolicy()`, overridable via three-tier TOML merge),
- the three-tier policy merge precedence (per-provider TOML > global TOML > Go defaults) in `MergedMeasurementPolicy()`,
- input validation rules for allowlist values (length/encoding),
- whether allowlist mismatches are enforced fail-closed or informational (depends on whether the factor is in `allow_fail`),
- the `--update-config` bootstrapping flow for operator maintenance of observed RTMR values.

### 4.6 CVM Image Verification (Compose Binding)

The attestation API will provide a full docker compose stanza, or equivalent podman/cloud config image description, as an auxiliary portion of the attestation API response.

The code MUST calculate a hash of these contents, which MUST be verified to be properly attested in the TDX MRConfigID field.

The audit MUST verify the exact binding format expected by the implementation (for example, 48-byte MRConfigID layout, prefix rules, and byte-level comparison semantics).

The audit MUST also verify the extraction path for the app_compose field, including:
- whether the tcb_info field supports double-encoded JSON (string-within-JSON),
- that the extracted compose content is the raw value that was hashed, not a re-serialized version that could differ in whitespace or key ordering.

### 4.7 CVM Image Component Verification (Sigstore/Rekor)

The docker compose file (or podman/cloud config) will list a series of sub-images.

The teep code MUST provide an enforced allow-list of sub-images and/or sub-image repositories for a given inference provider that are allowed to appear in this docker-compose file. The hashes need not be included in the teep code, but each of these sub-images MUST be checked against Sigstore and Rekor (or equivalent systems) to establish that they are official builds and not custom variations.

Additionally, the teep code MUST provide an expected Sigstore+Rekor Signer set (as OIDC or Fulcio certs). For Sigstore+Rekor checks, only this expected signer set is to be accepted.

The audit MUST verify:
- extraction logic for image digests from compose content (regex vs structured parsing, and whether non-sha256 digest algorithms are handled or rejected),
- deduplication of extracted digests,
- all sub-images of the docker compose are in the provider's allow-list,
- Sigstore query behavior and failure handling (is a Sigstore timeout a hard fail or a skip? — per fail-closed policy, a skip is a defect unless explicitly documented as an accepted offline-mode risk),
- Rekor provenance extraction logic,
- issuer/identity checks used to classify provenance as trusted (what OIDC issuer values are accepted?),
- behavior when a digest appears in Sigstore but has no Fulcio certificate (raw key signature — is this treated as passing provenance or only presence?),
- handling of Rekor entries that lack DSSE (Dead Simple Signing Envelope) signatures — some images have Rekor transparency log entries but no DSSE envelope signatures; the `NoDSSE` field in `ImageProvenance` controls whether this is accepted.

For the neardirect provider, the current supply chain policy (`internal/provider/neardirect/policy.go`) defines three allowed image repositories:
- `datadog/agent` — Sigstore verification required, with a pinned cosign key fingerprint,
- `certbot/dns-cloudflare` — compose binding only (no Sigstore requirement),
- `nearaidev/compose-manager` — Fulcio-signed via GitHub Actions OIDC (`https://token.actions.githubusercontent.com`), with expected source repository `nearai/compose-manager`.

The audit MUST explicitly state if Sigstore/Rekor are soft-fail in default policy and what traffic is still allowed during outage conditions.

### 4.8 Event Log Integrity

If event logs are present in provider attestation payloads, the code MUST replay them and verify recomputed RTMR values against quote RTMR fields.

The audit MUST describe replay algorithm details, including:
- hash algorithm used for extend operations (SHA-384 is expected for TDX RTMRs),
- initial RTMR state (48 zero bytes),
- extend formula: `RTMR_new = SHA-384(RTMR_old || digest)`,
- handling of short digests (padding to 48 bytes),
- IMR index validation (must be within [0, 3]),
- failure semantics: does a malformed event log entry skip the entry or fail the entire replay? Per fail-closed policy, skipping is a defect.

The audit MUST separately verify pre-replay parsing behavior for event log entries, and flag any path that silently drops malformed entries before replay.

The audit MUST also state the exact security boundary of this check: event log replay validates internal consistency of event-log-derived RTMR values with quoted RTMR values, but does not by itself prove that RTMR values match an approved software baseline. If no baseline policy is enforced for MRTD/RTMR/MRSEAM-class measurements, that gap MUST be reported explicitly.

### 4.9 Encryption Binding (REPORTDATA)

The attestation report must bind channel identity and key material in a way that prevents key-substitution attacks.

For each provider, the audit MUST document the exact REPORTDATA scheme and verify it byte-for-byte.

For the NEAR AI provider, this includes verifying:
- `REPORTDATA[0:32]` = `SHA256(signing_address_bytes || tls_fingerprint_bytes)`
- `REPORTDATA[32:64]` = raw client nonce bytes (32 bytes, not hex-encoded)

The audit MUST verify:
- that `signing_address` hex decoding handles optional "0x" prefix stripping,
- that `tls_fingerprint` is decoded from hex before hashing (not hashed as ASCII),
- that decoded input lengths are validated where applicable (or residual collision/ambiguity risk is documented),
- that the concatenation order is strictly `(address || fingerprint)` with no separator or length prefix,
- that both halves of the 64-byte REPORTDATA are verified (not just the first half),
- that the binding comparison uses constant-time comparison (`subtle.ConstantTimeCompare`),
- that failure of this check is enforced (blocks forwarding), not merely logged.

The audit MUST also verify that the REPORTDATA verifier is pluggable per provider (so different providers can use different binding schemes) and that a missing or unconfigured verifier fails safely (no default pass-through — per fail-closed policy).

### 4.10 TLS Pinning and Connection-Bound Attestation

For direct inference providers that use attestation-bound TLS pinning:
- the live TLS certificate SPKI hash MUST be extracted from the same active TLS connection used for attestation,
- the SPKI hash algorithm MUST be documented (SHA-256 of DER-encoded SubjectPublicKeyInfo is standard),
- the attested TLS fingerprint MUST match the live connection SPKI using exact string comparison,
- the comparison implementation MUST be evaluated for constant-time behavior (or explicitly justified if not constant-time),
- attestation fetch and inference request MUST occur on the same TLS connection to prevent TOCTOU swaps,
- closing the response body MUST close the underlying TCP connection (preventing connection reuse for a different unattested host),
- any TLS verification bypass mode (for example, `InsecureSkipVerify` / custom pinning replacing CA checks) MUST be justified and cryptographically compensated by attestation checks,
- the `ServerName` field MUST still be set on the TLS config (for SNI) even when CA verification is bypassed.

The audit MUST verify pin-cache behavior:
- TTL and maximum entries per domain,
- eviction strategy (LRU, random, or oldest) and whether it is bounded,
- that a cache miss always triggers full re-attestation (never a pass-through — per fail-closed policy),
- that concurrent attestation attempts for the same (domain, SPKI) are collapsed (singleflight) with a double-check-after-winning pattern,
- that the singleflight key includes both domain and SPKI (so a certificate rotation triggers a new attestation rather than coalescing with the old one).

### 4.11 NVIDIA TEE Verification Depth

The audit MUST verify both layers when present:

**Local NVIDIA evidence verification (EAT/SPDM):**
- EAT JSON parsing and top-level nonce verification (constant-time),
- per-GPU certificate chain validation against a pinned NVIDIA root CA (not system trust store),
- the root CA pinning method (embedded certificate with hardcoded SHA-256 fingerprint check),
- SPDM message parsing (GET_MEASUREMENTS request/response structure, variable-length field handling),
- SPDM signature verification algorithm (ECDSA P-384 with SHA-384 is expected),
- the signed-data construction (must include both request and response-minus-signature, in order),
- all-or-nothing semantics (one GPU failure must fail the entire check — per fail-closed policy),
- extraction of GPU count and architecture for reporting.

**Remote NVIDIA NRAS verification:**
- JWT signature verification using a cached JWKS endpoint (accepted algorithms: ES256, ES384, ES512 only — HS256 MUST be rejected),
- JWKS caching behavior (auto-refresh, rate-limited unknown-kid fallback),
- JWT claims validation (expiration, issuer, overall attestation result),
- nonce forwarding to NRAS (is it the same client-generated nonce?),
- the exact NRAS endpoint URL and whether it is configurable or hardcoded.

If offline mode exists, the audit MUST state which NVIDIA checks remain active and which are skipped.

---

## Part 5 — Operational Safety

### 5.1 Enforcement Policy and Failure Semantics

The audit report MUST include a table of verification factors with:
- pass/fail/skip semantics,
- whether the factor is enforced by policy,
- whether failure blocks request forwarding,
- whether failure disables confidentiality guarantees without blocking traffic.

This section is required to prevent regressions where checks continue to be reported but are no longer security-enforcing.

The audit MUST also verify:
- the mechanism by which the enforced factor list is configured (hardcoded defaults, config file, environment),
- that misspelled or unknown factor names in the enforcement config are rejected at startup (not silently ignored — per Part 1 error handling rules),
- that there is a code path (`Blocked()` or equivalent) that inspects the report before every forwarded request and returns an error response to the client when any enforced factor has failed.

Teep uses an inverted enforcement model: any factor NOT in the provider's `DefaultAllowFail` list is enforced by default. Adding a new factor automatically enforces it — this is safer than a positive enforce list. The neardirect provider uses `NeardirectDefaultAllowFail` (defined in `internal/attestation/report.go`), which is stricter than the global `DefaultAllowFail`.

The current neardirect-specific allowed-to-fail factors are:
- `tdx_hardware_config` — RTMR0 (varies per deployment hardware configuration),
- `tdx_boot_config` — RTMR1/RTMR2 (varies per dstack image build),
- `e2ee_usable` — uses the Deferred factor mechanism: starts as Skip with `Deferred: true` in the proxy path, exempt from Skip→Fail promotion even when enforced; promoted to Pass after successful E2EE relay, or demoted to Fail on decryption failure,
- `cpu_gpu_chain` — not yet implemented,
- `measured_model_weights` — not yet implemented,
- `cpu_id_registry` — Proof-of-Cloud hardware registry.

All other factors are enforced by default, including:
- `nonce_match` — prevents replay of stale attestations,
- `tdx_quote_present`, `tdx_quote_structure` — TDX quote integrity,
- `tdx_cert_chain` — validates PCK chain to Intel roots,
- `tdx_quote_signature` — validates quote signature,
- `tdx_debug_disabled` — prevents debug enclaves from being trusted,
- `tdx_mrseam_mrtd` — enforces MRSEAM and MRTD allowlists (Go-coded defaults from Intel and dstack),
- `signing_key_present` — ensures the enclave provided a public key,
- `tdx_reportdata_binding` — prevents key-substitution MITM,
- `tdx_tcb_not_revoked` — rejects revoked TCB levels,
- `intel_pcs_collateral`, `tdx_tcb_current` — Intel PCS collateral and TCB currency,
- `nvidia_payload_present`, `nvidia_signature`, `nvidia_claims`, `nvidia_nonce_client_bound`, `nvidia_nras_verified` — NVIDIA attestation factors,
- `e2ee_capable` — model backend advertises E2EE support,
- `tls_key_binding` — TLS certificate SPKI binding,
- `compose_binding` — enforces image/config binding to MRCONFIGID,
- `sigstore_verification` — enforces Sigstore presence for image digests,
- `build_transparency_log` — enforces Rekor provenance,
- `event_log_integrity` — enforces RTMR replay consistency when event logs are present.

The audit MUST evaluate whether additional factors should be enforced by default and document the rationale for the current enforcement boundary.

### 5.2 Verification Cache Safety

The necessary verification information MAY be cached locally so that Sigstore and Rekor do not need to be queried on every single connection attempt.

However, the attestation report MUST be verified against either cached or live data, for EACH new TLS connection to the API provider.

The audit MUST explicitly document each cache layer, its keys, TTLs, expiry/pruning behavior, maximum entry limits, and whether stale data is ever served. Specifically:

| Cache | Expected Keys | Expected TTL | Security-Critical Properties |
|-------|--------------|-------------|------------------------------|
| Attestation report cache | (provider, model) | ~minutes | Signing key MUST NOT be cached; must be fetched fresh for each E2EE session |
| Negative cache | (provider, model) | ~seconds | Must prevent upstream hammering; must expire so recovery is possible |
| SPKI pin cache | (domain, spkiHash) | ~hour | Must be populated only after successful attestation; eviction must force re-attestation |
| Endpoint mapping cache | model→domain | ~minutes | Stale mapping must not bypass attestation |

The audit MUST verify that cache eviction under memory pressure does not silently allow unattested connections. A cache miss MUST trigger re-attestation, never a pass-through. Per the fail-closed policy, any cache failure path that allows forwarding is a defect.

### 5.3 Negative Cache and Failure Recovery

The audit MUST verify the negative cache behavior:
- that a failed attestation attempt records a negative entry preventing repeated upstream requests,
- that negative entries expire after a bounded TTL (not indefinitely cached),
- that the negative cache has bounded size with eviction of expired entries under pressure,
- that a negative cache hit returns a clear error to the client (for example, HTTP 503) rather than silently failing open or forwarding unauthenticated.

### 5.4 Connection Lifetime Safety

TLS connections to the model server MUST be closed after each request-response cycle (Connection: close) to ensure each new request triggers a fresh attestation or SPKI cache check.

If the implementation reuses connections, the audit MUST verify that re-attestation is correctly triggered on every new request, not just on new connections.

The audit MUST verify:
- that the response body wrapper closes the underlying TCP connection when the body is consumed or closed,
- that connection read/write timeouts are set and reasonable (preventing indefinite hangs),
- that a half-closed or errored connection cannot be mistakenly reused for a subsequent request.

### 5.5 Offline Mode Safety

If the system supports an offline mode, the audit MUST enumerate exactly which checks are skipped (for example, Intel PCS collateral, NRAS, Sigstore, Rekor, Proof-of-Cloud) and which checks still execute locally (for example, quote parsing/signature checks, report-data binding, event-log replay).

For the pinned connection path, the audit MUST verify whether offline mode is honored (the PinnedHandler receives an `offline` flag). The offline flag must suppress only network-dependent checks — all local cryptographic verification must remain active.

The report MUST include residual risk of running in offline mode.

### 5.6 Proof-of-Cloud

Ensure that the code verifies that the machine ID from the attestation is covered in proof-of-cloud.

The audit MUST document:
- machine identity derivation inputs (for example, PPID from the PCK certificate),
- remote registry verification flow,
- quorum/threshold requirements if multiple trust servers are used (expected: 3-of-3 nonce collection, then chained partial signatures),
- behavior when Proof-of-Cloud is unavailable (skip with informational status, or hard fail),
- whether the Proof-of-Cloud result is cached and under what conditions it is re-queried.

Track future expansion items separately (for example, DCEA and TPM quote integration), but keep this audit focused on checks currently implemented and required for production security decisions.

---

## Part 6 — Input/Output Safety

### 6.1 HTTP Request Construction Safety

For direct inference providers that construct raw HTTP requests on the underlying TLS connection (bypassing Go's http.Client connection pooling), the audit MUST verify:
- that the Host header is always set and matches the attested domain,
- that Content-Length is derived from the actual body length (not caller-supplied),
- that no user-supplied data is interpolated into HTTP request lines or headers without sanitization (HTTP header injection prevention),
- that header values reject CR/LF characters (or equivalent canonicalization/sanitization is applied),
- that the request path is constructed from trusted constants plus URL-encoded query parameters.

### 6.2 Response Size and Resource Limits

The audit MUST verify that all HTTP response bodies read by the proxy are bounded:
- attestation responses (recommended: ≤1 MiB),
- endpoint discovery responses (recommended: ≤1 MiB),
- SSE streaming buffers (bounded scanner buffer sizes with pooling),
- any other external data read during verification (Sigstore, Rekor, NRAS, PCS).

Per Part 1 input bounds rules, unbounded reads from untrusted sources represent a denial-of-service vector and MUST be flagged.

---

## Part 7 — Report Requirements

### Report Writing

The report MUST avoid vague language such as "looks secure" without code-backed evidence.

Each finding MUST include:
- severity and exploitability context,
- exact impacted control and whether it is currently enforced,
- realistic impact statement (integrity, confidentiality, availability),
- remediation guidance with concrete code-level direction,
- at least one source citation proving current behavior.

When no findings are present for a section, the report MUST explicitly state "no issues found in this section" and still note any residual risk or testing gap.

### Fail-Closed Verification Summary

The report MUST include a dedicated section confirming that every error path in the attestation and forwarding pipeline was checked against the fail-closed policy from Part 1. For each code path where an error is caught, the report MUST state whether the error results in request blocking or whether it falls through — and flag any fall-through as a critical finding.
