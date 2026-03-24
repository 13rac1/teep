# Gateway Inference Provider Audit

This repository implements a proxy that ensures private LLM inference by performing attestation-bound TLS pinning to a TEE-attested API gateway, which in turn routes traffic to TEE-attested model inference backends. The proxy validates that both the gateway and the model backend run genuine TEE hardware with verifiable software, prevents man-in-the-middle attacks through cryptographic binding of the TLS channel to the gateway's attestation report, and protects request and response confidentiality through E2EE using a signing key obtained from the model backend's attestation.

Please verify every stage of attestation for the requested provider, following this audit guide to produce a detailed report.

This audit applies to gateway inference providers, where a single TEE-attested API gateway load balancer receives all client traffic and forwards it to model-specific TEE-attested inference backends. This means there are two layers of attestation to verify:
- **Tier 1–3 (model):** the model inference backend's TDX quote, NVIDIA attestation, compose binding, event log, REPORTDATA binding, and supply chain verification,
- **Tier 4 (gateway):** the gateway's own TDX quote, compose binding, event log, REPORTDATA binding, and TLS certificate binding.

Additionally, the model backend's attestation provides an E2EE signing key that the proxy uses to encrypt request messages and decrypt response messages, protecting header and body confidentiality even if the gateway is compromised.

The report MUST cite the source code locations relevant to BOTH positive AND negative audit findings, using relative markdown links to the source locations, for human validation of audit claims.

The report MUST also distinguish between:
- checks that are computed but do not block traffic, and
- checks that are enforced fail-closed (request rejected on failure).

## Quality Bar and Deliverables

Gateway-provider audits MUST meet the following quality bar:
- include an executive summary with severity counts and a one-paragraph overall risk statement,
- present findings first (ordered by severity) before narrative walkthrough,
- include at least one concrete positive control and one concrete negative/residual-risk observation for every major section,
- classify every security check as one of: `enforced fail-closed`, `computed but non-blocking`, or `skipped/advisory`,
- separate implementation fact from recommendation (no implicit policy assumptions),
- quantify residual risk when a control is informational-only,
- cite source locations for every substantive claim (positive and negative).

The final report MUST include all of the following artifacts:
- findings summary table (severity, location, impact),
- verification-factor matrix with pass/fail/skip and enforcement status — covering BOTH model factors (Tier 1–3) and gateway factors (Tier 4),
- cache-layer table (keys, TTL, bounds, eviction, stale behavior),
- offline-mode matrix (active checks vs skipped checks),
- explicit "open questions / assumptions" section when behavior cannot be proven from code.

## Gateway Architecture Overview

Unlike direct inference providers where the proxy connects directly to the model server, the gateway architecture interposes a TEE-attested load balancer (the "gateway") between the proxy and the model backend:

```
Client → teep proxy → cloud-api.near.ai (gateway CVM) → model backend CVM
                          ↑ TLS pinned               ↑ internal routing
                          ↑ gateway attestation       ↑ model attestation
```

The gateway host is fixed (not resolved via a model routing API). The proxy opens a single TLS connection to the gateway, performs attestation on that connection (receiving both gateway and model attestation in a single response), and then sends the chat request on the same connection.

The audit MUST verify:
- that the gateway host is a hardcoded constant (no DNS-based routing indirection),
- that no model routing / endpoint resolution is performed (unlike direct inference providers),
- that the gateway attestation endpoint returns both gateway and model attestation in a single response,
- that there is no code path that allows connecting to an unattested alternate host.

## Attestation Fetch and Response Parsing

Upon connection to the gateway, the attestation API MUST be queried and fully validated before any inference request is sent. A single attestation request returns a combined response containing both the gateway attestation and the model attestation.

Certificate Transparency MUST be consulted for the TLS certificate of the gateway endpoint. This CT log report SHOULD be cached.

The attestation response is a JSON object that includes:
- a `gateway_attestation` section with the gateway's own TDX quote, event log, TLS certificate fingerprint, and tcb_info (containing app_compose), and
- a `model_attestations` array with per-model Intel TDX attestation, NVIDIA TEE attestation, signing key, and auxiliary information.

The audit MUST verify the attestation response parsing path, including:
- maximum response body size limit (to prevent memory exhaustion) — note that gateway responses are expected to be larger than direct inference responses due to the presence of two attestation payloads,
- JSON strict unmarshalling behavior (unknown fields rejection or warning) — this applies to BOTH the top-level gateway response AND the inner model attestation,
- whether unknown-field warnings are rate-limited/deduplicated,
- handling of polymorphic response formats for the model attestation (array vs flat object),
- bounds checking on array lengths (model_attestations, all_attestations) to cap iteration,
- model selection logic when the response contains multiple attestation entries (exact match, prefix, or fuzzy), and whether failure to find a matching model is a hard error,
- that the gateway event_log field is a JSON string (not a native array) and is correctly double-parsed,
- that the gateway tcb_info field supports double-encoded JSON (string-within-JSON) for app_compose extraction,
- malformed-element behavior for event-log or nested arrays (fail-whole-response vs silently drop element),
- that no provider-asserted "verified" field is trusted without independent verification.

### Nonce Freshness and Replay Resistance

The verifier MUST generate a fresh 32-byte cryptographic nonce per attestation attempt.

In the gateway model, a single nonce is sent to the gateway, which shares it with the model backend. Both the gateway and the model backend echo the same nonce back. The audit MUST verify:
- that exactly one nonce is generated per attestation attempt (not separate nonces for gateway and model),
- that the single nonce is transmitted to the gateway endpoint by the proxy, not delegated to the server,
- that the gateway's echoed nonce is verified using constant-time comparison against the client-generated nonce,
- that the model's echoed nonce is verified using constant-time comparison against the same client-generated nonce,
- that both nonce checks fail closed on mismatch,
- that the nonce originates solely from the client and is not sourced from or influenced by the server response.

If cryptographic randomness fails, nonce generation MUST fail closed (no weak fallback mode). The recommended behavior is to panic or abort — never fall back to a weaker entropy source.

### TDX Quote Verification (Model Backend)

Signatures over the model backend's Intel TEE attestation MUST be verified for the entire certificate chain, including:
- quote structure parsing (supported quote versions),
- PCK chain validation back to Intel trust roots,
- quote signature verification,
- debug bit check (debug enclaves rejected for production trust),
- TCB collateral and currency classification when online.

Document how trust roots are obtained (embedded/provisioned), and how third-party verification libraries are called and interpreted.

The audit MUST explicitly describe the two-pass verification architecture if present (offline first, online collateral second), and whether a Pass-1-only result (no collateral) is still treated as blocking or advisory.

### TDX Quote Verification (Gateway)

The gateway's TDX quote MUST undergo the same verification as the model backend's quote. The audit MUST verify that all of the following are checked for the gateway quote:
- quote structure parsing,
- PCK chain validation back to Intel trust roots,
- quote signature verification,
- debug bit check.

The audit MUST verify that the gateway TDX verification uses the same code path / library as the model TDX verification (to avoid diverging security standards).

### TDX Measurement Fields and Policy Expectations

The audit MUST explicitly cover the following TDX fields from the parsed quote body, for BOTH the model backend AND the gateway:
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

#### What Each Register Measures

Understanding the security semantics of each register is critical for assessing attestation completeness. The following describes the trust-chain role of each register, based on Intel TDX architecture and the dstack CVM implementation used by inference providers:

**MRSEAM** — Measurement of the TDX module (SEAM firmware). This 48-byte hash represents the identity and integrity of the Intel TDX module running in Secure Arbitration Mode. Intel signs and guarantees TDX module integrity; the MRSEAM value should correspond to a known Intel-released TDX module version. Verification of MRSEAM ensures the TDX firmware has not been tampered with and is a recognised, trusted version. Without MRSEAM verification, an attacker who compromises the hypervisor could potentially load a modified TDX module that subverts TD isolation guarantees.

**MRTD** — Measurement Register for Trust Domain. This 48-byte hash captures the initial memory contents and configuration of the TD at creation time, specifically the virtual firmware (OVMF/TDVF) measurement. MRTD is measured by the TDX module in SEAM mode before any guest code executes, making it the root-of-trust anchor for the entire guest boot chain. In dstack's architecture, MRTD corresponds to TPM PCR[0] (FirmwareCode). MRTD can be pre-calculated from the built dstack OS image. Without MRTD verification, an attacker could substitute a different virtual firmware (e.g., one that leaks secrets or skips subsequent measured boot steps) while preserving the correct compose hash and RTMR3 values.

**RTMR0** — Runtime firmware configuration measurement. RTMR0 records the CVM's virtual hardware setup as measured by OVMF, including CPU count, memory size, device configuration, secure boot policy variables (PK, KEK, db, dbx), boot variables, and TdHob/CFV data provided by the VMM. Corresponds to TPM PCR[1,7]. While dstack uses fixed devices, CPU and memory specifications can vary, so RTMR0 can be computed from the dstack image given specific CPU and RAM parameters. Without RTMR0 verification, a malicious VMM could alter the virtual hardware configuration (e.g., inject rogue devices or disable secure boot) without detection.

**RTMR1** — Runtime OS loader measurement. RTMR1 records the Linux kernel measurement as extended by OVMF, along with the GPT partition table and boot loader (shim/grub) code. Corresponds to TPM PCR[2,3,4,5]. RTMR1 can be pre-calculated from the built dstack OS image. Without RTMR1 verification, a modified kernel could be loaded that bypasses security controls while leaving application-level measurements intact.

**RTMR2** — Runtime OS component measurement. RTMR2 records the kernel command line (including the rootfs hash), initrd binary, and grub configuration/modules as measured by the boot loader. Corresponds to TPM PCR[8-15]. RTMR2 can be pre-calculated from the built dstack OS image. Without RTMR2 verification, the kernel command line could be altered (e.g., to disable security features or change the root filesystem hash) without detection.

**RTMR3** — Application-specific runtime measurement. In dstack's implementation, RTMR3 records application-level details including the compose hash, instance ID, app ID, and key provider. Unlike RTMR0-2, RTMR3 cannot be pre-calculated from the image alone because it contains runtime information. It is verified by replaying the event log: if replayed RTMR3 matches the quoted RTMR3, the event log content is authentic, and the compose hash, key provider, and other details can be extracted and verified from the event log entries. The existing compose binding check (MRConfigID) partially overlaps with RTMR3 for compose hash verification.

#### How Thorough Verification Should Work

For complete attestation of a dstack-based CVM — applicable to BOTH the gateway CVM and the model backend CVM — the verification process should:

1. **Obtain golden values**: The inference provider MUST publish reference values for MRTD, RTMR0, RTMR1, and RTMR2 corresponding to each released CVM image version, for both the gateway and model backend deployments. These values can be computed using reproducible build tooling (e.g., dstack's `dstack-mr` tool) from the source-built image given the specific CPU and RAM configuration of the deployment.

2. **Verify MRSEAM against Intel's published values**: MRSEAM should match a known Intel TDX module release. Intel publishes TDX module versions; the expected MRSEAM value can be derived from the specific TDX module version running on the platform.

3. **Verify MRTD, RTMR0, RTMR1, RTMR2 against golden values**: These four registers, taken together, attest that the firmware, kernel, initrd, rootfs, and boot configuration all match the expected dstack OS image for the provider's declared CPU/RAM configuration. This is the only way to establish that the base operating environment is the expected one.

4. **Verify RTMR3 via event log replay**: RTMR3 contains runtime-specific measurements that cannot be pre-calculated. Replay the event log, compare the replayed RTMR3 against the quoted value, and then inspect the event log entries for expected compose hash, app ID, and key provider values.

5. **Verify MRSEAM + MRTD + RTMR0-2 as a set**: These five values together form a complete chain-of-trust from the TDX module through firmware, kernel, and OS components. Verifying only a subset (e.g., only compose binding via MRConfigID + RTMR3 event log replay) leaves significant gaps where the base system could be substituted.

#### Current Gap: Inference Provider Has Not Published Golden Values

The code currently supports an allowlist-based `MeasurementPolicy` for MRTD, MRSEAM, and RTMR0-3, but the current gateway inference provider (NearCloud / NEAR AI) does not publish:
- reproducible build instructions or pre-built images for their gateway CVM or model backend CVM,
- golden/reference values for MRTD, MRSEAM, RTMR0, RTMR1, or RTMR2 for either the gateway or the model backend,
- documentation of their specific CPU/RAM configuration (needed to compute RTMR0) for either CVM type,
- the dstack OS version or TDX module version deployed on either the gateway or the model backends.

Because these reference values are unavailable, the code does not currently enforce checking MRSEAM, MRTD, or RTMR0-2 against any baseline for either the gateway or the model backend. The `MeasurementPolicy` allowlists remain empty, meaning these fields are extracted and logged but not policy-enforced. This is the correct behavior given the absence of reference data — enforcing against fabricated or unverified golden values would provide false assurance.

**The audit MUST flag this as a residual risk**: without MRSEAM/MRTD/RTMR0-2 verification for BOTH the gateway and the model backend, the attestation trusts any TDX module version and any VM image that happens to produce the correct compose hash (MRConfigID) and valid RTMR3 event log. This means:
- A compromised or outdated TDX module would not be detected (MRSEAM gap) — on either the gateway or model backend,
- A substituted virtual firmware could bypass measured boot (MRTD gap),
- A modified kernel, initrd, or rootfs could go undetected (RTMR0-2 gap),
- Only the application-layer compose binding (MRConfigID) and event log replay (RTMR3) provide assurance, which is insufficient for full CVM integrity.

**The audit MUST recommend** that the inference provider (NearCloud / NEAR AI) publish:
1. The specific dstack OS version (or equivalent CVM image) and TDX module version used in their gateway and model backend deployments,
2. Reproducible build instructions or source references for both CVM images,
3. Pre-computed golden values for MRTD, RTMR0, RTMR1, and RTMR2 for each supported CPU/RAM configuration, for both gateway and model backend,
4. The expected MRSEAM value for the Intel TDX module version deployed on their hardware,
5. A versioned manifest or API endpoint that maps deployment configurations to expected measurement values, so that verifiers like teep can populate `MeasurementPolicy` allowlists automatically.

Until this information is provided, the attestation provides application-layer assurance (compose hash and RTMR3) but not full system-level assurance. The auditor MUST quantify this gap by noting that an attacker with hypervisor-level access could substitute the firmware/kernel/initrd while preserving compose binding, and report it as a high-severity residual risk. This applies independently to both the gateway CVM and the model backend CVM.

#### Current gateway-provider expectation summary

**Model backend attestation (Tier 1–3):**
- MRCONFIGID is expected to be cryptographically checked via compose binding,
- RTMR fields are expected to be consistency-checked via event log replay when event logs are present,
- REPORTDATA is expected to be cryptographically verified via the nearai binding scheme (sha256(signing_address + tls_fingerprint) + nonce),
- MRSEAM, MRTD, RTMR0, RTMR1, and RTMR2 are currently informational-only due to the absence of provider-published golden values — this MUST be documented as a gap with high residual risk,
- MRSIGNERSEAM, MROWNER, MROWNERCONFIG are expected to be all-zeros for standard dstack deployments and should be documented as informational-only.

**Gateway attestation (Tier 4):**
- MRCONFIGID is expected to be cryptographically checked via gateway compose binding,
- RTMR fields are expected to be consistency-checked via gateway event log replay when gateway event logs are present,
- REPORTDATA is expected to be cryptographically verified via the gateway binding scheme (sha256(tls_fingerprint) + nonce — note: no signing_address for the gateway),
- MRSEAM, MRTD, RTMR0, RTMR1, and RTMR2 are currently informational-only (same gap as model backend),
- MRSIGNERSEAM, MROWNER, MROWNERCONFIG are expected to be all-zeros.

When allowlist policy exists (i.e., when the inference provider eventually publishes golden values), the audit MUST verify:
- how MRTD/MRSEAM/RTMR allowlists are configured (and whether separate policies can be specified for gateway vs model backends),
- input validation rules for allowlist values (length/encoding),
- whether allowlist mismatches are enforced fail-closed or informational.

### CVM Image Verification (Model Backend)

The model backend attestation API provides a full docker compose stanza, or equivalent podman/cloud config image description, as an auxiliary portion of the attestation API response.

The code MUST calculate a hash of these contents, which MUST be verified to be properly attested in the model backend's TDX MRConfigID field.

The audit MUST verify the exact binding format expected by the implementation (for example, 48-byte MRConfigID layout, prefix rules, and byte-level comparison semantics).

The audit MUST also verify the extraction path for the app_compose field, including:
- whether the tcb_info field supports double-encoded JSON (string-within-JSON),
- that the extracted compose content is the raw value that was hashed, not a re-serialized version that could differ in whitespace or key ordering.

### CVM Image Verification (Gateway)

The gateway attestation also provides an app_compose via its tcb_info field. The code MUST calculate a hash of the gateway's app_compose and verify it matches the gateway's TDX MRConfigID field.

The audit MUST verify:
- that the gateway's app_compose extraction path correctly handles double-encoded JSON (the gateway's tcb_info may be a JSON string containing escaped JSON),
- that the gateway compose binding uses the same verification function as the model compose binding,
- that the gateway compose binding check is a separate enforced factor from the model compose binding check.

### CVM Image Component Verification

The docker compose files (or podman/cloud configs) for BOTH the gateway and model backend will list a series of sub-images.

The teep code MUST provide an enforced allow-list of sub-images and/or sub-image repositories for a given inference provider that are allowed to appear in these docker-compose files. The hashes need not be included in the teep code, but each of these sub-images MUST be checked against Sigstore and Rekor (or equivalent systems) to establish that they are official builds and not custom variations.

Additionally, the teep code MUST provide an expected Sigstore+Rekor Signer set (as OIDC or Fulcio certs). For Sigstore+Rekor checks, only this expected signer set is to be accepted.

The audit MUST verify:
- extraction logic for image digests from compose content (regex vs structured parsing, and whether non-sha256 digest algorithms are handled or rejected),
- deduplication of extracted digests,
- all sub-images of BOTH the model backend and gateway docker compose files are in the provider's allow-list,
- Sigstore query behavior and failure handling (is a Sigstore timeout a hard fail or a skip?),
- Rekor provenance extraction logic,
- issuer/identity checks used to classify provenance as trusted (what OIDC issuer values are accepted?),
- behavior when a digest appears in Sigstore but has no Fulcio certificate (raw key signature — is this treated as passing provenance or only presence?).

The audit MUST explicitly state if Sigstore/Rekor are soft-fail in default policy and what traffic is still allowed during outage conditions.

> NOTE: The current implementation performs Sigstore/Rekor checks only on the model backend's compose images. The audit MUST flag whether gateway compose images are also subject to these checks, and if not, report this as a gap.

### Verification Cache Safety

The necessary verification information MAY be cached locally so that Sigstore and Rekor do not need to be queried on every single connection attempt.

However, the attestation report MUST be verified against either cached or live data, for EACH new TLS connection to the gateway.

The audit MUST explicitly document each cache layer, its keys, TTLs, expiry/pruning behavior, maximum entry limits, and whether stale data is ever served. Specifically:

| Cache | Expected Keys | Expected TTL | Security-Critical Properties |
|-------|--------------|-------------|------------------------------|
| Attestation report cache | (provider, model) | ~minutes | Signing key MUST NOT be cached; must be fetched fresh for each E2EE session |
| Negative cache | (provider, model) | ~seconds | Must prevent upstream hammering; must expire so recovery is possible |
| SPKI pin cache | (domain, spkiHash) | ~hour | Must be populated only after successful attestation of BOTH gateway and model; eviction must force re-attestation |
| Signing key cache | (provider, model) | ~minute | Shorter than attestation cache; holds REPORTDATA-verified signing key for E2EE key exchange |

The audit MUST verify that cache eviction under memory pressure does not silently allow unattested connections. A cache miss MUST trigger re-attestation of BOTH gateway and model, never a pass-through.

The audit MUST also verify that the SPKI pin cache uses the gateway's domain and SPKI (since the proxy connects to the gateway, not the model backend directly).

### Encryption Binding — Model Backend REPORTDATA

The model backend's attestation report must bind channel identity and key material in a way that prevents key-substitution attacks.

For the model backend in the NearCloud provider, REPORTDATA uses the same scheme as the direct NEAR AI provider:
- `REPORTDATA[0:32]` = `SHA256(signing_address_bytes || tls_fingerprint_bytes)`
- `REPORTDATA[32:64]` = raw client nonce bytes (32 bytes, not hex-encoded)

The audit MUST verify:
- that `signing_address` hex decoding handles optional "0x" prefix stripping,
- that `tls_fingerprint` is decoded from hex before hashing (not hashed as ASCII),
- that decoded input lengths are validated where applicable (or residual collision/ambiguity risk is documented),
- that the concatenation order is strictly `(address || fingerprint)` with no separator or length prefix,
- that both halves of the 64-byte REPORTDATA are verified (not just the first half),
- that the binding comparison uses constant-time comparison (`subtle.ConstantTimeCompare` or equivalent),
- that failure of this check is enforced (blocks forwarding), not merely logged.

The audit MUST also verify that the model backend's REPORTDATA verifier is the shared nearai ReportDataVerifier (not a different implementation), and that a missing or unconfigured verifier fails safely (no default pass-through).

> NOTE: The model backend's `tls_cert_fingerprint` in REPORTDATA refers to the model backend's own TLS certificate, not the gateway's. Since the proxy connects to the gateway (not the model backend), the proxy cannot directly verify the model backend's TLS fingerprint against a live connection. The model backend's REPORTDATA binding establishes that the signing key for E2EE is bound to the attested model backend — but the TLS channel pinning is handled separately by the gateway attestation. The audit MUST document this trust delegation and note that the gateway's TLS attestation is the link that binds the live TLS connection to the overall attestation chain.

### Encryption Binding — Gateway REPORTDATA

The gateway's attestation report must bind the gateway's TLS certificate identity to its TDX quote.

For the gateway, REPORTDATA uses a different scheme from the model backend:
- `REPORTDATA[0:32]` = `SHA256(tls_fingerprint_bytes)` — note: NO signing_address, only the TLS fingerprint
- `REPORTDATA[32:64]` = raw client nonce bytes (32 bytes, not hex-encoded)

The audit MUST verify:
- that `tls_fingerprint` is decoded from hex before hashing (not hashed as ASCII),
- that an absent `tls_cert_fingerprint` results in a hard failure (not a skip),
- that both halves of the 64-byte REPORTDATA are verified,
- that the binding comparison uses constant-time comparison,
- that failure of this check is enforced (blocks the request).

The audit MUST also verify that the gateway REPORTDATA verifier is a separate implementation from the model REPORTDATA verifier (because the binding scheme differs), and that the correct verifier is used for each quote.

### TLS Pinning and Connection-Bound Attestation (Gateway)

For the gateway inference provider:
- the live TLS certificate SPKI hash MUST be extracted from the TLS connection to the gateway,
- the SPKI hash algorithm MUST be documented (SHA-256 of DER-encoded SubjectPublicKeyInfo is standard),
- the gateway's attested `tls_cert_fingerprint` MUST match the live connection SPKI using constant-time hex comparison,
- this comparison MUST be a hard error if it fails (not a skip),
- attestation fetch and inference request MUST occur on the same TLS connection to prevent TOCTOU swaps,
- closing the response body MUST close the underlying TCP connection (preventing connection reuse for a different unattested host),
- any TLS verification bypass mode (for example, `InsecureSkipVerify` / custom pinning replacing CA checks) MUST be justified and cryptographically compensated by attestation checks,
- the `ServerName` field MUST still be set on the TLS config (for SNI) even when CA verification is bypassed.

The audit MUST verify that:
- the gateway's `tls_cert_fingerprint` is compared against the live SPKI (not the model backend's fingerprint),
- the model backend's `tls_cert_fingerprint` is logged but NOT compared against the live SPKI (since the proxy connects to the gateway, not the model backend directly),
- there is no code path that confuses the gateway and model TLS fingerprints.

The audit MUST verify pin-cache behavior:
- TTL and maximum entries per domain,
- eviction strategy (LRU, random, or oldest) and whether it is bounded,
- that a cache miss always triggers full re-attestation (including both gateway and model), never a pass-through,
- that concurrent attestation attempts for the same (domain, SPKI) are collapsed (singleflight) with a double-check-after-winning pattern,
- that the singleflight key includes both domain and SPKI (so a certificate rotation triggers a new attestation rather than coalescing with the old one).

### E2EE: End-to-End Encryption via Model Signing Key

In the gateway inference model, the model backend's attestation provides a secp256k1 public key (`signing_key`) that is bound to the model backend's TDX quote via REPORTDATA. The proxy uses this key for ECDH-based E2EE, encrypting request messages so that even the gateway cannot read them, and decrypting response messages that were encrypted by the model backend.

The audit MUST verify:
- that the `signing_key` is obtained from the model backend's attestation (not the gateway's attestation),
- that the `signing_key` is present in the attestation response and validated as a 130-hex-character uncompressed secp256k1 public key starting with "04",
- that the `signing_key` is bound to the model backend's TDX quote via `tdx_reportdata_binding` — without this binding, a MITM could substitute the key,
- that the E2EE session is created with a fresh ephemeral key pair per request,
- that the ephemeral public key is transmitted to the model backend (typically via HTTP headers),
- that the ECDH shared secret derivation uses HKDF-SHA256 with the expected info string,
- that AES-256-GCM is used for symmetric encryption/decryption with random nonces,
- that the session private key is zeroed after use (`Session.Zero()`),
- that E2EE is only activated when `tdx_reportdata_binding` has passed — if binding fails, E2EE is refused (not silently degraded to plaintext).

#### E2EE Header Protection

A key security benefit of the gateway inference model is that E2EE protects request and response content from the gateway. The audit MUST verify:
- that request message content is encrypted before being sent through the gateway,
- that response message content (both streaming SSE chunks and non-streaming JSON bodies) is decrypted by the proxy,
- that non-encrypted content fields in an E2EE session are treated as errors (not silently accepted as plaintext),
- that the "role" and "refusal" fields are correctly exempted from encryption expectations,
- that streaming SSE decryption handles all encrypted delta fields (content, reasoning_content, etc.), not just a hardcoded subset.

#### Signing Key Cache

The signing key (model backend's public key) MAY be cached with a short TTL to avoid re-fetching attestation on every request.

The audit MUST verify:
- that the signing key cache has a shorter TTL than the attestation report cache,
- that the signing key is only cached after successful REPORTDATA binding verification,
- that a key rotation (different signing key from the same provider/model) emits a warning,
- that the cached signing key is the one verified by REPORTDATA binding, not from a subsequent unverified response.

### NVIDIA TEE Verification Depth

The audit MUST verify both layers when present:

**Local NVIDIA evidence verification (EAT/SPDM):**
- EAT JSON parsing and top-level nonce verification (constant-time),
- per-GPU certificate chain validation against a pinned NVIDIA root CA (not system trust store),
- the root CA pinning method (embedded certificate with hardcoded SHA-256 fingerprint check),
- SPDM message parsing (GET_MEASUREMENTS request/response structure, variable-length field handling),
- SPDM signature verification algorithm (ECDSA P-384 with SHA-384 is expected),
- the signed-data construction (must include both request and response-minus-signature, in order),
- all-or-nothing semantics (one GPU failure must fail the entire check),
- extraction of GPU count and architecture for reporting.

**Remote NVIDIA NRAS verification:**
- JWT signature verification using a cached JWKS endpoint (accepted algorithms: ES256, ES384, ES512 only — HS256 MUST be rejected),
- JWKS caching behavior (auto-refresh, rate-limited unknown-kid fallback),
- JWT claims validation (expiration, issuer, overall attestation result),
- nonce forwarding to NRAS (is it the same client-generated nonce?),
- the exact NRAS endpoint URL and whether it is configurable or hardcoded.

If offline mode exists, the audit MUST state which NVIDIA checks remain active and which are skipped.

> NOTE: NVIDIA attestation is for the model backend only. The gateway is a CPU-only TEE and does not have GPU attestation. The audit MUST verify that the code does not expect or require NVIDIA attestation from the gateway.

### Event Log Integrity (Model Backend)

If event logs are present in the model backend's attestation payload, the code MUST replay them and verify recomputed RTMR values against the model backend's quote RTMR fields.

The audit MUST describe replay algorithm details, including:
- hash algorithm used for extend operations (SHA-384 is expected for TDX RTMRs),
- initial RTMR state (48 zero bytes),
- extend formula: `RTMR_new = SHA-384(RTMR_old || digest)`,
- handling of short digests (padding to 48 bytes),
- IMR index validation (must be within [0, 3]),
- failure semantics: does a malformed event log entry skip the entry or fail the entire replay?

### Event Log Integrity (Gateway)

If event logs are present in the gateway's attestation payload, the code MUST replay them and verify recomputed RTMR values against the gateway's quote RTMR fields.

The audit MUST verify:
- that the gateway event log replay uses the same algorithm as the model backend event log replay,
- that the gateway event log is correctly parsed from its string-encoded JSON format,
- that gateway event log integrity is a separate enforced factor from model event log integrity,
- that a malformed gateway event log entry fails the entire replay (not silently dropped).

The audit MUST also state the exact security boundary of this check: event log replay validates internal consistency of event-log-derived RTMR values with quoted RTMR values, but does not by itself prove that RTMR values match an approved software baseline. If no baseline policy is enforced for MRTD/RTMR/MRSEAM-class measurements, that gap MUST be reported explicitly — for both gateway and model backend.

## Connection Lifetime Safety

TLS connections to the gateway MUST be closed after each request-response cycle (Connection: close) to ensure each new request triggers a fresh attestation or SPKI cache check.

If the implementation reuses connections, the audit MUST verify that re-attestation is correctly triggered on every new request, not just on new connections.

The audit MUST verify:
- that the response body wrapper closes the underlying TCP connection when the body is consumed or closed,
- that connection read/write timeouts are set and reasonable (noting that gateway connections may need longer timeouts due to two attestation payloads being fetched on a single connection),
- that a half-closed or errored connection cannot be mistakenly reused for a subsequent request,
- that the attestation request uses Connection: keep-alive (to allow the chat request on the same connection) while the chat request uses Connection: close.

## Enforcement Policy and Failure Semantics

The audit report MUST include a table of verification factors with:
- pass/fail/skip semantics,
- whether the factor is enforced by policy,
- whether failure blocks request forwarding,
- whether failure disables confidentiality guarantees without blocking traffic.

This section is required to prevent regressions where checks continue to be reported but are no longer security-enforcing.

The audit MUST also verify:
- the mechanism by which the enforced factor list is configured (hardcoded defaults, config file, environment),
- that misspelled or unknown factor names in the enforcement config are rejected at startup (not silently ignored),
- that there is a code path (`Blocked()` or equivalent) that inspects the report before every forwarded request and returns an error response to the client when any enforced factor has failed.

The current expected default enforced factors for gateway providers are:

**Model backend factors (Tier 1–3):**
- `nonce_match` — prevents replay of stale model attestations,
- `tdx_cert_chain` — validates model PCK chain to Intel roots,
- `tdx_quote_signature` — validates model quote signature,
- `tdx_debug_disabled` — prevents model debug enclaves from being trusted,
- `signing_key_present` — ensures the model enclave provided a public key for E2EE,
- `tdx_reportdata_binding` — prevents key-substitution MITM on the model backend's E2EE key,
- `compose_binding` — enforces model image/config binding to MRConfigID,
- `nvidia_signature` — enforces local NVIDIA signature validation when NVIDIA evidence exists,
- `nvidia_nonce_match` — enforces NVIDIA nonce freshness binding,
- `build_transparency_log` — enforces provenance for attested container images,
- `sigstore_verification` — enforces Sigstore presence for image digests,
- `event_log_integrity` — enforces model RTMR replay consistency when event logs are present.

**Gateway factors (Tier 4):**
- `gateway_nonce_match` — prevents replay of stale gateway attestations,
- `gateway_tdx_cert_chain` — validates gateway PCK chain to Intel roots,
- `gateway_tdx_quote_signature` — validates gateway quote signature,
- `gateway_tdx_debug_disabled` — prevents gateway debug enclaves from being trusted,
- `gateway_tdx_reportdata_binding` — binds gateway TLS certificate to its TDX quote,
- `gateway_compose_binding` — enforces gateway image/config binding to MRConfigID,
- `gateway_event_log_integrity` — enforces gateway RTMR replay consistency when event logs are present.

The audit MUST evaluate whether additional factors should be enforced by default (for example, `tdx_tcb_current`, or gateway-specific Sigstore/Rekor checks), and document the rationale for the current enforcement boundary.

## Negative Cache and Failure Recovery

The audit MUST verify the negative cache behavior:
- that a failed attestation attempt (for either gateway or model) records a negative entry preventing repeated upstream requests,
- that negative entries expire after a bounded TTL (not indefinitely cached),
- that the negative cache has bounded size with eviction of expired entries under pressure,
- that a negative cache hit returns a clear error to the client (for example, HTTP 503) rather than silently failing open or forwarding unauthenticated.

## Offline Mode Safety

If the system supports an offline mode, the audit MUST enumerate exactly which checks are skipped (for example, Intel PCS collateral, NRAS, Sigstore, Rekor, Proof-of-Cloud) and which checks still execute locally (for example, quote parsing/signature checks, report-data binding, event-log replay) — for BOTH the gateway and model backend attestation.

For the pinned connection path, the audit MUST verify whether offline mode is honored (the PinnedHandler receives an `offline` flag). The offline flag must suppress only network-dependent checks — all local cryptographic verification must remain active for both gateway and model.

The report MUST include residual risk of running in offline mode.

## Proof-of-Cloud

Ensure that the code verifies that the machine ID from the model backend's attestation is covered in proof-of-cloud.

The audit MUST document:
- machine identity derivation inputs (for example, PPID from the PCK certificate),
- remote registry verification flow,
- quorum/threshold requirements if multiple trust servers are used (expected: 3-of-3 nonce collection, then chained partial signatures),
- behavior when Proof-of-Cloud is unavailable (skip with informational status, or hard fail),
- whether the Proof-of-Cloud result is cached and under what conditions it is re-queried.

The audit MUST also document whether Proof-of-Cloud is checked for the gateway CVM, or only for the model backend CVM, and whether a missing gateway PoC check is a residual risk.

Track future expansion items separately (for example, DCEA and TPM quote integration), but keep this audit focused on checks currently implemented and required for production security decisions.

## HTTP Request Construction Safety

For gateway providers that construct raw HTTP requests on the underlying TLS connection (bypassing Go's http.Client connection pooling), the audit MUST verify:
- that the Host header is always set to the gateway domain,
- that Content-Length is derived from the actual body length (not caller-supplied),
- that no user-supplied data is interpolated into HTTP request lines or headers without sanitization (HTTP header injection prevention),
- that header values reject CR/LF characters (or equivalent canonicalization/sanitization is applied),
- that the request path is constructed from trusted constants plus URL-encoded query parameters,
- that the attestation request uses keep-alive while the chat request uses Connection: close,
- that the Authorization header is set correctly for both the attestation and chat requests.

## Response Size and Resource Limits

The audit MUST verify that all HTTP response bodies read by the proxy are bounded:
- gateway attestation responses (recommended: ≤2 MiB, larger than direct inference due to dual payloads),
- SSE streaming buffers (bounded scanner buffer sizes with pooling),
- any other external data read during verification (Sigstore, Rekor, NRAS, PCS).

Unbounded reads from untrusted sources represent a denial-of-service vector and MUST be flagged.

## Sensitive Data Handling

The audit MUST verify:
- that API keys are not logged in plaintext (redaction to first-N characters),
- that the config file permission check behavior is clearly classified as warning-only or hard-fail,
- that ephemeral cryptographic key material (E2EE session keys) is zeroed after use, with acknowledgment of language-level limitations (GC may copy),
- that attestation nonces are not reused across requests,
- that the model backend's signing key is only used for ECDH key exchange after REPORTDATA binding verification.

## Trust Delegation and Gateway Compromise Resilience

The gateway inference model introduces a trust delegation that does not exist in the direct inference model. The proxy trusts:
1. the gateway's TLS certificate (pinned via gateway attestation REPORTDATA),
2. the gateway to faithfully forward the model attestation response,
3. the model backend's signing key (bound via model REPORTDATA).

The audit MUST evaluate the security properties that survive a gateway compromise:
- **E2EE key integrity**: Because the model backend's signing key is bound to the model's TDX quote via REPORTDATA (not to the gateway's quote), a compromised gateway cannot substitute the E2EE key without also compromising the model backend's TDX quote.
- **Request/response confidentiality**: If E2EE is active, the gateway sees only encrypted content. A compromised gateway cannot read or modify encrypted message content.
- **Metadata visibility**: A compromised gateway can observe HTTP headers, request timing, model selection, and response sizes — even with E2EE enabled. This is a residual risk inherent to the gateway architecture.
- **Attestation relay integrity**: A compromised gateway could attempt to relay a different model backend's attestation (pointing to a compromised machine). The pinning of the gateway's own TLS certificate via its TDX quote limits this — but the model backend's TLS fingerprint is not directly verified against a live connection (since the proxy connects to the gateway). The audit MUST document whether there is a binding between the gateway and the specific model backend that prevents the gateway from routing to an unattested machine.

The audit MUST quantify the residual risk and clearly state which attack scenarios are mitigated by E2EE and which are not.

## Report Writing Requirements

The report MUST avoid vague language such as "looks secure" without code-backed evidence.

Each finding MUST include:
- severity and exploitability context,
- exact impacted control and whether it is currently enforced,
- realistic impact statement (integrity, confidentiality, availability),
- remediation guidance with concrete code-level direction,
- at least one source citation proving current behavior.

When no findings are present for a section, the report MUST explicitly state "no issues found in this section" and still note any residual risk or testing gap.
