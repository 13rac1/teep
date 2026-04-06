# Gateway Inference Provider Audit

This repository implements a proxy that ensures private LLM inference by performing attestation-bound TLS pinning to a TEE-attested API gateway, which in turn routes traffic to TEE-attested model inference backends. The proxy validates that both the gateway and the model backend run genuine TEE hardware with verifiable software, prevents man-in-the-middle attacks through cryptographic binding of the TLS channel to the gateway's attestation report, and protects request and response confidentiality through E2EE using a signing key obtained from the model backend's attestation.

Please verify every stage of attestation for the requested provider, following this audit guide to produce a detailed report.

This audit applies to gateway inference providers, where a gateway receives all client traffic and forwards it to model-specific TEE-attested inference backends. Some gateways are TEE-attested CVMs (NearCloud), while others are unattested infrastructure (Chutes). In both cases, the proxy connects to the gateway, not directly to model backends.

Two reference provider architectures are covered:

**NearCloud / NEAR AI (dstack-based):** A dual-tier gateway model with two layers of attestation:
- **Tier 1–3 (model):** the model inference backend's TDX quote, NVIDIA attestation, compose binding, event log, REPORTDATA binding, and supply chain verification,
- **Tier 4 (gateway):** the gateway's own TDX quote, compose binding, event log, REPORTDATA binding, and TLS certificate binding.

Additionally, the model backend's attestation provides an E2EE signing key (Ed25519) that the proxy uses to encrypt request messages and decrypt response messages, protecting header and body confidentiality even if the gateway is compromised.

**Chutes (sek8s-based):** A gateway inference model using Intel TDX confidential VMs running sek8s (a custom Kubernetes distribution). Requests route through the Chutes gateway (`api.chutes.ai`/`llm.chutes.ai`) to specific TEE instance IDs. Key architectural differences from dstack:
- **Unattested gateway**: The Chutes gateway routes traffic to sek8s TEE instances but is not itself a TEE-attested CVM — it produces no TDX quote and has no `gateway_*` attestation factors.
- **No compose binding**: sek8s does not use docker-compose or MRCONFIGID. Container image integrity relies on a cosign admission controller running inside the measured TEE.
- **No client-visible event log**: RTMR3/IMA measurements are verified server-side by the Chutes validator; the event log is not exposed to clients.
- **ML-KEM-768 E2EE**: Chutes uses post-quantum ML-KEM-768 key encapsulation + ChaCha20-Poly1305, not Ed25519/X25519/XChaCha20-Poly1305.
- **LUKS boot gating**: Disk decryption is gated on measurement verification by the Chutes validator — VMs that fail measurement checks cannot boot.
- **Different REPORTDATA scheme**: `SHA256(nonce_hex + e2e_pubkey_base64)` bound to TDX quote, with no signing_address or tls_fingerprint.

For a detailed analysis of the sek8s integrity model and residual trust assumptions, see `docs/attestation_gaps/sek8s_integrity.md`.

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
- The model backend's signing key MUST only be used for ECDH key exchange after REPORTDATA binding verification.

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

---

## Part 3 — Attestation Architecture Reference

This section provides background for auditors on the TDX attestation model used by gateway inference providers. This is reference material — the audit checklist follows in Part 4.

### Gateway Architecture Overview

Unlike direct inference providers where the proxy connects directly to the model server, the gateway architecture interposes a TEE-attested load balancer (the "gateway") between the proxy and the model backend:

```
Client → teep proxy → cloud-api.near.ai (gateway CVM) → model backend CVM
                          ↑ TLS pinned               ↑ internal routing
                          ↑ gateway attestation       ↑ model attestation
```

The gateway host is fixed (not resolved via a model routing API). The proxy opens a single TLS connection to the gateway, performs attestation on that connection (receiving both gateway and model attestation in a single response), and then sends the chat request on the same connection.

### Chutes/Sek8s Architecture Overview

Chutes uses a gateway model where an **unattested** gateway (`api.chutes.ai`/`llm.chutes.ai`) routes requests to specific sek8s TEE instances by instance ID. Unlike nearcloud, the Chutes gateway is not a TEE-attested CVM and produces no TDX quote:

**Chutes gateway access:**
```
Client → teep proxy → api.chutes.ai (unattested gateway) → sek8s TDX instance (model)
                          ↑ HTTPS (standard CA)              ↑ TDX attestation
                          ↑ no gateway TDX quote              ↑ ML-KEM-768 E2EE
```

**Chutes evidence via another provider's gateway (e.g., NanoGPT):**
```
Client → teep proxy → NanoGPT gateway → chutes sek8s TDX instance (model)
                          ↑ NanoGPT gateway attestation may or may not be present
                          ↑ chutes evidence in gateway-wrapped format
```

The attestation flow is two-step:
1. **Instances endpoint** (`GET /e2e/instances/{chute}`): Returns available TEE instances with ML-KEM-768 public keys and nonces.
2. **Evidence endpoint** (`GET /chutes/{chute}/evidence?nonce={hex}`): Returns TDX quotes and GPU evidence per instance.

Teep matches evidence to instances by instance ID, then verifies the TDX quote and REPORTDATA binding.

### What Each TDX Register Measures

Understanding the security semantics of each register is critical for assessing attestation completeness. The following describes the trust-chain role of each register, based on Intel TDX architecture. Register usage differs between dstack (NearCloud) and sek8s (Chutes) — differences are noted where applicable:

**MRSEAM** — Measurement of the TDX module (SEAM firmware). This 48-byte hash represents the identity and integrity of the Intel TDX module running in Secure Arbitration Mode. Intel signs and guarantees TDX module integrity; the MRSEAM value should correspond to a known Intel-released TDX module version. Verification of MRSEAM ensures the TDX firmware has not been tampered with and is a recognised, trusted version. Without MRSEAM verification, an attacker who compromises the hypervisor could potentially load a modified TDX module that subverts TD isolation guarantees.

**MRTD** — Measurement Register for Trust Domain. This 48-byte hash captures the initial memory contents and configuration of the TD at creation time, specifically the virtual firmware (OVMF/TDVF) measurement. MRTD is measured by the TDX module in SEAM mode before any guest code executes, making it the root-of-trust anchor for the entire guest boot chain. In dstack's architecture, MRTD corresponds to TPM PCR[0] (FirmwareCode). MRTD can be pre-calculated from the built dstack OS image. Without MRTD verification, an attacker could substitute a different virtual firmware (e.g., one that leaks secrets or skips subsequent measured boot steps) while preserving the correct compose hash and RTMR3 values.

**RTMR0** — Runtime firmware configuration measurement. RTMR0 records the CVM's virtual hardware setup as measured by OVMF, including CPU count, memory size, device configuration, secure boot policy variables (PK, KEK, db, dbx), boot variables, and TdHob/CFV data provided by the VMM. Corresponds to TPM PCR[1,7]. While dstack uses fixed devices, CPU and memory specifications can vary, so RTMR0 can be computed from the dstack image given specific CPU and RAM parameters. Without RTMR0 verification, a malicious VMM could alter the virtual hardware configuration (e.g., inject rogue devices or disable secure boot) without detection.

**RTMR1** — Runtime OS loader measurement. RTMR1 records the Linux kernel measurement as extended by OVMF, along with the GPT partition table and boot loader (shim/grub) code. Corresponds to TPM PCR[2,3,4,5]. RTMR1 can be pre-calculated from the built dstack OS image. Without RTMR1 verification, a modified kernel could be loaded that bypasses security controls while leaving application-level measurements intact.

**RTMR2** — Runtime OS component measurement. RTMR2 records the kernel command line (including the rootfs hash), initrd binary, and grub configuration/modules as measured by the boot loader. Corresponds to TPM PCR[8-15]. RTMR2 can be pre-calculated from the built dstack OS image. Without RTMR2 verification, the kernel command line could be altered (e.g., to disable security features or change the root filesystem hash) without detection.

**RTMR3** — Application-specific runtime measurement. In dstack's implementation, RTMR3 records application-level details including the compose hash, instance ID, app ID, and key provider. Unlike RTMR0-2, RTMR3 cannot be pre-calculated from the image alone because it contains runtime information. It is verified by replaying the event log: if replayed RTMR3 matches the quoted RTMR3, the event log content is authentic, and the compose hash, key provider, and other details can be extracted and verified from the event log entries. The existing compose binding check (MRConfigID) partially overlaps with RTMR3 for compose hash verification.
#### Sek8s (Chutes) Register Usage Differences

Sek8s uses standard Intel TDX registers, but the measurements reflect a different guest stack:

| Register | Sek8s behavior | Difference from dstack |
|----------|---------------|------------------------|
| **MRSEAM** | Same Intel TDX module values | Fleet may include different TDX module versions (1.5.0d, 2.0.06) |
| **MRTD** | Sek8s-specific OVMF firmware image | Different firmware image; distinct MRTD value |
| **RTMR0** | ACPI tables, early boot; sek8s host-tools fix memory/vCPU/GPU sizing for determinism | Deterministic per deployment class (e.g., 8×H200) |
| **RTMR1** | Kernel + initramfs per sek8s image build | Different kernel; deterministic per build |
| **RTMR2** | Kernel command line per deployment class | Different command line; deterministic per class |
| **RTMR3** | Runtime / IMA measurements | **Not verified by teep** — verified server-side by Chutes validator; event log not exposed to clients |
| **MRCONFIGID** | **Not used** | Sek8s does not bind a compose hash; container verification is via cosign admission inside the TEE |
| **REPORTDATA** | `SHA256(nonce_hex + e2e_pubkey_base64)` | Different binding scheme; no signing_address or tls_fingerprint |
### How Thorough Verification Should Work

For complete attestation of a dstack-based CVM — applicable to BOTH the gateway CVM and the model backend CVM — the verification process should:

1. **Obtain golden values**: The inference provider MUST publish reference values for MRTD, RTMR0, RTMR1, and RTMR2 corresponding to each released CVM image version, for both the gateway and model backend deployments. These values can be computed using reproducible build tooling (e.g., dstack's `dstack-mr` tool) from the source-built image given the specific CPU and RAM configuration of the deployment.

2. **Verify MRSEAM against Intel's published values**: MRSEAM should match a known Intel TDX module release. Intel publishes TDX module versions; the expected MRSEAM value can be derived from the specific TDX module version running on the platform.

3. **Verify MRTD, RTMR0, RTMR1, RTMR2 against golden values**: These four registers, taken together, attest that the firmware, kernel, initrd, rootfs, and boot configuration all match the expected dstack OS image for the provider's declared CPU/RAM configuration. This is the only way to establish that the base operating environment is the expected one.

4. **Verify RTMR3 via event log replay**: RTMR3 contains runtime-specific measurements that cannot be pre-calculated. Replay the event log, compare the replayed RTMR3 against the quoted value, and then inspect the event log entries for expected compose hash, app ID, and key provider values.

5. **Verify MRSEAM + MRTD + RTMR0-2 as a set**: These five values together form a complete chain-of-trust from the TDX module through firmware, kernel, and OS components. Verifying only a subset (e.g., only compose binding via MRConfigID + RTMR3 event log replay) leaves significant gaps where the base system could be substituted.

#### Sek8s (Chutes) Verification Differences

For sek8s-based CVMs, the verification process differs from dstack in several important ways:

1. **No compose binding or event log replay**: Sek8s does not use MRCONFIGID for compose hashes, and the event log is not exposed to clients. Steps 4 and 5 above (RTMR3 event log replay and compose binding) are not applicable. Teep correctly returns `Skip` for `compose_binding`, `event_log_integrity`, and `sigstore_verification`.

2. **MRTD, RTMR0-2 are the primary verification surface**: Since compose binding and event log replay are unavailable, the MRTD and RTMR0-2 measurement allowlists are the most important client-side controls. These are pinned from known-good Chutes deployments in `internal/provider/chutes/policy.go`.

3. **MRSEAM allowlist extended for sek8s fleet**: The sek8s fleet runs TDX module versions (1.5.0d, 2.0.06) that may differ from the dstack fleet. These are included in the chutes measurement policy.

4. **RTMR3 verified server-side only**: The Chutes validator verifies RTMR3 against golden baselines as part of the LUKS boot gate. Teep cannot independently replay RTMR3.

5. **Container image integrity is trust-delegated**: Instead of client-verifiable compose binding + Sigstore/Rekor, sek8s relies on a cosign admission controller inside the TEE. Teep has zero visibility into which containers are running on a Chutes node. This is a documented trust assumption, not a teep deficiency.

6. **Golden values pinned from observed deployments**: Sek8s measurement values are captured from live Chutes deployments and coded in Go defaults. Independent reproduction requires building sek8s from source (`chutesai/sek8s`).

See `docs/attestation_gaps/sek8s_integrity.md` for the full trust model analysis.

### Current Stopgaps and Residual Gaps

The code supports an allowlist-based `MeasurementPolicy` for MRTD, MRSEAM, and RTMR0-3 for both the gateway and the model backend. If the gateway inference provider does not publish authenticated measurement baselines in-band, teep should use Go-coded stopgap defaults and operator tooling to partially close this gap:

**MRSEAM — Go-coded defaults from Intel releases.** `DstackBaseMeasurementPolicy()` in `internal/attestation/dstack_defaults.go` ships an allowlist of four Intel-published MRSEAM values corresponding to TDX module versions 1.5.08, 1.5.16, 2.0.08, and 2.0.02. These are sourced from Intel's official release notes. The `tdx_mrseam_mrtd` and `gateway_tdx_mrseam_mrtd` factors are enforced by default for nearcloud (they are NOT in `NearcloudDefaultAllowFail`).

**MRTD — Go-coded defaults from dstack reproducible builds.** The same base policy ships two MRTD values corresponding to dstack-nvidia image versions 0.5.4.1 and 0.5.5, derived from reproducible build artifacts. These apply to both the model backend and gateway CVMs.

**RTMR0, RTMR1, RTMR2 — Per-tier observed-value defaults.** NearCloud uses separate measurement policies for the model backend and the gateway:
- `DefaultMeasurementPolicy()` in `internal/provider/nearcloud/policy.go` provides model backend RTMR values,
- `DefaultGatewayMeasurementPolicy()` provides gateway CVM RTMR values (which differ from model backend values due to different hardware configurations and compose manifests).

The `tdx_hardware_config` / `gateway_tdx_hardware_config` (RTMR0) and `tdx_boot_config` / `gateway_tdx_boot_config` (RTMR1/RTMR2) factors are in `NearcloudDefaultAllowFail` — meaning they are computed and reported but do not block traffic by default.

**Measurement policy merge.** Policies are resolved via a three-tier precedence: per-provider TOML config → global TOML config → Go-coded defaults. Gateway measurement policies use separate TOML fields (`gateway_mrtd_allow`, `gateway_rtmr0_allow`, etc.) to allow independent configuration of gateway and model backend allowlists.

**Operator bootstrapping.** The `teep verify <provider> --model <model> --update-config` command runs a full attestation verification and appends newly observed measurement values to the per-provider policy section. For nearcloud, this captures both model backend and gateway measurements.

**Residual risk.** Despite these stopgaps:
- MRSEAM and MRTD defaults are independently verifiable from Intel and dstack sources — these are the strongest stopgaps.
- RTMR0-2 defaults are pinned from observed attestation data and cannot distinguish a legitimate provider infrastructure change from a compromised lower stack.
- No signed measurement manifest exists for automated consumption.
- These risks apply independently to both the gateway CVM and the model backend CVM.

**The audit MUST flag the remaining residual risk** and recommend that the inference provider publish authenticated measurement baselines. See `docs/attestation_gaps/dstack_integrity.md` for the detailed analysis and recommended in-band publication model.

#### Chutes/Sek8s Measurement Defaults

Chutes uses a separate set of Go-coded measurement defaults, defined in `internal/provider/chutes/policy.go`:

**MRSEAM** — Extended allowlist including TDX module versions 1.5.0d and 2.0.06, in addition to the dstack fleet versions. These are observed from the Chutes sek8s fleet.

**MRTD** — Single value corresponding to the sek8s OVMF firmware image, distinct from dstack's OVMF.

**RTMR0, RTMR1, RTMR2** — Values specific to the sek8s 8×H200 deployment class. Sek8s host-tools explicitly fix VM parameters (memory, vCPU, GPU MMIO, PCI hole sizing) to make these deterministic.

**RTMR3** — Not enforced by teep. Sek8s validates RTMR3 server-side via its LUKS boot gate; the event log is not exposed to clients.

**MRCONFIGID** — Not used. Sek8s does not bind compose hashes. Container image integrity depends on the cosign admission controller running inside the TEE.

**Measurement bootstrapping.** The `teep verify chutes --model <model> --update-config` command captures observed sek8s measurements. Unlike dstack, there is no golden-value reproduction tooling available to teep; values are pinned from observed deployments.

**Residual risk.** The sek8s measurement defaults are pinned from observed Chutes deployments and cannot be independently reproduced without building sek8s from source. Additionally, the absence of compose binding, event log replay, and Sigstore/Rekor checks means that the MRTD/RTMR0-2 allowlists are the sole client-side controls for the sek8s boot chain. See `docs/attestation_gaps/sek8s_integrity.md` for a detailed trust model analysis.

---

## Part 4 — Verification Stage Audit Checklist

Each subsection below is an audit stage. For every stage, the auditor MUST classify each check as `enforced fail-closed`, `computed but non-blocking`, or `skipped/advisory`, and verify that enforcement matches the fail-closed policy from Part 1.

### 4.1 Gateway Architecture Verification

The audit MUST verify:
- that the gateway host is a hardcoded constant (no DNS-based routing indirection),
- that no model routing / endpoint resolution is performed (unlike direct inference providers),
- that the gateway attestation endpoint returns both gateway and model attestation in a single response,
- that there is no code path that allows connecting to an unattested alternate host.

> **Known divergence: Chutes/Sek8s.** The Chutes gateway (`api.chutes.ai`) is not a TEE-attested CVM and produces no TDX quote — there is no `PinnedHandler` or attestation-bound TLS connection to the gateway. The proxy uses a two-step attestation flow via the Chutes gateway: an instances endpoint for model discovery and ML-KEM-768 key retrieval, then a separate evidence endpoint for TDX quotes from the backend instances. The audit for chutes MUST instead verify: (1) that the instances and evidence endpoints are constructed from hardcoded constants plus URL-encoded model identifiers, (2) that instance-to-evidence matching is by instance ID with bounds checking, (3) that failed or missing instances are handled fail-closed, (4) that response arrays are bounded (max 256 instances, max 256 evidence entries, max 64 GPU evidence per instance). When chutes evidence appears via another provider's gateway (e.g., NanoGPT), the audit MUST verify that the gateway-wrapped parsing extracts the inner chutes evidence correctly and applies all chutes-specific verification.

### 4.2 Attestation Fetch and Response Parsing

Upon connection to the gateway, the attestation API MUST be queried and fully validated before any inference request is sent. A single attestation request returns a combined response containing both the gateway attestation and the model attestation.

Certificate Transparency MUST be consulted for the TLS certificate of the gateway endpoint. This CT log report SHOULD be cached.

The attestation response is a JSON object that includes:
- a `gateway_attestation` section with the gateway's own TDX quote, event log, TLS certificate fingerprint, and tcb_info (containing app_compose), and
- a `model_attestations` array with per-model Intel TDX attestation, NVIDIA TEE attestation, signing key, and auxiliary information.

> **Known divergence: Chutes/Sek8s.** Chutes uses a two-step attestation flow with different response formats:
> 1. **Instances response** (`GET /e2e/instances/{chute}`): JSON with `instances` array (each with `instance_id`, `e2e_pubkey` as base64 ML-KEM-768, `nonces` array) and `nonce_expires_in`.
> 2. **Evidence response** (`GET /chutes/{chute}/evidence?nonce={hex}`): JSON with `evidence` array (each with `quote` as base64 TDX, `gpu_evidence` array, `instance_id`, `certificate`) and `failed_instance_ids`.
>
> The audit MUST verify: (a) that the instances response is fetched and validated before the evidence request, (b) strict JSON unmarshalling for both responses, (c) bounds checking on all array lengths, (d) that evidence is matched to instances by instance ID, (e) that an instance must have a non-empty `e2e_pubkey` and at least one nonce, (f) that `failed_instance_ids` are excluded from selection, (g) that no `e2e_pubkey` is used without a corresponding verified TDX quote.

The audit MUST verify the attestation response parsing path, including:
- maximum response body size limit (to prevent memory exhaustion — per Part 1 input bounds rules; note that gateway responses are larger due to dual payloads),
- JSON strict unmarshalling behavior (unknown fields rejection or warning — per Part 1 error handling rules) for BOTH the top-level gateway response AND the inner model attestation,
- whether unknown-field warnings are rate-limited/deduplicated,
- handling of polymorphic response formats for the model attestation (array vs flat object),
- bounds checking on array lengths (model_attestations, all_attestations) to cap iteration,
- model selection logic when the response contains multiple attestation entries (exact match, prefix, or fuzzy), and whether failure to find a matching model is a hard error,
- that the gateway event_log field is a JSON string (not a native array) and is correctly double-parsed,
- that the gateway tcb_info field supports double-encoded JSON (string-within-JSON) for app_compose extraction,
- malformed-element behavior for event-log or nested arrays (fail-whole-response vs silently drop element — per fail-closed policy, dropping is a defect),
- that no provider-asserted "verified" field is trusted without independent verification.

### 4.3 Nonce Freshness and Replay Resistance

The verifier MUST generate a fresh 32-byte cryptographic nonce per attestation attempt.

In the gateway model, a single nonce is sent to the gateway, which shares it with the model backend. Both the gateway and the model backend echo the same nonce back. The audit MUST verify:
- that exactly one nonce is generated per attestation attempt (not separate nonces for gateway and model),
- that the single nonce is transmitted to the gateway endpoint by the proxy, not delegated to the server,
- that the gateway's echoed nonce is verified using constant-time comparison (`subtle.ConstantTimeCompare`) against the client-generated nonce,
- that the model's echoed nonce is verified using constant-time comparison against the same client-generated nonce,
- that both nonce checks fail closed on mismatch,
- that the nonce originates solely from the client and is not sourced from or influenced by the server response.

If cryptographic randomness fails, nonce generation MUST fail closed (no weak fallback mode). The recommended behavior is to panic or abort — never fall back to a weaker entropy source. Per Part 1 cryptographic safety rules, `crypto/rand` is the only acceptable source.

> **Known divergence: Chutes/Sek8s.** Chutes uses a client-generated nonce but with a different lifecycle: (1) a fresh nonce is generated per attestation attempt, (2) the nonce is sent as a query parameter to the evidence endpoint (`?nonce={hex}`), (3) the nonce appears in REPORTDATA as `SHA256(nonce_hex + e2e_pubkey_base64)` — the nonce is verified via REPORTDATA binding, not via a separate echoed nonce field. Additionally, Chutes provides a nonce pool mechanism (`noncepool.go`) that caches instances and nonces from the instances endpoint; the audit MUST verify that cached nonces are never reused across attestation attempts and that nonce expiry (`nonce_expires_in`) is respected.

### 4.4 TDX Quote Verification (Model Backend)

Signatures over the model backend's Intel TEE attestation MUST be verified for the entire certificate chain, including:
- quote structure parsing (supported quote versions),
- PCK chain validation back to Intel trust roots,
- quote signature verification,
- debug bit check (debug enclaves rejected for production trust),
- TCB collateral and currency classification when online.

Document how trust roots are obtained (embedded/provisioned), and how third-party verification libraries are called and interpreted.

The audit MUST explicitly describe the two-pass verification architecture if present (offline first, online collateral second), and whether a Pass-1-only result (no collateral) is still treated as blocking or advisory.

### 4.5 TDX Quote Verification (Gateway)

The gateway's TDX quote MUST undergo the same verification as the model backend's quote. The audit MUST verify that all of the following are checked for the gateway quote:
- quote structure parsing,
- PCK chain validation back to Intel trust roots,
- quote signature verification,
- debug bit check.

The audit MUST verify that the gateway TDX verification uses the same code path / library as the model TDX verification (to avoid diverging security standards).

> **Known divergence: Chutes/Sek8s.** The Chutes gateway is unattested and produces no TDX quote — there are no `gateway_*` TDX factors. When auditing chutes, skip §4.5 entirely. When chutes evidence appears via another provider's gateway (e.g., NanoGPT), the wrapping gateway's TDX quote (if present) is verified by the wrapping provider, not by the chutes verification path.

### 4.6 TDX Measurement Fields and Policy

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

#### Current gateway-provider expectation summary

**Model backend attestation (Tier 1–3):**
- MRCONFIGID is expected to be cryptographically checked via compose binding,
- RTMR fields are expected to be consistency-checked via event log replay when event logs are present,
- REPORTDATA is expected to be cryptographically verified via the nearai binding scheme (sha256(signing_address + tls_fingerprint) + nonce),
- MRSEAM and MRTD are enforced by default via Go-coded allowlists sourced from Intel TDX module releases and dstack reproducible builds — the `tdx_mrseam_mrtd` factor is enforced,
- RTMR0 is checked via `tdx_hardware_config` against per-provider observed values — allowed to fail by default,
- RTMR1 and RTMR2 are checked via `tdx_boot_config` against per-provider observed values — allowed to fail by default,
- MRSIGNERSEAM, MROWNER, MROWNERCONFIG are expected to be all-zeros for standard dstack deployments and should be documented as informational-only.

**Gateway attestation (Tier 4):**
- MRCONFIGID is expected to be cryptographically checked via gateway compose binding,
- RTMR fields are expected to be consistency-checked via gateway event log replay when gateway event logs are present,
- REPORTDATA is expected to be cryptographically verified via the gateway binding scheme (sha256(tls_fingerprint) + nonce — note: no signing_address for the gateway),
- MRSEAM and MRTD are enforced by default via the same Go-coded allowlists as the model backend — `gateway_tdx_mrseam_mrtd` is enforced,
- RTMR0 is checked via `gateway_tdx_hardware_config` — allowed to fail by default,
- RTMR1 and RTMR2 are checked via `gateway_tdx_boot_config` — allowed to fail by default,
- MRSIGNERSEAM, MROWNER, MROWNERCONFIG are expected to be all-zeros.

The audit MUST verify:
- how MRTD/MRSEAM/RTMR allowlists are configured for both gateway and model,
- the three-tier policy merge precedence (per-provider TOML > global TOML > Go defaults) in `MergedMeasurementPolicy()`,
- that separate TOML fields exist for gateway measurement policies (`gateway_mrtd_allow`, `gateway_rtmr0_allow`, etc.),
- input validation rules for allowlist values (length/encoding),
- whether allowlist mismatches are enforced fail-closed or informational (depends on whether the factor is in `allow_fail`),
- the `--update-config` bootstrapping flow and that it correctly captures both model and gateway measurements.

> **Known divergence**: Venice does not have gateway TEE attestation — there is no gateway TDX quote, no gateway measurement policy, and no Tier 4 factors. Venice's `ServerVerification` field is an untrusted gateway-side claim that is parsed but NOT verified by teep. This is a server-side limitation of Venice that should be flagged in audits but not listed as a finding for teep to fix.
> **Known divergence: Chutes/Sek8s.** Chutes uses a fundamentally different measurement model:
> - **MRCONFIGID is not used.** Sek8s does not bind compose hashes. The `compose_binding` factor returns `Skip` with explanation.
> - **RTMR3 is not client-verifiable.** No event log is exposed; `event_log_integrity` returns `Skip`.
> - **Separate MRSEAM allowlist.** Chutes includes TDX module versions 1.5.0d and 2.0.06 not present in the dstack allowlist.
> - **Separate MRTD value.** Sek8s OVMF firmware is distinct from dstack OVMF.
> - **RTMR0-2 are the primary enforcement surface.** Since compose binding and event log replay are unavailable, these measurement allowlists are the sole client-side boot chain controls.
> - **REPORTDATA binding scheme differs.** `SHA256(nonce_hex + e2e_pubkey_base64)` — no signing_address or tls_fingerprint.
> - **No gateway measurement policy.** The Chutes gateway is unattested and produces no TDX quote.
> - The audit for chutes MUST evaluate whether the MRTD/RTMR0-2 allowlists provide sufficient assurance given the absence of compose binding, event log, and Sigstore/Rekor checks. See `docs/attestation_gaps/sek8s_integrity.md`.
### 4.7 CVM Image Verification — Model Backend (Compose Binding)

The model backend attestation API provides a full docker compose stanza, or equivalent podman/cloud config image description, as an auxiliary portion of the attestation API response.

The code MUST calculate a hash of these contents, which MUST be verified to be properly attested in the model backend's TDX MRConfigID field.

The audit MUST verify the exact binding format expected by the implementation (for example, 48-byte MRConfigID layout, prefix rules, and byte-level comparison semantics).

The audit MUST also verify the extraction path for the app_compose field, including:
- whether the tcb_info field supports double-encoded JSON (string-within-JSON),
- that the extracted compose content is the raw value that was hashed, not a re-serialized version that could differ in whitespace or key ordering.

> **Known divergence: Chutes/Sek8s.** Compose binding (§4.7 and §4.8) does not apply to chutes. Sek8s does not use docker-compose or MRCONFIGID. Container image integrity is enforced by a cosign admission controller running inside the measured TEE, which is not visible to teep. The `compose_binding` factor returns `Skip` with message: "chutes uses cosign image admission + IMA, not docker-compose; compose binding not applicable". When auditing chutes, skip §4.7 and §4.8 and instead verify that the `Skip` result is correctly returned and that no code path attempts compose binding for chutes quotes.

### 4.8 CVM Image Verification — Gateway (Compose Binding)

The gateway attestation also provides an app_compose via its tcb_info field. The code MUST calculate a hash of the gateway's app_compose and verify it matches the gateway's TDX MRConfigID field.

The audit MUST verify:
- that the gateway's app_compose extraction path correctly handles double-encoded JSON (the gateway's tcb_info may be a JSON string containing escaped JSON),
- that the gateway compose binding uses the same verification function as the model compose binding,
- that the gateway compose binding check is a separate enforced factor from the model compose binding check.

### 4.9 CVM Image Component Verification (Sigstore/Rekor)

The docker compose files (or podman/cloud configs) for BOTH the gateway and model backend will list a series of sub-images.

The teep code MUST provide an enforced allow-list of sub-images and/or sub-image repositories for a given inference provider that are allowed to appear in these docker-compose files. The hashes need not be included in the teep code, but each of these sub-images MUST be checked against Sigstore and Rekor (or equivalent systems) to establish that they are official builds and not custom variations.

Additionally, the teep code MUST provide an expected Sigstore+Rekor Signer set (as OIDC or Fulcio certs). For Sigstore+Rekor checks, only this expected signer set is to be accepted.

The audit MUST verify:
- extraction logic for image digests from compose content (regex vs structured parsing, and whether non-sha256 digest algorithms are handled or rejected),
- deduplication of extracted digests,
- all sub-images of BOTH the model backend and gateway docker compose files are in the provider's allow-list,
- Sigstore query behavior and failure handling (is a Sigstore timeout a hard fail or a skip? — per fail-closed policy, a skip is a defect unless explicitly documented as an accepted offline-mode risk),
- Rekor provenance extraction logic,
- issuer/identity checks used to classify provenance as trusted (what OIDC issuer values are accepted?),
- behavior when a digest appears in Sigstore but has no Fulcio certificate (raw key signature — is this treated as passing provenance or only presence?),
- handling of Rekor entries that lack DSSE (Dead Simple Signing Envelope) signatures — some images have Rekor transparency log entries but no DSSE envelope signatures; the `NoDSSE` field in `ImageProvenance` controls whether this is accepted.

The audit MUST explicitly state if Sigstore/Rekor are soft-fail in default policy and what traffic is still allowed during outage conditions.

> NOTE: The current implementation performs Sigstore/Rekor checks only on the model backend's compose images. The audit MUST flag whether gateway compose images are also subject to these checks, and if not, report this as a gap.

> **Known divergence: Chutes/Sek8s.** Sigstore/Rekor verification (§4.9) does not apply to chutes. Chutes attestation does not include container image digests or compose manifests. The `sigstore_verification` factor returns `Skip` with message: "chutes attestation does not include container image digests; cosign verification is validator-side only". The `build_transparency_log` factor also returns `Skip`. This is a structural limitation of the sek8s attestation model, not a teep deficiency. The residual risk is that teep has zero visibility into which container images are running on a Chutes node — this trust is delegated to the cosign admission controller running inside the TEE.

### 4.10 Event Log Integrity (Model Backend)

If event logs are present in the model backend's attestation payload, the code MUST replay them and verify recomputed RTMR values against the model backend's quote RTMR fields.

The audit MUST describe replay algorithm details, including:
- hash algorithm used for extend operations (SHA-384 is expected for TDX RTMRs),
- initial RTMR state (48 zero bytes),
- extend formula: `RTMR_new = SHA-384(RTMR_old || digest)`,
- handling of short digests (padding to 48 bytes),
- IMR index validation (must be within [0, 3]),
- failure semantics: does a malformed event log entry skip the entry or fail the entire replay? Per fail-closed policy, skipping is a defect.

### 4.11 Event Log Integrity (Gateway)

If event logs are present in the gateway's attestation payload, the code MUST replay them and verify recomputed RTMR values against the gateway's quote RTMR fields.

The audit MUST verify:
- that the gateway event log replay uses the same algorithm as the model backend event log replay,
- that the gateway event log is correctly parsed from its string-encoded JSON format,
- that gateway event log integrity is a separate enforced factor from model event log integrity,
- that a malformed gateway event log entry fails the entire replay (not silently dropped — per fail-closed policy).

The audit MUST also state the exact security boundary of this check: event log replay validates internal consistency of event-log-derived RTMR values with quoted RTMR values, but does not by itself prove that RTMR values match an approved software baseline. If no baseline policy is enforced for MRTD/RTMR/MRSEAM-class measurements, that gap MUST be reported explicitly — for both gateway and model backend.

> **Known divergence: Chutes/Sek8s.** Event log replay (§4.10 and §4.11) does not apply to chutes. Chutes performs RTMR verification server-side (validator-side) against a golden baseline; the event log is not exposed to clients. The `event_log_integrity` factor returns `Skip` with message: "chutes performs RTMR verification validator-side against a golden baseline; event log not exposed to clients". When auditing chutes, skip §4.10 and §4.11 and instead verify that the `Skip` result is correctly returned. The residual risk is that teep cannot independently verify RTMR3 runtime measurements for chutes.

### 4.12 Encryption Binding — Model Backend REPORTDATA

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
- that the binding comparison uses constant-time comparison (`subtle.ConstantTimeCompare`),
- that failure of this check is enforced (blocks forwarding), not merely logged.

The audit MUST also verify that the model backend's REPORTDATA verifier is the shared nearai ReportDataVerifier (not a different implementation), and that a missing or unconfigured verifier fails safely (no default pass-through — per fail-closed policy).

> **Known divergence: Chutes/Sek8s.** Chutes uses a completely different REPORTDATA binding scheme:
> - `REPORTDATA[0:32]` = `SHA256(nonce_hex_string + e2e_pubkey_base64_string)` — string concatenation of the hex nonce and base64-encoded ML-KEM-768 public key, then SHA-256 hashed.
> - `REPORTDATA[32:64]` = all zeros (no separate nonce half; the nonce is embedded in the first half).
>
> Key differences from nearcloud: (1) no `signing_address` or `tls_fingerprint` — the binding is nonce + public key only, (2) the nonce is included as a hex string (not raw bytes), (3) the E2EE public key is ML-KEM-768 (not Ed25519), (4) constant-time comparison via `subtle.ConstantTimeCompare` is still required.
>
> The chutes REPORTDATA verifier is in `internal/provider/chutes/reportdata.go` (a separate implementation from the nearai verifier). The audit for chutes MUST verify: (a) the string concatenation order is `nonce_hex + pubkey_base64` with no separator, (b) the ML-KEM-768 public key is the same key from the instances endpoint that will be used for E2EE, (c) a missing or empty `e2e_pubkey` results in a hard failure, (d) the comparison is constant-time.

> NOTE: The model backend's `tls_cert_fingerprint` in REPORTDATA refers to the model backend's own TLS certificate, not the gateway's. Since the proxy connects to the gateway (not the model backend), the proxy cannot directly verify the model backend's TLS fingerprint against a live connection. The model backend's REPORTDATA binding establishes that the signing key for E2EE is bound to the attested model backend — but the TLS channel pinning is handled separately by the gateway attestation. The audit MUST document this trust delegation and note that the gateway's TLS attestation is the link that binds the live TLS connection to the overall attestation chain.

### 4.13 Encryption Binding — Gateway REPORTDATA

The gateway's attestation report must bind the gateway's TLS certificate identity to its TDX quote.

For the gateway, REPORTDATA uses a different scheme from the model backend:
- `REPORTDATA[0:32]` = `SHA256(tls_fingerprint_bytes)` — note: NO signing_address, only the TLS fingerprint
- `REPORTDATA[32:64]` = raw client nonce bytes (32 bytes, not hex-encoded)

The audit MUST verify:
- that `tls_fingerprint` is decoded from hex before hashing (not hashed as ASCII),
- that an absent `tls_cert_fingerprint` results in a hard failure (not a skip — per fail-closed policy),
- that both halves of the 64-byte REPORTDATA are verified,
- that the binding comparison uses constant-time comparison (`subtle.ConstantTimeCompare`),
- that failure of this check is enforced (blocks the request).

The audit MUST also verify that the gateway REPORTDATA verifier is a separate implementation from the model REPORTDATA verifier (because the binding scheme differs), and that the correct verifier is used for each quote.

> **Known divergence: Chutes/Sek8s.** Gateway REPORTDATA (§4.13) does not apply to chutes — the Chutes gateway is unattested and has no TDX quote or REPORTDATA. Skip this section when auditing chutes.

### 4.14 TLS Pinning and Connection-Bound Attestation (Gateway)

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
- that a cache miss always triggers full re-attestation (including both gateway and model), never a pass-through (per fail-closed policy),
- that concurrent attestation attempts for the same (domain, SPKI) are collapsed (singleflight) with a double-check-after-winning pattern,
- that the singleflight key includes both domain and SPKI (so a certificate rotation triggers a new attestation rather than coalescing with the old one).

> **Known divergence: Chutes/Sek8s.** TLS pinning via gateway attestation (§4.14) does not apply to chutes — the Chutes gateway is unattested and there is no attestation-bound TLS pinning. The `tls_key_binding` factor is in `ChutesDefaultAllowFail`. The proxy connects to `llm.chutes.ai`/`api.chutes.ai` via standard HTTPS with no attestation-bound SPKI pinning. The E2EE layer (ML-KEM-768) provides the primary confidentiality control instead of TLS pinning. When chutes evidence appears via another provider's gateway, the TLS pinning belongs to the wrapping provider (not chutes).

### 4.15 NVIDIA TEE Verification Depth

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

> NOTE: NVIDIA attestation is for the model backend only. The gateway is a CPU-only TEE and does not have GPU attestation. The audit MUST verify that the code does not expect or require NVIDIA attestation from the gateway.

### 4.16 E2EE: End-to-End Encryption via Model Signing Key

In the gateway inference model, the model backend's attestation provides an Ed25519 public key (`signing_key`) that is bound to the model backend's TDX quote via REPORTDATA. The proxy uses this key for X25519-based E2EE (converting Ed25519 to X25519 for key exchange), encrypting request messages so that even the gateway cannot read them, and decrypting response messages that were encrypted by the model backend.

> **Known divergence**: Venice uses a different E2EE protocol — secp256k1 ECDH + AES-256-GCM with a keccak256-derived REPORTDATA binding scheme. The Venice protocol is actually a previous version of the nearcloud E2EE protocol, and so this section focuses on the mechanics of the latest nearcloud protocol.

> **Known divergence: Chutes/Sek8s.** Chutes uses a completely different E2EE protocol based on post-quantum cryptography:
>
> **Key exchange:** ML-KEM-768 (NIST post-quantum KEM) instead of Ed25519/X25519 ECDH. The model backend provides an ML-KEM-768 public key (`e2e_pubkey`, base64-encoded) via the instances endpoint. The proxy encapsulates a shared secret using this public key.
>
> **Key derivation:** HKDF-SHA256 with the KEM ciphertext’s first 16 bytes as salt and context-specific info strings: `"e2e-req-v1"` (request encryption), `"e2e-resp-v1"` (non-streaming response), `"e2e-stream-v1"` (streaming response). Each derives a separate 32-byte ChaCha20-Poly1305 key.
>
> **Symmetric encryption:** ChaCha20-Poly1305 (not XChaCha20-Poly1305 — 12-byte nonce, not 24-byte). Request wire format: `[KEM_CT(1088) + nonce(12) + ciphertext + tag(16)]`, gzipped.
>
> **Streaming:** SSE events use `e2e_init` (KEM ciphertext) and `e2e` (encrypted chunks) event types, with independent stream key derivation. The relay implementation is in `internal/e2ee/relay_chutes.go` (completely separate from `relay.go`).
>
> **REPORTDATA binding of E2EE key:** The ML-KEM-768 public key is bound to the TDX quote via `REPORTDATA[0:32] = SHA256(nonce_hex + e2e_pubkey_base64)`. This prevents key substitution.
>
> **Nonce pool:** Chutes caches instances and nonces (`noncepool.go`) to avoid re-fetching attestation on every request. The audit MUST verify that cached nonces expire correctly, that instance failure tracking prevents reuse of failed instances, and that no E2EE key is used without a verified REPORTDATA binding.
>
> The audit for chutes MUST verify: (a) ML-KEM-768 encapsulation uses a standard implementation (`mlkem.Encapsulate768`), (b) fresh KEM ciphertext is generated per request, (c) HKDF info strings are distinct per direction, (d) `crypto/rand` is the sole nonce source, (e) ChaCha20-Poly1305 tag is always verified on decryption, (f) KEM shared secret and derived keys are zeroed after use.

The audit MUST verify:
- that the `signing_key` is obtained from the model backend's attestation (not the gateway's attestation),
- that the `signing_key` is present in the attestation response and validated as a 64-hex-character Ed25519 public key (32 bytes),
- that the `signing_key` is bound to the model backend's TDX quote via `tdx_reportdata_binding` — without this binding, a MITM could substitute the key,
- that the E2EE session is created with a fresh ephemeral Ed25519 key pair per request, with the X25519 private key derived from the Ed25519 seed,
- that the ephemeral Ed25519 public key is transmitted to the model backend via the `X-Client-Pub-Key` header (64 hex chars),
- that the `X-Signing-Algo: ed25519` and `X-Encryption-Version: 2` headers are set,
- that the model's Ed25519 public key is converted to X25519 for the ECDH shared secret derivation,
- that the ECDH shared secret is used as input to HKDF-SHA256 with info string `"ed25519_encryption"`,
- that XChaCha20-Poly1305 is used for symmetric encryption/decryption (24-byte nonce, authenticated encryption),
- that nonce generation uses `crypto/rand` and that nonce failure is a hard error,
- that the session private key is zeroed after use (`Session.Zero()`) — per Part 1 sensitive data handling,
- that E2EE is only activated when `tdx_reportdata_binding` has passed — if binding fails, E2EE is refused (not silently degraded to plaintext; per fail-closed policy, degradation is a defect).

#### E2EE Header Protection

A key security benefit of the gateway inference model is that E2EE protects request and response content from the gateway. The audit MUST verify:
- that request message content is encrypted before being sent through the gateway,
- that response message content (both streaming SSE chunks and non-streaming JSON bodies) is decrypted by the proxy,
- that non-encrypted content fields in an E2EE session are treated as errors (not silently accepted as plaintext — per fail-closed policy),
- that the "role" and "refusal" fields are correctly exempted from encryption expectations (these are in the `NonEncryptedFields` allowlist in `internal/e2ee/relay.go`),
- that streaming SSE decryption handles all encrypted delta fields (content, reasoning_content, etc.), not just a hardcoded subset.

#### Signing Key Cache

The signing key (model backend's public key) MAY be cached with a short TTL to avoid re-fetching attestation on every request.

The audit MUST verify:
- that the signing key cache has a shorter TTL than the attestation report cache,
- that the signing key is only cached after successful REPORTDATA binding verification,
- that a key rotation (different signing key from the same provider/model) emits a warning,
- that the cached signing key is the one verified by REPORTDATA binding, not from a subsequent unverified response.

#### e2ee_usable Factor

The `e2ee_usable` factor tests live E2EE encryption/decryption. In the proxy path, the factor starts as Skip (pending live test) with `Deferred: true`, which exempts it from `BuildReport`'s Skip→Fail promotion even when enforced. This solves the chicken-and-egg problem: the proxy can forward the first E2EE request without blocking, then promotes the factor to Pass via `MarkE2EEUsable` after a successful relay. Post-relay decryption failures trigger `MarkE2EEFailed` (demoting to Fail), `e2eeFailed` blocking, and cache invalidation — fail-closed for all subsequent requests until re-attestation. `e2ee_usable` is enforced by default for NearCloud (not in `NearcloudDefaultAllowFail`).

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

Teep uses an inverted enforcement model: any factor NOT in the provider's `DefaultAllowFail` list is enforced by default. Adding a new factor automatically enforces it. The nearcloud provider uses `NearcloudDefaultAllowFail` (defined in `internal/attestation/report.go`), which is stricter than the global `DefaultAllowFail`.

The current nearcloud-specific allowed-to-fail factors are:
- `tdx_hardware_config` — model RTMR0 (varies per deployment hardware),
- `tdx_boot_config` — model RTMR1/RTMR2,
- `cpu_gpu_chain` — not yet implemented,
- `measured_model_weights` — not yet implemented,
- `cpu_id_registry` — Proof-of-Cloud hardware registry,
- `gateway_tdx_hardware_config` — gateway RTMR0,
- `gateway_tdx_boot_config` — gateway RTMR1/RTMR2,
- `gateway_tdx_reportdata_binding` — gateway REPORTDATA binding (currently allowed to fail; the audit MUST document whether this is a deliberate design choice or a gap),
- `gateway_cpu_id_registry` — gateway Proof-of-Cloud.

All other factors are enforced by default for nearcloud, including:

**Model backend factors (Tier 1–3):**
- `nonce_match` — prevents replay of stale model attestations,
- `tdx_quote_present`, `tdx_quote_structure` — TDX quote integrity,
- `tdx_cert_chain` — validates model PCK chain to Intel roots,
- `tdx_quote_signature` — validates model quote signature,
- `tdx_debug_disabled` — prevents model debug enclaves from being trusted,
- `tdx_mrseam_mrtd` — enforces model MRSEAM and MRTD allowlists,
- `signing_key_present` — ensures the model enclave provided a public key for E2EE,
- `tdx_reportdata_binding` — prevents key-substitution MITM on the model backend's E2EE key,
- `tdx_tcb_not_revoked` — rejects revoked TCB levels,
- `intel_pcs_collateral`, `tdx_tcb_current` — Intel PCS collateral and TCB currency,
- `nvidia_payload_present`, `nvidia_signature`, `nvidia_claims`, `nvidia_nonce_client_bound`, `nvidia_nras_verified` — NVIDIA attestation factors,
- `e2ee_capable` — model backend advertises E2EE support,
- `tls_key_binding` — TLS certificate SPKI binding,
- `compose_binding` — enforces model image/config binding to MRCONFIGID,
- `sigstore_verification` — enforces Sigstore presence,
- `build_transparency_log` — enforces Rekor provenance,
- `event_log_integrity` — enforces model RTMR replay consistency.

**Gateway factors (Tier 4):**
- `gateway_nonce_match` — prevents replay of stale gateway attestations,
- `gateway_tdx_quote_present`, `gateway_tdx_quote_structure` — gateway TDX quote integrity,
- `gateway_tdx_cert_chain` — validates gateway PCK chain to Intel roots,
- `gateway_tdx_quote_signature` — validates gateway quote signature,
- `gateway_tdx_debug_disabled` — prevents gateway debug enclaves from being trusted,
- `gateway_tdx_mrseam_mrtd` — enforces gateway MRSEAM and MRTD allowlists,
- `gateway_compose_binding` — enforces gateway image/config binding to MRConfigID,
- `gateway_event_log_integrity` — enforces gateway RTMR replay consistency.

The audit MUST evaluate whether additional factors should be enforced by default and document the rationale for the current enforcement boundary.

> **Known divergence**: Venice uses the global `DefaultAllowFail` (less strict than `NearcloudDefaultAllowFail`), has no gateway factors, and does not enforce `tdx_mrseam_mrtd` or `build_transparency_log` by default. Venice should have its own allowlist in the future.

> **Known divergence: Chutes/Sek8s.** Chutes uses its own `ChutesDefaultAllowFail` list (defined in `internal/attestation/report.go`), which reflects the sek8s attestation model’s structural limitations. The chutes-specific allowed-to-fail factors include:
> - `nvidia_signature` — GPU cert validation (sek8s doesn’t validate NVIDIA root the same way as dstack),
> - `nvidia_nras_verified` — NRAS EAT not required,
> - `tls_key_binding` — TLS cert fingerprint not included in REPORTDATA,
> - `cpu_gpu_chain` — CPU-GPU binding not implemented,
> - `measured_model_weights` — no weight evidence available (see `docs/attestation_gaps/model_weights.md`),
> - `build_transparency_log` — no Rekor entries (no compose manifest),
> - `cpu_id_registry` — Proof-of-Cloud not available for sek8s,
> - `compose_binding` — not applicable (returns `Skip`; sek8s uses cosign admission, not docker-compose),
> - `sigstore_verification` — not applicable (returns `Skip`; no container image digests in attestation),
> - `event_log_integrity` — not applicable (returns `Skip`; event log not exposed to clients),
> Note: `e2ee_usable` is enforced for chutes (not in `ChutesDefaultAllowFail`). The Deferred factor mechanism allows it to start as Skip without blocking requests (see §4.16).
>
> Factors that remain **enforced** for chutes include: `nonce_match`, `tdx_quote_present`, `tdx_quote_structure`, `tdx_cert_chain`, `tdx_quote_signature`, `tdx_debug_disabled`, `tdx_mrseam_mrtd`, `tdx_reportdata_binding`, `intel_pcs_collateral`, `tdx_tcb_current`, `tdx_tcb_not_revoked`, `e2ee_capable`, `signing_key_present`.
>
> The audit for chutes MUST verify: (a) that Skip results for compose_binding, sigstore_verification, event_log_integrity, and build_transparency_log are correctly returned with explanatory messages, (b) that these Skip factors are in `ChutesDefaultAllowFail` and do not block traffic, (c) that the enforced factors provide adequate security despite the absence of compose/event-log/supply-chain checks, (d) that no `gateway_*` factors exist (the Chutes gateway is unattested).

### 5.2 Verification Cache Safety

The necessary verification information MAY be cached locally so that Sigstore and Rekor do not need to be queried on every single connection attempt.

However, the attestation report MUST be verified against either cached or live data, for EACH new TLS connection to the gateway.

The audit MUST explicitly document each cache layer, its keys, TTLs, expiry/pruning behavior, maximum entry limits, and whether stale data is ever served. Specifically:

| Cache | Expected Keys | Expected TTL | Security-Critical Properties |
|-------|--------------|-------------|------------------------------|
| Attestation report cache | (provider, model) | ~minutes | Signing key MUST NOT be cached; must be fetched fresh for each E2EE session |
| Negative cache | (provider, model) | ~seconds | Must prevent upstream hammering; must expire so recovery is possible |
| SPKI pin cache | (domain, spkiHash) | ~hour | Must be populated only after successful attestation of BOTH gateway and model; eviction must force re-attestation |
| Signing key cache | (provider, model) | ~minute | Shorter than attestation cache; holds REPORTDATA-verified signing key for E2EE key exchange |

The audit MUST verify that cache eviction under memory pressure does not silently allow unattested connections. A cache miss MUST trigger re-attestation of BOTH gateway and model, never a pass-through. Per the fail-closed policy, any cache failure path that allows forwarding is a defect.

The audit MUST also verify that the SPKI pin cache uses the gateway's domain and SPKI (since the proxy connects to the gateway, not the model backend directly).

> **Known divergence: Chutes/Sek8s.** Chutes has a different caching model due to the absence of a gateway and the two-step attestation flow:\n> - **Nonce pool cache** (`noncepool.go`): Caches instances and nonces from the instances endpoint, keyed per chute, with TTL from `nonce_expires_in`. The audit MUST verify that nonce pool entries expire correctly and that a cache miss triggers a fresh instances fetch.\n> - **No SPKI pin cache**: Chutes does not use attestation-bound TLS pinning, so there is no SPKI pin cache.\n> - **Model resolver cache**: Human-readable model names are resolved to chute UUIDs with a 5-minute TTL. The audit MUST verify that a failed resolution does not serve a stale mapping.\n> - Cache eviction MUST NOT allow unattested E2EE key usage. A nonce pool miss must trigger fresh attestation before any E2EE session.

### 5.3 Negative Cache and Failure Recovery

The audit MUST verify the negative cache behavior:
- that a failed attestation attempt (for either gateway or model) records a negative entry preventing repeated upstream requests,
- that negative entries expire after a bounded TTL (not indefinitely cached),
- that the negative cache has bounded size with eviction of expired entries under pressure,
- that a negative cache hit returns a clear error to the client (for example, HTTP 503) rather than silently failing open or forwarding unauthenticated.

### 5.4 Connection Lifetime Safety

TLS connections to the gateway MUST be closed after each request-response cycle (Connection: close) to ensure each new request triggers a fresh attestation or SPKI cache check.

If the implementation reuses connections, the audit MUST verify that re-attestation is correctly triggered on every new request, not just on new connections.

The audit MUST verify:
- that the response body wrapper closes the underlying TCP connection when the body is consumed or closed,
- that connection read/write timeouts are set and reasonable (noting that gateway connections may need longer timeouts due to two attestation payloads being fetched on a single connection),
- that a half-closed or errored connection cannot be mistakenly reused for a subsequent request,
- that the attestation request uses Connection: keep-alive (to allow the chat request on the same connection) while the chat request uses Connection: close.

### 5.5 Offline Mode Safety

If the system supports an offline mode, the audit MUST enumerate exactly which checks are skipped (for example, Intel PCS collateral, NRAS, Sigstore, Rekor, Proof-of-Cloud) and which checks still execute locally (for example, quote parsing/signature checks, report-data binding, event-log replay) — for BOTH the gateway and model backend attestation.

For the pinned connection path, the audit MUST verify whether offline mode is honored (the PinnedHandler receives an `offline` flag). The offline flag must suppress only network-dependent checks — all local cryptographic verification must remain active for both gateway and model.

The report MUST include residual risk of running in offline mode.

### 5.6 Proof-of-Cloud

Ensure that the code verifies that the machine ID from the model backend's attestation is covered in proof-of-cloud.

The audit MUST document:
- machine identity derivation inputs (for example, PPID from the PCK certificate),
- remote registry verification flow,
- quorum/threshold requirements if multiple trust servers are used (expected: 3-of-3 nonce collection, then chained partial signatures),
- behavior when Proof-of-Cloud is unavailable (skip with informational status, or hard fail),
- whether the Proof-of-Cloud result is cached and under what conditions it is re-queried.

The audit MUST also document whether Proof-of-Cloud is checked for the gateway CVM, or only for the model backend CVM, and whether a missing gateway PoC check is a residual risk.

Track future expansion items separately (for example, DCEA and TPM quote integration), but keep this audit focused on checks currently implemented and required for production security decisions.

---

## Part 6 — Input/Output Safety

### 6.1 HTTP Request Construction Safety

For gateway providers that construct raw HTTP requests on the underlying TLS connection (bypassing Go's http.Client connection pooling), the audit MUST verify:
- that the Host header is always set to the gateway domain,
- that Content-Length is derived from the actual body length (not caller-supplied),
- that no user-supplied data is interpolated into HTTP request lines or headers without sanitization (HTTP header injection prevention),
- that header values reject CR/LF characters (or equivalent canonicalization/sanitization is applied),
- that the request path is constructed from trusted constants plus URL-encoded query parameters,
- that the attestation request uses keep-alive while the chat request uses Connection: close,
- that the Authorization header is set correctly for both the attestation and chat requests.

### 6.2 Response Size and Resource Limits

The audit MUST verify that all HTTP response bodies read by the proxy are bounded:
- gateway attestation responses (recommended: ≤2 MiB, larger than direct inference due to dual payloads),
- SSE streaming buffers (bounded scanner buffer sizes with pooling),
- any other external data read during verification (Sigstore, Rekor, NRAS, PCS).

Per Part 1 input bounds rules, unbounded reads from untrusted sources represent a denial-of-service vector and MUST be flagged.

---

## Part 7 — Trust Model and Report Requirements

### 7.1 Trust Delegation and Gateway Compromise Resilience

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

#### Chutes/Sek8s Trust Model

The chutes trust model differs from the nearcloud gateway model. The Chutes gateway (`api.chutes.ai`/`llm.chutes.ai`) routes requests to sek8s TEE instances but is itself unattested, so the trust delegation is different:

1. **Unattested gateway**: The proxy connects to the Chutes gateway via standard HTTPS. There is no attestation-bound TLS pinning and no gateway TDX quote. The gateway can observe request routing metadata but, with E2EE active, cannot read inference content.
2. **E2EE key integrity via REPORTDATA**: The ML-KEM-768 public key is bound to the TDX quote via REPORTDATA. The proxy encrypts using this key, ensuring that only the attested TEE can decrypt.
3. **Request/response confidentiality**: ML-KEM-768 + ChaCha20-Poly1305 E2EE protects content from any intermediary, including the Chutes infrastructure itself.

**Residual trust assumptions specific to chutes/sek8s** (documented in `docs/attestation_gaps/sek8s_integrity.md`):
- **Cosign admission controller**: Teep trusts that the cosign admission webhook inside each sek8s TEE VM is correctly configured and enforcing. Teep has zero visibility into which containers are running.
- **LUKS boot gating**: Teep trusts that the Chutes validator (`chutes-api`) correctly withholds the LUKS decryption key for VMs whose measurements do not match golden values. If the LUKS passphrase leaked, measurement-passing VMs could be substituted.
- **Golden measurement correctness**: Teep's pinned MRTD/RTMR0-2 values are captured from observed Chutes deployments. They are only trustworthy if the deployment was running the correct sek8s image at capture time.
- **Runtime attestation**: RTMR3/IMA verification is entirely server-side. Teep trusts that Chutes re-attests running VMs.
- **Model weight integrity**: Depends entirely on the measured boot chain preventing unauthorized image loading. Neither watchtower verification nor cllmv per-token verification is available to teep for TEE instances.

The audit for chutes MUST include a dedicated section evaluating these trust assumptions and their residual risk.

### 7.2 Report Writing

The report MUST avoid vague language such as "looks secure" without code-backed evidence.

Each finding MUST include:
- severity and exploitability context,
- exact impacted control and whether it is currently enforced,
- realistic impact statement (integrity, confidentiality, availability),
- remediation guidance with concrete code-level direction,
- at least one source citation proving current behavior.

When no findings are present for a section, the report MUST explicitly state "no issues found in this section" and still note any residual risk or testing gap.

### 7.3 Fail-Closed Verification Summary

The report MUST include a dedicated section confirming that every error path in the attestation and forwarding pipeline was checked against the fail-closed policy from Part 1. For each code path where an error is caught, the report MUST state whether the error results in request blocking or whether it falls through — and flag any fall-through as a critical finding.
