# Direct Inference Provider Audit

This repository implements a proxy that ensures private LLM inference by performing end-to-end encryption of inference data, using attestation for encryption key binding, and validating proof-of-integrity of infrastructure.

Please verify every stage of attestation for the requested provider, following this audit guide to produce a detailed report.

This audit applies to direct inference providers, where the API endpoint is running the inference directly on the same machine, meaning that there will only be one layer of attestation to verify.

The report MUST cite the source code locations relevant to BOTH positive AND negative audit findings, using relative markdown links to the source locations, for human validation of audit claims.

The report MUST also distinguish between:
- checks that are computed but do not block traffic, and
- checks that are enforced fail-closed (request rejected on failure).

## Model Routing

In this direct inference model, the attestation covers a single model server. There is a model mapping routing API that the teep proxy consults to determine the destination host for a particular model identity string.

Certificate Transparency MUST be consulted for the TLS certificate of this model router endpoint. This CT log report SHOULD be cached.

The audit MUST verify model routing safety controls, including:
- model-to-domain mapping cache TTL and refresh behavior,
- rejection of malformed endpoint domains (scheme/path/whitespace injection),
- exact model selection behavior when multiple endpoint entries exist,
- concurrency behavior for refreshes (singleflight or equivalent anti-stampede control).

## Attestation Verification

Upon connection to the model server, the attestation API of this model server MUST be queried and fully validated before any inference request is sent to the model server.

Certificate Transparency MUST be consulted for the TLS certificate of this model endpoint. This CT log report SHOULD be cached.

The attestation information is provided by an API endpoint as a JSON object that includes the Intel TEE attestation, NVIDIA TEE attestation, and auxiliary information such as docker compose contents and event log metadata.

### Nonce Freshness and Replay Resistance

The verifier MUST generate a fresh 32-byte cryptographic nonce per attestation attempt.

The code MUST verify nonce equality using constant-time comparison and fail closed on mismatch.

If cryptographic randomness fails, nonce generation MUST fail closed (no weak fallback mode).

Signatures over the Intel TEE attestation MUST be verified for the entire certificate chain, including:
- quote structure parsing (supported quote versions),
- PCK chain validation back to Intel trust roots,
- quote signature verification,
- debug bit check (debug enclaves rejected for production trust),
- TCB collateral and currency classification when online.

Document how trust roots are obtained (embedded/provisioned), and how third-party verification libraries are called and interpreted.

### TDX Measurement Fields and Policy Expectations

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

Current direct-provider expectation:
- MRCONFIGID is expected to be cryptographically checked via compose binding,
- RTMR fields are expected to be consistency-checked via event log replay when event logs are present,
- all other TDX measurement fields MUST be documented as either policy-checked or currently informational-only, with residual risk called out.

### CVM Image Verification

The attestation API will provide a full docker compose stanza, or equivalent podman/cloud config image description, as an auxiliary portion of the attestation API response.

The code MUST calculate a hash of these contents, which MUST be verified to be properly attested in the TDX mrconfig field.

The audit MUST verify the exact binding format expected by the implementation (for example, 48-byte MRConfigID layout, prefix rules, and byte-level comparison semantics).

### CVM Image Component Verification

The docker compose file (or podman/cloud config) will list a series of sub-images. Each of these sub-images MUST be checked against Sigstore and Rekor (or equivalent systems) to establish that they are official builds and not custom variations.

The audit MUST verify:
- extraction logic for image digests from compose content,
- Sigstore query behavior and failure handling,
- Rekor provenance extraction logic,
- issuer/identity checks used to classify provenance as trusted.

### CVM Verification Cache Safety

The necessary verification information MAY be cached locally so that Sigstore and Rekor do not need to be queried on every single connection attempt.

However, the docker compose hash MUST be verified against either cached or live data, for EACH new TLS connection to the API provider.

If the docker compose hash is not present in the cache, or any of the sub-images are not present in the cache, these must be validated against Sigstore and Rekor before proceeding.

The audit MUST explicitly document cache keys, TTLs, expiry/pruning behavior, and whether each verification datum is actually cached in the current implementation.

### Encryption Binding

The attestation report must bind channel identity and key material in a way that prevents key-substitution attacks.

For each provider, the audit MUST document the exact REPORTDATA scheme and verify it byte-for-byte.

For NearAI, this includes verifying:
- REPORTDATA[0:32] = SHA256(signing_address_bytes || tls_fingerprint_bytes)
- REPORTDATA[32:64] = raw client nonce bytes

The binding comparison MUST be constant-time.

The code MUST validate this binding cryptographically and the report MUST state whether failure blocks forwarding or only downgrades security posture.

### TLS Pinning and Connection-Bound Attestation

For direct inference providers that use attestation-bound TLS pinning:
- the live TLS certificate fingerprint/SPKI MUST be extracted from the same active connection,
- attested TLS fingerprint MUST match the live connection fingerprint,
- attestation fetch and inference request SHOULD occur on the same TLS connection to avoid TOCTOU swaps,
- any TLS verification bypass mode (for example, custom pinning replacing CA checks) MUST be justified and cryptographically compensated by attestation checks.

The audit MUST verify pin-cache behavior (TTL, cache miss behavior, and re-attestation trigger).

### NVIDIA TEE Verification Depth

The audit MUST verify both layers when present:
- local NVIDIA evidence verification (EAT/SPDM signature, cert chain, nonce), and
- remote NVIDIA NRAS verification (JWT signature, accepted algorithms, claims validity, overall attestation result).

If offline mode exists, the audit MUST state which NVIDIA checks remain active and which are skipped.

### Event Log Integrity

If event logs are present in provider attestation payloads, the code MUST replay them and verify recomputed RTMR values against quote RTMR fields.

The audit MUST describe replay algorithm details and failure handling.

The audit MUST also state the exact security boundary of this check: event log replay validates internal consistency of event-log-derived RTMR values with quoted RTMR values, but does not by itself prove that RTMR values match an approved software baseline. If no baseline policy is enforced for MRTD/RTMR/MRSEAM-class measurements, that gap MUST be reported explicitly.

## Connection Lifetime Safety

TLS connections to a model server SHOULD be kept open and re-used for subsequent requests, to avoid the need to re-attest upon every HTTP request.

If any connection times out or is prematurely closed, full attestation MUST be performed again.

The audit MUST verify whether attestation is performed pre-request on every new connection, or skipped based on a validated pin cache, and under what TTL/expiry conditions.

## Enforcement Policy and Failure Semantics

The audit report MUST include a table of verification factors with:
- pass/fail/skip semantics,
- whether the factor is enforced by policy,
- whether failure blocks request forwarding,
- whether failure disables confidentiality guarantees without blocking traffic.

This section is required to prevent regressions where checks continue to be reported but are no longer security-enforcing.

## Offline Mode Safety

If the system supports an offline mode, the audit MUST enumerate exactly which checks are skipped (for example, Intel PCS collateral, NRAS, Sigstore, Rekor, Proof-of-Cloud) and which checks still execute locally (for example, quote parsing/signature checks, report-data binding, event-log replay).

The report MUST include residual risk of running in offline mode.

## Proof-of-Cloud

Ensure that the code verifies that the machine ID from the attestation is covered in proof-of-cloud.

The audit MUST document:
- machine identity derivation inputs,
- remote registry verification flow,
- quorum/threshold requirements if multiple trust servers are used,
- behavior when Proof-of-Cloud is unavailable.

Track future expansion items separately (for example, DCEA and TPM quote integration), but keep this audit focused on checks currently implemented and required for production security decisions.