# Direct Inference Provider Audit

This repository implements a proxy for private LLM inference using attestation-bound TLS pinning. The goal is to verify the remote machine runs genuine TEE hardware with verifiable software, and to prevent MITM through cryptographic binding between TLS channel identity and attestation evidence.

This is a **direct inference** provider audit: attestation covers a single model server layer.

## Architectural Overview

The verification pipeline proceeds through these stages for every new TLS connection to an inference provider:

1. **Model Routing & Endpoint Discovery** — The proxy consults a provider-specific routing API to resolve a model identity string to a destination host. Certificate Transparency is checked for the routing endpoint.
2. **Attestation Fetch & Parsing** — The proxy connects to the model server's attestation API, sends a fresh cryptographic nonce, and retrieves a JSON attestation response containing Intel TDX evidence, NVIDIA TEE evidence, and auxiliary data (docker compose, event logs).
3. **TDX Quote Verification** — The Intel TDX quote is parsed, the PCK certificate chain is validated to Intel trust roots, quote signature is verified, and debug-mode enclaves are rejected.
4. **TDX Measurement & Policy Enforcement** — MRTD, RTMR0-3, MRSEAM, MRCONFIGID, and REPORTDATA fields are extracted. Policy allowlists are checked where available; event log replay verifies RTMR consistency.
5. **CVM Image & Component Verification** — The docker compose hash is bound to MRConfigID. Sub-images are checked against provider allowlists and verified through Sigstore/Rekor for build provenance.
6. **NVIDIA TEE Verification** — Local EAT/SPDM evidence is validated (per-GPU certificate chains, SPDM signatures). Remote NRAS JWT verification provides an additional attestation layer.
7. **TLS Pinning & Connection Binding** — The live TLS certificate SPKI hash is bound to the attestation report via REPORTDATA. The SPKI pin is cached for subsequent connections.
8. **Enforcement & Forwarding** — All enforced verification factors are checked; if any fail, the request is rejected. Only after successful attestation is the inference request forwarded on the same TLS connection.

## Threat Model Summary

The primary threats this system defends against:
- **MITM by infrastructure operators**: A cloud provider or network intermediary intercepting inference traffic.
- **Model server impersonation**: An attacker substituting a non-TEE server that mimics the API but exfiltrates prompts.
- **Replay attacks**: Reusing stale attestation evidence to bypass freshness checks.
- **Key substitution attacks**: An attacker providing valid attestation but swapping the encryption key used for the TLS channel.
- **Supply chain attacks**: Modified container images or firmware running inside the TEE.
- **Downgrade attacks**: Forcing the use of debug enclaves, outdated TCB levels, or weaker verification modes.

The trust boundary is the TEE itself: the proxy trusts nothing outside cryptographically verified attestation evidence.

## Quality Bar and Deliverables

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

## Report Requirements

Your report MUST:
- cite source code locations for all substantive claims (positive and negative), using relative markdown links,
- distinguish checks as `enforced fail-closed`, `computed but non-blocking`, or `skipped/advisory`,
- separate implementation facts from recommendations,
- avoid vague claims without code-backed evidence.

Each finding MUST include:
- severity + exploitability context,
- impacted control and enforcement status,
- realistic CIA impact statement,
- concrete remediation guidance,
- at least one source citation.

When no issues are found in your delegated section, explicitly state: **"no issues found in this section"**, and include residual risk or testing gap notes.

## Cross-Cutting Audit Concerns

The following apply across all sections and should be evaluated wherever relevant:

### Go (Golang) Best Practices
- **Error handling**: Verify errors are checked and wrapped with `fmt.Errorf("context: %w", err)` for traceability. Sentinel errors should be used for control flow decisions (`errors.Is`, `errors.As`).
- **Type safety**: Verify that byte slices used in cryptographic operations have explicit length checks before indexing or slicing. Ensure no silent truncation of hash digests or nonces.
- **Interface usage**: Provider-specific logic should be abstracted behind interfaces (e.g., REPORTDATA verification pluggable per provider). Verify that a missing or unconfigured implementation fails safely.
- **Concurrency safety**: Shared caches and state must be protected by `sync.RWMutex`, `sync.Map`, or `singleflight`. Verify no data races on hot paths (especially attestation caches, SPKI pin caches, endpoint caches).
- **Resource cleanup**: Verify `defer` usage for closing HTTP response bodies, TLS connections, and temporary buffers. Verify that `io.LimitReader` is used on all untrusted response bodies.

### Cryptography Best Practices
- **Constant-time comparison**: All security-critical comparisons (nonces, REPORTDATA, SPKI hashes, measurement values) MUST use `subtle.ConstantTimeCompare` or equivalent. Flag any use of `==` or `bytes.Equal` on secret-adjacent data.
- **Randomness source**: All nonces and cryptographic key material MUST come from `crypto/rand`. Flag any use of `math/rand` in security-relevant paths.
- **Key/nonce lifecycle**: Ephemeral key material should be zeroed after use where feasible (acknowledging Go GC limitations). Nonces must never be reused across requests.
- **Certificate validation**: Verify that certificate chain validation uses proper path building with expiry, revocation, and name constraint checks. Pin to specific trust roots rather than the system trust store for TEE-related chains.

### General Security Audit Practices
- **Input validation at trust boundaries**: All data received from external sources (attestation APIs, routing APIs, NRAS, PCS, Sigstore) is untrusted and must be validated before use.
- **Defense in depth**: Verify that multiple independent checks protect critical security properties. No single check failure should silently degrade the overall security posture.
- **Fail-secure defaults**: Missing configuration, unavailable services, and ambiguous states must default to denial, not permission.
- **Bounded resource consumption**: All external reads must be size-bounded to prevent memory exhaustion DoS. Caches must have maximum entry limits and bounded TTLs.
- **Sensitive data handling**: API keys must not be logged in plaintext (redact to first-N characters). Config file permissions should be checked. Attestation nonces must not be reused.

## Report Output

Write your report to a *file*, and inform the orchestrator of the location of this file. Do *not* provide the full contents of your report to the orchestrator as text.