# Gateway Inference Provider Audit

This repository implements a proxy that ensures private LLM inference by performing attestation-bound TLS pinning to a TEE-attested API gateway, which in turn routes traffic to TEE-attested model inference backends. The proxy validates that both the gateway and the model backend run genuine TEE hardware with verifiable software, prevents man-in-the-middle attacks through cryptographic binding of the TLS channel to the gateway's attestation report, and protects request and response confidentiality through E2EE using a signing key obtained from the model backend's attestation.

This is a **gateway inference** provider audit: attestation covers two layers — a gateway CVM and a model backend CVM. The primary reference provider is **nearcloud** (NearCloud / NEAR AI), which provides full dual-tier TEE attestation. **Venice** is a secondary reference: it forwards model backend attestation but does NOT provide gateway-level TEE attestation — see Section 01 for architectural divergences.

## Architectural Overview

Unlike direct inference providers where the proxy connects directly to the model server, the gateway architecture interposes a TEE-attested load balancer (the "gateway") between the proxy and the model backend:

```
Client → teep proxy → cloud-api.near.ai (gateway CVM) → model backend CVM
                          ↑ TLS pinned               ↑ internal routing
                          ↑ gateway attestation       ↑ model attestation
```

The gateway host is fixed (not resolved via a model routing API). The proxy opens a single TLS connection to the gateway, performs attestation on that connection (receiving both gateway and model attestation in a single response), and then sends the chat request on the same connection.

The two layers of attestation to verify are:
- **Tier 1–3 (model):** the model inference backend's TDX quote, NVIDIA attestation, compose binding, event log, REPORTDATA binding, and supply chain verification,
- **Tier 4 (gateway):** the gateway's own TDX quote, compose binding, event log, REPORTDATA binding, and TLS certificate binding.

Additionally, the model backend's attestation provides an E2EE signing key that the proxy uses to encrypt request messages and decrypt response messages, protecting header and body confidentiality even if the gateway is compromised.

## Threat Model Summary

The primary threats this system defends against:
- **MITM by infrastructure operators**: A cloud provider or network intermediary intercepting inference traffic.
- **Model server impersonation**: An attacker substituting a non-TEE server that mimics the API but exfiltrates prompts.
- **Replay attacks**: Reusing stale attestation evidence to bypass freshness checks.
- **Key substitution attacks**: An attacker providing valid attestation but swapping the encryption key used for E2EE.
- **Supply chain attacks**: Modified container images or firmware running inside the TEE.
- **Downgrade attacks**: Forcing the use of debug enclaves, outdated TCB levels, or weaker verification modes.
- **Gateway compromise**: A compromised gateway attempting to relay a different model backend's attestation, intercept encrypted inference content, or route to an unattested machine.

The trust boundary is the TEE itself: the proxy trusts nothing outside cryptographically verified attestation evidence.

## Repository Security Rules

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
- Allows requests to be forwarded without TEE-attested E2EE encryption and authentication.
- Serves stale or cached data when re-validation fails, without blocking.

If an error path does anything other than return/propagate an error, it is a defect.

There are **NO** acceptable workarounds, fallbacks, or error recoveries for security validation.

### Additional Mandatory Rules

- Encryption MUST be authenticated (AES-GCM, not AES-CTR/CBC alone).
- Encryption keys MUST be bound to TEE attestation.
- Nonce generation MUST use `crypto/rand`. If randomness fails, the code MUST panic or return an error — never use a weak source.
- NEVER log or print API keys, inference request bodies, or response bodies.
- Unknown or misspelled config values MUST be rejected at startup (not silently ignored).
- JSON unmarshalling SHOULD use strict mode (reject unknown fields).
- All reads from untrusted sources (HTTP bodies, JSON arrays) MUST be bounded.

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
- **Concurrency safety**: Shared caches and state must be protected by `sync.RWMutex`, `sync.Map`, or `singleflight`. Verify no data races on hot paths (especially attestation caches, SPKI pin caches).
- **Resource cleanup**: Verify `defer` usage for closing HTTP response bodies, TLS connections, and temporary buffers. Verify that `io.LimitReader` is used on all untrusted response bodies.

### Cryptography Best Practices
- **Constant-time comparison**: All security-critical comparisons (nonces, REPORTDATA, SPKI hashes, measurement values) MUST use `subtle.ConstantTimeCompare` or equivalent. Flag any use of `==` or `bytes.Equal` on secret-adjacent data.
- **Randomness source**: All nonces and cryptographic key material MUST come from `crypto/rand`. Flag any use of `math/rand` in security-relevant paths.
- **Key/nonce lifecycle**: Ephemeral key material should be zeroed after use where feasible (acknowledging Go GC limitations). Nonces must never be reused across requests.
- **Certificate validation**: Verify that certificate chain validation uses proper path building with expiry, revocation, and name constraint checks. Pin to specific trust roots rather than the system trust store for TEE-related chains.

### General Security Audit Practices
- **Input validation at trust boundaries**: All data received from external sources (attestation APIs, NRAS, PCS, Sigstore) is untrusted and must be validated before use.
- **Defense in depth**: Verify that multiple independent checks protect critical security properties. No single check failure should silently degrade the overall security posture.
- **Fail-secure defaults**: Missing configuration, unavailable services, and ambiguous states must default to denial, not permission.
- **Bounded resource consumption**: All external reads must be size-bounded to prevent memory exhaustion DoS. Caches must have maximum entry limits and bounded TTLs.
- **Sensitive data handling**: API keys must not be logged in plaintext (redact to first-N characters). Config file permissions should be checked. Attestation nonces must not be reused.

## Report Output

Write your report to a *file*, and inform the orchestrator of the location of this file. Do *not* provide the full contents of your report to the orchestrator as text.
