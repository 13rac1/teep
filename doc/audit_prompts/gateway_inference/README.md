# Gateway Inference Audit Prompt Pack

This prompt pack defines the audit process for gateway (NearCloud / NEAR AI) inference providers. It is intended to be delegated to sub-agents in self-contained sections.

**NOTE**: To minimize context bloat, communicate by referring to prompts and sub-agent reports by *filename*. Do NOT repeat the contents of these prompts or the audit results in communication to agents.

## Dispatch Model (Orchestrator)

The audit is to be performed by five sub-agents, each given one of the following groups of prompt files from this directory:

1. Gateway Architecture & Attestation Surface
    - [`00_shared_preamble.md`](00_shared_preamble.md)
    - [`01_gateway_architecture.md`](01_gateway_architecture.md)
    - [`02_attestation_fetch.md`](02_attestation_fetch.md)
    - [`03_transport_safety.md`](03_transport_safety.md)

2. TDX Core Integrity
    - [`00_shared_preamble.md`](00_shared_preamble.md)
    - [`04_tdx_quote.md`](04_tdx_quote.md)
    - [`05_tdx_measurements.md`](05_tdx_measurements.md)
    - [`06_event_log.md`](06_event_log.md)

3. Binding, Pinning & E2EE
    - [`00_shared_preamble.md`](00_shared_preamble.md)
    - [`07_reportdata_tls.md`](07_reportdata_tls.md)
    - [`08_e2ee.md`](08_e2ee.md)

4. Supply-Chain Provenance & Policy
    - [`00_shared_preamble.md`](00_shared_preamble.md)
    - [`09_cvm_image.md`](09_cvm_image.md)
    - [`10_policy_caching.md`](10_policy_caching.md)

5. Auxiliary Attestation Signals
    - [`00_shared_preamble.md`](00_shared_preamble.md)
    - [`11_nvidia_tee.md`](11_nvidia_tee.md)
    - [`12_proof_of_cloud.md`](12_proof_of_cloud.md)

Note that *all* five (5) sub-agents are given [`00_shared_preamble.md`](00_shared_preamble.md).

The five sub-agents are *not* given this README file. This README file contains orchestration and report assembly instructions only. You MAY give this README file to a sixth sub-agent, along with all of the result *files* from the five other sub-agents, to write the final report file.

## Key Differences from Direct Inference

Gateway inference introduces a **two-tier attestation architecture** where both a gateway CVM and a model backend CVM are independently attested. Sub-agents must track two sets of verification factors across the audit:

- **Model backend** (Tiers 1–3): TDX quote, measurements, event log, REPORTDATA binding, CVM image, NVIDIA GPU, Proof-of-Cloud.
- **Gateway** (Tier 4): TDX quote, measurements, event log, REPORTDATA binding, CVM image. No GPU attestation and potentially no Proof-of-Cloud.

Additionally, the gateway architecture introduces:
- **E2EE** between the local proxy and the model backend, bypassing the gateway for confidentiality,
- **Trust delegation** where the model backend's TLS fingerprint is communicated only within the gateway's verified attestation response,
- **Dual REPORTDATA schemes** — the model backend binds `signing_address + tls_fingerprint + nonce` while the gateway binds `tls_fingerprint + nonce` only.

Sub-agents in Groups 2–5 must verify each control for **both** the gateway and the model backend where applicable, and explicitly document gaps where a control applies to one tier but not the other.

## Final Report Assembly Rules

Do NOT copy report *contents* between yourself and sub-agents. Refer to sub-reports by *filename*, prior to assembly. Write the final report itself to a *file*, not to direct output.

The assembled final report MUST include:
- executive summary with severity counts and one-paragraph overall risk statement,
- findings summary table (severity, location, impact),
- findings-first narrative sections (ordered by severity within each section),
- for every major section, at least one concrete positive control observation and one concrete negative/residual-risk observation,
- **dual-tier verification-factor matrix** showing pass/fail/skip + enforcement status for BOTH the gateway CVM and the model backend CVM,
- cache-layer table (keys, TTL, bounds, stale behavior),
- offline-mode matrix (active checks vs skipped checks),
- trust delegation summary — controls that rely on the gateway's attestation to vouch for model backend properties,
- E2EE assessment — whether end-to-end encryption provides confidentiality even if the gateway is compromised,
- explicit open questions / assumptions where behavior cannot be proven from code.

Each finding MUST include:
- severity + exploitability context,
- exact impacted control,
- which tier(s) affected (gateway, model backend, or both),
- whether control is enforced fail-closed,
- realistic CIA impact statement,
- concrete remediation guidance,
- at least one source citation.

If a delegated section has no issues, that section must still state: **"no issues found in this section"** and include residual risk / test gap notes.

## Merge & Conflict Policy

- Deduplicate cross-sectional findings by code location + control name.
- Preserve all source citations from delegated outputs.
- If severity disagrees across sections, keep the higher severity and note disagreement.
- Keep implementation facts separate from recommendations (no implicit policy assumptions).
- When the same code path handles both gateway and model backend attestation, merge findings but note the dual scope.
