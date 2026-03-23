# Direct Inference Audit Prompt Pack

This prompt pack decomposes [`direct_inference.md`](../direct_inference.md) into self-contained sections for delegated sub-agent review.

## Dispatch Model (Orchestrator)

For each delegated task, provide exactly:
1. [`00_shared_preamble.md`](00_shared_preamble.md)
2. one numbered section file (for example [`03_tdx_quote.md`](03_tdx_quote.md))

Do not send multiple numbered sections to the same sub-agent unless intentionally combining scopes.

## Available Delegated Sections

1. [`01_model_routing.md`](01_model_routing.md)
2. [`02_attestation_fetch.md`](02_attestation_fetch.md)
3. [`03_tdx_quote.md`](03_tdx_quote.md)
4. [`04_tdx_measurements.md`](04_tdx_measurements.md)
5. [`05_cvm_image.md`](05_cvm_image.md)
6. [`06_nvidia_tee.md`](06_nvidia_tee.md)
7. [`07_tls_binding.md`](07_tls_binding.md)
8. [`08_event_log.md`](08_event_log.md)
9. [`09_policy_caching.md`](09_policy_caching.md)
10. [`10_proof_of_cloud.md`](10_proof_of_cloud.md)
11. [`11_transport_safety.md`](11_transport_safety.md)

## Final Report Assembly Rules

The assembled final report MUST include:
- executive summary with severity counts and one-paragraph overall risk statement,
- findings summary table (severity, location, impact),
- findings-first narrative sections (ordered by severity within each section),
- for every major section, at least one concrete positive control observation and one concrete negative/residual-risk observation,
- verification-factor matrix (pass/fail/skip + enforcement status),
- cache-layer table (keys, TTL, bounds, stale behavior),
- offline-mode matrix (active checks vs skipped checks),
- explicit open questions / assumptions where behavior cannot be proven from code.

Each finding MUST include:
- severity + exploitability context,
- exact impacted control,
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
