# Shared Preamble — Direct Inference Provider Audit

This repository implements a proxy for private LLM inference using attestation-bound TLS pinning. The goal is to verify the remote machine runs genuine TEE hardware with verifiable software, and to prevent MITM through cryptographic binding between TLS channel identity and attestation evidence.

This is a **direct inference** provider audit: attestation covers a single model server layer.

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

