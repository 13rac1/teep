# [Gap Title]: [Concise Description]

**Date:** YYYY-MM-DD
**Status:** Open | Remediation in progress | Resolved

<!-- TITLE: Name the specific gap. Examples from existing reports:
  - "Dstack Integrity Chain: In-Band Discovery Gap"
  - "NearCloud E2EE: Gateway Header-Forwarding Gaps"
  - "Hardware Attestation Binding Issues and Mitigations"
-->

<!-- OPENING PARAGRAPH: 2-3 sentences. What is the gap, what's at risk, what's
the current status. A product manager should be able to read this paragraph and
decide whether to keep reading. No protocol names or register identifiers. -->

## The Problem

<!-- Plain language. What is missing or broken, why it matters for users and
customers, what could go wrong. Write for someone who knows what TEE attestation
is and why it matters, but does not know the specifics of TDX registers, SPDM
sessions, or dstack event logs.

Avoid jargon here — save protocol details for Technical Background below.

Write for the product manager responsible for the provider's infrastructure —
they may have no knowledge of teep or how it works. Describe what is missing
or broken in the provider's system and why it matters for their users and
customers. Do not mention teep in this section. -->

## Impact

<!-- Concrete risks. What could an attacker do? What do users lose? What should
providers worry about? Frame severity clearly.

Before listing impacts, verify that no compensating controls exist elsewhere in
the protocol. Check for: signing key rotation schedules, alternative
authentication, request nonces that prevent replay, independent freshness
mechanisms, and any other means by which the protocol achieves the same goal
through a different path. If compensating controls exist, the gap may be a
best-practice violation rather than a security vulnerability.

Distinguish security impact from operational impact:
- Security impact: What can an attacker do? Can they impersonate hardware,
  replay credentials, bypass checks? What is the concrete attack scenario?
- Operational impact: What reliability, performance, or availability
  consequences result? Does the gap force workarounds that increase fragility?
  Frame operational impact for any security-conscious consumer of the
  provider's service — do not reference teep factor names, workarounds, or
  internals.

If the gap is a standards violation but has no identifiable security impact
beyond best practice, note this explicitly — it may belong in a nitpick
category rather than a gap report.

Examples of good impact framing from existing reports:
- "A forged quote is cryptographically indistinguishable from a legitimate one"
- "The gateway can observe all non-chat traffic"
- "Embedding vectors leak semantic content"
- "Voice data contains biometric identifiers" -->

## Current Status

<!-- Summary table of the provider's current implementation status for the
security properties in question. What does the provider verify? What is
missing? Frame for the provider's engineers and product managers.

Teep-specific factor status and workarounds belong in the optional
"Teep Status" section at the end of the document.

Example format:

| Property | Provider status | Detail |
|---|---|---|
| TDX quote authenticity | Implemented | Standard DCAP verification |
| Container image identity | Not implemented | Provider does not expose image digests |
| Model weight hashes | Not implemented | No mechanism exists |
-->

---

## Technical Background

<!-- For the motivated reader who wants to understand the gap in depth.
Architecture diagrams, protocol details, register meanings, relevant standards.

This section should provide enough context that an engineer unfamiliar with the
specific subsystem can understand the Detailed Analysis that follows.

Mermaid diagrams and ASCII architecture diagrams are welcome. Examples from
existing reports:
- TDX register table (dstack_integrity.md)
- Client → Gateway → Model TEE flow (e2ee_plaintext_gaps.md)
- Trust chain diagram with color-coded verification status (dstack_integrity.md)
-->

## Detailed Analysis

<!-- The deep dive. Source code analysis, protocol traces, test results,
research findings. Reference specific files, line numbers, and function names.

Subsection as needed — existing reports use subsections like:
- "Server Source Code Analysis" with per-component breakdowns
- "Research Findings" with per-register investigation results
- "What Works" / "What Does Not Work" split
- Per-approach analysis with comparison tables

This is where you put the evidence that supports the claims in The Problem
and Impact sections above. -->

---

## Remediation

<!-- What the provider should change to close the gap. Be specific: reference
source files, API fields, protocol extensions, or configuration changes.
Prioritize by implementation ease and security impact. Use stage-based
trajectories when options build on each other.

### What providers should implement

List concrete changes. Reference existing patterns where applicable.

### Deployment priority

If there are multiple remediation options, order by implementation ease and
security impact. -->

## References

<!-- Papers, repositories, specifications, documentation links.
Group by topic when there are many. Examples:

- **Source code:** GitHub links to specific files/functions analyzed
- **Standards:** IETF, PCI-SIG, DMTF specifications
- **Research:** Academic papers, whitepapers, security advisories
- **Documentation:** Provider docs, attestation guides -->

---

<!-- OPTIONAL SECTIONS: Include when applicable.

## Test Descriptions

Integration test methodology and results. Describe what each test does, what
it proves, and how to run it. Include a results summary table dated to when
tests were last run. See e2ee_plaintext_gaps.md for a thorough example.

## Trust Model

Explicit trust assumptions and residual risks. What must the user trust the
provider to implement correctly? What can teep not independently verify?
Number each assumption. See sek8s_integrity.md for a thorough example.

## Comparison

Side-by-side comparison of providers, approaches, or architectures. Use tables.
See sek8s_integrity.md (dstack vs sek8s) and model_weights.md (approach
comparison tables).

## Research Findings

When original research (code analysis, live testing, public data correlation)
informs the gap analysis. See dstack_integrity.md (publicly available golden
values) and e2ee_plaintext_gaps.md (direct vs gateway E2EE test results).

## Teep Status

Current teep behavior in response to this gap: what factors are affected,
whether teep has a workaround, and what teep will enforce once the provider
fixes the gap. This section is for teep maintainers and reviewers, not for
the provider.
-->
