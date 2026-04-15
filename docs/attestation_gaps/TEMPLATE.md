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

---

## Technical Background

<!-- Provide the foundational knowledge a reader needs to understand both the
gap analysis and the proposed remediations. Write for an engineer who is
familiar with TEE attestation in general but does not know the specifics of
the subsystem where this gap lives.

Cover the relevant architecture, protocols, register meanings, standards, or
deployment patterns — whatever prerequisite knowledge is needed so that
the Detailed Gap Analysis section can reference specifics without stopping
to explain them, and the Remediation section's proposed solutions make sense.

Examples of what belongs here:
- A primer on TDX measurement registers and what each one covers
  (dstack_integrity.md: "TDX in One Page", "Full Dstack TDX Authentication")
- The provider's TEE architecture and request flow
  (e2ee_plaintext_gaps.md: "Architecture" with Gateway → Model TEE diagram)
- Protocol mechanics relevant to the gap (key exchange, attestation evidence
  format, event log structure)

Mermaid diagrams, ASCII architecture diagrams, and register tables are
welcome. The goal is a self-contained reference that makes the rest of the
document accessible to someone encountering this subsystem for the first time.

-->

---

## Detailed Gap Analysis

<!-- Evidence that the gap exists. This section diagnoses the PROBLEM, not the
solution. Analyze the provider's infrastructure, source code, deployment
configuration, and/or protocol behavior to demonstrate exactly where and how
the gap manifests.

Focus on:
- Provider source code analysis (specific files, functions, line numbers)
- Protocol traces or observed behavior that proves the gap
- Test results from integration tests that reproduce the issue
- Teep report factor behavior that surfaces the gap

Do NOT put remediation approaches, solution designs, or "how this could be
fixed" content here — that belongs in the Remediation section below.

Subsection as needed. Examples from existing reports:
- "Server Source Code Analysis" with per-component breakdowns
- "Gateway: Partial Header Forwarding" — pinpointing which handlers omit
  required logic
- "Test Descriptions" — integration tests in teep that prove the issue exists
- "Teep Report Factor Behavior" — report factor code that surfaces the issue

-->

---

## Remediation

<!-- What the provider should change to close the gap. This is where solution
approaches, fix designs, and alternative implementation strategies belong.

For simple gaps with a single fix, describe the concrete change: reference
source files, API fields, protocol extensions, or configuration changes.

For gaps where multiple remediation approaches exist (e.g., different
technical strategies with different trade-offs, or incremental stages that
build on each other), structure this section as a survey of options. Each
approach may need its own technical background, feasibility analysis, and
barriers — that depth belongs here, not in Detailed Analysis above.

When multiple approaches are available, use subsections such as:

### Implementation Options

One subsection per approach. Each may include its own background, mechanism
description, feasibility assessment, and current barriers. Reference existing
patterns and provider infrastructure where applicable.

Provide per-approach analysis with comparison tables when useful.

### Deployment Priority

Order approaches by implementation ease and security impact. Identify the
fastest path, the strongest path, and any approaches that are documented for
reference but not yet viable. -->

---

## References

<!-- Papers, repositories, specifications, documentation links.

Use markdown links directly to URL sources throughout the document.
This section should list all such links used in the document.

Group by topic when there are many. Examples:

- **Source code:** GitHub links to specific files/functions analyzed
- **Standards:** IETF, PCI-SIG, DMTF specifications
- **Research:** Academic papers, whitepapers, security advisories
- **Documentation:** Provider docs, attestation guides -->

---

## Teep Status

<!--
Current teep behavior in response to this gap: what factors are affected,
whether teep has a workaround, and what teep will enforce once the provider
fixes the gap. This section is for teep maintainers and reviewers, not for
the provider.
-->