# [Gap Title]: [Concise Description]

**Date:** YYYY-MM-DD
**Status:** Open | Remediation in progress | Resolved

<!-- TITLE: Name the specific gap or provider assessment. Examples from
existing reports:
  - "Dstack Integrity Chain: In-Band Discovery Gap"
  - "NearCloud E2EE: Gateway Header-Forwarding Gaps"
  - "Hardware Attestation Binding Issues and Mitigations"
  - "Sek8s Integrity Chain — Chutes Provider"

A document may cover multiple gaps if they are deeply interrelated — shared
mitigations, compound attack scenarios, or gaps that only make sense when
analyzed together. If splitting the gaps into separate documents would cause
massive duplication in the Remediation section, keep them together and track
them as named sub-problems (e.g., "Gap 1", "Gap 2") throughout.

A document may also be a **provider assessment** — a comprehensive analysis
of a provider's entire attestation posture, covering both what can be
independently verified and where gaps remain. Provider assessments use this
template with the optional Verification Surface section included. -->

<!-- OPENING PARAGRAPH: 2-3 sentences. What is the gap (or, for provider
assessments, the verification posture and its limitations), what's at risk,
what's the current status. A product manager should be able to read this
paragraph and decide whether to keep reading. No protocol names or register
identifiers. -->

## The Problem

<!-- Plain language. What is missing or broken, why it matters for users and
customers, what could go wrong. Write for someone who knows what TEE attestation
is and why it matters, but does not know the specifics of TDX registers, SPDM
sessions, or dstack event logs.

Avoid jargon here — save protocol details for Technical Background below.

Write for the product manager responsible for the provider's infrastructure —
they may have no knowledge of teep or how it works. Describe what is missing
or broken in the provider's system and why it matters for their users and
customers. Do not mention teep in this section.

For industry-wide gaps (hardware limitations, protocol-level omissions) that
affect the entire ecosystem rather than a single provider, write for the
broader infrastructure audience. Frame the problem in terms of what the
technology stack does not provide, not what any particular provider failed
to do. -->

## Impact

<!-- Concrete risks. What could an attacker do? What do users lose? What should
providers worry about? Frame severity clearly.

Before listing impacts, verify that no compensating controls exist elsewhere in
the protocol. Check for: signing key rotation schedules, alternative
authentication, request nonces that prevent replay, independent freshness
mechanisms, and any other means by which the protocol achieves the same goal
through a different path. If compensating controls exist, the gap may be a
best-practice violation rather than a security vulnerability.

For gaps in the industry-wide hardware or protocol stack where no compensating
controls currently exist, state this explicitly and frame the unmitigated
attack surface. Defer mitigation analysis to the Remediation section.

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
  (gpu_cpu_binding.md: "Architecture" with a CPU ↔ GPU trust/binding diagram)
- Protocol mechanics relevant to the gap (key exchange, attestation evidence
  format, event log structure)

Mermaid diagrams, ASCII architecture diagrams, and register tables are
welcome. The goal is a self-contained reference that makes the rest of the
document accessible to someone encountering this subsystem for the first time.

For remediation surveys where multiple options each require their own
substantial prerequisite knowledge, keep this section focused on background
that is SHARED across all options — what every reader needs regardless of
which remediation they care about. Option-specific background (e.g., a
protocol primer needed only for one remediation approach) belongs with that
option's subsection in Remediation. This keeps Technical Background lean
and avoids a wall of unrelated protocols upfront.

-->

---

## Verification Surface

<!-- OPTIONAL — include this section only for provider assessment documents
that analyze an entire provider's attestation posture. For focused gap reports
(single gap or tightly related set), skip this section entirely; Technical
Background provides sufficient context.

This section documents what a remote verifier can independently enforce
today and how:

- Hardware-attested measurements that can be pinned and verified
  (e.g., firmware identity, boot chain registers, key bindings).
- Cryptographic bindings the provider exposes in attestation evidence.
- Collateral checks (certificate chains, TCB freshness, debug flags).
- The enforcement status of each property (enforced, enforceable with
  configuration, not yet enforceable).

This section describes WORKING VERIFICATION ONLY — what is currently
enforced or enforceable and how. Gaps, missing verification, and
properties that depend on trusting the provider's implementation belong
in Detailed Gap Analysis below.

Write for any security-conscious consumer of the provider's service.
Describe what external clients can verify about the provider's TEE
deployment in terms of the attestation evidence and cryptographic
properties available to any remote verifier.

Cross-provider comparison tables may be included here when they help
contextualize the verification surface against a known baseline (e.g.,
comparing a novel provider architecture against a well-understood one).

For provider assessments where server-side-only security mechanisms
(admission controllers, boot gating, runtime re-attestation) form part
of the provider's security story but are not client-verifiable, summarize
them here to establish context, then analyze the trust implications in
Detailed Gap Analysis. -->

---

## Detailed Gap Analysis

<!-- Evidence that the gap exists. This section diagnoses the PROBLEM, not the
solution. Analyze the provider's infrastructure, source code, deployment
configuration, and/or protocol behavior to demonstrate exactly where and how
the gap manifests.

The evidence may take different forms depending on the gap's nature:

- **Provider-specific gaps:** Source code analysis (specific files, functions,
  line numbers), protocol traces, observed behavior, integration test results.
- **Industry-wide gaps:** Published vulnerability research, standards and
  specification analysis demonstrating the absence of a required binding or
  mechanism, architectural analysis showing why independent subsystems cannot
  be linked by existing protocols.
- **Compound attack construction:** For gaps whose full severity only becomes
  apparent through a multi-step attack scenario, construct and walk through
  the attack here. If the attack demonstrates the unmitigated gap, it belongs
  in this section. If it demonstrates the residual risk of a specific partial
  mitigation, it may belong in Remediation alongside that mitigation stage
  (see Remediation guidance below).
- **Teep factor behavior:** Report factor results that surface the gap.

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
barriers — that depth belongs here, not in Detailed Gap Analysis above.

When multiple approaches are available, use subsections such as:

### Implementation Options

One subsection per approach. Each may include its own background, mechanism
description, feasibility assessment, and current barriers. Reference existing
patterns and provider infrastructure where applicable.

For deep remediation surveys, each option may warrant self-contained
subsections covering: overview, architecture, binding/security strength,
implementation requirements (provider-side and verifier-side), security
analysis, and deployment considerations. This keeps each option readable
independently without forcing the reader to cross-reference other sections.

Option-specific prerequisite knowledge (protocol primers, register mappings,
architecture diagrams) that is not shared across options belongs here with
its option, not in the top-level Technical Background section.

Provide per-approach analysis with comparison tables when useful.

### Deployment Priority

Order approaches by implementation ease and security impact. Identify the
fastest path, the strongest path, and any approaches that are documented for
reference but not yet viable.

For staged trajectories where options are complementary (each layer
strengthens an earlier one rather than replacing it), consider:
- A cumulative security posture table showing which gaps are covered at
  each stage and what residual risk remains.
- Per-stage residual risk analysis. For compound gaps, some residual risks
  only become apparent when analyzing partial mitigations — residual risk
  analysis (including compound attack scenarios) may live alongside the
  mitigation stage it applies to rather than in Detailed Gap Analysis.
- A summary table mapping stages to actions, responsible parties, effort
  level, and gap coverage. -->

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