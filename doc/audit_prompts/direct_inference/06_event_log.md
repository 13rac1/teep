# Section 06 — Event Log Integrity & RTMR Replay

## Scope

Audit event-log parsing and replay integrity checks that recompute RTMR values and compare them with quoted RTMR evidence.

If event logs are present in provider attestation payloads, the code MUST replay them and verify recomputed RTMR values against quote RTMR fields.

## Primary Files

- [`internal/attestation/eventlog.go`](../../../internal/attestation/eventlog.go)
- [`internal/attestation/report.go`](../../../internal/attestation/report.go)

## Required Checks

Verify and report replay algorithm details:
- hash algorithm used for extend operations (expected SHA-384 for TDX RTMRs),
- initial RTMR state (48 zero bytes),
- extend formula correctness: `RTMR_new = SHA-384(RTMR_old || digest)`,
- behavior for short digests (padding/normalization semantics),
- IMR index bounds validation (must stay within [0,3]),
- malformed-entry semantics (skip vs fail-whole-replay).

Also verify pre-replay behavior:
- whether malformed entries are silently dropped before replay,
- whether parser behavior can mask integrity failures.

The audit MUST separately verify pre-replay parsing behavior for event log entries, and flag any path that silently drops malformed entries before replay.

You MUST define the check's security boundary:
- event-log replay validates internal consistency of event-log-derived RTMR values with quoted RTMR values,
- replay alone does not prove software baseline approval — it does not by itself prove that RTMR values match an approved software baseline,
- if no baseline policy is enforced for MRTD/RTMR/MRSEAM-class measurements, that gap MUST be reported explicitly as a distinct residual risk.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. replay-algorithm correctness summary,
3. explicit malformed-input behavior classification,
4. include at least one concrete positive control and one concrete negative/residual-risk observation,
5. source citations for all claims.
