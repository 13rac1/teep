# Section 06 — Event Log Integrity & RTMR Replay

## Scope

Audit event-log parsing and replay integrity checks that recompute RTMR values and compare them with quoted RTMR evidence.

If event logs are present in provider attestation payloads, the code MUST replay them and verify recomputed RTMR values against quote RTMR fields.

## Primary Files

- [`internal/attestation/eventlog.go`](../../../internal/attestation/eventlog.go)
- [`internal/attestation/report.go`](../../../internal/attestation/report.go)

## Secondary Context Files

- [`internal/attestation/measurement_policy.go`](../../../internal/attestation/measurement_policy.go)
- [`internal/attestation/eventlog_test.go`](../../../internal/attestation/eventlog_test.go)

## Background: RTMR3 and Event Log Role in Attestation

RTMR3 is the application-specific runtime measurement register. In dstack's implementation, RTMR3 records application-level details including the compose hash, instance ID, app ID, and key provider. Unlike RTMR0-2, RTMR3 cannot be pre-calculated from the image alone because it contains runtime information.

RTMR3 is verified by replaying the event log: if the replayed RTMR3 matches the quoted RTMR3, the event log content is authentic, and the compose hash, key provider, and other details can be extracted and verified from the event log entries. The existing compose binding check (`MRConfigID`) partially overlaps with RTMR3 for compose hash verification.

The `event_log_integrity` factor is one of the default enforced factors — failure of RTMR replay comparison MUST block request forwarding. The audit MUST verify that this enforcement is wired through the `Blocked()` code path (or equivalent) and not merely logged.

## Required Checks

### Replay Algorithm Correctness

Verify and report replay algorithm details:
- hash algorithm used for extend operations (expected SHA-384 for TDX RTMRs via `crypto/sha512.New384()`),
- initial RTMR state (four [48]byte arrays, zero-initialized by Go's value semantics),
- extend formula correctness: `RTMR_new = SHA-384(RTMR_old || digest)`,
- behavior for short digests (padding/normalization semantics — code zero-pads to 48 bytes via `copy()` into a fresh 48-byte slice),
- behavior for oversized digests (digests ≥ 48 bytes are used as-is; verify no truncation occurs),
- IMR index bounds validation (must stay within [0,3]),
- malformed-entry semantics (skip vs fail-whole-replay).

### Pre-Replay Parsing Behavior

Also verify pre-replay behavior:
- whether malformed entries are silently dropped before replay,
- whether parser behavior can mask integrity failures,
- how `EventLogEntry` structs are populated from the attestation response JSON (the `IMR` and `Digest` fields),
- whether the event log array has bounds limits on its length (or whether a maliciously large event log array could cause resource exhaustion),
- whether unknown fields in event log entry JSON are rejected, warned, or silently ignored.

The audit MUST separately verify pre-replay parsing behavior for event log entries, and flag any path that silently drops malformed entries before replay.

### Security Boundary Definition

You MUST define the check's security boundary:
- event-log replay validates internal consistency of event-log-derived RTMR values with quoted RTMR values,
- replay alone does not prove software baseline approval — it does not by itself prove that RTMR values match an approved software baseline,
- if no baseline policy is enforced for MRTD/RTMR/MRSEAM-class measurements, that gap MUST be reported explicitly as a distinct residual risk,
- the `MeasurementPolicy` struct supports optional allowlists for `MRTD`, `MRSEAM`, and each `RTMR[0-3]`, but empty allowlists mean "no policy" — verify whether the current provider configuration populates any of these allowlists for baseline enforcement beyond event log consistency.

### Relationship to Measurement Policy

The audit MUST distinguish between two separate verification layers:
1. **Event log replay (consistency check)**: verifies that the event log entries, when replayed, produce RTMR values matching the TDX-quoted RTMR values — this proves the event log has not been tampered with post-quote.
2. **Measurement policy (golden-value check)**: verifies that the quoted RTMR/MRTD/MRSEAM values match a provider-published set of known-good values — this proves the actual software running is the expected software.

If only layer (1) is implemented without layer (2), the residual risk is that any internally-consistent event log will be accepted, even if it represents a compromised software stack. This gap MUST be reported with severity and exploitability context.

### Cross-Reference to RTMR3 Extracted Values

After replay succeeds, the audit MUST verify:
- which fields are extracted from the authenticated event log entries (compose hash, app ID, instance ID, key provider),
- whether extracted values are subsequently used in further enforcement checks (e.g., compose hash feeding into MRConfigID binding in Section 08),
- whether the event log entry extraction uses the same authenticated data that was replayed, or could diverge from it.

## Go Best-Practice Audit Points

- **Error wrapping**: verify that `ReplayEventLog` wraps errors with `%w` and includes per-entry index context for debuggability.
- **Fail-closed on malformed input**: confirm that invalid hex digest (`hex.DecodeString` failure) and out-of-range IMR index both return errors that halt replay rather than skipping entries.
- **No silent error swallowing**: check that no `error` return values from hash operations or slice operations are discarded.
- **Bounds checking**: verify that `e.IMR` bounds check (`0 <= IMR <= 3`) uses correct inclusive/exclusive semantics for the 4-element array.
- **Test coverage**: review `eventlog_test.go` for coverage of edge cases — empty log, single extend, multiple extends, invalid IMR, invalid hex, and short-digest padding are expected.

## Cryptography Best-Practice Audit Points

- **Correct hash primitive**: confirm `crypto/sha512.New384()` is used (not `sha256` or `sha512.New()`), matching TDX RTMR extend specification.
- **Deterministic initialization**: verify RTMR initial state is exactly 48 zero bytes (Go's zero-value for `[4][48]byte` guarantees this, but auditor should confirm no pre-initialization code alters it).
- **Concatenation correctness**: the extend formula must concatenate `RTMR_old` (48 bytes) then `digest` (48 bytes, possibly padded) — verify ordering is not reversed.
- **No hash reuse**: confirm `sha512.New384()` creates a fresh hasher per extend operation (no state leakage between iterations).
- **Padding semantics**: document that short digests are left-padded-by-copy (content at low indices, zeros at high indices) — this must match the TDX event log specification. If the specification requires right-padding or a different scheme, flag as a discrepancy.

## General Security Audit Points

- **Input validation at trust boundary**: event log entries come from the attestation API response (untrusted provider data). Verify that all fields are validated before use — no raw bytes from the event log should be used without parsing and bounds checking.
- **Denial-of-service via large event logs**: verify whether the number of event log entries is bounded. A malicious attestation response could include millions of entries to exhaust CPU during SHA-384 replay.
- **Constant-time comparison for RTMR matching**: after replay, the comparison between replayed RTMR values and quoted RTMR values SHOULD use constant-time comparison (`subtle.ConstantTimeCompare`) to prevent timing side-channels, even though the security impact is limited here.
- **Fail-secure default**: if the event log is absent from the attestation response, verify whether this is treated as a pass (dangerous) or a skip/fail (safe). The `event_log_integrity` enforcement factor behavior when no event log exists must be documented.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. replay-algorithm correctness summary,
3. explicit malformed-input behavior classification,
4. security boundary statement distinguishing event-log replay (consistency) from measurement policy (golden-value),
5. enforcement status of the `event_log_integrity` factor (enforced fail-closed vs advisory),
6. include at least one concrete positive control and one concrete negative/residual-risk observation,
7. source citations for all claims.
