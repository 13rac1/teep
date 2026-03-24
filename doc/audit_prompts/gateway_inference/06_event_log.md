# Section 06 — Event Log Integrity & RTMR Replay (Gateway and Model)

## Scope

Audit event-log parsing and replay integrity checks that recompute RTMR values and compare them with quoted RTMR evidence, for BOTH the model backend and the gateway.

If event logs are present in either attestation payload, the code MUST replay them and verify recomputed RTMR values against the respective quote's RTMR fields.

## Primary Files

- [`internal/attestation/eventlog.go`](../../../internal/attestation/eventlog.go)
- [`internal/attestation/report.go`](../../../internal/attestation/report.go)

## Secondary Context Files

- [`internal/attestation/measurement_policy.go`](../../../internal/attestation/measurement_policy.go)
- [`internal/attestation/eventlog_test.go`](../../../internal/attestation/eventlog_test.go)
- [`internal/provider/nearcloud/nearcloud.go`](../../../internal/provider/nearcloud/nearcloud.go)

## Background: Two Event Logs in Gateway Model

The gateway inference model has two separate event logs:
1. **Model backend event log**: provided as part of the model attestation, parsed the same way as in direct inference.
2. **Gateway event log**: provided as part of the gateway attestation section. The gateway's event log has unique parsing requirements — it is provided as a **JSON string** (not a native array), requiring double-parsing: first as a JSON string from the gateway attestation, then parsing the string contents as a JSON array of event log entries.

Each event log is replayed against the respective quote's RTMR fields. The enforcement factors are separate:
- `event_log_integrity` for the model backend event log,
- `gateway_event_log_integrity` for the gateway event log.

## Required Checks

### Replay Algorithm Correctness

Verify and report (applying to both model and gateway replay):
- hash algorithm used for extend operations (expected SHA-384 for TDX RTMRs via `crypto/sha512.New384()`),
- initial RTMR state (four [48]byte arrays, zero-initialized),
- extend formula correctness: `RTMR_new = SHA-384(RTMR_old || digest)`,
- behavior for short digests (padding/normalization — code zero-pads to 48 bytes via `copy()` into a fresh 48-byte slice),
- behavior for oversized digests (digests ≥ 48 bytes used as-is; verify no truncation),
- IMR index bounds validation (must stay within [0,3]),
- malformed-entry semantics (skip vs fail-whole-replay — silent drops MUST be flagged).

### Gateway Event Log Parsing

The gateway event log has unique parsing requirements that differ from the model backend event log:
- the gateway `event_log` field is a **JSON string** (not a native array) — verify double-parsing: the string must first be extracted, then its contents parsed as JSON array of event log entries,
- verify that the gateway event log array has bounds limits on its length (e.g., `maxGatewayEventLogEntries`) to prevent resource exhaustion,
- verify that the same replay algorithm is used for both gateway and model event logs,
- verify that gateway event log parsing errors are propagated correctly (not silently swallowed).

### Pre-Replay Parsing Behavior

For both model and gateway event logs, verify:
- whether malformed entries are silently dropped before replay,
- whether parser behavior can mask integrity failures,
- how `EventLogEntry` structs are populated from the attestation response JSON,
- whether unknown fields in event log entry JSON are rejected, warned, or silently ignored.

### Security Boundary Definition

You MUST define the check's security boundary for BOTH event logs:
- event-log replay validates internal consistency of event-log-derived RTMR values with quoted RTMR values,
- replay alone does not prove software baseline approval — it does not by itself prove that RTMR values match an approved software baseline,
- if no baseline policy is enforced for MRTD/RTMR/MRSEAM-class measurements, that gap MUST be reported explicitly as a distinct residual risk,
- the `MeasurementPolicy` struct supports optional allowlists, but empty allowlists mean "no policy" — verify whether the current provider configuration populates any allowlists.

### Separate Enforcement Factors

The audit MUST verify that:
- model event log integrity (`event_log_integrity`) is a separate enforcement factor from gateway event log integrity (`gateway_event_log_integrity`),
- both factors are in the default enforced set,
- failure of either factor independently blocks request forwarding via the `Blocked()` gate,
- a malformed gateway event log does not prevent model event log verification (or vice versa — they are independent checks).

### Cross-Reference to RTMR3 Extracted Values

After replay succeeds, the audit MUST verify (for both model and gateway event logs):
- which fields are extracted from the authenticated event log entries (compose hash, app ID, instance ID, key provider),
- whether extracted values are subsequently used in further enforcement checks (e.g., compose hash feeding into MRConfigID binding),
- whether the event log entry extraction uses the same authenticated data that was replayed, or could diverge from it.

## Go Best-Practice Audit Points

- **Error wrapping**: verify that `ReplayEventLog` wraps errors with `%w` and includes per-entry index context.
- **Fail-closed on malformed input**: confirm that invalid hex digest and out-of-range IMR index return errors that halt replay.
- **No silent error swallowing**: check that no `error` return values from hash operations or slice operations are discarded.
- **Bounds checking**: verify that `e.IMR` bounds check uses correct inclusive/exclusive semantics for the 4-element array.
- **Test coverage**: review `eventlog_test.go` for coverage of edge cases — empty log, single extend, multiple extends, invalid IMR, invalid hex, short-digest padding.

## Cryptography Best-Practice Audit Points

- **Correct hash primitive**: confirm `crypto/sha512.New384()` is used (not `sha256` or `sha512.New()`).
- **Deterministic initialization**: verify RTMR initial state is exactly 48 zero bytes.
- **Concatenation correctness**: the extend formula must concatenate `RTMR_old` (48 bytes) then `digest` (48 bytes, possibly padded) — verify ordering.
- **No hash reuse**: confirm `sha512.New384()` creates a fresh hasher per extend operation.
- **Padding semantics**: document that short digests are correctly padded and verify this matches the TDX event log specification.

## General Security Audit Points

- **Input validation at trust boundary**: event log entries come from the attestation API response (untrusted provider data). Verify all fields are validated before use.
- **Denial-of-service via large event logs**: verify whether the number of event log entries is bounded for both model and gateway event logs. A malicious response could include millions of entries to exhaust CPU during SHA-384 replay.
- **Constant-time comparison for RTMR matching**: after replay, the comparison between replayed RTMR values and quoted RTMR values SHOULD use constant-time comparison.
- **Fail-secure default for absent event log**: if the event log is absent from the attestation response, verify whether this is treated as a pass (dangerous) or a skip/fail (safe). Document behavior for both the gateway and model event logs independently.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. replay-algorithm correctness summary (covering both model and gateway),
3. gateway event log double-parsing correctness assessment,
4. explicit malformed-input behavior classification,
5. security boundary statement distinguishing event-log replay (consistency) from measurement policy (golden-value),
6. enforcement status of both `event_log_integrity` and `gateway_event_log_integrity` factors,
7. include at least one concrete positive control and one concrete negative/residual-risk observation,
8. source citations for all claims.
