# Plan: Fable review M1 — nanogpt/phalacloud defaults disable freshness and identity binding

Source: `docs/2026-07-02-fable-review.md`, finding M1. Verified still present
on main @ 4152307.

## Current state

- `NanoGPTDefaultAllowFail` (`internal/attestation/report.go:324-343`)
  exempts `FactorNonceMatch` (:325), `FactorTEEMeasurement` (:326), and
  `FactorTEEReportData` (:330) — no replay protection, no enforced
  measurement allowlist, no proof the enclave key is bound into the quote.
- `PhalaCloudDefaultAllowFail` (`report.go:349-367`) exempts
  `FactorNonceMatch` (:350) and `FactorTEEMeasurement` (:351).
  `FactorTEEReportData` is **enforced** for phalacloud (correction to the
  review, which implied both exempted it).
- Compounding: `teep verify <provider> --update-config` refuses only when
  `report.Blocked()` (`cmd/teep/main.go:427,431`). Because these factors are
  allow-failed they never set `Blocked()`, so a replayed/foreign quote's
  measurements can be pinned into the user's allowlist
  (`internal/config/update.go`).

Failure scenario: a genuine-but-stale or foreign TDX quote (valid Intel
signature, arbitrary machine, replayed indefinitely) passes for these
providers, and `--update-config` then persists its measurements as the
user's trust anchor.

## Design

Three coordinated changes; the third stands alone even if the first two are
debated.

### 1. Reclassify the exemptions as an explicit weak-tier opt-in

Keep the mechanical allow-fail model but stop hiding the tier in a Go
default:

- Add a per-provider config flag `attestation_tier = "full" | "reduced"`
  (strictly validated; default `full`). The nanogpt/phalacloud reduced
  lists apply **only** when the operator has explicitly set
  `attestation_tier = "reduced"` for that provider. With `full` (default),
  `MergedAllowFail` (`internal/config/config.go:456-479`) uses
  `DefaultAllowFail` only — nonce/measurement/reportdata enforced, and
  these providers block until they attest properly.
- Startup WARN (loud, once) when a reduced-tier provider is enabled,
  enumerating exactly which integrity factors are waived — the review's
  "effective enforcement summary" recommendation, scoped to this finding.
- This is a breaking default-behavior change for nanogpt/phalacloud users:
  they must either accept blocking or opt in to `reduced`. That is the
  correct fail-closed direction per AGENTS.md ("the measure of correctness
  is how strictly it evaluates providers, not how many pass").

### 2. Shrink the reduced lists to what is genuinely impossible

Audit which exemptions reflect real provider limitations vs. historical
convenience:

- `nonce_match`: if the provider API accepts a client nonce at all, remove
  the exemption even in reduced tier — replay protection is cheap and
  structural. Confirm current nanogpt/phalacloud attestation endpoints'
  nonce support from captures (`internal/integration/testdata/`) and
  `make reports`.
- `tee_reportdata_binding` (nanogpt): both nanogpt and phalacloud reuse the
  venice `ReportDataVerifier` (`internal/verify/factory.go:91-97`), so the
  binding formula exists; determine why nanogpt fails it today (missing
  signing key field? different binding?) and fix the verifier rather than
  exempt the factor if at all possible.
- `tee_measurement`: keep in reduced tier only until
  `docs/measurement_allowlists.md`-style golden values exist for these
  providers.

### 3. Harden `--update-config` pinning (independent, do first)

`--update-config` must refuse to pin measurements from a report that only
avoided `Blocked()` via exemptions on integrity factors:

- In the update path (`cmd/teep/main.go:427-431` +
  `internal/config/update.go`), compute "would this report block if
  `nonce_match`, `tee_reportdata_binding`, `tee_measurement`,
  `tee_quote_signature`, `tee_cert_chain` were all enforced?" If yes,
  refuse with a diagnostic listing the failing factors. Pinning is a trust
  bootstrap (TOFU); it must be held to full-tier standards regardless of
  the serving tier.
- This also interlocks with fable-review M6 (the same command silently
  erasing `allow_fail = []`) — coordinate the two changes in
  `update.go`.

## Tests

- Config: `attestation_tier` parsing (unknown value rejected at startup);
  default `full` yields `DefaultAllowFail` for nanogpt/phalacloud;
  `reduced` yields the provider lists; WARN emitted.
- Report: replayed-quote simulation (stale nonce, foreign measurement) →
  `Blocked() == true` under full tier for both providers.
- `--update-config` regression: report passing only via exemptions →
  refusal with the factor list; genuine full-pass report → pins as before.
- Existing `MergedAllowFail` tests updated for the tier dimension.

## Verification

- `make check`; `go test -race ./internal/attestation/...
  ./internal/config/... ./cmd/teep/...`; `make integration` — nanogpt/
  phalacloud fixtures must be re-baselined under their real tier (if the
  fixtures only pass under `reduced`, the fixtures declare that tier
  explicitly, keeping tests honest per AGENTS.md "tests MUST fail closed
  the same way live codepaths do").

## Open questions (from the review, still open)

- Are nanogpt/phalacloud expected to reach full attestation parity, or are
  they permanently limited? Permanent limitation argues for the tier
  design above; imminent parity argues for simply deleting the exemptions
  and letting them block until fixed. **Maintainer input needed; the tier
  design is forward-compatible with either answer.**
