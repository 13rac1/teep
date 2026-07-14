# Plan: Fable review H1 — tinfoil_v3_cloud exempts TEE quote signature and cert chain

Source: `docs/2026-07-02-fable-review.md` (fable-review branch), finding H1.

## Status

**A full fix plan already exists: `docs/code-review/2026-07-02-h1-fix-plan.md`.**
This document records the verified current state (2026-07-06) and defers the
design to that plan rather than duplicating it.

## Verified current state (main @ 4152307)

Still present. `TinfoilCloudDefaultAllowFail`
(`internal/attestation/report.go:408-420`) includes `FactorTEECertChain`
(:411) and `FactorTEEQuoteSignature` (:412); selected via
`providerDefaultAllowFail` (`internal/config/config.go:63`), merged by
`MergedAllowFail` (`config.go:456-479`). The rationale comment
(`report.go:390-407`, esp. :399-401) cites AMD KDS (`kdsintf.amd.com`)
flakiness.

Key facts confirming the fix plan's framing:

- `tinfoil_v3_cloud` is **SEV-SNP**; only `tinfoil_v3_direct` is TDX. The
  exposure is entirely on the SEV path.
- TDX signature verification is fully offline against the embedded Intel
  root (`internal/attestation/tdx.go:180-309`, offline path :365-369) — no
  KDS argument applies to TDX.
- SEV needs KDS online; in offline mode `evalSEVParseDependent`
  (`report.go:908-957`) renders both factors Skip (:928-946).

## Fix summary (see the full plan for details)

1. Split the fused SEV fetch+verify in `internal/attestation/sev.go` into a
   KDS fetch phase and an offline crypto phase (go-sev-guest v0.15.0 split
   API), classifying failures as `FetchErr` (availability) vs.
   `SignatureErr`/`CertChainErr` (forgery).
2. Add a concurrency-safe VCEK cache (`internal/attestation/sevcert.go`) so
   KDS outages stop mattering after first contact.
3. Remove both factors from `TinfoilCloudDefaultAllowFail`; add them to
   `OnlineFactors` (so `--offline` remains the one sanctioned skip); add a
   `BuildReport` override making a definitive **cryptographic** failure
   non-exemptible even if an operator re-adds the factors to `allow_fail`.

Result: forged quote → always blocks; KDS unreachable with cold cache →
fails closed by default, waivable only via `allow_fail`/`--offline`; warm
cache → unaffected by KDS outages.

## Next step

Execute `docs/code-review/2026-07-02-h1-fix-plan.md` as written (its line
references were verified against main on 2026-07-06; only minor drift). This
is the highest-priority item from the review — two independent review passes
converged on it.
