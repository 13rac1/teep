# Local dependency changes

`go-tdx-guest` is copied from
`github.com/google/go-tdx-guest v0.3.2-0.20260305110651-91f9a52f36c7`.
Its original license and source files are retained.

The local change exposes `verify.Options.VerifiedValidityBound`. The accessor
returns a value only after successful online quote verification, including
collateral and revocations. It uses the certificate and collateral objects that
the verifier already authenticated. A failed subsequent verification clears the
value. Teep uses the result to bound authorization lifetime without reparsing
cached evidence or inventing a local TTL.

Verification changes from the pinned source are limited to `verify/verify.go`,
`verify/validity.go`, and `verify/validity_test.go`. The heading in
`tools/extend/README.md` is also corrected to name the `extend` tool.
