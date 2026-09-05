# Local authenticated-validity patch

This directory contains `github.com/google/go-tdx-guest` at
`v0.3.2-0.20260305110651-91f9a52f36c7`, with its upstream license retained.
The root module selects it through a local `replace` directive.

Teep needs the validity bound of the evidence that the verifier actually
accepted. An application-side parser cannot establish that a collateral date
belongs to the authenticated verification result.

The verification changes are limited to `verify/verify.go`, `verify/validity.go`,
and `verify/validity_test.go`. The heading in `tools/extend/README.md` is also
corrected to name the `extend` tool. `Options.VerifiedValidityBound()` reports the earliest
CRL next-update, TCB-info next-update, QE-identity next-update, or applicable
certificate expiration after successful quote verification with collateral and
revocation checking. It clears the result before each verification and exposes
no bound on failure, including raw-quote parsing failure, or when those online
checks are disabled. Missing required
validity data returns an error.

Teep aggregates this result with other successfully authenticated current-time
evidence bounds. It does not derive authorization expiry from discovery cache
timers, inference TLS certificate dates, historical Sigstore certificates, or
unverified JWT claims. No verification checks were disabled by this patch.

Run `go test -race ./verify` in this directory. The root CI transport matrix
also runs these tests on the minimum and current Go versions. Preserve this
accessor and its failure semantics when updating the upstream dependency.
