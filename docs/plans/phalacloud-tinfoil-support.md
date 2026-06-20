# Plan: Phala Cloud Tinfoil Backend Support

Extracted from `tinfoil_support.md`. Phala Cloud (RedPill) is a multi-backend
gateway. It already routes to Chutes and dstack backends. This plan covers
adding Tinfoil as a third backend format.

## Current State

- `formatdetect.Detect` already identifies Tinfoil responses (`"format"` key).
- `phalacloud.ParseAttestationResponse` returns an explicit error:
  `"phalacloud: tinfoil attestation format not yet supported"`.
- Phala provider has no `Encryptor` set — E2EE is disabled.
- `multi.Verifier` only has `FormatDstack`; no Tinfoil verifier registered.
- `inapplicableForProvider("phalacloud")` returns `DefaultInapplicable`, which
  is wrong for Tinfoil backends (different inapplicable set).

## Code Changes

### 1. Attestation parsing (`phalacloud/phalacloud.go`)

Replace the `FormatTinfoil` error branch in `ParseAttestationResponse` with
delegation to Tinfoil's V3 parser. Requires importing the tinfoil provider
package or a shared parsing function.

```
case attestation.FormatTinfoil:
    return nil, errors.New("...not yet supported")
```
becomes delegation to `tinfoil.ParseV3Response(ctx, body)` or equivalent.

### 2. ReportDataVerifier (`proxy.go` ~line 740)

Add Tinfoil to Phala's `multi.Verifier`:

```go
p.ReportDataVerifier = multi.Verifier{
    Verifiers: map[attestation.BackendFormat]provider.ReportDataVerifier{
        attestation.FormatDstack:  venice.ReportDataVerifier{},
        attestation.FormatTinfoil: tinfoil.ReportDataVerifier{},
    },
}
```

### 3. Encryptor (`proxy.go` ~line 722)

Phala currently has no `Encryptor`. Tinfoil backends require EHBP encryption.
Chutes/dstack backends through Phala do not use E2EE.

The same Phala provider instance can route to different backend types depending
on the model, so the encryptor selection must be **dynamic per-request** based
on the backend format detected during attestation. This does not fit the
current static `p.Encryptor` field.

Options:
- A multi-format encryptor that dispatches based on `BackendFormat` in the
  cached attestation result (parallel to `multi.Verifier`).
- Backend-aware request path that selects EHBP vs plaintext after attestation.

### 4. Inapplicable factors (`proxy.go` ~line 1035)

`inapplicableForProvider("phalacloud")` returns `DefaultInapplicable`. When the
backend is Tinfoil, the inapplicable set is different (e.g., `compose_binding`,
`nvidia_nonce_client_bound` are inapplicable; `sigstore_code_verified`,
`tee_measurement` are applicable).

This must become backend-format-aware, like the ReportDataVerifier already is.

### 5. Supply chain verification (`proxy.go` ~line 745)

Currently `nil` for Phala. Tinfoil backends need `SigstoreRepoForModel` to
resolve the Sigstore repository for code measurement verification. The repo
depends on whether the Tinfoil backend is cloud-routed
(`tinfoilsh/confidential-model-router`) or direct (per-model repo via
`tinfoil.RepoForModel`).

### 6. TLS channel binding (see Unknowns)

The Tinfoil attester verifies the live TLS peer SPKI against the enclave's
`report_data.tls_key_fp`. When attestation is fetched through Phala's gateway,
the TLS peer is Phala, not the Tinfoil enclave. The check is guarded
(`peerSPKI != "" && tls_key_fp != ""`) so it degrades to a skip rather than a
hard failure, but the security property is lost.

## Unknowns

### Does Phala's RedPill gateway preserve EHBP headers?

EHBP requires two custom headers:
- Request: `Ehbp-Encapsulated-Key` (64 hex chars)
- Response: `Ehbp-Response-Nonce` (64 hex chars)

If RedPill strips unknown headers, EHBP E2EE through Phala is impossible
regardless of code changes. This must be tested against the live gateway
before any implementation work.

### Does RedPill actually route to Tinfoil backends today?

The format detection suggests it does (or will), but we have not confirmed
that any model on `api.redpill.ai` is backed by a Tinfoil enclave. Without a
live test target, this work cannot be validated end-to-end.

### TLS channel binding through the gateway

When the proxy fetches attestation from Phala, the TLS peer certificate is
Phala's, not the Tinfoil enclave's. The enclave's `tls_key_fp` will not match.
Options:
1. Accept the degradation — attestation verifies the quote and Sigstore chain,
   but not the live TLS channel to the enclave.
2. Fetch attestation directly from the Tinfoil enclave (bypass Phala for
   attestation only) — requires knowing the enclave's domain, which may not
   be discoverable through RedPill.
3. Have RedPill forward the enclave's TLS certificate info in the attestation
   response — requires RedPill cooperation.

### Dynamic encryptor selection

The current provider model assumes one encryptor per provider. Phala routing
to multiple backend types means the encryptor must vary per-request. This is
the most significant architectural change and may affect the proxy's request
lifecycle.

## Tests

- Parse Tinfoil V3 attestation through `phalacloud.ParseAttestationResponse`.
- Verify `multi.Verifier` dispatches to `tinfoil.ReportDataVerifier` for
  Tinfoil-format responses.
- Verify inapplicable factors are correct for Tinfoil-behind-Phala.
- Integration test (requires live Tinfoil-backed model on RedPill):
  - Plaintext request/response through Phala to Tinfoil backend.
  - EHBP E2EE request/response (if headers are preserved).
  - Attestation report with correct factor evaluations.
