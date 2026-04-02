# Section 04 — TDX Quote Structure & Signature Verification (Gateway and Model)

## Scope

Audit Intel TDX quote verification pipeline for BOTH the gateway CVM and the model backend CVM: parsing, certificate chain validation, signature checks, debug status checks, and collateral currency behavior. This covers the full cryptographic verification path from raw quote bytes through to the Intel root CA trust anchor.

In the gateway inference model, both the gateway and the model backend produce separate TDX quotes that must each be independently verified. The audit MUST verify that the gateway TDX verification uses the same code path / library as the model TDX verification (to avoid diverging security standards).

## Primary Files

- [`internal/attestation/tdx.go`](../../../internal/attestation/tdx.go)
- [`internal/attestation/crypto.go`](../../../internal/attestation/crypto.go)

## Secondary Context Files

- [`internal/attestation/report.go`](../../../internal/attestation/report.go)
- [`internal/attestation/spki.go`](../../../internal/attestation/spki.go)
- [`internal/provider/nearcloud/nearcloud.go`](../../../internal/provider/nearcloud/nearcloud.go)

## Required Checks

### Quote Structure Parsing

Verify and report:
- supported TDX quote versions (version 4 is expected for TDX; version handling and rejection of unknown versions),
- quote header parsing: version, attestation key type, TEE type fields,
- quote body parsing: extraction of all measurement registers (MRTD, RTMRs, MRSEAM, MRCONFIGID, REPORTDATA, etc.),
- bounds checking on variable-length fields within the quote structure (preventing buffer over-reads),
- handling of malformed or truncated quote data (fail-closed with descriptive error, not partial parsing),
- byte-order handling (Intel quotes use little-endian; verify correct endianness for multi-byte fields),
- that the **same** quote parsing code is invoked for both the gateway TDX quote and the model backend TDX quote.

### ECDSA Signature Verification

Verify and report:
- quote signature algorithm: ECDSA with P-256 (secp256r1) is the expected algorithm for TDX quote signatures,
- that the signature is verified over the correct data (quote header + quote body, not just the body),
- that the ECDSA verification uses Go's `crypto/ecdsa.VerifyASN1` or equivalent, with proper handling of the (r, s) signature components,
- that the attestation key used for signature verification is extracted from the QE (Quoting Enclave) certification data within the quote,
- that raw (r, s) integer encoding from the quote is correctly converted to the format expected by the Go crypto library.

### PCK Certificate Chain Validation

Verify and report:
- full chain validation: PCK leaf certificate → Intermediate CA (Platform CA or Processor CA) → Intel SGX Root CA,
- that the Intel SGX Root CA trust anchor is embedded in the code (not fetched from the network at verification time),
- how the embedded root CA is identified and verified (e.g., hardcoded SHA-256 fingerprint of the root CA certificate),
- that certificate validity periods (NotBefore/NotAfter) are checked against current time,
- that certificate key usage and extended key usage fields are validated where applicable,
- that the PCK certificate's FMSPC (Family-Model-Stepping-Platform-CustomSKU) value is extracted for TCB collateral lookup,
- that the PCK certificate's SGX Extensions (OID 1.2.840.113741.1.13.1) are parsed for platform identity information,
- that certificate parsing errors (malformed DER/PEM, unexpected extensions) are treated as hard failures.

### Quoting Enclave (QE) Identity Validation

Verify and report:
- whether QE Identity collateral is fetched from Intel PCS and validated,
- that the QE Report within the quote is verified (QE measurement and signer match expected QE Identity values),
- that QE Identity validation includes MRSIGNER check (the QE was built by Intel),
- that QE version/SVN is checked against the QE Identity structure's TCB levels,
- whether QE Identity validation failure is enforced or advisory.

### Intel PCS Collateral Checks

The Intel Provisioning Certification Service (PCS) provides collateral needed for full TCB evaluation. Verify and report:
- **TCBInfo** retrieval and validation: fetched for the platform's FMSPC, signed by Intel, used to classify TCB status,
- **QE Identity** retrieval and validation: signed by Intel, used to verify Quoting Enclave measurement and version,
- **PCK CRL** (Certificate Revocation List) retrieval and checking,
- **Root CA CRL** retrieval and checking,
- that all PCS collateral responses are verified against Intel's signing certificate (not trusted at face value),
- how PCS collateral freshness is managed (caching TTL, forced refresh triggers),
- behavior when PCS is unreachable: which checks are skipped vs which remain active locally.

### Debug Bit Evaluation

Verify and report:
- debug-bit evaluation and enforcement behavior for BOTH the gateway and model backend quotes (debug enclaves MUST be rejected for production trust),
- that the TD Attributes field in the quote body is parsed and the DEBUG bit (bit 0) is explicitly checked,
- that debug-bit check is enforced fail-closed (not merely logged),
- the enforcement factor names for this check (expected: `tdx_debug_disabled` for model, `gateway_tdx_debug_disabled` for gateway).

### Gateway-Specific Verification

The audit MUST verify that the gateway's TDX quote undergoes the same verification as the model backend's quote:
- same code path / library for quote parsing, signature verification, and chain validation,
- separate enforcement factors for gateway (prefixed with `gateway_`) vs model factors,
- that a failure in the gateway's TDX verification blocks the request independently of model verification results,
- that the gateway TDX verification result and the model TDX verification result are both checked by the `Blocked()` gate.

### Verification Architecture

Verify and report:
- third-party verification library invocation boundaries and interpretation of return values,
- two-pass architecture (offline cryptographic pass then online collateral pass) if present,
- what Pass 1 (offline) covers vs what Pass 2 (online) covers,
- policy behavior for Pass-1-only outcomes (blocking vs advisory),
- whether the two passes are atomic (both must complete for a "pass") or independent.

## Best-Practice Audit Points

### Go (Golang) Best Practices

- **Error handling for crypto operations**: Verify that every cryptographic operation returns an error that is checked and propagated, never silently ignored.
- **Type assertions for certificate parsing**: Verify that `x509.Certificate.PublicKey` type assertions include the `ok` boolean check.
- **Proper use of `crypto/x509`**: Verify that certificate chain validation uses `x509.Certificate.Verify()` with an appropriately configured `x509.VerifyOptions`.
- **Byte slice handling**: Verify that fixed-size fields (48-byte measurements, 64-byte REPORTDATA, etc.) are validated for correct length before indexing.
- **No `unsafe` package usage**: Verify that quote parsing does not use Go's `unsafe` package for struct casting.
- **`encoding/binary` for structured parsing**: Verify that multi-byte integer fields are decoded using `binary.LittleEndian.Uint16()` / `Uint32()` / `Uint64()`.

### Cryptography Best Practices

- **ECDSA signature verification**: Verify that ECDSA signature verification is performed using Go's standard library, not a custom implementation.
- **Certificate chain validation order**: Root → intermediate → leaf. Verify no self-signed certificates other than the embedded Intel root CA are trusted.
- **CRL checking completeness**: Verify that both root CA CRL and intermediate CA CRL are checked.
- **Signature algorithm restriction**: Verify that the code explicitly checks signature algorithms, rejecting unexpected ones.
- **Constant-time comparison**: Where quote fields are compared against expected values, verify `subtle.ConstantTimeCompare` is used.

### General Security Audit Practices

- **Fail-closed on all parsing errors**: Any failure to parse the quote must result in hard verification failure.
- **Reject unknown/unsupported versions**: Unknown quote version, attestation key type, or TEE type must cause immediate failure.
- **Trust boundary clarity**: Every field within the quote is untrusted input until cryptographic verification succeeds.
- **Defense in depth**: Passing signature verification alone does not constitute a "pass" — additional checks required.

## Known Divergence: Chutes/Sek8s

Chutes providers produce TDX quotes only from the backend sek8s instances, not from the Chutes gateway (which is unattested). Key differences for TDX quote verification:

- **No gateway TDX quote**: The Chutes gateway is unattested and produces no TDX quote. No `gateway_*` TDX factors exist for chutes.
- **Two-step fetch**: The TDX quote is fetched via the evidence endpoint (`/chutes/{chute}/evidence?nonce={hex}`) through the Chutes gateway, separate from the instances endpoint that returns E2EE keys. The audit should verify that the evidence response is correctly parsed and that the TDX quote bytes are extracted from the response structure.
- **Same verification code**: The TDX quote parsing, signature verification, PCK chain validation, and debug-bit checking should use the same `internal/attestation/tdx.go` code path as nearcloud. Verify this is the case.
- **Sek8s-specific measurements**: The chutes measurement policy defines different MRTD, MRSEAM, and RTMR0-2 golden values than nearcloud. These are checked via the same `tdx_mrseam_mrtd` factor. See Section 05 for measurement details.
- **Multiple instances**: Chutes may return multiple instances (up to `MaxInstances = 256`), each producing its own TDX quote. Verify that each instance's quote is independently verified and that a single verification failure blocks the request.

Primary reference: `internal/provider/chutes/fetch.go`, `internal/attestation/tdx.go`.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. explicit statement of cryptographic-verification boundary vs collateral-dependent checks,
3. full certificate chain validation assessment,
4. confirmation that gateway and model TDX verification use the same code path,
5. enforcement classification for each factor (`tdx_cert_chain`, `tdx_quote_signature`, `tdx_debug_disabled`, and their `gateway_` counterparts),
6. include at least one concrete positive control and one concrete negative/residual-risk observation,
7. source citations for all claims.
