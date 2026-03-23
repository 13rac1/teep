# Section 04 — TDX Quote Structure & Signature Verification

## Scope

Audit Intel TDX quote verification pipeline: parsing, certificate chain validation, signature checks, debug status checks, and collateral currency behavior. This covers the full cryptographic verification path from raw quote bytes through to the Intel root CA trust anchor.

## Primary Files

- [`internal/attestation/tdx.go`](../../../internal/attestation/tdx.go)
- [`internal/attestation/crypto.go`](../../../internal/attestation/crypto.go)

## Secondary Context Files

- [`internal/attestation/report.go`](../../../internal/attestation/report.go)
- [`internal/attestation/spki.go`](../../../internal/attestation/spki.go)

## Required Checks

### Quote Structure Parsing

Verify and report:
- supported TDX quote versions (version 4 is expected for TDX; version handling and rejection of unknown versions),
- quote header parsing: version, attestation key type, TEE type fields,
- quote body parsing: extraction of all measurement registers (MRTD, RTMRs, MRSEAM, MRCONFIGID, REPORTDATA, etc.),
- bounds checking on variable-length fields within the quote structure (preventing buffer over-reads),
- handling of malformed or truncated quote data (fail-closed with descriptive error, not partial parsing),
- byte-order handling (Intel quotes use little-endian; verify correct endianness for multi-byte fields).

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
- **TCBInfo** retrieval and validation: fetched for the platform's FMSPC, signed by Intel, used to classify TCB status (UpToDate, OutOfDate, Revoked, ConfigurationNeeded, etc.),
- **QE Identity** retrieval and validation: signed by Intel, used to verify Quoting Enclave measurement and version,
- **PCK CRL** (Certificate Revocation List) retrieval and checking: ensures the PCK certificate has not been revoked,
- **Root CA CRL** retrieval and checking: ensures intermediate CAs have not been revoked,
- that all PCS collateral responses are verified against Intel's signing certificate (not trusted at face value),
- that PCS collateral response headers (e.g., `SGX-TCB-Info-Issuer-Chain`, `SGX-PCK-CRL-Issuer-Chain`) are parsed for intermediate certificates,
- how PCS collateral freshness is managed (caching TTL, forced refresh triggers),
- behavior when PCS is unreachable: which checks are skipped vs which remain active locally.

### Debug Bit Evaluation

Verify and report:
- debug-bit evaluation and enforcement behavior (debug enclaves MUST be rejected for production trust),
- that the TD Attributes field in the quote body is parsed and the DEBUG bit (bit 0) is explicitly checked,
- that debug-bit check is enforced fail-closed (not merely logged),
- the enforcement factor name for this check (expected: `tdx_debug_disabled`).

### TCB Currency and Status Classification

Verify and report:
- how the TCB level from the quote is compared against the TCBInfo collateral to determine TCB status,
- the set of possible TCB status values and how each is handled (UpToDate → pass, OutOfDate → warning/fail, Revoked → hard fail, ConfigurationNeeded → advisory, SWHardeningNeeded → advisory/fail, OutOfDateConfigurationNeeded → warning),
- whether a non-UpToDate TCB status blocks traffic or is advisory-only,
- the enforcement factor name for TCB currency (expected: something like `tdx_tcb_current` or similar),
- whether TCB evaluation is skipped in offline mode and the residual risk of doing so.

### Trust Root Acquisition Model

Verify and report:
- trust-root acquisition model (embedded/provisioned/network) and update assumptions,
- whether the Intel SGX Root CA certificate is embedded in source code or fetched at runtime,
- if embedded, how updates to the root CA would be deployed (code update required),
- if fetched, how the initial trust bootstrap is performed (chicken-and-egg problem),
- whether any trust roots are derived from the system certificate store (this would be a finding — TEE trust must not depend on the OS trust store).

### Verification Architecture

Verify and report:
- third-party verification library invocation boundaries and interpretation of return values,
- two-pass architecture (offline cryptographic pass then online collateral pass) if present,
- what Pass 1 (offline) covers: quote parsing, signature verification, PCK chain validation against embedded root, debug bit check, report-data binding,
- what Pass 2 (online) covers: PCS collateral fetch, TCB status evaluation, CRL checking, QE Identity validation,
- policy behavior for Pass-1-only outcomes (blocking vs advisory) — a Pass-1-only result means the quote is cryptographically valid but TCB currency is unknown,
- whether the two passes are atomic (both must complete for a "pass") or independent (Pass 1 alone can allow traffic).

## Best-Practice Audit Points

### Go (Golang) Best Practices

- **Error handling for crypto operations**: Verify that every cryptographic operation (signature verification, certificate parsing, chain validation) returns an error that is checked and propagated, never silently ignored. Look for patterns like `if err != nil { return }` that discard the error.
- **Type assertions for certificate parsing**: Verify that `x509.Certificate.PublicKey` type assertions (e.g., to `*ecdsa.PublicKey`) include the `ok` boolean check and fail safely on unexpected key types.
- **Proper use of `crypto/x509`**: Verify that certificate chain validation uses `x509.Certificate.Verify()` with an appropriately configured `x509.VerifyOptions` (including the root pool, intermediate pool, and current time), not manual signature checks.
- **Byte slice handling**: Verify that fixed-size fields (48-byte measurements, 64-byte REPORTDATA, etc.) are validated for correct length before indexing, preventing panics from out-of-bounds access.
- **No `unsafe` package usage**: Verify that quote parsing does not use Go's `unsafe` package for struct casting, which would bypass type safety and potentially cause memory corruption on malformed input.
- **`encoding/binary` for structured parsing**: Verify that multi-byte integer fields are decoded using `binary.LittleEndian.Uint16()` / `Uint32()` / `Uint64()` rather than manual bit shifting, reducing endianness bugs.

### Cryptography Best Practices

- **ECDSA signature verification**: Verify that ECDSA signature verification is performed using Go's standard library (`crypto/ecdsa`), not a custom implementation. Verify that low-S normalization is handled if required by the quote format.
- **Certificate chain validation order**: The chain must be validated root → intermediate → leaf, with each certificate's signature verified by its issuer. Verify that the code does not trust self-signed certificates other than the embedded Intel root CA.
- **CRL checking completeness**: Verify that CRL checking covers both the root CA CRL (for intermediate revocation) and the intermediate CA CRL (for PCK leaf revocation). A missing CRL check at either level is a gap.
- **Time-of-check concerns**: Verify that certificate validity and CRL checks use a consistent time source, not separate `time.Now()` calls that could span a validity boundary.
- **Signature algorithm restriction**: Verify that the code explicitly checks the signature algorithm used in certificates and quote signatures, rejecting unexpected algorithms (e.g., RSA when ECDSA is expected).
- **No signature malleability**: For ECDSA, verify that the code handles potential signature malleability (different (r, s) encodings for the same valid signature) appropriately — this is primarily relevant for quote deduplication/caching.

### General Security Audit Practices

- **Fail-closed on all parsing errors**: Any failure to parse the quote structure, certificate chain, or signature must result in a hard verification failure, not a partial result or warning.
- **Reject unknown/unsupported versions**: If the quote version, attestation key type, or TEE type is not in the expected set, verification must fail immediately rather than attempting best-effort parsing.
- **Trust boundary clarity**: The quote arrives from a potentially compromised server. Every field within the quote is untrusted input until cryptographic verification succeeds. Verify that no quote fields are used for security decisions before signature verification completes.
- **Defense in depth**: Even after signature verification succeeds, additional checks (debug bit, TCB status, measurement policy) must be applied. Verify that passing signature verification alone does not constitute a "pass."
- **Constant-time comparison**: Where quote fields are compared against expected values (e.g., nonce in REPORTDATA), verify that `subtle.ConstantTimeCompare` is used to prevent timing side-channels.
- **Deterministic error messages**: Verify that error messages from quote parsing do not leak the content of fields that failed validation (potential information disclosure to a caller probing the verifier).

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. explicit statement of cryptographic-verification boundary vs collateral-dependent checks,
3. full certificate chain validation assessment (root CA → intermediate → PCK leaf),
4. QE Identity and PCS collateral handling assessment,
5. TCB status classification and enforcement behavior,
6. enforcement classification for each verification factor (`tdx_cert_chain`, `tdx_quote_signature`, `tdx_debug_disabled`, TCB currency),
7. include at least one concrete positive control and one concrete negative/residual-risk observation,
8. source citations for all claims.
