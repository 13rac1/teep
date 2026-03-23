# Section 10 — NVIDIA TEE Verification Depth

## Scope

Audit NVIDIA evidence verification depth across both local evidence validation (EAT/SPDM) and remote NVIDIA NRAS validation.

The audit MUST verify both layers when present: local NVIDIA evidence verification (EAT/SPDM) performs direct cryptographic validation of GPU attestation tokens, while remote NRAS verification delegates validation to NVIDIA's attestation service and verifies the resulting JWT.

The NVIDIA attestation provides a secondary layer of TEE assurance alongside the primary Intel TDX CPU attestation. The EAT (Entity Attestation Token) is an NVIDIA-defined JSON structure containing per-GPU evidence entries, each with an X.509 certificate chain and SPDM binary evidence blob. The NRAS (NVIDIA Remote Attestation Service) provides defense-in-depth by comparing GPU firmware measurements against NVIDIA's Reference Integrity Manifest (RIM) golden values.

## Primary Files

- [`internal/attestation/nvidia_eat.go`](../../../internal/attestation/nvidia_eat.go) — EAT JSON parsing, certificate chain validation, SPDM evidence verification
- [`internal/attestation/nvidia.go`](../../../internal/attestation/nvidia.go) — NRAS cloud verification, JWKS caching, JWT validation

## Secondary Context Files

- [`internal/attestation/report.go`](../../../internal/attestation/report.go) — NVIDIA-related factor evaluation (factors 11–15)
- [`internal/attestation/testdata/nvidia_eat_hopper.json`](../../../internal/attestation/testdata/nvidia_eat_hopper.json) — Reference EAT payload for Hopper GPUs
- [`internal/attestation/testdata/nvidia_device_identity_root_ca.pem`](../../../internal/attestation/testdata/nvidia_device_identity_root_ca.pem) — Pinned NVIDIA root CA certificate
- [`internal/attestation/nvidia_eat_test.go`](../../../internal/attestation/nvidia_eat_test.go)
- [`internal/attestation/nvidia_test.go`](../../../internal/attestation/nvidia_test.go)

## Required Checks

### NVIDIA Enforcement Factors

The following verification factors in [`report.go`](../../../internal/attestation/report.go) relate to NVIDIA attestation. Map each to its enforcement status:

| Factor | Default Enforced | Description |
|--------|-----------------|-------------|
| `nvidia_payload_present` | No | NVIDIA payload field exists in attestation response |
| `nvidia_signature` | **Yes** | Local SPDM ECDSA P-384 cert chain + signature verification |
| `nvidia_claims` | No | EAT claims (arch, GPU count, nonce) are valid |
| `nvidia_nonce_match` | **Yes** | Nonce in NVIDIA payload matches client-submitted nonce |
| `nvidia_nras_verified` | No | Remote NRAS JWT verification passed |

Verify that `nvidia_signature` and `nvidia_nonce_match` are in [`DefaultEnforced`](../../../internal/attestation/report.go:76) and that their failure blocks traffic via [`Blocked()`](../../../internal/attestation/report.go:63).

### Local NVIDIA Evidence (EAT/SPDM)

#### EAT JSON Structure and Parsing

The [`nvidiaEAT`](../../../internal/attestation/nvidia_eat.go:40) struct defines the expected JSON format with `arch`, `nonce`, and `evidence_list` fields. Verify and report:
- EAT JSON parsing uses [`jsonstrict.UnmarshalWarn()`](../../../internal/attestation/nvidia_eat.go:60) for strict unmarshalling (check behavior on unknown fields),
- empty `evidence_list` is rejected as error (not silently accepted),
- top-level nonce comparison uses [`subtle.ConstantTimeCompare`](../../../internal/attestation/nvidia_eat.go:78) against `expectedNonce.Hex()`,
- the nonce is compared as hex string representation, not raw bytes — verify this format matches what the attestation endpoint provides.

#### Certificate Chain Validation

Verify and report:
- per-GPU certificate chain verification to the pinned NVIDIA Device Identity root CA via [`verifyCertChain()`](../../../internal/attestation/nvidia_eat.go:200),
- root CA pinning method: embedded PEM certificate via `//go:embed` directive at [`nvidia_eat.go:23`](../../../internal/attestation/nvidia_eat.go:23), with SHA-256 fingerprint verification against hardcoded [`nvidiaRootCAFingerprint`](../../../internal/attestation/nvidia_eat.go:28),
- the pinned root CA is **not** in the system trust store — verification uses a custom `x509.VerifyOptions` with an explicit root pool containing only the pinned certificate,
- certificate chain minimum depth check: at least 2 certificates required (leaf + root/intermediate),
- chain root fingerprint comparison (`sha256.Sum256(chainRoot.Raw)`) against pinned root fingerprint,
- NVIDIA device identity certificates have non-standard expiry (`notAfter=9999-12-31`) and may lack standard key usage extensions — verify how `x509.VerifyOptions` handles this (time and usage checks may be disabled).

#### SPDM Evidence Verification

Verify and report:
- SPDM version validation (`0x11` for SPDM 1.1) in both request and response headers,
- message code validation (`0xe0` GET_MEASUREMENTS, `0x60` MEASUREMENTS),
- requester nonce extraction from request bytes `[4:36]` and constant-time comparison against expected nonce,
- variable-length field parsing: MeasurementRecordLength (3 bytes LE), OpaqueDataLength (2 bytes LE),
- bounds checking at every offset calculation (prevents buffer overread on malformed evidence),
- minimum evidence length validation (`spdmGetMeasurementsLen + 10` = 47 bytes minimum),
- SPDM signature verification algorithm: ECDSA P-384 with SHA-384 hash of the signed message,
- signed-data construction: `signedMsg = evidence[:requestLen + responseWithoutSignature]` (concatenation of full request + response-minus-signature, in order),
- signature format: raw `r || s` (48 bytes each = 96 bytes total), not ASN.1 DER encoded — verify this matches NVIDIA's SPDM implementation,
- leaf certificate public key type assertion: must be `*ecdsa.PublicKey` on curve `P-384`.

#### All-or-Nothing Semantics

Verify:
- [`verifyNVIDIAEAT()`](../../../internal/attestation/nvidia_eat.go:56) iterates all GPUs and returns on the **first** failure — one GPU failure fails the entire NVIDIA verification,
- the failure detail includes the GPU index (`"GPU %d verification failed"`),
- extraction/reporting of GPU count and architecture metadata occurs regardless of verification outcome (for informational display).

### Remote NRAS Verification

#### NRAS Endpoint and Request Construction

- [`NRASAttestURL`](../../../internal/attestation/nvidia.go:30) is `https://nras.attestation.nvidia.com/v3/attest/gpu` — verify whether this is configurable or hardcoded (currently a `var` — mutable for tests, but no config mechanism),
- the raw EAT JSON payload is POSTed directly to NRAS for RIM-based measurement comparison,
- response body is limited to 1 MiB via [`io.LimitReader`](../../../internal/attestation/nvidia.go:257),
- Content-Type and Accept headers are set to `application/json`.

#### NRAS Response Format

- NRAS returns a JSON array of `[type, token]` pairs: `[["JWT","eyJ..."]]`,
- [`extractNRASJWT()`](../../../internal/attestation/nvidia.go:301) parses this structure to extract the first JWT — verify error handling if the response format changes or is unexpected,
- non-JWT elements in the array are silently skipped — assess whether this is acceptable behavior.

#### JWT Signature Verification

Verify and report:
- JWT signature verification using a cached JWKS endpoint — [`NvidiaJWKSURL`](../../../internal/attestation/nvidia.go:23) is `https://nras.attestation.nvidia.com/.well-known/jwks.json`,
- accepted algorithms: `ES256`, `ES384`, `ES512` only — **HS256 MUST be rejected** (verify via [`jwt.WithValidMethods`](../../../internal/attestation/nvidia.go:182) parser option),
- expiration is required (`jwt.WithExpirationRequired()`),
- claims validation: `x-nvidia-overall-att-result` (boolean), `nonce`, standard `iss`/`exp` claims.

#### JWKS Caching Behavior

The [`getOrCreateKeyfunc()`](../../../internal/attestation/nvidia.go:99) function caches JWKS keyfunc instances:
- caching uses `sync.Map` (concurrent-safe) keyed by JWKS URL,
- hard max age bounded by [`jwksCacheTTL`](../../../internal/attestation/nvidia.go:92) (1 hour),
- double-checked locking pattern: check `sync.Map` → acquire `jwksMu` mutex → re-check → create,
- keyfunc/v3 library provides background refresh and rate-limited unknown-kid refresh internally,
- stale entries are replaced: old entry's `cancel()` is called before storing new entry,
- verify that JWKS cache initialization failure on the first request results in a verification failure (not silent pass-through).

### CPU-GPU Attestation Chain Binding

The reference document notes that the audit MUST verify the relationship between GPU TEE and CPU TEE (TDX). Currently:
- factor `cpu_gpu_chain` in [`report.go`](../../../internal/attestation/report.go:417) is **hardcoded to Fail** with detail `"CPU-GPU attestation not bound"`,
- this means there is no cryptographic binding between the TDX attestation (CPU) and the NVIDIA EAT (GPU),
- **residual risk**: an attacker could present a valid TDX quote from one machine paired with a valid NVIDIA EAT from a different machine,
- the shared nonce provides some binding (same nonce in both TDX REPORTDATA and NVIDIA EAT), but this is not a cryptographic chain.

Document this as a known gap with high residual risk.

### GPU Driver/Firmware Version Checks

- Local EAT verification proves that GPU evidence is well-formed and signed by NVIDIA-issued device certificates,
- NRAS verification goes further by comparing GPU firmware measurements against NVIDIA's Reference Integrity Manifest (RIM) golden values,
- the `x-nvidia-overall-att-result` claim in the NRAS JWT indicates whether measurements match the RIM,
- **without NRAS verification**, firmware version currency cannot be established — document this as a residual risk when running in offline mode.

### Offline Behavior

If offline mode exists, identify exactly which NVIDIA checks remain active and which are skipped:
- **Active offline**: local EAT parsing, certificate chain validation, SPDM signature verification, nonce matching,
- **Skipped offline**: NRAS cloud verification (factor `nvidia_nras_verified` reports `"offline mode; NRAS verification skipped"`),
- verify that `nvidia_nras_verified` is **not** in `DefaultEnforced` (so skipping it does not block traffic in offline mode).

## Best-Practice Audit Points

### Go (Golang) Best Practices

- **Type assertion safety**: [`getOrCreateKeyfunc()`](../../../internal/attestation/nvidia.go:101) uses forced type assertions on `sync.Map` values (with `//nolint:forcetypeassert` annotations). Verify that the `sync.Map` is only written to with `*jwksEntry` values to prevent runtime panics.
- **Context propagation**: [`VerifyNVIDIANRAS()`](../../../internal/attestation/nvidia.go:233) accepts a `context.Context` for HTTP request cancellation. Verify that caller-supplied context deadlines propagate correctly to prevent hanging requests to NRAS.
- **Error wrapping with `%w`**: NVIDIA verification errors use `fmt.Errorf("... %w", err)` for proper error wrapping. Verify this is consistent throughout, enabling callers to use `errors.Is()` for sentinel error detection.
- **Resource cleanup**: [`jwksEntry`](../../../internal/attestation/nvidia.go:79) holds a `cancel` function for the keyfunc's background goroutine. Verify that [`resetJWKS()`](../../../internal/attestation/nvidia.go:134) is called during graceful shutdown (not just in tests) to prevent goroutine leaks.

### Cryptography Best Practices

- **ECDSA signature format**: SPDM uses raw `r || s` concatenation (48+48 bytes for P-384), not ASN.1 DER. Verify that the [`ecdsa.Verify()`](../../../internal/attestation/nvidia_eat.go:317) call receives correctly parsed `big.Int` values from the raw bytes — incorrect byte-order or padding would cause silent verification failure.
- **Hash algorithm matching**: SHA-384 is used for P-384 ECDSA verification. Verify the hash is computed over the correct signed-data span (request + response-minus-signature) and not over a subset or superset.
- **Root CA pinning strength**: The embedded root CA is verified by SHA-256 fingerprint _of the DER encoding_. This is stronger than subject-name matching but could be circumvented if the embedded PEM file is modified — verify the `//go:embed` file is under source control and not user-modifiable at runtime.
- **Algorithm restriction on JWT**: The `WithValidMethods([]string{"ES256", "ES384", "ES512"})` parser option MUST be present to prevent algorithm confusion attacks (e.g., HS256 with a public key as HMAC secret).
- **Constant-time nonce comparison**: Both the top-level EAT nonce and per-GPU SPDM requester nonce use `subtle.ConstantTimeCompare`. Verify no code path falls back to `==` or `bytes.Equal` for nonce comparison.

### General Security Audit Practices

- **Response size limits**: NRAS response is bounded by `io.LimitReader(resp.Body, 1<<20)` (1 MiB). Verify this limit is sufficient for legitimate responses but prevents memory exhaustion from malicious or misconfigured NRAS endpoints.
- **All-or-nothing verification**: A single GPU failure in the EAT evidence list fails the entire NVIDIA verification. This is correct fail-secure behavior — verify there is no short-circuit path that could skip remaining GPUs after a success.
- **Trust boundary**: Local EAT verification proves the evidence is well-formed and signed by NVIDIA device certificates. NRAS verification proves the firmware measurements match NVIDIA's golden values. Both are needed for complete assurance — document which layer provides what guarantee.
- **Input validation on binary parsing**: SPDM evidence parsing performs bounds checks before every buffer slice. Verify there are no integer overflow risks in offset calculations (e.g., `offset + measRecordLen` where `measRecordLen` is read from untrusted input).

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. local-vs-remote NVIDIA verification matrix with enforcement status for all 5 NVIDIA factors,
3. CPU-GPU binding gap assessment,
4. outage/offline residual risk statement,
5. include at least one concrete positive control and one concrete negative/residual-risk observation,
6. source citations for all claims.
