# Section 11 — NVIDIA TEE Verification Depth

## Scope

Audit NVIDIA evidence verification depth across both local evidence validation (EAT/SPDM) and remote NVIDIA NRAS validation.

The NVIDIA attestation is for the **model backend only**. The gateway is a CPU-only TEE and does not have GPU attestation. The audit MUST verify that the code does not expect or require NVIDIA attestation from the gateway.

The NVIDIA attestation provides a secondary layer of TEE assurance alongside the primary Intel TDX CPU attestation. The EAT (Entity Attestation Token) is an NVIDIA-defined JSON structure containing per-GPU evidence entries, each with an X.509 certificate chain and SPDM binary evidence blob. The NRAS (NVIDIA Remote Attestation Service) provides defense-in-depth by comparing GPU firmware measurements against NVIDIA's Reference Integrity Manifest (RIM) golden values.

## Primary Files

- [`internal/attestation/nvidia_eat.go`](../../../internal/attestation/nvidia_eat.go) — EAT JSON parsing, certificate chain validation, SPDM evidence verification
- [`internal/attestation/nvidia.go`](../../../internal/attestation/nvidia.go) — NRAS cloud verification, JWKS caching, JWT validation

## Secondary Context Files

- [`internal/attestation/report.go`](../../../internal/attestation/report.go) — NVIDIA-related factor evaluation
- [`internal/attestation/testdata/nvidia_eat_hopper.json`](../../../internal/attestation/testdata/nvidia_eat_hopper.json) — Reference EAT payload for Hopper GPUs
- [`internal/attestation/nvidia_eat_test.go`](../../../internal/attestation/nvidia_eat_test.go)
- [`internal/attestation/nvidia_test.go`](../../../internal/attestation/nvidia_test.go)

## Required Checks

### NVIDIA Attestation Scope: Model Backend Only

The audit MUST verify:
- that NVIDIA attestation is expected only from the model backend, NOT from the gateway,
- that the gateway attestation code path does not attempt to parse or verify NVIDIA evidence,
- that the absence of NVIDIA attestation in the gateway does not trigger an enforcement failure.

### NVIDIA Enforcement Factors

Map each factor to its enforcement status:

| Factor | Default Enforced | Description |
|--------|-----------------|-------------|
| `nvidia_payload_present` | No | NVIDIA payload field exists in attestation response |
| `nvidia_signature` | **Yes** | Local SPDM ECDSA P-384 cert chain + signature verification |
| `nvidia_claims` | No | EAT claims (arch, GPU count, nonce) are valid |
| `nvidia_nonce_client_bound` | **Yes** | Nonce in NVIDIA payload matches client-submitted nonce |
| `nvidia_nras_verified` | No | Remote NRAS JWT verification passed |

Verify that `nvidia_signature` and `nvidia_nonce_client_bound` are NOT in `NearcloudDefaultAllowFail` (i.e., they are enforced for nearcloud) and that their failure blocks traffic via `Blocked()`.

### Local NVIDIA Evidence (EAT/SPDM)

#### EAT JSON Structure and Parsing

Verify and report:
- EAT JSON parsing uses strict unmarshalling (check behavior on unknown fields),
- empty `evidence_list` is rejected as error,
- top-level nonce comparison uses `subtle.ConstantTimeCompare`,
- the nonce is compared as hex string representation — verify format matches attestation endpoint.

#### Certificate Chain Validation

Verify and report:
- per-GPU certificate chain verification to the pinned NVIDIA Device Identity root CA,
- root CA pinning method: embedded PEM certificate via `//go:embed` directive, with SHA-256 fingerprint verification,
- the pinned root CA is **not** in the system trust store — custom `x509.VerifyOptions` with explicit root pool,
- certificate chain minimum depth check (at least 2 certificates),
- chain root fingerprint comparison against pinned root fingerprint,
- handling of non-standard NVIDIA device identity certificate properties (expiry, key usage).

#### SPDM Evidence Verification

Verify and report:
- SPDM version validation (`0x11` for SPDM 1.1) in both request and response headers,
- message code validation (`0xe0` GET_MEASUREMENTS, `0x60` MEASUREMENTS),
- requester nonce extraction from request bytes and constant-time comparison,
- variable-length field parsing: MeasurementRecordLength (3 bytes LE), OpaqueDataLength (2 bytes LE),
- bounds checking at every offset calculation (prevents buffer overread),
- minimum evidence length validation,
- SPDM signature verification algorithm: ECDSA P-384 with SHA-384,
- signed-data construction: `signedMsg = evidence[:requestLen + responseWithoutSignature]`,
- signature format: raw `r || s` (48+48 bytes), not ASN.1 DER,
- leaf certificate public key type assertion: `*ecdsa.PublicKey` on curve `P-384`.

#### All-or-Nothing Semantics

Verify:
- one GPU failure fails the entire NVIDIA verification,
- failure detail includes GPU index,
- extraction/reporting of GPU count and architecture occurs regardless of verification outcome.

### Remote NRAS Verification

Verify and report:
- NRAS endpoint URL and whether it is configurable or hardcoded,
- raw EAT JSON payload POSTed directly to NRAS,
- response body limited to 1 MiB via `io.LimitReader`,
- NRAS response format: JSON array of `[type, token]` pairs,
- JWT signature verification using cached JWKS endpoint,
- accepted algorithms: `ES256`, `ES384`, `ES512` only — **HS256 MUST be rejected**,
- JWT claims validation (expiration, overall attestation result, nonce),
- JWKS caching behavior (auto-refresh, rate-limited unknown-kid fallback, hard max age).

### CPU-GPU Attestation Chain Binding

The audit MUST verify the relationship between GPU TEE (NVIDIA) and CPU TEE (TDX):
- whether the `cpu_gpu_chain` factor is hardcoded to Fail,
- the residual risk: an attacker could present a valid TDX quote from one machine paired with a valid NVIDIA EAT from a different machine,
- the shared nonce provides some binding but is not a cryptographic chain,
- document this as a known gap with high residual risk.

### Offline Behavior

Identify which NVIDIA checks remain active offline and which are skipped:
- **Active offline**: local EAT parsing, certificate chain validation, SPDM signature verification, nonce matching,
- **Skipped offline**: NRAS cloud verification (`nvidia_nras_verified` reports "offline mode; NRAS verification skipped"),
- verify that `nvidia_nras_verified` is NOT in `NearcloudDefaultAllowFail` (enforced for nearcloud; note it IS in the global `DefaultAllowFail` but provider-specific lists override).

## Best-Practice Audit Points

### Go (Golang) Best Practices

- **Type assertion safety**: Verify `sync.Map` forced type assertions are safe.
- **Context propagation**: NRAS HTTP requests respect context cancellation.
- **Error wrapping**: Consistent `%w` wrapping.
- **Resource cleanup**: Keyfunc background goroutine cleanup.

### Cryptography Best Practices

- **ECDSA signature format**: SPDM raw `r || s` correctly parsed to `big.Int`.
- **Hash algorithm matching**: SHA-384 for P-384 ECDSA, computed over correct signed-data span.
- **Root CA pinning strength**: Embedded PEM verified by SHA-256 fingerprint of DER encoding.
- **Algorithm restriction on JWT**: `WithValidMethods` prevents algorithm confusion attacks.
- **Constant-time nonce comparison**: Both EAT and SPDM nonces use `subtle.ConstantTimeCompare`.

### General Security Audit Practices

- **Response size limits**: NRAS response bounded by `io.LimitReader`.
- **All-or-nothing verification**: Single GPU failure fails the entire check.
- **Trust boundary**: Local EAT proves evidence is well-formed and signed. NRAS proves firmware matches golden values.
- **Input validation on binary parsing**: SPDM bounds checks prevent buffer overread.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. confirmation that NVIDIA attestation applies only to model backend (not gateway),
3. local-vs-remote NVIDIA verification matrix with enforcement status for all 5 factors,
4. CPU-GPU binding gap assessment,
5. outage/offline residual risk statement,
6. include at least one concrete positive control and one concrete negative/residual-risk observation,
7. source citations for all claims.
