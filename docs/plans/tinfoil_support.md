# Plan: Tinfoil Provider Support

## Overview

Add Tinfoil as a teep provider with full attestation verification and E2EE
support. Tinfoil runs OpenAI-compatible inference in secure enclaves
(TDX and SEV-SNP). Attestation is fetched from a well-known HTTP endpoint on
the enclave, verified against hardware roots of trust and Sigstore supply-chain
attestations, and bound to TLS via the enclave's certificate fingerprint. E2EE
uses the EHBP protocol (HPKE-based full-body encryption).

Reference providers for implementation patterns: **nearcloud**, **neardirect**,
**chutes**.

**Byte range notation**: This document uses Go slice notation throughout.
`REPORTDATA[0:32]` means bytes at indices 0 through 31 (32 bytes).
`REPORTDATA[32:64]` means bytes at indices 32 through 63 (32 bytes).

### Provider: `tinfoil`

Tinfoil's attestation endpoint supports both a legacy format and the current V3
format. V3 is the fully deployed format as of June 2026, providing client-nonce
freshness, GPU evidence binding, and a structured JSON response that enables
full external verification. The `tinfoil` provider **always supplies a client
nonce** (`?nonce=<64hex>`) when fetching attestation to guarantee V3 format is
returned. The server returns V3 format when a nonce is present; omitting the
nonce may result in a legacy format response. Implementations MUST reject any
response that does not contain the `report_data` structured field (i.e., any
non-V3 response).

## Provider Characteristics

| Property | Value |
|---|---|
| Provider name | `tinfoil` |
| Base URL | `https://inference.tinfoil.sh` |
| API key env | `TINFOIL_API_KEY` |
| E2EE | Yes (EHBP: HPKE + AES-256-GCM full-body encryption) |
| Connection model | Standard TLS with SPKI pinning (not connection-pinned) |
| Attestation endpoint | `GET /.well-known/tinfoil-attestation?nonce=<64hex>` on the enclave |
| PinnedHandler | No — uses standard HTTP client with SPKI verification |
| Supply chain | Sigstore DSSE bundles from GitHub attestations API |
| Hardware platforms | Intel TDX and AMD SEV-SNP (multi-platform code measurements) |
| GPU support | NVIDIA H100/H200 (Hopper), Blackwell; 1-GPU and 8-GPU (HGX) configurations |
| TEE.fail mitigation | None (same as all current providers) |
| Attestation format | V3: structured JSON with `report_data`, `cpu`, `gpu`, `nvswitch`, `certificate`, `signature` fields |
| Nonce model | Client nonce via `?nonce=<64hex>` query parameter (32 bytes → 64 hex chars); REQUIRED to receive V3 format |
| REPORTDATA layout | `[0:32]` SHA-256(tls_fp \|\| hpke \|\| nonce \|\| gpu_hash \|\| nvswitch_hash), `[32:64]` zeros |
| HPKE key source | From `report_data.hpke_key` field in response (authenticated via REPORTDATA hash) |
| GPU attestation | SPDM evidence in response; GPU evidence hash bound into REPORTDATA (Option 2 from gpu_cpu_binding.md) |
| GPU-CPU binding | Yes — SHA-256 of GPU/NVSwitch evidence in REPORTDATA hash |

## Supported Endpoints

This plan must account for the full API surface currently exposed by the
Tinfoil router, while explicitly marking which endpoints teep will implement
in each phase.

Teep Target terminology in this plan:
- Implement in teep: endpoint is in-scope for this provider integration.
- Not in teep (reject fail-closed): endpoint exists upstream but is out of
   scope for this integration and must be rejected explicitly.

| Endpoint | Upstream Path | E2EE | Teep Target | Notes |
|---|---|---|---|---|
| Chat completions | `/v1/chat/completions` | Yes (EHBP) | Implement in teep | OpenAI-compatible chat; supports multimodal content arrays |
| Responses API | `/v1/responses` | Yes (EHBP) | Implement in teep | OpenAI Responses API shape; includes tool-calling flows |
| Embeddings | `/v1/embeddings` | Yes (EHBP) | Implement in teep | OpenAI embeddings |
| Audio transcriptions | `/v1/audio/transcriptions` | Yes (EHBP) | Implement in teep | Multipart form-data accepted and encrypted as full body |
| Audio endpoints (generic) | `/v1/audio/*` | Yes (EHBP) | Implement known paths; reject unknown fail-closed | Upstream router accepts catch-all audio subpaths; teep must explicitly enumerate and implement only known OpenAI-compatible audio paths and reject unknown audio semantics fail-closed |
| TTS (text-to-speech) | `/v1/audio/speech` | Yes (EHBP) | Implement in teep | OpenAI-compatible speech synthesis; upstream default model is `qwen3-tts` if omitted |
| Models list | `/v1/models` | No (bodyless GET) | Implement in teep | Plaintext over attested TLS binding; no request body to encrypt |
| Realtime (WebSocket) | `/v1/realtime` | No EHBP (WS transport) | Not in teep (reject fail-closed) | Tinfoil supports realtime websocket routing; teep rejects until websocket attestation+binding design is implemented |
| File conversion | `/v1/convert/file` | Endpoint-specific | Not in teep (reject fail-closed) | Tinfoil-specific service endpoint, not part of teep OpenAI-compatible core |
| Router operational endpoints | `/health`, `/.well-known/tinfoil-proxy`, `/.well-known/prometheus-targets`, `/metrics` | No | Not in teep (reject fail-closed) | Operational/monitoring endpoints; out of scope for OpenAI-compatible provider integration |

Vision models (qwen3-vl-30b, gemma4-31b, kimi-k2-6) use the chat completions
endpoint with multimodal content arrays — no separate vision endpoint is needed.

Note: For exchanges with non-empty HTTP bodies, EHBP encrypts the entire body
as a single AEAD stream. There are **no field-level gaps** for those encrypted
exchanges. Bodyless endpoints (for example `GET /v1/models`) are plaintext at
the HTTP-body layer by design.

### Endpoint Routing and Request-Shape Mechanics

To produce a compatible implementation without depending on upstream source
code, teep must follow these endpoint-specific routing mechanics:

1. `/v1/chat/completions` and `/v1/responses` are both first-class inference
   APIs and must both be routed through attested + EHBP-protected transports.
2. `/v1/chat/completions` and `/v1/responses` require `model` in the JSON body.
   Missing or non-string model is a fail-closed request error.
3. `/v1/audio/speech` requires a non-empty JSON `model` string at the teep
   boundary. Missing, empty, or non-string `model` is a fail-closed request
   error. Upstream defaults may exist, but teep must not rely on them.
4. Audio upload-style paths (`/v1/audio/transcriptions`) use multipart or
   binary request bodies and must preserve body bytes exactly across EHBP
   encryption/decryption boundaries. (Note: `/v1/audio/speech` uses JSON
   request bodies and is handled separately as a JSON endpoint.)
5. For multipart audio requests, the model must be extracted from multipart
   field `model` as a non-empty string. Missing or empty `model` is a
   fail-closed request error.
6. `/v1/models` is a bodyless GET and therefore plaintext at the HTTP-body
   layer; this is acceptable because confidentiality is provided by TLS and the
   payload is non-sensitive model metadata.
7. For `/v1/responses`, router-owned tool activation is driven by
   `tools[].type` entries of `web_search` and `code_execution`; unknown
   tool types must be rejected fail-closed at the teep boundary, and duplicate
   activations are deduplicated.
8. Requests with `stream=true` should preserve caller stream intent, and
   implementations should be prepared for usage metadata fields/chunks in both
   chat and responses streams.
9. Unknown or unsupported endpoints must fail closed with explicit error
   diagnostics; do not silently pass through unknown paths.
10. `POST /v1/convert/file` and WebSocket `/v1/realtime` are out of scope for
    teep integration and must be explicitly rejected by teep until dedicated
    attestation + transport designs are added.
11. Upstream browser WebSocket clients may authenticate via
    `Sec-WebSocket-Protocol: openai-insecure-api-key.<key>` when `Authorization`
    cannot be set; teep should not emulate this until realtime support exists.
12. Vision-capable models are accessed through `/v1/chat/completions`; no
    separate vision endpoint is required.

### Tinfoil-Specific Request Options

The Tinfoil router recognizes optional top-level request fields that are not
standard OpenAI schema. A compatible proxy must handle these deterministically:

1. `code_execution_options`
2. `web_search_options`
3. `pii_check_options`

These options are router-control metadata. They must not weaken attestation,
E2EE, or verification gates.

Compatibility validation behavior:
1. `code_execution_options` is strict-validated when present.
   - Must be an object.
   - Required non-empty string fields: `accessToken`, `encryptionKey`,
     `containerAuthToken`.
   - Optional `uploads` must be an array of objects; each entry requires
     non-empty string fields `fileAccessToken`, `filename`, `sha256`.
   - Any malformed shape is a fail-closed request error.
2. `web_search_options` currently behaves as presence-based metadata; router
   activation can proceed even when no strict schema validation is applied at
   the edge.
3. `pii_check_options` is currently presence-based opt-in metadata.
4. For `/v1/responses`, tool activation may come from either top-level options
   or `tools[]` entries; implementations should deduplicate activations and
   reject unknown `tools[].type` values fail-closed.

## Architecture Comparison with Existing Providers

### Similarities to Chutes

- Full-body encryption (no field-level dispatch needed)
- Standard TLS (not connection-pinned like neardirect/nearcloud)
- No PinnedHandler needed
- TDX attestation verification reuses `attestation.VerifyTDXQuoteOffline()` /
  `attestation.VerifyTDXQuoteOnline()` (via `attestation.TDXVerifier`)

### Key Differences from All Existing Providers

1. **Attestation format**: Tinfoil uses its own V3 format — a structured JSON
   response with separate `cpu`, `gpu`, `nvswitch`, `report_data`,
   `certificate`, and `signature` fields. Not dstack, not chutes, not NEAR.
2. **Supply chain**: Sigstore verification of GitHub Actions build attestations
   (DSSE in-toto bundles), checked against code image digests published in
   GitHub Releases. This is independent of the compose-hash / IMA supply chain
   used by other providers.
3. **REPORTDATA binding**: `[0:32]` = SHA-256(tls_fp || hpke || nonce ||
   gpu_hash || nvswitch_hash); `[32:64]` = zeros. Client nonce and GPU binding.
4. **E2EE protocol**: EHBP (RFC 9180 HPKE + AES-256-GCM), not
   Ed25519/XChaCha20-Poly1305 or ML-KEM-768/ChaCha20-Poly1305.
5. **HPKE key from attestation**: HPKE key in the `report_data.hpke_key`
   response field, authenticated by being part of the REPORTDATA[0:32] hash.
   Cipher suite is fixed (X25519_HKDF_SHA256 / HKDF_SHA256 / AES_256_GCM)
   per the EHBP spec. No key config endpoint needed.
6. **Hardware measurement verification**: TDX hardware platforms (MRTD, RTMR0)
   matched against a separate Sigstore-attested hardware measurements registry
   (`tinfoilsh/hardware-measurements`).
7. **Multi-platform code measurements**: Code attestation uses a unified
   `snp-tdx-multiplatform/v1` predicate that cross-matches SEV-SNP and TDX
   measurements from a single Sigstore bundle.
8. **SEV-SNP support**: Tinfoil enclaves can run on AMD SEV-SNP (not just TDX).
   The `cpu.platform` field in the attestation response determines which
   hardware verification path to take.
9. **GPU attestation binding**: GPU evidence is included in the attestation
   response and hash-bound into REPORTDATA (Option 2 from gpu_cpu_binding.md).
   GPU SPDM evidence and NVSwitch evidence are hash-bound into the CPU quote.
   Boot-time GPU attestation is fail-closed.
10. **No TEE.fail mitigations**: Like all current providers, Tinfoil has no
    Proof of Cloud participation, no vTPM, and no DCEA. TEE.fail is an open
    vulnerability. See "Authentication Chain 5" for full analysis.

---

## Authentication Chain Analysis

This section documents the complete authentication chains from hardware root
of trust through to the user's plaintext, explicitly comparing Tinfoil's
model against the gaps documented in `docs/attestation_gaps/dstack_integrity.md`
and `docs/attestation_gaps/model_weights.md`. The code agent must enforce every
link in these chains.

### Gap Comparison: Tinfoil vs. Dstack Providers

The dstack integrity gap (dstack_integrity.md) identifies that dstack-based
providers (Venice, Nearcloud, Neardirect) suffer from an **in-band discovery
gap**: the boot-chain registers MRTD, RTMR0–RTMR2 must be compared against
externally-sourced expected values, but no provider publishes those values in
a signed, machine-readable format. Operators must manually maintain measurement
allowlists, and provider infrastructure changes silently break verification.

The model weights gap (model_weights.md) documents that no dstack provider
includes model identity in the attestation chain. The Docker Compose manifest
binds the container image, but model weights are downloaded at runtime inside
the container — the attestation proves the correct software, not the correct
model.

**Tinfoil closes both gaps by design:**

1. **Boot-chain measurements are published in Sigstore.** Tinfoil's
   `pri-build-action` GitHub Actions workflow computes expected measurements
   for every deployment configuration and publishes them as a signed Sigstore
   bundle in the transparency log. Teep fetches the bundle and compares its
   measurement predicates against the hardware attestation report. There are
   no operator-maintained allowlists — the expected values are authenticated
   and machine-readable.

2. **Model weights are attested via dm-verity + Sigstore.** Tinfoil uses a
   tool called `modelwrap` to create a read-only volume containing model
   weights and compute a cryptographic commitment (dm-verity root hash) over
   it. This commitment is pinned in `tinfoil-config.yml`, whose SHA-256 hash
   is embedded in the kernel command line (measured into the attestation
   report). At runtime, the CVM mounts the model volume read-only and
   dm-verity validates every block read against the Merkle tree root hash.
   Any tampered block causes an I/O error. The `tinfoil-config.yml` and its
   model commitment are covered by the Sigstore bundle, so teep can verify
   that the model weights running in the enclave are exactly what was
   committed at build time.

3. **All disks are read-only and stateless.** The CVM mounts all virtual
   disks read-only and uses ramdisk for ephemeral data. There is no
   persistent writable state between boots. This eliminates the runtime
   weight substitution vector that model_weights.md identifies for dstack
   providers, where the inference engine could download alternative weights.

4. **Configuration is measured into the attestation.** The
   `tinfoil-config.yml` file (containing the model commitment, container
   images, CVM version, and resource allocation) has its SHA-256 embedded in
   the kernel command line. Since the kernel command line is measured into
   RTMR2 (TDX) or the launch measurement (SEV-SNP), any change to the
   configuration produces a different attestation that will not match the
   Sigstore bundle.

5. **No per-deployment-class variation.** Unlike dstack, where RTMR0 varies
   with CPU/RAM/GPU count and operators must pin multiple values, Tinfoil's
   Sigstore bundle is scoped to a specific deployment configuration. The
   bundle contains the exact expected measurements for that configuration.
   If Tinfoil changes the hardware profile, a new Sigstore bundle is
   published.

| Gap | Dstack Providers | Tinfoil |
|---|---|---|
| Boot-chain register discovery | Out-of-band, operator-maintained | In-band via Sigstore bundle |
| MRSEAM / firmware identity | Derivable from Intel, needs manual pin | Published in Sigstore bundle |
| MRTD / CVM image identity | Derivable from dstack build, needs manual pin | Published in Sigstore bundle |
| RTMR0 / hardware config | Per-deployment-class, no signed publication | Published in Sigstore bundle |
| RTMR1-2 / kernel+rootfs | Per-image build, no signed publication | Published in Sigstore bundle |
| Model weight authentication | Not attested (downloaded at runtime) | dm-verity root hash in attested config |
| Model identity in attestation | Not present | config.yml commitment → kernel cmdline → RTMR2 |
| Configuration authenticity | Compose hash in MRCONFIGID | config.yml hash in kernel cmdline + Sigstore |
| Measurement baseline maintenance | Manual operator burden | Automated via Sigstore transparency log |
| GPU attestation (boot-time) | Not enforced at boot | nvattest + SPDM verified at boot; fail-closed |
| GPU-CPU binding | Not implemented (`cpu_gpu_chain` = Fail) | GPU evidence hash in REPORTDATA (Option 2, Pass) |
| GPU topology validation | Not validated | 8-GPU + 4-NVSwitch PCIe mesh validated at boot |
| TEE.fail defense | Proof of Cloud (conditional) | None (same vulnerability) |
| vTPM / DCEA | Not implemented | Not implemented |

### Gap Status Determination Rules

This section makes the gap conclusions mechanically decidable from verifier
outputs, rather than narrative interpretation.

1. **Dstack in-band discovery gap analogue (boot-measurement publication):**
   `Closed` only when both conditions hold:
   - `sigstore_code_verified` is `Pass` from a verified DSSE bundle for the
     deployment repo, and
   - for TDX, hardware platform matching (MRTD+RTMR0) against
     `hardware-measurements` passes; for SEV-SNP, launch measurement matching
     against the verified multi-platform predicate passes.
   Any failure or `Skip` in those checks means `Open`.

2. **Model-weights identity gap (runtime weight substitution):**
   `Closed` only when `sigstore_code_verified` is `Pass` and the measured chain
   explicitly ties the verified config to dm-verity root commitments
   (`measured_model_weights=Pass` with transitive detail). If the Sigstore
   chain fails/skip, this gap is `Open`.

3. **GPU-to-CPU binding gap (Option 2):**
   `Closed` only when both `cpu_gpu_chain` and `nvidia_gpu_attestation` are
   `Pass` in the same verification event, including topology-conditional
   NVSwitch requirements. Any missing required evidence, hash mismatch,
   malformed normalization input, or SPDM failure makes it `Open`.

4. **TEE.fail key-extraction gap:**
   Always `Open` until an independent CPU identity registry / anti-relay
   mitigation is enforced (for example Proof-of-Cloud identity registration,
   DCEA/vTPM-backed identity, or equivalent hardware-rooted anti-forgery
   control). Passing quote/supply-chain/E2EE checks does not close this gap.

### Authentication Chain 1: CVM Environment (Hardware → Code)

This chain proves that the enclave is running the expected firmware, kernel,
and application code on genuine hardware. Every link must be verified; a
break at any point means the enclave identity is unproven.

```
Link 1: Hardware Root of Trust
│   AMD PSP signs with VCEK (per-chip key → AMD root)
│   Intel QE signs with attestation key → Intel PCK → Intel root
│   Verified by: validating report signature against manufacturer cert chain
│
├── Link 2: Firmware Identity (OVMF)
│   │   TDX: measured into MRTD
│   │   SEV-SNP: measured into launch measurement
│   │   Verified by: comparing against Sigstore bundle measurements
│   │
│   ├── Link 3: Hardware Configuration
│   │   │   TDX: measured into RTMR0 (vCPU, RAM, GPU, PCI config)
│   │   │   SEV-SNP: folded into launch measurement
│   │   │   Verified by: comparing against Sigstore hardware measurements
│   │   │
│   │   ├── Link 4: Kernel + Initrd
│   │   │   │   TDX: kernel measured into RTMR1
│   │   │   │   SEV-SNP: folded into launch measurement
│   │   │   │   Verified by: comparing against Sigstore bundle measurements
│   │   │   │
│   │   │   ├── Link 5: Kernel Cmdline + Rootfs
│   │   │   │   │   TDX: measured into RTMR2
│   │   │   │   │   Includes SHA-256 of tinfoil-config.yml
│   │   │   │   │   SEV-SNP: folded into launch measurement
│   │   │   │   │   Verified by: comparing against Sigstore bundle
│   │   │   │   │
│   │   │   │   ├── Link 6: Application Configuration
│   │   │   │   │   │   tinfoil-config.yml specifies:
│   │   │   │   │   │     - container images (by digest)
│   │   │   │   │   │     - model weight dm-verity commitment
│   │   │   │   │   │     - CVM version
│   │   │   │   │   │     - resource allocation
│   │   │   │   │   │   Authenticated by: hash in kernel cmdline (Link 5)
│   │   │   │   │   │
│   │   │   │   │   ├── Link 7: Model Weights
│   │   │   │   │   │       Read-only volume, dm-verity validated
│   │   │   │   │   │       Root hash pinned in config.yml (Link 6)
│   │   │   │   │   │       Every block read verified at kernel level
│   │   │   │   │   │
│   │   │   │   │   └── Link 8: Container Images
│   │   │   │   │           Digest-pinned in config.yml (Link 6)
│   │   │   │   │           Covered by Sigstore bundle provenance
│   │   │   │   │
│   │   │   │   └── Link 5a: TDX-specific Policy
│   │   │   │           TD_ATTRIBUTES, XFAM, MR_SEAM, TEE_TCB_SVN
│   │   │   │           RTMR3 must be zero (no runtime extensions)
│   │   │   │           MR_CONFIG_ID, MR_OWNER, MR_OWNER_CONFIG = 0
│   │   │   │
│   │   │   └── (SEV-SNP: guest policy, TCB SVN minimums)
│   │   │
│   │   └── Link 3a: Hardware Platform Registry (TDX only)
│   │           MRTD + RTMR0 matched against Sigstore-attested
│   │           hardware-measurements predicate
│   │
│   └── Link 2a: GPU Verification
│           NVIDIA local-gpu-verifier run at boot inside CVM
│           GPU CC mode validated before service startup
│           Failure aborts boot (no enclave starts)
│           Transitively verified via CPU attestation
│           GPU evidence hash bound into REPORTDATA (Chain 5)
│           SPDM evidence independently verifiable by client
│
└── Link 1a: Sigstore Supply Chain Anchor
        Sigstore bundle from pri-build-action (GitHub Actions)
        OIDC issuer: token.actions.githubusercontent.com
        Workflow bound to specific GitHub repo + tag
   Code bundle contains code measurements (RTMR1/RTMR2 or SNP measurement)
   Hardware-measurements bundle contains platform measurements (MRTD/RTMR0)
        Verified by: sigstore-go against Sigstore root trust anchor
```

**What teep must verify (enforcement checklist):**

1. Validate hardware attestation report signature against manufacturer cert
   chain (AMD ARK→ASK→VCEK or Intel root→PCK→QE). → `tee_quote_structure`
2. Compare all measurement registers against values from Sigstore bundle:
   - TDX code registers: RTMR1, RTMR2 against the multi-platform predicate
   - SEV-SNP code register: launch measurement against `snp_measurement`
   → `sigstore_code_verified` (code measurement match)
3. Verify Sigstore bundle: DSSE signature, Fulcio certificate, SCT,
   transparency log entry, observer timestamp. → `sigstore_code_verified`
4. Apply platform-specific policy checks:
   - TDX: TD_ATTRIBUTES, XFAM, MR_SEAM whitelist, RTMR3==0, zero fields
   - SEV-SNP: guest policy (Debug=false, SMT, etc.), TCB minimums
   → `tee_hardware_config`
5. Match TDX MRTD + RTMR0 against hardware measurements registry.
   → `tee_boot_config` (hardware-platform measurement validation)
6. Verify RTMR3 is all zeros (no unexpected runtime extensions).

### Authentication Chain 2: Encryption Keys (Hardware → Plaintext)

This chain proves that only the attested enclave can decrypt user data. Every
link must hold; a break means an intermediary could read plaintext.

```
Link 1: Key Generation Inside Enclave
│   At boot, enclave generates:
│     - ECDSA key pair for TLS (private key in encrypted memory)
│     - X25519 key pair for HPKE/EHBP (private key in encrypted memory)
│   Private keys never leave enclave memory.
│   Destroyed when enclave terminates (stateless CVM).
│
├── Link 2: Key Binding to Attestation
│   │   REPORTDATA[0:32] = SHA-256(TLS FP || HPKE key || nonce || GPU hash || NVSwitch hash)
│   │   REPORTDATA[32:64] = zeros
│   │   HPKE key in response report_data field (authenticated by hash)
│   │   REPORTDATA is part of the hardware-signed attestation report.
│   │   Verified by: extracting REPORTDATA from verified quote.
│   │
│   ├── Link 3: TLS Key Binding
│   │   │   Client connects to enclave via TLS.
│   │   │   Computes SHA-256 of server's TLS public key (PKIX DER).
│   │   │   Constant-time compares against report_data.tls_key_fp
│   │   │   (authenticated by REPORTDATA[0:32] hash).
│   │   │   Mismatch → reject connection (fail closed).
│   │   │   Guarantees: TLS terminates inside the attested enclave.
│   │   │   No intermediary can MITM or terminate TLS.
│   │   │
│   │   └── Link 3a: TLS-Bound Transport (teep implementation)
│   │           Custom http.Transport with VerifyPeerCertificate callback
│   │           Checks SPKI fingerprint on every connection
│   │           Re-attestation on fingerprint mismatch
│   │           Connection: close on attestation boundary
│   │
│   └── Link 4: HPKE Key Binding
│       │   HPKE public key from response report_data.hpke_key
│       │   (authenticated by REPORTDATA[0:32] hash).
│       │   Used as the recipient public key for EHBP encryption.
│       │   Since it is part of the hardware-signed REPORTDATA hash, the key
│       │   is authenticated by the same hardware root of trust as the
│       │   CVM identity. No separate key endpoint needed.
│       │
│       ├── Link 5: EHBP Request Encryption
│       │   │   Client calls HPKE SetupBaseS with attested public key.
│       │   │   Request body encrypted as chunked AES-256-GCM stream.
│       │   │   Ehbp-Encapsulated-Key header sent to server.
│       │   │   Only the enclave holding the HPKE private key can decrypt.
│       │   │
│       │   └── Link 5a: Request Confidentiality
│       │           HTTP headers (routing, auth) visible to intermediaries.
│       │           Body (user prompts, data) encrypted end-to-end.
│       │           No plaintext fallback. Missing encryption → fail closed.
│       │
│       └── Link 6: EHBP Response Decryption
│           │   Server returns Ehbp-Response-Nonce header.
│           │   Client derives response key from HPKE context + nonce
│           │   (OHTTP/RFC 9458 key derivation).
│           │   Response body decrypted as chunked AES-256-GCM stream.
│           │
│           ├── Link 6a: Response Authenticity
│           │       AEAD tag on every chunk proves the response came from
│           │       the holder of the HPKE private key (the enclave).
│           │       Corrupted or forged chunks → decryption failure → fail closed.
│           │
│           └── Link 6b: Missing Nonce = Fail Closed
│                   If Ehbp-Response-Nonce header is absent, the response
│                   cannot be authenticated. Treat as unverified. Reject.
```

**What teep must verify (enforcement checklist):**

1. Extract TLS public key fingerprint from `report_data.tls_key_fp` of the
   verified attestation response (authenticated by REPORTDATA[0:32] hash).
   → `tls_key_binding`
2. On every TLS connection to the enclave, compute SHA-256 of the server's
   PKIX-encoded public key and constant-time compare against the attested
   fingerprint. Mismatch → re-attest → mismatch again → block.
   → `tls_key_binding`
3. Extract HPKE public key from response `report_data.hpke_key` (verified via
   REPORTDATA[0:32] hash). → `e2ee_capable`
4. Use **only** this attested HPKE key for EHBP encryption. Never accept a
   key from any other source. The cipher suite is fixed:
   X25519_HKDF_SHA256 / HKDF_SHA256 / AES_256_GCM. → `e2ee_capable`
5. Encrypt every request body via EHBP before sending. No plaintext POST
   requests. → `e2ee_usable`
6. Require `Ehbp-Response-Nonce` header on every response. If absent, fail
   closed. → `e2ee_usable`
7. Decrypt and AEAD-verify every response chunk. On any auth failure, abort
   the response. → `e2ee_usable`

### Authentication Chain 3: Enclave Chaining (Router → Model)

Tinfoil uses a confidential model router that forwards requests to
per-model inference enclaves. Each hop is independently attested and
encrypted.

```
Client (teep proxy)
  │
  │  1. Verify router attestation (Sigstore + hardware quote)
  │  2. TLS-bind to router's attested TLS key
  │  3. EHBP-encrypt request to router's attested HPKE key
  │
  ▼
Model Router Enclave (tinfoilsh/confidential-model-router)
  │
  │  4. Router verifies target model enclave's attestation
  │  5. Router TLS-binds to model enclave's attested TLS key
  │  6. Router EHBP-encrypts forwarded request to model enclave
  │
  ▼
Model Inference Enclave (e.g. tinfoilsh/confidential-nomic-embed-text)
  │
  │  7. Model enclave decrypts request
  │  8. Inference runs on dm-verity-attested model weights
  │  9. Response EHBP-encrypted back through chain
  │
  ▼
Client receives AEAD-authenticated response
```

**Implication for teep:** Teep verifies the **router** enclave only. The
router performs the second-hop verification internally, using the same
Sigstore + hardware attestation + TLS binding logic. This is documented by
Tinfoil at https://docs.tinfoil.sh/verification/verification-in-tinfoil
(section "Chaining enclaves"). Teep trusts the router's code to do this
correctly, which is justified because the router code itself is verified via
Sigstore supply chain attestation.

The router's Sigstore bundle attests the code that performs second-hop
verification. If the router code were modified to skip model enclave
verification, the code measurement would change and the Sigstore comparison
would fail. This makes the chain self-enforcing: teep verifies the router,
and the verified router code verifies the models.

### Authentication Chain 4: Model Weight Integrity

Unlike dstack providers where model weights are downloaded at runtime and
not covered by attestation, Tinfoil binds model weights into the attestation
chain through a combination of dm-verity and configuration pinning.

```
Sigstore Transparency Log
  │
  │  Contains: pri-build-action output with expected measurements
  │  Including: hash of tinfoil-config.yml
  │
  ▼
tinfoil-config.yml (committed to GitHub)
  │
  │  Contains: modelwrap dm-verity root hash for each model volume
  │  Contains: container image digests
  │  Contains: CVM version, resource allocation
  │  SHA-256 hash embedded in kernel command line
  │
  ▼
Kernel command line → measured into RTMR2 (TDX) / launch measurement (SEV-SNP)
  │
  │  At boot: CVM verifies config on disk matches attested hash
  │  Mismatch → boot aborts
  │
  ▼
dm-verity volume mount
  │
  │  Model weight volume mounted read-only
  │  dm-verity Merkle tree root hash from tinfoil-config.yml
  │  Every block read validated by kernel dm-verity subsystem
  │  Tampered block → I/O error → inference fails
  │
  ▼
vLLM loads model from verified volume
  │
  │  Volume is read-only; no runtime download possible
  │  All .safetensors shards validated block-by-block
  │
  ▼
Inference output from attested model weights
```

**What teep must verify (enforcement checklist):**

Teep does not directly verify dm-verity — that happens inside the CVM kernel.
Teep's role is to verify the chain that makes dm-verity trustworthy:

1. Verify the Sigstore bundle for the deployment repo (contains the
   measurements derived from the tinfoil-config.yml). → `sigstore_code_verified`
2. Compare attestation register values against the Sigstore bundle to confirm
   the CVM booted with the attested config (which pins the model dm-verity
   hash). → `sigstore_code_verified`
3. The `measured_model_weights` factor should be set to `Pass` for Tinfoil
   when `sigstore_code_verified` passes, because the Sigstore chain
   transitively authenticates the model weights via config.yml → dm-verity.
   Detail string should explain the transitive chain.

### Authentication Chain 5: GPU Attestation and CPU-GPU Binding

Tinfoil uses NVIDIA GPUs (Hopper H100/H200, Blackwell) with NVIDIA
Confidential Computing. GPU attestation uses Option 2 from
`docs/attestation_gaps/gpu_cpu_binding.md`: GPU evidence hash in TDX/SEV-SNP
REPORTDATA.

#### What Tinfoil Implements

**Boot-time GPU attestation (fail-closed):**
- At CVM boot, the `nvattest` tool performs local NVIDIA GPU attestation
  (`nvattest attest --device gpu --verifier local`).
- SPDM reports are collected from each GPU and validated locally.
- For 8-GPU HGX Hopper systems: NVSwitch attestation and full PCIe topology
   validation (8 GPUs + 4 NVSwitches mesh integrity) are enforced.
- For 8-GPU HGX Blackwell systems (B200/B300): in-guest NVSwitch evidence is
   not exposed under Blackwell MPT, so NVSwitch collection is skipped by design.
- If GPU attestation fails, the CVM sets GPU ready state to
  `ACCEPTING_CLIENT_REQUESTS_FALSE` and boot aborts. **No enclave starts
  without passing GPU attestation.**

**Runtime GPU evidence collection:**
- The attestation endpoint (`/.well-known/tinfoil-attestation?nonce=<hex>`)
   collects fresh SPDM evidence from all GPUs and collects NVSwitch evidence
   only when topology/architecture requires it.
- Evidence is collected via NVML APIs (`GetConfComputeGpuAttestationReport`)
  with the client-supplied nonce passed through to the GPU.
- GPU evidence is returned in the attestation response as `gpu` and
   optionally `nvswitch` JSON fields alongside the CPU report.

**GPU evidence hash in REPORTDATA:**
- REPORTDATA is computed as:
  ```
  REPORTDATA[0:32] = SHA-256(tls_key_fp || hpke_key || nonce || gpu_evidence_hash || nvswitch_evidence_hash)
  REPORTDATA[32:64] = zeros
  ```
  Where `gpu_evidence_hash = SHA-256(gpu_evidence_json)` and
  `nvswitch_evidence_hash = SHA-256(nvswitch_evidence_json)`.
- This cryptographically binds GPU evidence to the TDX/SEV-SNP CPU quote.
  The CPU hardware signs REPORTDATA, so the GPU evidence hash is
  hardware-authenticated.

**This implements Option 2 from gpu_cpu_binding.md** (GPU evidence hash in
TDX REPORTDATA). Tinfoil also extends it to include NVSwitch evidence.

#### Router vs. Model Enclaves

The Tinfoil confidential model router (`inference.tinfoil.sh`) handles all
model routing. Teep verifies the **router** enclave. The router verifies
model enclaves internally (see Authentication Chain 3). If the router reports
no GPUs (e.g., SEV-SNP router without GPUs), GPU evidence in REPORTDATA will
reflect the router's GPU state; `nvswitch_expected` normalization must still
apply, and absent GPU evidence must fail closed.

#### Gap Analysis: GPU CPU Binding (gpu_cpu_binding.md)

| Issue from gpu_cpu_binding.md | Tinfoil |
|---|---|
| **Gap 1: TEE.fail** | **Unmitigated** |
| **Gap 2: CPU-to-GPU binding** | **Pass** (GPU evidence hash in REPORTDATA) |
| **GPU nonce freshness** | **Yes** (nonce passed through to GPU SPDM) |
| **GPU topology validation** | Boot-time + NVSwitch evidence in response |
| **vTPM / DCEA (Option 3)** | Not implemented |
| **TDX Connect / TDISP (Option 5)** | Not implemented |
| **Proof of Cloud (Option 1)** | Not implemented |
#### TEE.fail Implications for Tinfoil

Tinfoil's security posture against TEE.fail is identical to other providers
(NearAI, dstack): **no specific mitigation exists**. If an attacker extracts
attestation signing keys via DDR5 memory bus interposition (applicable to
both TDX and SEV-SNP):

1. The attacker can forge quotes with arbitrary REPORTDATA, including
   fabricated TLS key fingerprints and HPKE keys.
2. The attacker can forge measurement registers (MRTD, RTMRs) that match the
   Sigstore-expected values.
3. The Sigstore supply chain verification would pass (it only checks that
   measurements match — it cannot detect that the quote was forged).
4. E2EE would be defeated: the attacker's fabricated HPKE key would be
   accepted as the enclave's key.
5. The GPU evidence relay attack applies: an attacker with extracted keys can
   relay real GPU evidence from the legitimate machine while fabricating the
   CPU quote to bind their own keys. The GPU hash in REPORTDATA provides no
   defense when the attacker controls REPORTDATA (via TEE.fail).

**Tinfoil-specific nuance**: Tinfoil's hermetically built CVM image is
stronger than dstack in one respect — if an attacker forges a quote, they
must also provide a complete Tinfoil CVM environment (or intercept
connections), which is harder than with dstack where the attacker could run
arbitrary code. However, this is defense-in-obscurity, not a cryptographic
mitigation.

**What teep should do:**
1. `cpu_id_registry`: Reserve this factor for **Proof of Cloud CPU identity
   registration** checks (proofofcloud.org), which can cover both TDX and
   SEV-SNP platform identity registration. Do not reuse this factor for
   MRTD/RTMR or launch-measurement comparisons; those are covered by
   `tee_boot_config` / `sigstore_code_verified` and related report details.
   Since Tinfoil currently has no Proof of Cloud participation, keep
   `cpu_id_registry` in default `allow_fail` until Proof-of-Cloud-backed
   identity registration is implemented.
2. Apply the same TEE.fail residual risk assessment as for other providers.
3. When DCEA/vTPM support becomes available, add verification support.
4. `cpu_gpu_chain`: `Pass` only when GPU evidence is present and its hash is
   verified in REPORTDATA (missing GPU evidence = `Fail`).
5. `nvidia_gpu_attestation`: `Pass` only when GPU SPDM evidence is present
   and verifies per GPU (missing GPU evidence = `Fail`).
6. NVSwitch evidence is topology-conditional: if GPU evidence indicates an
   NVSwitch-backed topology (for example 8-GPU HGX Hopper / mesh fabric),
   `nvswitch` evidence and `report_data.nvswitch_evidence_hash` are required;
   8-GPU Blackwell (B200/B300) may legitimately omit NVSwitch evidence under
   MPT; if required evidence is missing or mismatched, both `cpu_gpu_chain` and
   `nvidia_gpu_attestation` must be `Fail`.

#### REPORTDATA Verification

1. Extract `tls_key_fp` and `hpke_key` from the response `report_data`
   field (not from REPORTDATA bytes directly).
2. Recompute `gpu_evidence_hash = SHA-256(raw_gpu_json)` from the `gpu` field
   in the attestation response. **Important**: The hash must be computed over
   the exact bytes received in the HTTP response, not a parsed-and-reserialized
   JSON object. Different JSON libraries produce different byte sequences for
   identical data (key ordering, whitespace). The implementation must extract
   the `gpu` field as a `json.RawMessage` and hash those raw bytes directly
   (i.e., `sha256.Sum256([]byte(rawGPUMessage))`) without re-encoding.
3. Recompute `nvswitch_evidence_hash = SHA-256(raw_nvswitch_json)` from the
   `nvswitch` field (if present; omitted from hash input when absent). Same raw-byte
   requirement as the GPU evidence hash above.
4. Enforce field/hash consistency:
    - `gpu` evidence is REQUIRED. If `gpu` is absent or empty, fail closed
       and set both `cpu_gpu_chain` and `nvidia_gpu_attestation` to `Fail`.
    - If `gpu` is present, `report_data.gpu_evidence_hash` must be present and
       equal the recomputed hash.
    - Determine `nvswitch_expected` using this deterministic normalization
      algorithm (in order):
      1. Parse `gpu` as JSON object and require `gpu.evidences` array.
      2. Set `gpu_count = len(gpu.evidences)`.
      3. If `nvswitch` field is present and parses to JSON object with
         non-empty `nvswitch.evidences`, set `nvswitch_expected = true`.
      4. Else inspect `gpu.evidences[*].arch` values (raw evidence metadata).
      5. If `gpu_count == 8` and any arch is `HOPPER`, set
         `nvswitch_expected = true`.
      6. Else set `nvswitch_expected = false` (including Blackwell B200/B300
         and unknown arches).
      7. If required fields for this derivation are malformed, missing, or
         ambiguous (for example `gpu` present but `gpu.evidences` missing),
         fail closed and set both `cpu_gpu_chain` and
         `nvidia_gpu_attestation` to `Fail`.
    - If `nvswitch_expected` is true, `nvswitch` evidence is REQUIRED and
       `report_data.nvswitch_evidence_hash` must be present and equal the
       recomputed hash; missing/mismatch is a fail-closed error and sets both
       `cpu_gpu_chain` and `nvidia_gpu_attestation` to `Fail`.
    - If `nvswitch_expected` is false (for example single-GPU systems or
       8-GPU Blackwell MPT systems),
       `nvswitch` may be absent.
    This prevents downgrade/omission ambiguity for GPU evidence.
5. Recompute the expected REPORTDATA:
   ```
   expected[0:32] = SHA-256(tls_key_fp || hpke_key || nonce || gpu_evidence_hash || nvswitch_evidence_hash)
   expected[32:64] = zeros
   ```
   Where `nvswitch_evidence_hash` contributes zero bytes (empty concatenation)
   when `nvswitch` is absent.
6. Constant-time compare against the CPU quote's actual REPORTDATA.
7. Verify each GPU evidence SPDM report (nonce matches client nonce,
   certificate chain validates against NVIDIA root).
8. If `nvswitch_expected` is true, verify NVSwitch evidence and fail closed
   on missing/invalid evidence. If `nvswitch_expected` is false, NVSwitch
   verification is not required.

This gives the `tinfoil` provider three properties:
- **GPU attestation binding**: GPU evidence is hardware-authenticated via CPU quote.
- **Client nonce freshness**: Nonce in REPORTDATA proves attestation is fresh.
- **NVSwitch topology**: NVSwitch evidence validates the GPU interconnect.

### Attestation Freshness

The `tinfoil` provider uses client-supplied nonces:

1. Client generates a random 32-byte nonce and appends `?nonce=<64hex>` to the
   attestation URL. The nonce is required — if omitted, the server may return
   a legacy format response; the attester MUST reject any response without a
   `report_data` structured field.
2. The nonce is included in the REPORTDATA hash, providing cryptographic
   freshness.
3. The nonce is also passed through to GPU SPDM reports for GPU freshness.

**What teep must enforce:**

- Always generate a random 32-byte nonce per attestation request (fail if empty).
- Include nonce as `?nonce=<64hex>` in the attestation URL.
- Reject any response that lacks the `report_data` structured field.
- Verify `report_data.nonce` equals the client nonce (constant-time compare).
- Verify the nonce is in the REPORTDATA hash (see REPORTDATA Verification above).
- The `nonce_in_reportdata` factor is `enforced`.
- On SPKI cache miss (new TLS certificate seen), trigger full re-attestation
  with a fresh nonce. The `VerifyPeerCertificate` callback computes the TLS
  fingerprint on every connection and compares it against `report_data.tls_key_fp`.

---

## Protocol Descriptions

### Tinfoil Attestation Protocol

#### Attestation Document Format

The enclave serves its attestation at
`GET /.well-known/tinfoil-attestation?nonce=<64hex>`.

The nonce parameter is **required** (32 bytes encoded as 64 lowercase hex
chars). Omitting the nonce may result in a legacy format response; the
attester must reject any response that lacks the `report_data` structured
field.

**Response format:**

```json
{
   "format": "https://tinfoil.sh/predicate/attestation/v3",
   "report_data": {
      "tls_key_fp": "<64 hex>",
      "hpke_key": "<64 hex>",
      "nonce": "<64 hex>",
      "gpu_evidence_hash": "<64 hex>",
      "nvswitch_evidence_hash": "<64 hex, conditional (required only when nvswitch_expected is true; omitted otherwise)>"
   },
   "cpu": {
      "platform": "tdx|sev-snp",
      "report": "<base64 raw hardware report>"
   },
   "gpu": {
      "evidences": [
         "<gpu spdm evidence item>"
      ]
   },
   "nvswitch": {
      "evidences": [
         "<nvswitch evidence item>"
      ]
   },
   "certificate": "<PEM leaf certificate>",
   "signature": "<base64 ECDSA ASN.1 signature>"
}
```

**Format values**:
- Envelope format URI: `https://tinfoil.sh/predicate/attestation/v3`.
- Hardware platform type: taken from `cpu.platform` (`tdx` or `sev-snp`).
  Do not infer CPU platform from `format`.

#### CPU Report

Base64-decode `cpu.report`. Bound the decoded size (10 MiB max) to prevent
oversized attestation payload abuse. The result is a raw binary attestation
report:
- For TDX (`cpu.platform == "tdx"`): a TDX QuoteV4 structure (min 1020 bytes).
- For SEV-SNP (`cpu.platform == "sev-snp"`): an SEV attestation report (1184 bytes).

#### REPORTDATA Layout (64 bytes)

Both TDX and SEV-SNP reports contain a 64-byte `report_data` field.

| Offset | Size | Content |
|---|---|---|
| 0–31 | 32 bytes | SHA-256(tls_key_fp \|\| hpke_key \|\| nonce \|\| gpu_evidence_hash \|\| nvswitch_evidence_hash) |
| 32–63 | 32 bytes | All zeros |

The HPKE key is in the response `report_data.hpke_key` JSON field,
authenticated by being part of the REPORTDATA[0:32] hash. When `nvswitch` is
absent, the REPORTDATA hash input omits `nvswitch_evidence_hash` bytes entirely
(empty concatenation).

#### Envelope Integrity Verification

In addition to REPORTDATA verification, the envelope must be validated as
follows:

1. Parse the full envelope with `internal/jsonstrict` and reject unknown
   fields fail-closed before any trust decisions.
2. Require `format` equals exactly `https://tinfoil.sh/predicate/attestation/v3`.
   Reject any response with a `body` field (legacy format indicator).
3. Parse and validate `report_data.tls_key_fp`, `report_data.hpke_key`,
   `report_data.nonce`, and optional hash fields as hex strings that decode
   to exactly 32 bytes (64 hex chars).
4. Verify `report_data.nonce` equals the client nonce used in
   `?nonce=<hex>` (constant-time compare on decoded bytes).
5. Parse `certificate` as PEM and extract the leaf public key.
6. Verify leaf public key fingerprint equals `report_data.tls_key_fp`
   (constant-time). This binds the envelope signer key to REPORTDATA.
7. Verify attestation-envelope key/channel consistency:
   - Extract the live TLS peer leaf public key from the HTTPS connection used
     to fetch attestation.
   - Constant-time compare its SPKI fingerprint to `report_data.tls_key_fp`.
   - Fail closed on mismatch.
8. Validate envelope cross-field consistency before signature checks:
    - `gpu` field is REQUIRED. If absent/empty, fail closed and mark
       GPU-related factors `Fail`.
    - If `gpu` field is present, `report_data.gpu_evidence_hash` must be
       present and equal `SHA-256(raw_gpu_json)`.
    - Determine `nvswitch_expected` with the normalization algorithm defined
      in "REPORTDATA Verification" above.
    - If `nvswitch_expected` is true, `nvswitch` field and
       `report_data.nvswitch_evidence_hash` are required and must match.
    - If `nvswitch_expected` is false (including Blackwell B200/B300 MPT
       systems), `nvswitch` may be absent.
9. Verify `signature` using ECDSA ASN.1 over SHA-256 of the JSON payload
   produced from the parsed envelope with the `signature` field set to empty
   string (`""`), using the implementation's deterministic serializer
   (for Go, `encoding/json` marshaling of the typed struct).
   - Reject non-ecdsa leaf public keys.
   - Decode `signature` from base64 and verify DER ASN.1 form.
   - Signature verification input must be derived from typed fields, not raw
     map iteration order, to avoid parser-dependent ambiguity.
10. If envelope signature verification fails, fail closed before any CPU/GPU
   evidence trust decisions.

Rationale: REPORTDATA hash authenticates key fields via CPU hardware
signature; envelope signature adds tamper evidence for the full structured
payload and avoids ambiguous parsing attacks.

### TDX Verification (Reuse Existing)

For TDX-format attestation (`cpu.platform == "tdx"`), hex-encode the decoded
binary `cpu.report` and call the
existing `attestation.VerifyTDXQuoteOffline()` / `attestation.VerifyTDXQuoteOnline()` (via
the `attestation.TDXVerifier` function type). Extract measurements:

- Register 0: MRTD (48 bytes hex)
- Register 1: RTMR0 (48 bytes hex)
- Register 2: RTMR1 (48 bytes hex)
- Register 3: RTMR2 (48 bytes hex)
- Register 4: RTMR3 (48 bytes hex) — must be all zeros

Additionally, preserve QE report-data binding verification in the quote
verification pipeline (do not accept quote-verification implementations that
skip this check).

#### TDX Additional Policy Checks (Tinfoil-Specific)

After the standard TDX quote verification, apply these additional checks:

1. **TD Attributes**: Must equal `0x0000001000000000` (SEPT_VE_DISABLE=1).
2. **XFAM**: Must equal `0xe702060000000000`.
3. **Minimum TEE TCB SVN**: Must be >= `0x03010200000000000000000000000000`.
4. **MR_SEAM**: Must be in the accepted firmware whitelist (see Measurement
   Policy section).
5. **MR_CONFIG_ID, MR_OWNER, MR_OWNER_CONFIG**: Must be all zeros.
6. **RTMR3**: Must be all zeros (96 hex chars of '0').

### SEV-SNP Verification (New)

For SEV-SNP-format attestation:

1. Parse the binary as an AMD SEV-SNP attestation report.
2. Fetch the VCEK certificate from AMD KDS (or cache). The AMD KDS can be
   accessed via the proxy at `kds-proxy.tinfoil.sh` or directly from AMD.
3. Verify the report signature against the VCEK cert chain (AMD Genoa root).
4. Validate guest policy:
   - SMT: true
   - Debug: false
   - SingleSocket: false
   - MinimumBuild: 21
   - MinimumVersion: 1.55
5. Validate TCB:
   - BlSpl >= 0x07
   - TeeSpl >= 0x00
   - SnpSpl >= 0x0e
   - UcodeSpl >= 0x48
6. Extract measurement: `report.Measurement` (single 48-byte hex register).

The SEV-SNP verification is new code — teep only verifies TDX quotes via
`attestation.VerifyTDXQuoteOffline()` / `attestation.VerifyTDXQuoteOnline()`. However,
go-sev-guest (google/go-sev-guest) provides the verification primitives,
similar to how go-tdx-guest is used for TDX.

### Supply Chain Verification (Sigstore)

Tinfoil's supply chain verification uses GitHub Actions build attestations
verified through Sigstore.

#### Step 1: Fetch Code Image Digest

For a given configuration repo (e.g. `tinfoilsh/confidential-model-router`):

```
GET https://github-proxy.tinfoil.sh/repos/{repo}/releases/latest
```

Parse `tag_name` from the response. Then fetch the digest:

```
GET https://github-proxy.tinfoil.sh/repos/{repo}/releases/download/{tag}/tinfoil.hash
```

Returns a plain-text SHA-256 hex digest.

#### Step 2: Fetch Sigstore DSSE Bundle

```
GET https://github-proxy.tinfoil.sh/repos/{repo}/attestations/sha256:{digest}
```

Returns JSON with `attestations[0].bundle` containing a Sigstore DSSE
envelope.

#### Step 3: Verify Bundle

Verify the DSSE bundle using Sigstore's verification library:

- **OIDC issuer**: `https://token.actions.githubusercontent.com`
- **Workflow identity**: enforce both repository and tag-ref binding. The
   certificate identity must match the exact repository under verification and
   a tagged workflow ref (no branch refs, no pull-request refs). Use an anchored
   regex built from `regexp.QuoteMeta(repo)`, for example:
   `^https://github.com/<repo>/\.github/workflows/[^@]+@refs/tags/[^/]+$`.
   If Tinfoil publishes workflow-path allowlists per repo, pin to those exact
   workflow files instead of wildcard matching.
- **Artifact digest**: Must match the `sha256:{digest}` from Step 1.
- **Require**: At least 1 signed certificate timestamp, 1 transparency log
  entry, 1 observer timestamp.

#### Step 4: Extract Code Measurements

The verified DSSE bundle contains an in-toto statement with a predicate. The
predicate type determines the measurement format:

- **`https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1`**: Three registers:
  - Register 0: `snp_measurement` (SEV-SNP launch measurement)
  - Register 1: `tdx_measurement.rtmr1` (TDX RTMR1)
  - Register 2: `tdx_measurement.rtmr2` (TDX RTMR2)

#### Step 5: Compare Code vs. Enclave Measurements

Cross-platform comparison logic:

**Multi-platform code vs. TDX enclave:**
- Compare code register 1 (RTMR1) == enclave register 2 (RTMR1).
- Compare code register 2 (RTMR2) == enclave register 3 (RTMR2).
- Verify enclave register 4 (RTMR3) is all zeros.

**Multi-platform code vs. SEV-SNP enclave:**
- Compare code register 0 (snp_measurement) == enclave register 0 (measurement).

All comparisons MUST be constant-time (`subtle.ConstantTimeCompare`).

### Hardware Measurement Verification (TDX Only)

For TDX enclaves, verify that the hardware platform (MRTD, RTMR0) matches a
known trusted platform:

1. Fetch latest hardware measurements from
   `tinfoilsh/hardware-measurements` repo via GitHub Releases + Sigstore
   (same flow as code measurements above).
2. The predicate type is
   `https://tinfoil.sh/predicate/hardware-measurements/v1`.
3. Each entry has: `id` (platform identifier), `mrtd`, `rtmr0`.
4. Match the enclave's MRTD (register 0) and RTMR0 (register 1) against the
   hardware measurement entries.
5. If no match is found, the hardware platform is unknown — record as a
   verification factor failure.

### TLS Certificate Fingerprint Verification

After attestation verification:

1. Extract the TLS fingerprint from `report_data.tls_key_fp` (authenticated
   by REPORTDATA[0:32] hash).
2. The proxy already has the upstream TLS certificate (from the HTTP
   connection).
3. Compute SHA-256 of the certificate's PKIX-encoded public key.
4. Constant-time compare the computed fingerprint with the attested
   fingerprint.
5. On mismatch: fail closed.

This binding ensures the TLS connection terminates inside the attested enclave.

### TLS-Fingerprint-Bound Transport

Tinfoil does not use a PinnedHandler (no in-band attestation on inference
connections). Instead, the proxy creates a **fingerprint-bound
`http.Transport`** that enforces the attested TLS identity on every
connection to the enclave.

Implementation pattern (similar to Tinfoil SDK's `TLSBoundRoundTripper`):

1. After attestation, extract the TLS SPKI fingerprint from
   `report_data.tls_key_fp` (verified via REPORTDATA[0:32] hash).
2. Create a custom `http.Transport` with a `VerifyPeerCertificate` callback:
   - Compute SHA-256 of the peer's PKIX-encoded public key.
   - Constant-time compare against the attested fingerprint.
   - On mismatch: return error (connection refused).
3. Set `DisableKeepAlives: false` — reuse TLS connections to the same
   enclave while the attestation is fresh.
4. Set `Connection: close` only when re-attestation is needed (attestation
   boundary).

**Re-attestation trigger**: When the SPKI cache entry expires or a TLS
handshake presents a new certificate fingerprint, the transport triggers
re-attestation before allowing any request through. On re-attestation:

1. Close existing connections (`Transport.CloseIdleConnections()`).
2. Generate a new client nonce (32 bytes from `crypto/rand`).
3. Fetch fresh attestation from `/.well-known/tinfoil-attestation?nonce=<hex>`.
4. Verify the new attestation (full pipeline: TDX/SEV-SNP + supply chain).
5. Update the fingerprint in the transport's `VerifyPeerCertificate` callback.
6. Verify the HPKE key in the new `report_data` for E2EE continuity.

This approach avoids the overhead of per-request attestation while maintaining
the invariant that every byte transits a connection verified against an
attested enclave.

### E2EE: Encrypted HTTP Body Protocol (EHBP)

EHBP is documented at https://docs.tinfoil.sh/resources/ehbp and specified at
https://github.com/tinfoilsh/encrypted-http-body-protocol/blob/main/SPEC.md

The protocol encrypts entire HTTP request and response bodies using HPKE
(RFC 9180) while leaving headers in cleartext for routing.

Key discovery/source in teep integration:
- The encryption key is the attested HPKE key from the V3 envelope hash chain
   (`report_data.hpke_key`, authenticated by REPORTDATA[0:32] hash), not an
   unauthenticated key-discovery endpoint.

Compatibility rule: for Tinfoil, apply EHBP behavior consistently across
`/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`,
`/v1/audio/transcriptions`, `/v1/audio/speech`, and any additional
non-empty-body `/v1/audio/*` request.

**Mode rule (mandatory)**:
- If request body is non-empty: request MUST be EHBP-encrypted, must include
   `Ehbp-Encapsulated-Key`, and encrypted response MUST include
   `Ehbp-Response-Nonce`.
- If request is bodyless by method/endpoint contract (for example
   GET/HEAD/DELETE/OPTIONS such as `/v1/models`): request is plaintext,
   response is plaintext, and EHBP headers MUST be absent.
- Empty-body POST/PUT/PATCH requests are not a plaintext fallback path. If an
   endpoint expects a request body, an empty body MUST be rejected fail-closed.
- Never downgrade an encrypted exchange to plaintext on missing/invalid EHBP
   headers; fail closed.

#### HPKE Parameters

| Parameter | Value |
|---|---|
| KEM | X25519_HKDF_SHA256 (0x0020) |
| KDF | HKDF_SHA256 (0x0001) |
| AEAD | AES_256_GCM (0x0002) |

#### Request Encryption

1. Use the HPKE public key from the verified attestation (extracted from
   `report_data.hpke_key`, verified via REPORTDATA[0:32] hash).
   The cipher suite is hardcoded:
   X25519_HKDF_SHA256 / HKDF_SHA256 / AES_256_GCM.
2. Establish an HPKE encryption context (`SetupBaseS`) using the server's
   public key and a fresh ephemeral keypair.
3. Encrypt the request body as a stream of length-prefixed chunks:
   - Each chunk: `[4-byte big-endian uint32 length] [AES-256-GCM ciphertext]`
   - Length counts ciphertext bytes only (not the 4-byte header).
   - AAD is empty. The HPKE sealer's internal nonce counter auto-increments.
   - Zero-length chunks may appear and should be skipped by receivers.
   - End of message is indicated by HTTP stream termination (no sentinel).
   - Enforce bounded chunk size in the decryptor (implementation limit) before
     allocating buffers; oversized chunk lengths are protocol errors.
4. Set request header `Ehbp-Encapsulated-Key` to the lowercase hex encoding
   of the HPKE encapsulated key (32 bytes → 64 hex chars for X25519).
5. Send encrypted bodies with unknown length (`Content-Length` unset/unknown).
   - HTTP/1.1: use chunked entity-body framing.
   - HTTP/2: rely on DATA frames with END_STREAM semantics (do not force
     `Transfer-Encoding: chunked`, which is HTTP/1.1-specific).
6. Preserve the original request `Content-Type` header exactly (including
   multipart boundary parameters) when forwarding encrypted requests. Do not
   overwrite `Content-Type` to `application/octet-stream` on paths where the
   upstream expects semantic media types.
7. Retain the HPKE sender context for response decryption.

#### Response Decryption

1. Read the `Ehbp-Response-Nonce` header (lowercase hex, 64 chars = 32 bytes).
   If absent, fail closed — do not treat the response as authenticated.
2. Derive response keys (following OHTTP / RFC 9458):
   ```
   secret = context.Export("ehbp response", 32)
   salt = concat(encapsulated_key, response_nonce)
   prk = HKDF-Extract(salt, secret)
   aead_key = HKDF-Expand(prk, "key", 32)    // AES-256 key
   aead_nonce = HKDF-Expand(prk, "nonce", 12) // GCM nonce
   ```
3. Decrypt response body chunks:
   - Same framing as request: `[4-byte length] [ciphertext]`.
   - Each chunk decrypted with AES-256-GCM using `aead_key`.
   - Nonce for chunk `i` (zero-indexed): `aead_nonce XOR i`.
   - AAD is empty.
   - Reject chunk lengths above implementation bounds before allocation.
4. On any decryption failure: fail closed, abort the response.

Response mode detection:
- If request body was encrypted, `Ehbp-Response-Nonce` is REQUIRED and the
   response body is encrypted.
- If request was bodyless by method/endpoint contract,
   `Ehbp-Response-Nonce` MUST be absent and the response body is plaintext.
- Any mismatch (encrypted request with missing/invalid nonce, or bodyless
   request with unexpected nonce) is a protocol failure; fail closed.

#### EHBP Header Validation

1. `Ehbp-Encapsulated-Key` must decode as exactly 32 bytes for X25519 KEM.
2. `Ehbp-Response-Nonce` must decode as exactly 32 bytes.
3. Invalid hex, wrong length, or unexpected header presence/absence is a
   protocol error and must fail closed.
4. Multiple instances of `Ehbp-Encapsulated-Key` or `Ehbp-Response-Nonce`
   headers in a single message are malformed input and must fail closed.
5. For encrypted requests where server returns plaintext error JSON without
   `Ehbp-Response-Nonce`, treat as unauthenticated diagnostic only and fail the
   request.
6. Recommended server-side error mapping (for compatibility with EHBP
    implementations):
    - `400 Bad Request`: malformed encapsulated key, framing, or AEAD failure
       attributable to request input.
    - `422 Unprocessable Entity`: key-configuration mismatch (for example,
       stale client key after rotation).
    - `500 Internal Server Error`: server-side failure not attributable to
       request cryptographic input.

#### API-Specific EHBP Handling Rules

1. `/v1/responses` follows the same EHBP behavior as `/v1/chat/completions`:
   full request-body encryption and full response-body authentication.
2. Multipart audio uploads (`/v1/audio/transcriptions` and other supported
   `/v1/audio/*` body-carrying requests) must be encrypted as opaque bytes;
   encryption layer must not parse or rewrite multipart structure.
3. For streaming endpoints (chat or responses), decrypt chunk stream before SSE
   parsing, and fail closed on any chunk authentication failure.
4. For bodyless GET `/v1/models`, do not send EHBP headers and do not expect
   EHBP response headers.

#### Bodyless Requests (GET /v1/models)

EHBP does not encrypt responses for bodyless requests (GET, HEAD, DELETE,
OPTIONS without a body). The `/v1/models` endpoint is a GET request, so it
transits in plaintext over the TLS connection pinned to the attested enclave.
This is acceptable because the models list is not user data.

#### Audio Transcription (Multipart)

For `/v1/audio/transcriptions`, the request body is `multipart/form-data`.
EHBP encrypts the entire multipart body as-is — the server middleware
decrypts it and reconstructs the multipart stream before passing to the
inference handler.

---

## Implementation Phases

### Phase 1: Attestation Document Parsing and Verification

**Goal**: Fetch and verify Tinfoil V3 attestation documents (TDX path only;
SEV-SNP deferred to Phase 3). Create the attester and REPORTDATA verifier.

**Note on phase ordering**: Phase 1 builds the provider plumbing, attester
interface, REPORTDATA verifier, and TDX policy checks — all of which can be
unit-tested with TDX fixtures. The deployed Tinfoil router currently runs
on SEV-SNP, so the provider cannot be validated against the live deployment
until Phase 3 (SEV-SNP verification) lands. Phase 1 is not independently
deployable against the live Tinfoil infrastructure.

**Files to create**:
- `internal/provider/tinfoil/tinfoil.go` — Shared types, constants, Preparer
- `internal/provider/tinfoil/attestation.go` — Attestation document parsing
  (V3 structured JSON, CPU report dispatch, TDX/SEV-SNP helpers)
- `internal/provider/tinfoil/attester.go` — `NewAttester`: V3 fetch (with
  nonce), structured JSON parsing, HPKE key from response field
- `internal/provider/tinfoil/reportdata.go` — `ReportDataVerifier`:
  SHA-256 hash recomputation, GPU evidence hash verification
- `internal/provider/tinfoil/policy.go` — TDX additional policy checks +
  MR_SEAM whitelist

**Implementation**:

1. **Shared types** (`tinfoil.go`):
   - Accepted envelope format URI: `https://tinfoil.sh/predicate/attestation/v3`.
   - CPU platform values: `tdx`, `sev-snp`.
   - Common `Preparer` (sets API key header).
   - Use existing `attestation.FormatTinfoil` backend format constant
     (defined in `internal/attestation/attestation.go`).

2. **Attestation parsing** (`attestation.go`):
   - `parseV3CPUReport(platform string, report []byte) (*attestation.RawAttestation, error)`
     — detect TDX vs SEV-SNP from `cpu.platform` (`tdx` or `sev-snp`),
     hex-encode binary, set `raw.IntelQuote` or SEV-SNP fields. Reject
     unknown platform values.
   - `parseV3Envelope(body []byte) (*V3Response, []byte, []byte, error)`
     — parse V3 JSON response (using `internal/jsonstrict`), return typed
     struct plus raw GPU and NVSwitch `json.RawMessage` bytes for hashing.
   - These are used by the attester and REPORTDATA verifier.

3. **Attester** (`attester.go`, `tinfoil.NewAttester(baseURL, apiKey, offline)`):
   - `FetchAttestation(ctx, model, nonce)` fetches
     `GET {baseURL}/.well-known/tinfoil-attestation?nonce=<hex>`
     (32 bytes → 64 hex chars). Nonce is required — fail if empty.
   - Parse the structured JSON response. Reject responses with a `body` field
     (legacy format indicator) or wrong `format` URI.
   - Base64-decode `cpu.report`, bound size to 10 MiB.
   - Dispatch CPU report parsing from `cpu.platform` and call the V3 CPU parser.
   - Extract `tls_key_fp` and `hpke_key` from `report_data` fields.
   - Verify `report_data.nonce` equals client nonce (constant-time).
   - Perform envelope signature verification (see Envelope Integrity
     Verification section).
   - Store GPU evidence raw JSON for REPORTDATA verification.
   - Store HPKE key via `raw.SigningKey` (hex-encoded).
   - Set `raw.BackendFormat = attestation.FormatTinfoil`.
   - Store the nonce in RawAttestation for report building.

4. **REPORTDATA Verifier** (`reportdata.go`, `tinfoil.ReportDataVerifier{}`):
   - `VerifyReportData(reportData [64]byte, raw, nonce)`:
     - Retrieve raw GPU JSON from raw attestation.
     - Retrieve raw NVSwitch JSON (may be empty) from raw attestation.
     - Recompute `gpu_evidence_hash = SHA-256(raw_gpu_json)`.
     - Determine `nvswitch_expected` using the normalization algorithm.
     - Compute `nvswitch_evidence_hash`:
       - If `nvswitch_expected` is true: `SHA-256(raw_nvswitch_json)`.
       - else if false: append zero bytes (empty concatenation) for this component.
     - Recompute `expected[0:32] = SHA-256(tls_fp || hpke_key || nonce || gpu_hash || nvswitch_hash)`.
     - Constant-time compare `expected[0:32]` against `reportData[0:32]`.
     - Verify `reportData[32:64]` is all zeros.
     - Fail closed on any mismatch.
     - Return detail string: `"v3: reportdata_hash verified, nonce_bound=true, gpu_bound=true"`.
   - The `nonce_in_reportdata` factor is `enforced`.

5. **Tinfoil TDX Policy** (`policy.go`, applies to TDX attestations):
   - After standard TDX verification, apply Tinfoil-specific policy:
     - Validate TD_ATTRIBUTES == `0x0000001000000000`.
     - Validate XFAM == `0xe702060000000000`.
     - Validate MR_SEAM is in the accepted set (from hardware-measurements registry).
     - Validate MR_CONFIG_ID, MR_OWNER, MR_OWNER_CONFIG are all zeros.
     - Validate RTMR3 is all zeros.
     - Validate TEE_TCB_SVN >= minimum.
   - Store results as `tee_hardware_config` factor details in the report.

6. **MR_SEAM Whitelist** (in `policy.go`):
   The Sigstore hardware-measurements registry (`tinfoilsh/hardware-measurements`)
   is the authoritative source for MR_SEAM values. The implementation must
   source MR_SEAM values from the verified hardware-measurements predicate. If
   the registry fetch fails or the predicate cannot be parsed, attestation
   verification must fail closed; there is no runtime fallback.

   The following values may be kept as test fixtures and for `--offline` mode
   only:
   ```
   TDX 2.0.08: 476a2997c62bccc78370913d0a80b956e3721b24272bc66c4d6307ced4be2865c40e26afac75f12df3425b03eb59ea7c
   TDX 1.5.16: 7bf063280e94fb051f5dd7b1fc59ce9aac42bb961df8d44b709c9b0ff87a7b4df648657ba6d1189589feab1d5a3c9a9d
   TDX 2.0.02: 685f891ea5c20e8fa27b151bf34bf3b50fbaf7143cc53662727cbdb167c0ad8385f1f6f3571539a91e104a1c96d75e04
   TDX 1.5.08: 49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6
   ```
   The `--offline` flag is an explicit user choice (not a connectivity
   fallback). When `--offline` is active, the MR_SEAM / `tee_hardware_config`
   factor must be marked as `Skip` with detail text indicating that
   registry-backed validation was not performed. It must never report `Pass`
   from the hardcoded list.

**Unit tests**:
- Test V3 document parsing with captured attestation response.
- Test attester rejects responses with `body` field (legacy format indicator).
- Test attester rejects wrong envelope format URI.
- Test attester rejects mismatched `report_data.nonce`.
- Test attester rejects invalid envelope signatures and cert/tls_key_fp mismatches.
- Test REPORTDATA verification: recompute SHA-256 hash, compare constant-time.
  Verify zeros in [32:64].
- Test GPU evidence hash computation (raw JSON bytes, not re-encoded).
- Test NVSwitch normalization: all branches (Hopper 8-GPU, Blackwell, single-GPU,
  malformed gpu.evidences).
- Test nonce required (empty nonce → error).
- Test TDX additional policy checks: valid, TD_ATTRIBUTES mismatch, XFAM
  mismatch, bad MR_SEAM, non-zero RTMR3.
- Test CPU report bounds check (oversized >10 MiB).
- Test format URI rejection (unknown URI, wrong platform value).
- Test MR_SEAM matching from verified hardware-measurements predicate.
- Test registry fetch/verification/parsing failure causes attestation rejection.
- Test `--offline` mode records MR_SEAM / `tee_hardware_config` as `Skip`,
  never `Pass`.

**Commit**: Phase 1 — Tinfoil attestation document parsing and TDX verification.

---

### Phase 2: Supply Chain Verification (Sigstore)

**Goal**: Verify Tinfoil code measurements via Sigstore DSSE bundles from
GitHub Releases.

**Files to create**:
- `internal/provider/tinfoil/sigstore.go` — Sigstore bundle fetching and
  verification
- `internal/provider/tinfoil/measurements.go` — Measurement comparison logic

**Implementation**:

1. **GitHub Release Fetcher**:
   - Fetch latest release tag from GitHub API (via `github-proxy.tinfoil.sh`
     or directly from `api.github.com`).
   - Fetch `tinfoil.hash` artifact from the release.
   - Fetch Sigstore attestation bundle from
     `repos/{repo}/attestations/sha256:{digest}`.

2. **Sigstore Bundle Verifier**:
   - Use the `sigstore-go` library to verify the DSSE bundle. This is a new
     dependency for Tinfoil bundle verification; teep's existing
     `internal/attestation/sigstore.go` and `internal/attestation/rekor.go`
     do not use `sigstore-go` and should only be referenced for reusable
     Rekor/Sigstore validation patterns. The `RekorClient` struct (with
     `NewRekorClient`, `NewRekorClientWithKey` constructors) manages Rekor
     interactions and public key validation without globals.
   - Certificate identity: OIDC issuer =
     `https://token.actions.githubusercontent.com`.
    - Workflow identity: enforce repository and tag-ref binding with an anchored
       pattern built from `regexp.QuoteMeta(repo)`, e.g.
       `^https://github.com/<repo>/\.github/workflows/[^@]+@refs/tags/[^/]+$`.
       Reject branch refs, pull-request refs, and repository mismatches.
   - Require SCT, transparency log entry, observer timestamp.
   - Extract the in-toto predicate after verification.

3. **Code Measurement Extraction**:
   - Parse predicateType from the verified statement.
   - For `https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1`:
     Extract `snp_measurement`, `tdx_measurement.rtmr1`,
     `tdx_measurement.rtmr2` as 3-register measurement.

4. **Hardware Measurement Fetcher** (TDX only):
   - Same GitHub + Sigstore flow, but for repo
     `tinfoilsh/hardware-measurements`.
   - Predicate type: `https://tinfoil.sh/predicate/hardware-measurements/v1`.
   - Extract list of `{id, mrtd, rtmr0}` entries.
   - Match enclave's MRTD (register 0) and RTMR0 (register 1) against entries.

5. **Measurement Comparison**:
   - Implement cross-platform comparison:
     - Multi-platform vs. TDX: compare RTMR1 and RTMR2; verify RTMR3 == 0.
     - Multi-platform vs. SEV-SNP: compare snp_measurement.
   - All comparisons constant-time.
   - Record code match as `sigstore_code_verified` factor.
   - Record hardware-measurement match as `tee_boot_config` detail (not `cpu_id_registry`).

6. **Configuration Repo Mapping**:
   - Per-model Sigstore repo (from Tinfoil's published docs):
     - Chat router: `tinfoilsh/confidential-model-router`
     - Embeddings: `tinfoilsh/confidential-nomic-embed-text`
     - Audio (whisper): `tinfoilsh/confidential-audio-processing`
     - Audio (voxtral): `tinfoilsh/confidential-voxtral-small-24b`
     - Vision (qwen3-vl): `tinfoilsh/confidential-qwen3-vl-30b`
     - TTS (qwen3-tts): `tinfoilsh/confidential-qwen3-tts` (inferred)
   - Store this mapping in config or as defaults. The router handles model
     routing, so the proxy may only need to verify the router's attestation
     (which covers all models routed through it). Verify this during
     integration testing.

**Unit tests**:
- Test Sigstore bundle verification with a captured bundle (testdata).
- Test measurement extraction for multi-platform predicate.
- Test cross-platform comparison: TDX match, TDX mismatch, SEV-SNP match.
- Test hardware measurement matching: found, not found.
- Test RTMR3 zero validation.

**Commit**: Phase 2 — Tinfoil supply chain verification via Sigstore.

---

### Phase 3: SEV-SNP Attestation Verification

**Goal**: Support Tinfoil enclaves running on AMD SEV-SNP.

**Files to create**:
- `internal/attestation/sev.go` — SEV-SNP report parsing and verification
- `internal/attestation/sev_test.go` — Unit tests
- `internal/attestation/certs/genoa_cert_chain.pem` — AMD Genoa ARK+ASK certs

**Implementation**:

1. **Add `google/go-sev-guest` dependency** (analogous to `go-tdx-guest` for
   TDX).

2. **Parse SEV-SNP Report**:
   - Use `abi.ReportToProto()` to parse the binary report.
   - Extract: `Measurement` (48 bytes), `ReportData` (64 bytes), TCB
     version, guest policy.

3. **Verify SEV-SNP Attestation**:
   - Fetch VCEK certificate from AMD KDS (cache with filesystem caching).
   - Verify report signature against VCEK chain rooted at AMD Genoa ARK.
   - Validate guest policy (SMT=true, Debug=false, etc.).
   - Validate TCB minimums (BlSpl=0x07, TeeSpl=0x00, SnpSpl=0x0e,
     UcodeSpl=0x48).

4. **Return `SEVVerifyResult`**: analogous to `TDXVerifyResult`, with
   measurement, REPORTDATA, parse error, signature error, policy error.

5. **Integration into Tinfoil Attester**:
   - Detect platform from `cpu.platform` field (`sev-snp` or `tdx`).
   - For SEV-SNP, call the new SEV verifier instead of TDX.

**Unit tests**:
- Test SEV-SNP report parsing with captured attestation (testdata).
- Test VCEK chain validation.
- Test policy validation: valid, debug=true rejection, low TCB rejection.
- Test REPORTDATA extraction.

**Commit**: Phase 3 — AMD SEV-SNP attestation verification.

---

### Phase 4: EHBP E2EE Implementation

**Goal**: Implement the Encrypted HTTP Body Protocol for full-body request
encryption and response decryption.

**Files to create**:
- `internal/e2ee/ehbp.go` — EHBP client transport (encrypt request, decrypt
  response)
- `internal/e2ee/ehbp_test.go` — Unit tests
- `internal/provider/tinfoil/e2ee.go` — Tinfoil RequestEncryptor

**Go dependency**: Use `github.com/cloudflare/circl/hpke` or the standard
`crypto/hpke` (available in Go 1.24+) for HPKE operations.

**Implementation**:

1. **EHBP Encryption** (`ehbp.go`):
   - `EncryptRequest(body io.Reader, serverPubKey [32]byte) (encBody io.ReadCloser, encapKey [32]byte, senderCtx, error)`:
     - Call HPKE `SetupBaseS` with X25519_HKDF_SHA256 / HKDF_SHA256 /
       AES_256_GCM and the server's public key.
     - Stream-encrypt the body into EHBP chunk framing; do not buffer entire
       multipart/audio payloads in memory.
     - Return an encrypted body reader, the encapsulated key, and the retained
       HPKE sender context for response decryption.

2. **EHBP Decryption** (`ehbp.go`):
   - `DecryptResponse(encBody io.Reader, responseNonce [32]byte, encapKey [32]byte, senderCtx) (io.ReadCloser, error)`:
     - Export secret: `secret = senderCtx.Export("ehbp response", 32)`.
     - Construct salt: `salt = encapKey || responseNonce`.
     - Derive PRK: `prk = HKDF-Extract(salt, secret)`.
     - Derive key: `aead_key = HKDF-Expand(prk, "key", 32)`.
     - Derive nonce: `aead_nonce = HKDF-Expand(prk, "nonce", 12)`.
     - Read chunks: `[4-byte len] [ciphertext]`.
     - Decrypt each chunk with AES-256-GCM:
       nonce = `aead_nonce XOR chunk_index`.
     - Reject oversized chunk lengths before allocation.
     - On any auth failure: fail closed, return error immediately.

3. **Streaming Response Decryption**:
   - `DecryptResponseStream(body io.Reader, nonce, encapKey, ctx) (io.Reader, error)`:
     - Wraps response body in a reader that decrypts chunks on-the-fly.
     - Used for SSE streaming responses.
     - Each read returns one decrypted chunk.

4. **Tinfoil RequestEncryptor** (`tinfoil/e2ee.go`):
   - Implements `provider.RequestEncryptor`.
   - `EncryptRequest(body, raw, endpointPath)`:
     - Extract HPKE public key from raw attestation (`raw.SigningKey`,
       already extracted by the V2 or V3 attester).
     - Call `ehbp.EncryptRequest(body, pubKey)`.
     - Return encrypted body bytes and a Decryptor for the response.
   - Return a `Decryptor` that reads `Ehbp-Response-Nonce` from the response
     headers and calls `ehbp.DecryptResponse`.

5. **Proxy Integration**:
   - The existing proxy E2EE flow calls `Encryptor.EncryptRequest()` and then
     uses the returned Decryptor. The EHBP encryptor follows this same pattern.
   - Set `Ehbp-Encapsulated-Key` header on the outgoing request.
   - Ensure encrypted requests have unknown content length (chunked transfer);
      never send encrypted body with fixed `Content-Length`.
   - On response: read `Ehbp-Response-Nonce` header, pass to Decryptor.
   - If `Ehbp-Response-Nonce` is missing: fail closed.
   - If `Ehbp-Response-Nonce` appears on a bodyless request path, fail closed
      (header presence mismatch).
   - For bodyless requests, do not attach EHBP headers and do not attempt
     decryption.

**Unit tests**:
- Test encryption round-trip: encrypt with a test key, decrypt with known
  private key.
- Test chunked framing: single chunk, multiple chunks, zero-length chunks.
- Test chunk length bounds: oversized length prefix is rejected fail-closed
   before allocation.
- Test response key derivation: verify against known test vectors (derive key
  from a known HPKE context and nonce, compare expected output).
- Test fail-closed: missing Ehbp-Response-Nonce, duplicate EHBP headers,
  unexpected Ehbp-Response-Nonce on bodyless requests, corrupted ciphertext.

**Commit**: Phase 4 — EHBP E2EE implementation.

---

### Phase 5: Provider Wiring and Configuration

**Goal**: Wire the `tinfoil` provider into the proxy, config, and endpoint
dispatch.

**Files to modify**:
- `internal/proxy/proxy.go` — Add `case "tinfoil"` to `fromConfig()`
- `internal/verify/factory.go` — Add `tinfoil` cases to `newAttester`,
  `newReportDataVerifier`, `supplyChainPolicy`, `e2eeEnabledByDefault`, and
  `chatPathForProvider`; add `"tinfoil": "TINFOIL_API_KEY"` to `ProviderEnvVars`
- `internal/config/config.go` — Add `TINFOIL_API_KEY` env resolution
- `teep.toml.example` — Add Tinfoil provider example
- `internal/defaults/defaults.go` — Add default allow-fail factors
- `docs/api_support.md` — Update endpoint and E2EE support matrices

**Implementation**:

1. **Config** (`config.go`):
   - Env var: `TINFOIL_API_KEY`.
   - Default base URL: `https://inference.tinfoil.sh`.
   - E2EE default: `true`.

2. **Provider Construction** (`proxy.go:fromConfig`):

   `fromConfig()` takes `cp`, `spkiCache`, `offline`, `allowFail`, `policy`,
   `gatewayPolicy`, `rekorClient`, `nvidiaVerifier`, and `getter`
   (Intel PCS collateral getter).

   ```go
   case "tinfoil":
       p.ChatPath = "/v1/chat/completions"
       p.ResponsesPath = "/v1/responses"
       p.EmbeddingsPath = "/v1/embeddings"
       p.AudioPath = "/v1/audio/transcriptions"
       p.SpeechPath = "/v1/audio/speech"
       p.Attester = tinfoil.NewAttester(cp.BaseURL, cp.APIKey, offline)
       p.Preparer = tinfoil.NewPreparer(cp.APIKey)
       p.ReportDataVerifier = tinfoil.ReportDataVerifier{}
       p.Encryptor = tinfoil.NewE2EE(cp.BaseURL, config.NewAttestationClient(offline))
       p.SupplyChainPolicy = nil // Sigstore-based, not compose-based
       p.ModelLister = provider.NewModelLister(cp.BaseURL, cp.APIKey, config.NewAttestationClient(offline))
   ```

3. **SPKI Caching**: Returns the base URL host for all models:
   ```go
   p.SPKIDomainForModel = func(_ context.Context, _ string) (string, bool) {
       return "inference.tinfoil.sh", true
   }
   ```

4. **TLS-Fingerprint-Bound Transport**: Create a `tinfoil.NewTransport()`
   that returns an `http.Transport` with `VerifyPeerCertificate` enforcing the
   attested SPKI fingerprint on every connection (see the TLS-Fingerprint-
   Bound Transport protocol section above). The `tlsct` package provides the
   `Conn` type (via `tlsct.Dial`) and `NewHTTPClient` for building TLS-aware
   transports. On fingerprint mismatch during inference, trigger
   re-attestation before retrying.

5. **Allow-Fail Defaults**: `attestation.TinfoilDefaultAllowFail`:
   - `cpu_id_registry` — `allow_fail` (Proof of Cloud identity-registry
     factor; Tinfoil currently has no PoC participation)

   > **Note on naturally-enforced factors**: All GPU and nonce factors are
   > `enforced` because the tinfoil provider supplies full GPU evidence and
   > request nonces. `sigstore_code_verified` is `enforced` — Tinfoil's core
   > security advantage is Sigstore-based code measurement; an attacker running
   > modified code in a valid enclave passes attestation if this factor is
   > `allow_fail`.

6. **Config example** (`teep.toml.example`):
   ```toml
   [providers.tinfoil]
   base_url = "https://inference.tinfoil.sh"
   api_key_env = "TINFOIL_API_KEY"
   e2ee = true
   ```

7. **Responses + TTS Endpoints**:
    - Add `/v1/responses` as a first-class endpoint (same security gates as
       `/v1/chat/completions`).
    - Add `/v1/audio/speech` if not already exposed.
    - Keep `/v1/realtime` and `/v1/convert/file` rejected fail-closed until
       explicit websocket/non-OpenAI compatibility design is implemented.

**Unit tests**:
- Test provider construction from config for `tinfoil` (verifies correct
  Attester and ReportDataVerifier types).
- Test `internal/verify/factory.go` switch cases: `newAttester`,
  `newReportDataVerifier`, `supplyChainPolicy`, `e2eeEnabledByDefault`, and
  `chatPathForProvider` return the correct types for the Tinfoil provider.
- Test SPKI domain resolution.
- Test that unknown Tinfoil config fields are rejected (strict TOML).

**Commit**: Phase 5 — Tinfoil provider wiring and configuration.

---

### Phase 6: Integration Tests

**Goal**: Full API-key-based integration tests for the `tinfoil` provider
against all Tinfoil endpoints.

**Files to create**:
- `internal/integration/tinfoil_test.go` — Tinfoil integration tests
- `internal/integration/testdata/tinfoil/` — Captured attestation fixtures

**Tests** (all require `TINFOIL_API_KEY`):

1. **Attestation Fetch and Verify**:
   - Fetch attestation from `inference.tinfoil.sh` using the attester.
   - Verify TDX or SEV-SNP quote.
   - Verify REPORTDATA binding (HPKE key + nonce + GPU hashes).
   - Log all verification results.

2. **Supply Chain Verification**:
   - Fetch code measurements from `tinfoilsh/confidential-model-router`.
   - Verify Sigstore bundle.
   - Compare against enclave measurements.

3. **TLS Fingerprint Binding**:
   - Fetch attestation, extract TLS fingerprint from `report_data.tls_key_fp`.
   - Connect to enclave, extract TLS certificate fingerprint.
   - Verify match.

4. **Client Nonce in Attestation**:
   - Generate random nonce, fetch attestation with `?nonce=<hex>`.
   - Verify nonce is in the REPORTDATA hash.
   - Verify `nonce_in_reportdata` factor is `Pass`.

5. **GPU Evidence Verification**:
   - Fetch attestation, extract GPU evidence from response.
   - Verify GPU evidence hash matches REPORTDATA binding.
   - Verify SPDM certificate chain validates against NVIDIA root.
   - Derive `nvswitch_expected` using the ordered normalization algorithm.
   - If `nvswitch_expected` is true, verify NVSwitch evidence is present and
     `nvswitch_evidence_hash` matches REPORTDATA binding; missing/malformed
     evidence must fail closed.
   - If normalization inputs are ambiguous/malformed, verify both
     `cpu_gpu_chain` and `nvidia_gpu_attestation` are `Fail`.
   - Verify `cpu_gpu_chain` factor is `Pass` only when all required checks pass.

6. **HPKE Key from Response Field**:
   - Verify HPKE key is extracted from `report_data.hpke_key` (not from
     REPORTDATA bytes directly).
   - Verify the HPKE key is authenticated by the REPORTDATA hash.
   - Use the key for E2EE and verify round-trip encryption works.

7. **Chat Completions (non-streaming)**:
   - Send a simple chat request through the proxy.
   - Verify response contains expected fields.
   - Verify request and response were EHBP encrypted/decrypted.

8. **Chat Completions (streaming)**:
   - Send a streaming chat request.
   - Verify SSE events are received and decrypted.

9. **Responses API (non-streaming and streaming)**:
   - Send `/v1/responses` requests for tool-free and tool-enabled flows.
   - Verify encrypted request body, authenticated response body, and expected
     output-item semantics in both non-streaming and streaming modes.

10. **Embeddings**:
    - Send an embedding request with model `nomic-embed-text`.
    - Verify response contains embedding vectors.
    - Verify E2EE.

11. **Audio Transcription**:
    - Send a multipart audio transcription request.
    - Verify response contains transcription text.
    - Verify E2EE (entire multipart body encrypted).

12. **TTS (text-to-speech)**:
    - Send a TTS request.
    - Verify response contains audio data.

13. **Models List**:
    - Send GET /v1/models.
    - Verify response contains expected model IDs.
    - Verify response is plaintext (EHBP does not encrypt GET responses).

14. **Vision (via chat completions)**:
    - Send a chat completion with image content array.
    - Verify response describes the image.

15. **Negative Tests**:
    - Verify that a request with a corrupted `Ehbp-Encapsulated-Key` is
      rejected by the server.
    - Verify that a response with a missing `Ehbp-Response-Nonce` is
      rejected by the proxy (fail-closed).
    - Verify `/v1/realtime` is rejected with an explicit unsupported error.
    - Verify `/v1/convert/file` is rejected with explicit unsupported error.
    - Verify that a response without `report_data` field (legacy format) is
      rejected fail-closed.
    - Verify that a wrong nonce in `report_data.nonce` causes attestation
      failure.

**Fixture Tests** (offline, no API key):
- Capture a real V3 attestation response and save as testdata.
- Test the full V3 verification pipeline against the fixture.
- Refresh V3 attestation fixtures periodically to detect schema/policy drift.

**Commit**: Phase 6 — Tinfoil integration tests.

---

### Phase 7: Verification Report and Documentation

**Goal**: Update verification report generation and documentation.

**Files to modify**:
- `internal/attestation/report.go` — Add Tinfoil-specific verification
  factors to `KnownFactors` and `BuildReport`
- `internal/verify/verify.go` — Update `FormatReport` if new factor display
  logic is needed
- `docs/api_support.md` — Add Tinfoil provider section
- `docs/measurement_allowlists.md` — Add Tinfoil MR_SEAM values

**Verification factor mapping** (reusing existing factors where possible):

Existing factors reused as-is:
- `tls_key_binding` — TLS fingerprint matches REPORTDATA[0:32]
- `e2ee_capable` — HPKE key extracted from attestation (subsumes key binding)
- `e2ee_usable` — Request encrypted and response authenticated via EHBP

Existing factors proposed for TEE-generic rename (`tdx_*` → `tee_*`):
- `tee_quote_present` (was `tdx_quote_present`) — Hardware quote fetched
- `tee_quote_structure` (was `tdx_quote_structure`) — Quote parses correctly
- `tee_hardware_config` (was `tdx_hardware_config`) — Platform-specific policy
  (TDX: attributes, XFAM, MR_SEAM, RTMR3; SEV-SNP: guest policy, TCB)
- `tee_boot_config` (was `tdx_boot_config`) — Boot measurements match expected
- `tee_tcb_current` (was `tdx_tcb_current`) — TCB SVN meets minimum
- `intel_pcs_collateral` — Remains Intel-specific (TDX only); AMD equivalent
  covered by VCEK chain validation within `tee_quote_structure`

New cross-provider factors:
- `sigstore_code_verified` — Code measurement verified via Sigstore DSSE bundle
- `cpu_id_registry` — Proof of Cloud CPU identity registration factor
   (proofofcloud.org), separate from register/measurement matching
   (reuses existing factor name)

Existing factors with provider-specific behavior:
- `measured_model_weights` — Set to `Pass` when `sigstore_code_verified`
  passes, because the Sigstore chain transitively authenticates model weights
  via tinfoil-config.yml → dm-verity. Detail: "model weights attested via
  dm-verity commitment in Sigstore-verified config"
- `nonce_in_reportdata` — `enforced`. Client nonce in REPORTDATA hash.
  Detail: "tinfoil: client nonce in REPORTDATA hash".

### Factor Status to Teep Policy Mapping

All factor status language in this plan maps directly to teep policy modes:

| Plan term | Teep config/policy mode | Runtime meaning |
|---|---|---|
| `enforced` | factor is NOT in `allow_fail` | Factor failure blocks request (fail-closed) |
| `allow_fail` | factor is in `allow_fail` | Factor failure is recorded but does not block by itself |
| `skip` | verifier emits `Skip` status | Factor is not applicable/unverifiable for that provider path; no pass claim is made |

Normalization rules for this document:
1. Use only `enforced`, `allow_fail`, or `skip` when describing factor policy.
2. Do not use `Advisory` or `Yes/No` for factor policy state.
3. `skip` is a verifier outcome status, not a config override; it means
    "not verifiable on this path" and must include explicit detail text.
4. `allow_fail` must always be justified in text (threat-model rationale).

**Documentation updates**:
- Add Tinfoil to the endpoint support matrix in `api_support.md`.
- Add Tinfoil E2EE details (EHBP, HPKE, full-body encryption).
- Document that Tinfoil has **no field-level encryption gaps** (full-body).
- Note `tinfoil` as the provider name.

**Commit**: Phase 7 — Verification report factors and documentation.

---

## Verification Factors Summary

### `tinfoil` Factors

| Factor | Teep Policy Mode | Description |
|---|---|---|
| `tee_quote_present` | `enforced` | Hardware quote fetched and non-empty |
| `tee_quote_structure` | `enforced` | Quote parses and signature verifies (TDX or SEV-SNP) |
| `tee_hardware_config` | `enforced` | Platform policy (TDX: attrs/XFAM/MR_SEAM/RTMR3; SEV-SNP: guest policy/TCB) |
| `tee_boot_config` | `enforced` | Boot measurements match expected (MRTD/RTMR0 or measurement) |
| `tee_tcb_current` | `enforced` | TCB SVN meets minimum threshold |
| `intel_pcs_collateral` | `enforced` (TDX only) | Intel collateral valid; N/A for SEV-SNP |
| `tls_key_binding` | `enforced` | TLS fingerprint matches `report_data.tls_key_fp` (authenticated via REPORTDATA hash) |
| `e2ee_capable` | `enforced` | HPKE key from `report_data.hpke_key`, authenticated via REPORTDATA hash |
| `e2ee_usable` | `enforced` | EHBP request encrypted + response AEAD-authenticated |
| `sigstore_code_verified` | `enforced` | Code measurement verified via Sigstore DSSE |
| `cpu_id_registry` | `allow_fail` (default) | Proof of Cloud CPU identity registration factor (applies to both TDX and SEV-SNP when available) |
| `measured_model_weights` | `enforced` (transitive) | Model weights attested via dm-verity + Sigstore chain |
| `nonce_in_reportdata` | `enforced` | Client nonce in REPORTDATA hash |
| `cpu_gpu_chain` | `enforced` | GPU evidence is required and its hash is verified in REPORTDATA; NVSwitch evidence/hash are also required when topology implies NVSwitch (missing required evidence = Fail) |
| `nvidia_gpu_attestation` | `enforced` | SPDM evidence is required and verified per GPU; NVSwitch evidence is required and verified when topology implies NVSwitch (missing required evidence = Fail) |

#### Factor Rename Migration (`tdx_*` → `tee_*`)

The `tee_*` factors are proposed renames of the existing `tdx_*` factors,
generalized to cover both Intel TDX and AMD SEV-SNP. **This rename must be
performed atomically within a single commit** to avoid silent breakage.

The following references must all be updated together:

1. **`KnownFactors` list** in `internal/attestation/report.go` — rename all
   `tdx_*` entries (and `gateway_tdx_*` entries) to `tee_*` / `gateway_tee_*`.
2. **`ReportDataBindingPassed()`** in `internal/attestation/report.go` —
   currently hardcodes the string `"tdx_reportdata_binding"`. Must be
   updated to `"tee_reportdata_binding"` (or the new equivalent name).
3. **All factor emission sites** across provider packages (`nearcloud`,
   `neardirect`, `chutes`, `venice`, etc.) that emit `tdx_*` factor names.
4. **`proxy.go`** — lines that gate E2EE on `ReportDataBindingPassed()`
   are safe if the function is updated, but verify no other string
   literals reference old names.
5. **`internal/verify/factory.go`** — the `newReportDataVerifier`,
   `newAttester`, `supplyChainPolicy`, `e2eeEnabledByDefault`, and
   `chatPathForProvider` switch blocks reference provider names. Factor name
   strings emitted by these functions must also be updated.
6. **`validateAllowFail()`** in `internal/config/config.go` — validates
   against `KnownFactors`. After the rename, existing user `teep.toml`
   files with `allow_fail = ["tdx_hardware_config"]` will fail validation
   at startup because the factor name is no longer recognized. **This is
   correct fail-closed behavior** — unrecognized config entries must produce
   an error (per AGENTS.md: "Unknown or misspelled config values MUST be
   rejected at startup"). Users must update their config to use the new
   `tee_*` names.
7. **Default allow-fail lists** in `internal/defaults/defaults.go` — update
   all `tdx_*` entries in per-provider defaults.
8. **Documentation** — update `docs/measurement_allowlists.md`,
   `docs/api_support.md`, and any other docs referencing `tdx_*` factors.
9. **Test assertions** — update all test files that assert on `tdx_*` factor
   name strings.

This rename should be applied across all providers (not just Tinfoil) as a
prerequisite or co-requisite commit. Until the rename lands, Tinfoil can
emit the existing `tdx_*` factor names for TDX attestations and introduce
`sev_*` equivalents for SEV-SNP.

## Dependencies

New Go module dependencies:
- `github.com/google/go-sev-guest` — AMD SEV-SNP verification (Phase 3)
- `github.com/cloudflare/circl/hpke` or `crypto/hpke` (Go 1.24+) — HPKE
  operations for EHBP (Phase 4)
- `github.com/sigstore/sigstore-go` — Sigstore bundle verification (new dependency; Phase 2)

## Public Documentation References

- Tinfoil attestation specification: https://docs.tinfoil.sh/verification/predicate
- Tinfoil verification overview: https://docs.tinfoil.sh/verification/verification-in-tinfoil
- Tinfoil backend infrastructure: https://docs.tinfoil.sh/verification/attestation-architecture
- Tinfoil secure enclave primer: https://docs.tinfoil.sh/verification/secure-enclave-primer
- EHBP spec: https://github.com/tinfoilsh/encrypted-http-body-protocol/blob/main/SPEC.md
- EHBP documentation: https://docs.tinfoil.sh/resources/ehbp
- EHBP Go reference: https://pkg.go.dev/github.com/tinfoilsh/encrypted-http-body-protocol
- Tinfoil model catalog: https://docs.tinfoil.sh/models/overview
- RFC 9180 (HPKE): https://www.rfc-editor.org/rfc/rfc9180
- RFC 9458 (OHTTP key config): https://www.rfc-editor.org/rfc/rfc9458

## Risk Assessment

1. **SEV-SNP is new attestation hardware for teep**: No existing SEV-SNP
   verification code. Phase 3 adds this. The deployed Tinfoil router currently
   runs on SEV-SNP, so the `tinfoil` provider cannot be validated against the
   live deployment until SEV-SNP verification lands. TDX-only support is
   insufficient for the deployed Tinfoil infrastructure.

2. **EHBP is a new E2EE protocol**: Unlike existing field-level or ML-KEM
   protocols, EHBP uses HPKE (RFC 9180). The protocol is well-specified with
   reference implementations in Go, JS, and Swift.

3. **Supply chain model differs**: Tinfoil uses Sigstore/GitHub Actions
   attestations rather than compose-hash/IMA. This is a stronger model (code
   measurement signed by transparent CI) but requires new verification code.

4. **Router architecture**: Tinfoil uses a confidential model router that
   handles multiple models. The attestation covers the router, not individual
   models. This is similar to nearcloud's gateway model. The router performs
   second-hop verification of each model enclave internally — teep trusts
   this because the router code is Sigstore-attested (see Authentication
   Chain 3 above).

5. **Model weight authentication is fully solved**: Unlike all existing teep
   providers, Tinfoil's model weights are cryptographically bound into the
   attestation chain via dm-verity + tinfoil-config.yml + Sigstore. The
   `measured_model_weights` factor can be set to `Pass` when the Sigstore
   supply chain verification succeeds (see Authentication Chain 4 above).
   This is a significant advantage over dstack providers where
   `measured_model_weights` always returns `Fail`.

6. **TEE.fail is unmitigated**: Tinfoil has no Proof of Cloud participation,
   no vTPM, and no DCEA. DDR5 memory bus key extraction attacks can forge
   TDX/SEV-SNP quotes with arbitrary measurements and REPORTDATA, defeating
   all software-layer security guarantees including Sigstore measurement
   matching and E2EE key binding. This is the same vulnerability affecting
   all TEE providers. `cpu_id_registry` is the Proof-of-Cloud identity factor;
   because Tinfoil currently has no PoC participation, it remains a default
   `allow_fail` factor. See "Authentication Chain 5" for full analysis.

7. **GPU-CPU binding**: GPU evidence is bound into REPORTDATA (Option 2 from
   gpu_cpu_binding.md), preventing GPU splicing attacks in the absence of
   TEE.fail. The nonce in REPORTDATA also provides freshness for GPU evidence.

8. **Format evolution risk**: The V3 attestation format is fully deployed, but
   protocol fields and evidence policy can evolve (for example
   architecture-specific NVSwitch requirements). Keep the attester/verifier
   isolated so updates can be shipped without disrupting other providers.
   Keep fixture-based regression tests active to detect schema/policy drift.
   The nonce requirement also safeguards against silent legacy-format
   downgrade: the attester always requests nonce-based attestation and rejects
   any response without a `report_data` structured field.

9. **Independent V3 verification coverage**: Public client libraries may have
   incomplete V3 verification coverage. Teep must maintain independent V3
   verification (envelope signature, REPORTDATA hash, GPU evidence hash
   binding, and nonce checks) and fixture-based regression tests.
