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

### Two-Provider Model: `tinfoil_v2` and `tinfoil_v3`

Tinfoil has two attestation formats that differ in REPORTDATA layout, nonce
support, and GPU evidence binding. V2 is deployed today; V3 exists in source
but is not yet released. This plan implements them as **two separate provider
names** that share underlying infrastructure:

- **`tinfoil_v2`** — Deployed now. V2 attestation format (`{format, body}`),
  no client nonces, HPKE key directly in REPORTDATA[32:64], no GPU evidence
  in the attestation response. The router runs on SEV-SNP.
- **`tinfoil_v3`** — Not yet deployed. V3 attestation format with structured
  JSON response, client nonce via `?nonce=<hex>`, GPU/NVSwitch evidence bound
  into REPORTDATA hash, HPKE key in the response `report_data` field
  (authenticated via REPORTDATA hash).

**Shared code** (in `internal/provider/tinfoil/`): EHBP E2EE, Sigstore
supply chain verification, TLS-bound transport, TDX/SEV-SNP hardware
verification, policy checks, MR_SEAM whitelist.

**Provider-specific code** (in the same package): `NewV2Attester` /
`NewV3Attester`, `V2ReportDataVerifier` / `V3ReportDataVerifier`.

**Migration path**: When Tinfoil deploys V3 to all endpoints:
1. Users switch their config from `tinfoil_v2` to `tinfoil_v3`.
2. After a transition period, remove the `tinfoil_v2` case from
   `proxy.go:fromConfig()` and delete `attester_v2.go` / `reportdata_v2.go`.
3. Rename `tinfoil_v3` to `tinfoil` (optional cleanup).

## Provider Characteristics

### Shared Properties

| Property | Value |
|---|---|
| Base URL | `https://inference.tinfoil.sh` |
| API key env | `TINFOIL_API_KEY` |
| E2EE | Yes (EHBP: HPKE + AES-256-GCM full-body encryption) |
| Connection model | Standard TLS with SPKI pinning (not connection-pinned) |
| Attestation endpoint | `GET /.well-known/tinfoil-attestation` on the enclave |
| PinnedHandler | No — uses standard HTTP client with SPKI verification |
| Supply chain | Sigstore DSSE bundles from GitHub attestations API |
| Hardware platforms | Intel TDX and AMD SEV-SNP (multi-platform code measurements) |
| GPU support | NVIDIA H100/H200 (Hopper), Blackwell; 1-GPU and 8-GPU (HGX) configurations |
| TEE.fail mitigation | None (same as all current providers) |

### `tinfoil_v2` (Deployed)

| Property | Value |
|---|---|
| Name | `tinfoil_v2` |
| Attestation format | V2: `{format, body}` where body = base64(gzip(hardware_report)) |
| Nonce model | No client nonces. Freshness from TLS key lifecycle. |
| REPORTDATA layout | `[0:32]` SHA-256(TLS pubkey PKIX DER), `[32:64]` HPKE X25519 key |
| HPKE key source | Directly from REPORTDATA[32:64] (no separate fetch needed) |
| GPU attestation | Boot-time fail-closed inside CVM. Not externally verifiable. |
| Deployed platform | Router runs SEV-SNP (no GPUs). Model enclaves behind router have GPUs. |

### `tinfoil_v3` (Not Yet Deployed)

| Property | Value |
|---|---|
| Name | `tinfoil_v3` |
| Attestation format | V3: structured JSON with `report_data`, `cpu`, `gpu`, `nvswitch`, `certificate`, `signature` fields |
| Nonce model | Client nonce via `?nonce=<hex>` query parameter (32 bytes → 64 hex chars) |
| REPORTDATA layout | `[0:32]` SHA-256(tls_fp \|\| hpke \|\| nonce \|\| gpu_hash \|\| nvswitch_hash), `[32:64]` zeros |
| HPKE key source | From `report_data.hpke_key` field in response (authenticated via REPORTDATA hash) |
| GPU attestation | SPDM evidence in response; GPU evidence hash bound into REPORTDATA (Option 2 from gpu_cpu_binding.md) |
| GPU-CPU binding | Yes — SHA-256 of GPU/NVSwitch evidence in REPORTDATA hash |

## Supported Endpoints

| Endpoint | Upstream Path | E2EE | Notes |
|---|---|---|---|
| Chat completions | `/v1/chat/completions` | Yes (EHBP) | Multiple models: llama3-3-70b, gemma4-31b, glm-5-1, gpt-oss-120b, kimi-k2-5, etc. |
| Embeddings | `/v1/embeddings` | Yes (EHBP) | Model: nomic-embed-text |
| Audio transcriptions | `/v1/audio/transcriptions` | Yes (EHBP) | Models: whisper-large-v3-turbo, voxtral-small-24b. Multipart form data. |
| TTS (text-to-speech) | `/v1/audio/speech` | Yes (EHBP) | Models: qwen3-tts, whisper-large-v3-turbo |
| Models list | `/v1/models` | No | GET request; EHBP only encrypts bodies on POST requests |

Vision models (qwen3-vl-30b, gemma4-31b, kimi-k2-5) use the chat completions
endpoint with multimodal content arrays — no separate vision endpoint is needed.

Note: EHBP encrypts the entire HTTP body as a single AEAD stream. There are
**no field-level gaps**. All request and response fields are encrypted by
construction, like Chutes.

## Architecture Comparison with Existing Providers

### Similarities to Chutes

- Full-body encryption (no field-level dispatch needed)
- Standard TLS (not connection-pinned like neardirect/nearcloud)
- No PinnedHandler needed
- TDX attestation verification reuses `attestation.VerifyTDXQuote()`
- `tinfoil_v2` has no client-supplied nonces (like Chutes)

### Key Differences from All Existing Providers

1. **Attestation format**: Tinfoil uses its own format — a JSON object with
   `format` (predicate type URI) and `body` (base64-gzipped hardware quote)
   for V2, or a structured JSON response with separate `cpu`, `gpu`,
   `nvswitch` fields for V3. Not dstack, not chutes, not NEAR.
2. **Supply chain**: Sigstore verification of GitHub Actions build attestations
   (DSSE in-toto bundles), checked against code image digests published in
   GitHub Releases. This is independent of the compose-hash / IMA supply chain
   used by other providers.
3. **REPORTDATA binding**:
   - `tinfoil_v2`: `[0:32]` = SHA-256(TLS pubkey PKIX DER);
     `[32:64]` = HPKE X25519 public key. No nonce.
   - `tinfoil_v3`: `[0:32]` = SHA-256(tls_fp || hpke || nonce || gpu_hash ||
     nvswitch_hash); `[32:64]` = zeros. Client nonce and GPU binding.
4. **E2EE protocol**: EHBP (RFC 9180 HPKE + AES-256-GCM), not
   Ed25519/XChaCha20-Poly1305 or ML-KEM-768/ChaCha20-Poly1305.
5. **HPKE key from attestation**:
   - `tinfoil_v2`: HPKE key embedded directly in REPORTDATA[32:64].
   - `tinfoil_v3`: HPKE key in the `report_data.hpke_key` response field,
     authenticated by being part of the REPORTDATA[0:32] hash.
   - Both: cipher suite is fixed (X25519_HKDF_SHA256 / HKDF_SHA256 /
     AES_256_GCM) per the EHBP spec. No key config endpoint needed.
6. **Hardware measurement verification**: TDX hardware platforms (MRTD, RTMR0)
   matched against a separate Sigstore-attested hardware measurements registry
   (`tinfoilsh/hardware-measurements`).
7. **Multi-platform code measurements**: Code attestation uses a unified
   `snp-tdx-multiplatform/v1` predicate that cross-matches SEV-SNP and TDX
   measurements from a single Sigstore bundle.
8. **SEV-SNP support**: Tinfoil enclaves can run on AMD SEV-SNP (not just TDX).
   The attestation format field determines which hardware verification path to
   take. The deployed router currently runs SEV-SNP.
9. **GPU attestation binding (`tinfoil_v3` only)**: V3 is the first format
   that actually implements GPU evidence hash in REPORTDATA (Option 2 from
   gpu_cpu_binding.md). GPU SPDM evidence and NVSwitch evidence are
   hash-bound into the CPU quote. Boot-time GPU attestation is fail-closed
   in both V2 and V3, but only V3 exposes GPU evidence for external
   verification.
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
| GPU-CPU binding | Not implemented (`cpu_gpu_chain` = Fail) | `tinfoil_v2`: Not externally verifiable (Skip). `tinfoil_v3`: GPU evidence hash in REPORTDATA (Option 2, Pass). |
| GPU topology validation | Not validated | 8-GPU + 4-NVSwitch PCIe mesh validated at boot |
| TEE.fail defense | Proof of Cloud (conditional) | None (same vulnerability) |
| vTPM / DCEA | Not implemented | Not implemented |

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
│           tinfoil_v2: Boot-time only. Not externally verifiable.
│           tinfoil_v3: GPU evidence hash bound into REPORTDATA (Chain 5)
│           tinfoil_v3: SPDM evidence independently verifiable by client
│
└── Link 1a: Sigstore Supply Chain Anchor
        Sigstore bundle from pri-build-action (GitHub Actions)
        OIDC issuer: token.actions.githubusercontent.com
        Workflow bound to specific GitHub repo + tag
        Bundle contains expected measurements for all registers
        Verified by: sigstore-go against Sigstore root trust anchor
```

**What teep must verify (enforcement checklist):**

1. Validate hardware attestation report signature against manufacturer cert
   chain (AMD ARK→ASK→VCEK or Intel root→PCK→QE). → `tee_quote_structure`
2. Compare all measurement registers against values from Sigstore bundle:
   - TDX: MRTD, RTMR0, RTMR1, RTMR2 against multi-platform predicate
   - SEV-SNP: launch measurement against snp_measurement
   → `sigstore_code_verified`
3. Verify Sigstore bundle: DSSE signature, Fulcio certificate, SCT,
   transparency log entry, observer timestamp. → `sigstore_code_verified`
4. Apply platform-specific policy checks:
   - TDX: TD_ATTRIBUTES, XFAM, MR_SEAM whitelist, RTMR3==0, zero fields
   - SEV-SNP: guest policy (Debug=false, SMT, etc.), TCB minimums
   → `tee_hardware_config`
5. Match TDX MRTD + RTMR0 against hardware measurements registry.
   → `cpu_id_registry`
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
│   │   tinfoil_v2:
│   │       REPORTDATA[0:32] = SHA-256(TLS public key, PKIX DER)
│   │       REPORTDATA[32:64] = HPKE X25519 public key (raw 32 bytes)
│   │   tinfoil_v3:
│   │       REPORTDATA[0:32] = SHA-256(TLS FP || HPKE key || nonce || GPU hash || NVSwitch hash)
│   │       REPORTDATA[32:64] = zeros
│   │       HPKE key in response report_data field (authenticated by hash)
│   │   REPORTDATA is part of the hardware-signed attestation report.
│   │   Verified by: extracting REPORTDATA from verified quote.
│   │
│   ├── Link 3: TLS Key Binding
│   │   │   Client connects to enclave via TLS.
│   │   │   Computes SHA-256 of server's TLS public key (PKIX DER).
│   │   │   Constant-time compares against REPORTDATA[0:32].
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
│       │   tinfoil_v2: HPKE public key from REPORTDATA[32:64].
│       │   tinfoil_v3: HPKE public key from response report_data.hpke_key
│       │               (authenticated by REPORTDATA[0:32] hash).
│       │   Used as the recipient public key for EHBP encryption.
│       │   Since it is part of the hardware-signed REPORTDATA, the key
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

1. Extract TLS public key fingerprint from REPORTDATA[0:32] of the verified
   attestation report. → `tls_key_binding`
2. On every TLS connection to the enclave, compute SHA-256 of the server's
   PKIX-encoded public key and constant-time compare against the attested
   fingerprint. Mismatch → re-attest → mismatch again → block.
   → `tls_key_binding`
3. Extract HPKE public key from the verified attestation report:
   `tinfoil_v2`: from REPORTDATA[32:64]; `tinfoil_v3`: from response
   `report_data.hpke_key` (verified via REPORTDATA hash). → `e2ee_capable`
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
Confidential Computing. This section analyses Tinfoil's GPU attestation
model against the gaps documented in `docs/attestation_gaps/gpu_cpu_binding.md`.

The two providers handle GPU attestation very differently:
- **`tinfoil_v2`**: GPU attestation is boot-time only inside the CVM. The
  attestation response contains no GPU evidence. External clients trust GPU
  attestation transitively via the Sigstore-attested CVM code.
- **`tinfoil_v3`**: GPU evidence is included in the attestation response and
  hash-bound into REPORTDATA. External clients can independently verify GPU
  state.

#### What Tinfoil Implements

**Boot-time GPU attestation (fail-closed, both providers):**
- At CVM boot, the `nvattest` tool performs local NVIDIA GPU attestation
  (`nvattest attest --device gpu --verifier local`).
- SPDM reports are collected from each GPU and validated locally.
- For 8-GPU HGX systems: NVSwitch attestation and full PCIe topology
  validation (8 GPUs + 4 NVSwitches mesh integrity) are also enforced.
- If GPU attestation fails, the CVM sets GPU ready state to
  `ACCEPTING_CLIENT_REQUESTS_FALSE` and boot aborts. **No enclave starts
  without passing GPU attestation.**

**Runtime GPU evidence collection (`tinfoil_v3` only):**
- The V3 attestation endpoint (`/.well-known/tinfoil-attestation?nonce=<hex>`)
  collects fresh SPDM evidence from all GPUs and NVSwitches.
- Evidence is collected via NVML APIs (`GetConfComputeGpuAttestationReport`)
  with the client-supplied nonce passed through to the GPU.
- GPU evidence is returned in the attestation response as `gpu` and
  `nvswitch` JSON fields alongside the CPU report.

**GPU evidence hash in REPORTDATA (`tinfoil_v3` only):**
- For V3 attestation, REPORTDATA is computed as:
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

The Tinfoil confidential model router (`inference.tinfoil.sh`) runs on
SEV-SNP **without GPUs** — the `gpu-attestation` boot stage reports
`skipped no GPUs`. All model subdomains (e.g. `llama3-3-70b.inference.tinfoil.sh`)
route to the same router enclave.

Individual model inference enclaves (behind the router) run with GPUs and
perform boot-time GPU attestation. Since teep verifies the **router** (not
individual model enclaves), teep does not directly observe GPU attestation
on the router for either provider. The router verifies model enclaves
internally (see Authentication Chain 3). If `tinfoil_v3` is deployed on
model enclaves but the router still serves V2, the V3 GPU properties only
help router→model verification, not teep→router.

#### V2 vs V3 Attestation Formats

| Aspect | `tinfoil_v2` (deployed) | `tinfoil_v3` (not yet deployed) |
|---|---|---|
| Endpoint | `GET /.well-known/tinfoil-attestation` | `GET /.well-known/tinfoil-attestation?nonce=<64hex>` |
| REPORTDATA layout | `[0:32] SHA-256(TLS pubkey)` \| `[32:64] HPKE key` | `[0:32] SHA-256(tls_fp\|\|hpke\|\|nonce\|\|gpu_hash\|\|nvswitch_hash)` \| `[32:64] zeros` |
| GPU evidence | Not included | Included in response (`gpu`, `nvswitch` fields) |
| GPU binding | None | SHA-256 hash in REPORTDATA |
| Freshness | TLS key lifecycle | Client-supplied nonce |
| HPKE key location | REPORTDATA[32:64] (raw bytes) | `report_data.hpke_key` (JSON field) |
| Client verification | tinfoil-go verifier (existing) | Not yet verified by tinfoil-go |

**Important**: The tinfoil-go client library currently only verifies V2
attestation (no nonce, no GPU). The V3 format with GPU evidence binding
exists in the CVM source code (cvmimage, post-v0.7.5 on main) but has not
been released. When V3 deploys, `tinfoil_v3` will gain GPU binding and
client nonce freshness.

#### Gap Analysis: GPU CPU Binding (gpu_cpu_binding.md)

| Issue from gpu_cpu_binding.md | `tinfoil_v2` | `tinfoil_v3` |
|---|---|---|
| **Gap 1: TEE.fail** | **Unmitigated** | **Unmitigated** |
| **Gap 2: CPU-to-GPU binding** | **Skip** (not externally verifiable) | **Pass** (GPU evidence hash in REPORTDATA) |
| **GPU nonce freshness** | **N/A** (no client nonces) | **Yes** (nonce passed through to GPU SPDM) |
| **GPU topology validation** | Boot-time only (not observable) | Boot-time + NVSwitch evidence in response |
| **vTPM / DCEA (Option 3)** | Not implemented | Not implemented |
| **TDX Connect / TDISP (Option 5)** | Not implemented | Not implemented |
| **Proof of Cloud (Option 1)** | Not implemented | Not implemented |

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

For `tinfoil_v3` attestation, the GPU evidence relay attack described in
gpu_cpu_binding.md applies: an attacker with extracted keys can relay real
GPU evidence from the legitimate machine while fabricating the CPU quote to
bind their own keys. The GPU hash in REPORTDATA provides no defense when the
attacker controls REPORTDATA (via TEE.fail).

**Tinfoil-specific nuance**: Tinfoil's hermetically built CVM image is
stronger than dstack in one respect — if an attacker forges a quote, they
must also provide a complete Tinfoil CVM environment (or intercept
connections), which is harder than with dstack where the attacker could run
arbitrary code. However, this is defense-in-obscurity, not a cryptographic
mitigation.

**What teep should do (both providers):**
1. `cpu_id_registry`: Listed as a default `allow_fail` factor for both
   Tinfoil providers until Tinfoil supports the hardware platform registry.
   When Tinfoil publishes registry data, remove from `allow_fail` defaults
   to enforce it. Users may also remove it from their own `allow_fail` list
   at that time. (TEE.fail means Proof of Cloud is the only way to truly
   verify, but the hardware platform registry still provides
   defense-in-depth when enforced.)
2. Apply the same TEE.fail residual risk assessment as for other providers.
3. When DCEA/vTPM support becomes available, add verification support.

**`tinfoil_v2`-specific:**
4. `cpu_gpu_chain`: `Skip` (GPU evidence not in attestation response).
5. `nvidia_gpu_attestation`: `Skip` (same reason).

**`tinfoil_v3`-specific:**
4. `cpu_gpu_chain`: `Pass` (GPU evidence hash verified in REPORTDATA).
5. `nvidia_gpu_attestation`: `Pass` (SPDM evidence verified per GPU).

#### V3 REPORTDATA Verification (`tinfoil_v3` Only)

For `tinfoil_v3` attestation, the REPORTDATA verification differs from
`tinfoil_v2`:

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
   `nvswitch` field (if present; empty for single-GPU systems). Same raw-byte
   requirement as the GPU evidence hash above.
4. Recompute the expected REPORTDATA:
   ```
   expected[0:32] = SHA-256(tls_key_fp || hpke_key || nonce || gpu_evidence_hash || nvswitch_evidence_hash)
   expected[32:64] = zeros
   ```
5. Constant-time compare against the CPU quote's actual REPORTDATA.
6. Verify each GPU evidence SPDM report (nonce matches client nonce,
   certificate chain validates against NVIDIA root).
7. Verify the NVSwitch evidence likewise if present.

This gives `tinfoil_v3` three properties unavailable in `tinfoil_v2`:
- **GPU attestation binding**: GPU evidence is hardware-authenticated via CPU quote.
- **Client nonce freshness**: Nonce in REPORTDATA proves attestation is fresh.
- **NVSwitch topology**: NVSwitch evidence validates the GPU interconnect.

### Attestation Freshness

The two providers have fundamentally different freshness models:

**`tinfoil_v2`** does not use client nonces. Freshness is established
through the TLS key lifecycle:

1. Each enclave boot generates a fresh TLS key pair and HPKE key pair.
2. The TLS key fingerprint is embedded in REPORTDATA and signed by hardware.
3. The TLS certificate is issued by a public CA and logged in CT logs.
4. When the enclave reboots, new keys are generated and a new attestation
   report is produced with different REPORTDATA.

**Critical implementation constraint**: For `tinfoil_v2`, the attestation
response and the TLS certificate binding **must be verified on the same TCP
connection**. If teep fetches attestation on connection A (observing its TLS
certificate) but then opens a separate connection B for inference, an
adversary with network position can replay a valid-but-stale attestation on
A while controlling B. The SPKI-pinned transport (see TLS-Fingerprint-Bound
Transport section) enforces this: the `VerifyPeerCertificate` callback
computes the TLS fingerprint on every connection and compares it against the
attested REPORTDATA[0:32] value. This ensures attestation and inference
share the same TLS identity, even across connection reuse.

**`tinfoil_v3`** supports client-supplied nonces:

1. Client generates a random 32-byte nonce and appends `?nonce=<hex>` to the
   attestation URL.
2. The nonce is included in the REPORTDATA hash, providing cryptographic
   freshness equivalent to other providers.
3. The nonce is also passed through to GPU SPDM reports for GPU freshness.

**What teep must enforce:**

- **`tinfoil_v2`**: On SPKI cache miss (new TLS certificate seen), trigger
  full re-attestation. Verify TLS key binding matches the current connection.
  The `nonce_in_reportdata` factor should be advisory, with detail explaining
  the TLS-key-lifecycle freshness model.
- **`tinfoil_v3`**: Use client-supplied nonce in the query parameter. Verify
  the nonce is included in the REPORTDATA hash (see V3 REPORTDATA
  Verification in Authentication Chain 5). The `nonce_in_reportdata` factor
  should be enforced.
- Do NOT treat the absence of a client nonce as a verification failure when
  using `tinfoil_v2` attestation.

---

## Protocol Descriptions

### Tinfoil Attestation Protocol

#### Attestation Document Format

The enclave serves its attestation at `GET /.well-known/tinfoil-attestation`.
The response is a JSON object:

```json
{
  "format": "<predicate_type_uri>",
  "body": "<base64(gzip(hardware_attestation_report))>"
}
```

**Format values** (predicate type URIs):
- `https://tinfoil.sh/predicate/sev-snp-guest/v2` — AMD SEV-SNP attestation
- `https://tinfoil.sh/predicate/tdx-guest/v2` — Intel TDX attestation

The `body` field is base64 standard encoding of gzip-compressed raw hardware
attestation report bytes.

#### Decompression

1. Base64-decode the `body` string.
2. Gzip-decompress. Bound the decompressed size (10 MiB max) to prevent
   decompression bombs.
3. The result is a raw binary attestation report:
   - For TDX: a TDX QuoteV4 structure (min 1020 bytes).
   - For SEV-SNP: an SEV attestation report (1184 bytes).

#### REPORTDATA Layout (64 bytes)

Both TDX and SEV-SNP reports contain a 64-byte `report_data` field. The
layout depends on the provider:

**`tinfoil_v2` REPORTDATA** (deployed):

| Offset | Size | Content |
|---|---|---|
| 0–31 | 32 bytes | SHA-256 fingerprint of the enclave's TLS certificate public key (PKIX DER encoding) |
| 32–63 | 32 bytes | HPKE X25519 public key (raw 32 bytes) |

The HPKE key is embedded directly in REPORTDATA — no separate fetch needed.

**`tinfoil_v3` REPORTDATA** (not yet deployed):

| Offset | Size | Content |
|---|---|---|
| 0–31 | 32 bytes | SHA-256(tls_key_fp \|\| hpke_key \|\| nonce \|\| gpu_evidence_hash \|\| nvswitch_evidence_hash) |
| 32–63 | 32 bytes | All zeros |

The HPKE key is in the response `report_data.hpke_key` JSON field,
authenticated by being part of the REPORTDATA[0:32] hash.

The provider configured in teep.toml determines which layout
is expected. `tinfoil_v2` uses the V2 layout; `tinfoil_v3` uses the V3
layout. There is no runtime format detection — the provider choice is
explicit.

### TDX Verification (Reuse Existing)

For TDX-format attestation, hex-encode the decompressed binary and call the
existing `attestation.VerifyTDXQuote()`. Extract measurements:

- Register 0: MRTD (48 bytes hex)
- Register 1: RTMR0 (48 bytes hex)
- Register 2: RTMR1 (48 bytes hex)
- Register 3: RTMR2 (48 bytes hex)
- Register 4: RTMR3 (48 bytes hex) — must be all zeros

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

The SEV-SNP verification is new code — teep currently only verifies TDX
quotes. However, go-sev-guest (google/go-sev-guest) provides the verification
primitives, similar to how go-tdx-guest is used for TDX.

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
- **Workflow pattern**: `^https://github.com/{repo}/.github/workflows/.*@refs/tags/*`
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

1. Extract the TLS fingerprint from REPORTDATA bytes [0:32].
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
   REPORTDATA[0:32].
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
2. Fetch fresh attestation from `/.well-known/tinfoil-attestation`.
3. Verify the new attestation (full pipeline: TDX/SEV-SNP + supply chain).
4. Update the fingerprint in the transport's `VerifyPeerCertificate` callback.
5. Verify the HPKE key in the new REPORTDATA for E2EE continuity.

This approach avoids the overhead of per-request attestation while maintaining
the invariant that every byte transits a connection verified against an
attested enclave.

### E2EE: Encrypted HTTP Body Protocol (EHBP)

EHBP is documented at https://docs.tinfoil.sh/resources/ehbp and specified at
https://github.com/tinfoilsh/encrypted-http-body-protocol/blob/main/SPEC.md

The protocol encrypts entire HTTP request and response bodies using HPKE
(RFC 9180) while leaving headers in cleartext for routing.

#### HPKE Parameters

| Parameter | Value |
|---|---|
| KEM | X25519_HKDF_SHA256 (0x0020) |
| KDF | HKDF_SHA256 (0x0001) |
| AEAD | AES_256_GCM (0x0002) |

#### Request Encryption

1. Use the HPKE public key from the verified attestation (already extracted:
   `tinfoil_v2` from REPORTDATA[32:64], `tinfoil_v3` from response field).
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
4. Set request header `Ehbp-Encapsulated-Key` to the lowercase hex encoding
   of the HPKE encapsulated key (32 bytes → 64 hex chars for X25519).
5. Use chunked transfer encoding; omit Content-Length.
6. Retain the HPKE sender context for response decryption.

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
4. On any decryption failure: fail closed, abort the response.

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

**Goal**: Fetch and verify Tinfoil attestation documents (TDX path only;
SEV-SNP deferred to Phase 3). Create separate V2 and V3 attesters and
REPORTDATA verifiers in the same package.

**Note on phase ordering**: The deployed `tinfoil_v2` router currently serves
SEV-SNP attestation (not TDX). Phase 1 builds shared provider plumbing, V2/V3
attester interfaces, REPORTDATA verifiers, and TDX policy checks — all of
which can be unit-tested with TDX fixtures. However, `tinfoil_v2` cannot be
validated against the live deployment until Phase 3 (SEV-SNP verification)
lands. Phase 1 is not independently deployable for `tinfoil_v2`.

**Files to create**:
- `internal/provider/tinfoil/tinfoil.go` — Shared types, constants, Preparer
- `internal/provider/tinfoil/attestation.go` — Shared attestation document
  parsing (gzip decompression, format URI validation, TDX/SEV-SNP dispatch)
- `internal/provider/tinfoil/attester_v2.go` — `NewV2Attester`: V2 fetch
  (no nonce), V2 response parsing, HPKE key from REPORTDATA
- `internal/provider/tinfoil/attester_v3.go` — `NewV3Attester`: V3 fetch
  (with nonce), structured JSON parsing, HPKE key from response field
- `internal/provider/tinfoil/reportdata_v2.go` — `V2ReportDataVerifier`:
  direct TLS FP + HPKE extraction from REPORTDATA bytes
- `internal/provider/tinfoil/reportdata_v3.go` — `V3ReportDataVerifier`:
  SHA-256 hash recomputation, GPU evidence hash verification
- `internal/provider/tinfoil/policy.go` — TDX additional policy checks +
  MR_SEAM whitelist (shared between both providers)

**Implementation**:

1. **Shared types** (`tinfoil.go`):
   - Accepted format URIs:
     `https://tinfoil.sh/predicate/sev-snp-guest/v2`,
     `https://tinfoil.sh/predicate/tdx-guest/v2`.
   - Common `Preparer` (sets API key header, same for both providers).
   - `attestation.FormatTinfoil` backend format constant.

2. **Shared parsing** (`attestation.go`):
   - `parseV2Body(body string) ([]byte, error)` — base64-decode + gzip
     decompress, bound decompressed size to 10 MiB.
   - `parseHardwareReport(format string, report []byte) (*attestation.RawAttestation, error)`
     — detect TDX vs SEV-SNP from format URI, hex-encode binary, set
     `raw.IntelQuote` or SEV-SNP fields. Reject unknown format URIs.
   - These are used by both V2 and V3 attesters.

3. **V2 Attester** (`attester_v2.go`, `tinfoil.NewV2Attester(baseURL, apiKey, offline)`):
   - `FetchAttestation(ctx, model, nonce)` fetches
     `GET {baseURL}/.well-known/tinfoil-attestation` **without** nonce
     parameter. The `nonce` argument is ignored (V2 does not use nonces).
   - Parse the JSON response: `{ "format": "...", "body": "<base64(gzip(report))>" }`.
   - Reject responses that contain a `report_data` field (that is V3 format;
     the V2 attester must not accept V3 responses).
   - Call shared `parseV2Body` + `parseHardwareReport`.
   - Extract REPORTDATA from the parsed quote:
     - `raw.TLSFingerprint` = hex(REPORTDATA[0:32]).
     - HPKE key = REPORTDATA[32:64] (raw 32 bytes).
   - Store the HPKE public key via `raw.SigningKey` (hex-encoded).
   - Set `raw.BackendFormat = attestation.FormatTinfoil`.

4. **V3 Attester** (`attester_v3.go`, `tinfoil.NewV3Attester(baseURL, apiKey, offline)`):
   - `FetchAttestation(ctx, model, nonce)` fetches
     `GET {baseURL}/.well-known/tinfoil-attestation?nonce=<hex>`
     (32 bytes → 64 hex chars). Nonce is required — fail if empty.
   - Parse the structured JSON response:
     ```json
     {
       "format": "<format_uri>",
       "report_data": { "tls_key_fp": "...", "hpke_key": "...", "nonce": "...",
                         "gpu_evidence_hash": "...", "nvswitch_evidence_hash": "..." },
       "cpu": { "platform": "tdx|sev-snp", "report": "<base64>" },
       "gpu": { "evidences": [...] },
       "nvswitch": { "evidences": [...] },
       "certificate": "<PEM>",
       "signature": "<base64 ECDSA>"
     }
     ```
   - Reject responses that contain a `body` field (that is V2 format;
     the V3 attester must not accept V2 responses).
   - Base64-decode `cpu.report`, bound size to 10 MiB.
   - Call shared `parseHardwareReport` with the decoded report bytes.
   - Extract `tls_key_fp` and `hpke_key` from `report_data` fields.
   - Store GPU evidence JSON for later REPORTDATA verification.
   - Store HPKE key via `raw.SigningKey` (hex-encoded).
   - Set `raw.BackendFormat = attestation.FormatTinfoil`.
   - Store the `nonce` in the RawAttestation for report building.

5. **V2 REPORTDATA Verifier** (`reportdata_v2.go`, `tinfoil.V2ReportDataVerifier{}`):
   - `VerifyReportData(reportData [64]byte, raw, nonce)`:
     - Extract `tlsFP = hex(reportData[0:32])`.
     - Extract `hpkeKey = hex(reportData[32:64])`.
     - Verify `tlsFP` matches `raw.TLSFingerprint` (constant-time).
     - Verify `hpkeKey` matches `raw.SigningKey` (constant-time).
     - Return detail string: `"v2: tls_fp={first8}... hpke_key={first8}..."`.
   - The `nonce_in_reportdata` factor is set to advisory (V2 has no nonces).

6. **V3 REPORTDATA Verifier** (`reportdata_v3.go`, `tinfoil.V3ReportDataVerifier{}`):
   - `VerifyReportData(reportData [64]byte, raw, nonce)`:
     - Recompute `expected = SHA-256(tls_fp || hpke_key || nonce || gpu_hash || nvswitch_hash)`.
     - Constant-time compare `expected` against `reportData[0:32]`.
     - Verify `reportData[32:64]` is all zeros.
     - Return detail string: `"v3: reportdata_hash verified, gpu_bound=true"`.
   - The `nonce_in_reportdata` factor is set to enforced (V3 requires client
     nonce in REPORTDATA hash).

7. **Tinfoil TDX Policy** (`policy.go`, shared between both providers):
   - After standard TDX verification, apply Tinfoil-specific policy:
     - Validate TD_ATTRIBUTES == `0x0000001000000000`.
     - Validate XFAM == `0xe702060000000000`.
     - Validate MR_SEAM is in the accepted set.
     - Validate MR_CONFIG_ID, MR_OWNER, MR_OWNER_CONFIG are all zeros.
     - Validate RTMR3 is all zeros.
     - Validate TEE_TCB_SVN >= minimum.
   - Store results as `tee_hardware_config` factor details in the report.

8. **MR_SEAM Whitelist** (in `policy.go`):
   The Sigstore hardware-measurements registry (`tinfoilsh/hardware-measurements`),
   fetched and verified earlier in Phase 2, is the authoritative source for
   MR_SEAM values. At runtime, the implementation must source MR_SEAM values
   from the verified hardware-measurements predicate. If the registry fetch
   fails, Sigstore verification fails, or the predicate cannot be parsed into
   an accepted MR_SEAM set, attestation verification must fail closed and the
   request must be rejected; there is no runtime fallback that may convert this
   factor into `Pass`.

   The following values may be kept as test fixtures and for the explicit
   `--offline` mode only:
   ```
   TDX 2.0.08: 476a2997c62bccc78370913d0a80b956e3721b24272bc66c4d6307ced4be2865c40e26afac75f12df3425b03eb59ea7c
   TDX 1.5.16: 7bf063280e94fb051f5dd7b1fc59ce9aac42bb961df8d44b709c9b0ff87a7b4df648657ba6d1189589feab1d5a3c9a9d
   TDX 2.0.02: 685f891ea5c20e8fa27b151bf34bf3b50fbaf7143cc53662727cbdb167c0ad8385f1f6f3571539a91e104a1c96d75e04
   TDX 1.5.08: 49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6
   ```
   The `--offline` flag is an explicit user choice (not a connectivity
   fallback). When `--offline` is active, the MR_SEAM / `tee_hardware_config`
   factor must be marked as `Skip` with detail text indicating that
   registry-backed validation was not performed. It must never silently
   weaken production verification or report `Pass` from the hardcoded list.

**Unit tests** (split by provider):
- **Shared**: Test gzip decompression (valid, truncated, oversized >10 MiB).
  Test format URI rejection (unknown URI). Test MR_SEAM matching from verified
  hardware-measurements predicate. Test registry fetch/verification/parsing
  failure causes attestation rejection in normal mode. Test that `--offline`
  mode records MR_SEAM / `tee_hardware_config` as `Skip`, never `Pass`.
- **`tinfoil_v2`**: Test V2 document parsing with captured attestation response.
  Test V2 rejects responses with `report_data` field. Test V2 REPORTDATA
  extraction: verify correct byte offsets (TLS FP at [0:32], HPKE at [32:64]).
  Test HPKE key matches `raw.SigningKey`.
- **`tinfoil_v3`**: Test V3 document parsing with captured nonce-based
  attestation (with GPU evidence). Test V3 rejects responses with `body` field.
  Test V3 REPORTDATA verification: recompute SHA-256 hash, compare
  constant-time. Verify zeros in [32:64]. Test GPU evidence hash computation.
  Test nonce required (empty nonce → error).

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
   - Use `sigstore-go` library (same as used by teep's existing
     `attestation/sigstore.go`) to verify the DSSE bundle.
   - Certificate identity: OIDC issuer =
     `https://token.actions.githubusercontent.com`.
   - Workflow regex: `^https://github.com/{repo}/.github/workflows/.*@refs/tags/*`.
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
   - Record hardware match as `cpu_id_registry` factor.

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

5. **Integration into Tinfoil Attester**: In `FetchAttestation`, detect the
   format URI. For SEV-SNP, call the new SEV verifier instead of TDX.

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
   - `EncryptRequest(body []byte, serverPubKey [32]byte) (encBody []byte, encapKey [32]byte, senderCtx, error)`:
     - Call HPKE `SetupBaseS` with X25519_HKDF_SHA256 / HKDF_SHA256 /
       AES_256_GCM and the server's public key.
     - Encrypt the body as a single chunk:
       `[4-byte len] [AES-256-GCM ciphertext]`.
       (Or stream multiple chunks if the body is large.)
     - Return the encrypted body bytes, the encapsulated key, and the
       retained HPKE sender context for response decryption.

2. **EHBP Decryption** (`ehbp.go`):
   - `DecryptResponse(encBody io.Reader, responseNonce [32]byte, encapKey [32]byte, senderCtx) ([]byte, error)`:
     - Export secret: `secret = senderCtx.Export("ehbp response", 32)`.
     - Construct salt: `salt = encapKey || responseNonce`.
     - Derive PRK: `prk = HKDF-Extract(salt, secret)`.
     - Derive key: `aead_key = HKDF-Expand(prk, "key", 32)`.
     - Derive nonce: `aead_nonce = HKDF-Expand(prk, "nonce", 12)`.
     - Read chunks: `[4-byte len] [ciphertext]`.
     - Decrypt each chunk with AES-256-GCM:
       nonce = `aead_nonce XOR chunk_index`.
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
   - On response: read `Ehbp-Response-Nonce` header, pass to Decryptor.
   - If `Ehbp-Response-Nonce` is missing: fail closed.

**Unit tests**:
- Test encryption round-trip: encrypt with a test key, decrypt with known
  private key.
- Test chunked framing: single chunk, multiple chunks, zero-length chunks.
- Test response key derivation: verify against known test vectors (derive key
  from a known HPKE context and nonce, compare expected output).
- Test fail-closed: missing Ehbp-Response-Nonce, corrupted ciphertext.

**Commit**: Phase 4 — EHBP E2EE implementation.

---

### Phase 5: Provider Wiring and Configuration

**Goal**: Wire both `tinfoil_v2` and `tinfoil_v3` providers into the proxy,
config, and endpoint dispatch.

**Files to modify**:
- `internal/proxy/proxy.go` — Add `case "tinfoil_v2"` and `case "tinfoil_v3"`
  to `fromConfig()`
- `internal/config/config.go` — Add `TINFOIL_API_KEY` env resolution
- `teep.toml.example` — Add both provider examples (V2 active, V3 commented)
- `internal/defaults/defaults.go` — Add default allow-fail factors per provider
- `docs/api_support.md` — Update endpoint and E2EE support matrices

**Implementation**:

1. **Config** (`config.go`):
   - Env var: `TINFOIL_API_KEY` (shared by both provider names).
   - Default base URL: `https://inference.tinfoil.sh` (shared).
   - E2EE default: `true`.

2. **Provider Construction** (`proxy.go:fromConfig`):

   Both `case` blocks share the same endpoint paths, base URL, API key,
   E2EE encryptor, supply chain policy, model lister, SPKI domain, and
   TLS-bound transport. They differ only in Attester and ReportDataVerifier.

   ```go
   case "tinfoil_v2":
       p.ChatPath = "/v1/chat/completions"
       p.EmbeddingsPath = "/v1/embeddings"
       p.AudioPath = "/v1/audio/transcriptions"
       p.Attester = tinfoil.NewV2Attester(cp.BaseURL, cp.APIKey, offline)
       p.Preparer = tinfoil.NewPreparer(cp.APIKey)
       p.ReportDataVerifier = tinfoil.V2ReportDataVerifier{}
       p.Encryptor = tinfoil.NewE2EE(cp.BaseURL, config.NewAttestationClient(offline))
       p.SupplyChainPolicy = nil // Sigstore-based, not compose-based
       p.ModelLister = provider.NewModelLister(cp.BaseURL, cp.APIKey, config.NewAttestationClient(offline))

   case "tinfoil_v3":
       p.ChatPath = "/v1/chat/completions"
       p.EmbeddingsPath = "/v1/embeddings"
       p.AudioPath = "/v1/audio/transcriptions"
       p.Attester = tinfoil.NewV3Attester(cp.BaseURL, cp.APIKey, offline)
       p.Preparer = tinfoil.NewPreparer(cp.APIKey)
       p.ReportDataVerifier = tinfoil.V3ReportDataVerifier{}
       p.Encryptor = tinfoil.NewE2EE(cp.BaseURL, config.NewAttestationClient(offline))
       p.SupplyChainPolicy = nil // Sigstore-based, not compose-based
       p.ModelLister = provider.NewModelLister(cp.BaseURL, cp.APIKey, config.NewAttestationClient(offline))
   ```

   Consider extracting a `tinfoilCommon(p, cp, offline)` helper to avoid
   duplication between the two case blocks (all shared fields set in the
   helper, then only Attester and ReportDataVerifier overridden). This
   keeps the diff small when removing `tinfoil_v2` later.

3. **SPKI Caching**: Both providers use a single inference gateway, so
   `SPKIDomainForModel` returns the base URL host for all models:
   ```go
   p.SPKIDomainForModel = func(_ context.Context, _ string) (string, bool) {
       return "inference.tinfoil.sh", true
   }
   ```

4. **TLS-Fingerprint-Bound Transport**: Create a `tinfoil.NewTransport()`
   that returns an `http.Transport` with `VerifyPeerCertificate` enforcing the
   attested SPKI fingerprint on every connection (see the TLS-Fingerprint-
   Bound Transport protocol section above). The transport is shared between
   the Attester, E2EE Encryptor, and inference request forwarding. On
   fingerprint mismatch during inference, trigger re-attestation before
   retrying. Shared between both provider variants.

5. **Allow-Fail Defaults**: Create separate defaults per provider:
   - `attestation.TinfoilV2DefaultAllowFail`:
     - `nonce_in_reportdata` — advisory (V2 has no nonces)
     - `cpu_gpu_chain` — Skip (V2 has no GPU evidence)
     - `nvidia_gpu_attestation` — Skip (same)
     - `sigstore_code_verified` — enforced (Tinfoil's core security
       advantage is Sigstore-based code measurement; an attacker running
       modified code in a valid enclave environment passes attestation
       if this factor is advisory)
     - `cpu_id_registry` — default `allow_fail` (not yet supported by
       Tinfoil; remove from defaults when registry data is available)
   - `attestation.TinfoilV3DefaultAllowFail`:
     - `nonce_in_reportdata` — enforced
     - `cpu_gpu_chain` — enforced
     - `nvidia_gpu_attestation` — enforced
     - `sigstore_code_verified` — enforced (same rationale as V2)
     - `cpu_id_registry` — default `allow_fail` (same as V2; remove
       from defaults when registry data is available)

6. **Config example** (`teep.toml.example`):
   ```toml
   # Tinfoil V2 (deployed — use this now)
   [providers.tinfoil_v2]
   base_url = "https://inference.tinfoil.sh"
   api_key_env = "TINFOIL_API_KEY"
   e2ee = true

   # Tinfoil V3 (not yet deployed — uncomment when V3 is available)
   # [providers.tinfoil_v3]
   # base_url = "https://inference.tinfoil.sh"
   # api_key_env = "TINFOIL_API_KEY"
   # e2ee = true
   ```

7. **TTS Endpoint**: If TTS (`/v1/audio/speech`) is not yet a proxy endpoint,
   add it to `proxy.go` following the pattern of other endpoints.

**Unit tests**:
- Test provider construction from config for both `tinfoil_v2` and
  `tinfoil_v3` (verifies correct Attester and ReportDataVerifier types).
- Test SPKI domain resolution.
- Test that unknown Tinfoil config fields are rejected (strict TOML).
- Test that `tinfoil_v2` uses `V2ReportDataVerifier` and `tinfoil_v3` uses
  `V3ReportDataVerifier`.

**Commit**: Phase 5 — Tinfoil provider wiring and configuration.

---

### Phase 6: Integration Tests

**Goal**: Full API-key-based integration tests for both `tinfoil_v2` and
`tinfoil_v3` providers against all Tinfoil endpoints.

**Files to create**:
- `internal/integration/tinfoil_v2_test.go` — `tinfoil_v2` integration tests
- `internal/integration/tinfoil_v3_test.go` — `tinfoil_v3` integration tests
  (initially `t.Skip("V3 not yet deployed")`)
- `internal/integration/testdata/tinfoil/` — Captured attestation fixtures

**`tinfoil_v2` Tests** (all require `TINFOIL_API_KEY`, run now):

1. **Attestation Fetch and Verify**:
   - Fetch attestation from `inference.tinfoil.sh` using V2 attester.
   - Verify TDX or SEV-SNP quote.
   - Verify V2 REPORTDATA binding (TLS FP + HPKE key).
   - Verify HPKE key extracted from REPORTDATA[32:64].
   - Log all verification results.

2. **Supply Chain Verification**:
   - Fetch code measurements from `tinfoilsh/confidential-model-router`.
   - Verify Sigstore bundle.
   - Compare against enclave measurements.

3. **TLS Fingerprint Binding**:
   - Fetch attestation, extract TLS fingerprint from REPORTDATA[0:32].
   - Connect to enclave, extract TLS certificate fingerprint.
   - Verify match.

4. **Chat Completions (non-streaming)**:
   - Send a simple chat request through the proxy with `tinfoil_v2` config.
   - Verify response contains expected fields.
   - Verify request and response were EHBP encrypted/decrypted.

5. **Chat Completions (streaming)**:
   - Send a streaming chat request.
   - Verify SSE events are received and decrypted.

6. **Embeddings**:
   - Send an embedding request with model `nomic-embed-text`.
   - Verify response contains embedding vectors.
   - Verify E2EE.

7. **Audio Transcription**:
   - Send a multipart audio transcription request.
   - Verify response contains transcription text.
   - Verify E2EE (entire multipart body encrypted).

8. **TTS (text-to-speech)**:
   - Send a TTS request.
   - Verify response contains audio data.

9. **Models List**:
   - Send GET /v1/models.
   - Verify response contains expected model IDs.
   - Verify response is plaintext (EHBP does not encrypt GET responses).

10. **Vision (via chat completions)**:
    - Send a chat completion with image content array.
    - Verify response describes the image.

11. **Negative Tests**:
    - Verify that a request with a corrupted `Ehbp-Encapsulated-Key` is
      rejected by the server.
    - Verify that a response with a missing `Ehbp-Response-Nonce` is
      rejected by the proxy (fail closed).

**`tinfoil_v3` Tests** (initially skipped, activate when V3 deploys):

All `tinfoil_v2` tests above, plus:

12. **Client Nonce in Attestation**:
    - Generate random nonce, fetch attestation with `?nonce=<hex>`.
    - Verify nonce is in the REPORTDATA hash (V3 REPORTDATA verification).
    - Verify `nonce_in_reportdata` factor is `Pass`.

13. **GPU Evidence Verification**:
    - Fetch V3 attestation, extract GPU evidence from response.
    - Verify GPU evidence hash matches REPORTDATA binding.
    - Verify SPDM certificate chain validates against NVIDIA root.
    - Verify `cpu_gpu_chain` factor is `Pass`.

14. **HPKE Key from Response Field**:
    - Verify HPKE key is extracted from `report_data.hpke_key` (not from
      REPORTDATA bytes).
    - Verify the HPKE key is authenticated by the REPORTDATA hash.
    - Use the key for E2EE and verify round-trip encryption works.

**Fixture Tests** (offline, no API key, both providers):
- Capture a real V2 attestation response and save as testdata.
- Test the full V2 verification pipeline against the fixture.
- When V3 deploys, capture a V3 attestation response and add V3 fixture tests.

**Commit**: Phase 6 — Tinfoil integration tests.

---

### Phase 7: Verification Report and Documentation

**Goal**: Update verification report generation and documentation.

**Files to modify**:
- `internal/attestation/report.go` — Add Tinfoil-specific verification
  factors
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
- `cpu_id_registry` — Hardware platform matched against Sigstore-attested
  registry (reuses existing factor name)

Existing factors with provider-specific behavior:
- `measured_model_weights` — Set to `Pass` when `sigstore_code_verified`
  passes, because the Sigstore chain transitively authenticates model weights
  via tinfoil-config.yml → dm-verity. Detail: "model weights attested via
  dm-verity commitment in Sigstore-verified config"
- `nonce_in_reportdata` —
  `tinfoil_v2`: Advisory. V2 does not embed client nonces. Freshness from
  TLS key lifecycle. Detail: "tinfoil_v2: TLS key rotation for freshness,
  not client nonces".
  `tinfoil_v3`: Enforced. Client nonce in REPORTDATA hash. Detail:
  "tinfoil_v3: client nonce in REPORTDATA hash".

**Documentation updates**:
- Add Tinfoil to the endpoint support matrix in `api_support.md`.
- Add Tinfoil E2EE details (EHBP, HPKE, full-body encryption).
- Document that Tinfoil has **no field-level encryption gaps** (full-body).
- Note both `tinfoil_v2` and `tinfoil_v3` in the provider list, with V3
  marked as "not yet deployed".

**Commit**: Phase 7 — Verification report factors and documentation.

---

## Verification Factors Summary

### `tinfoil_v2` Factors

| Factor | Enforced | Description |
|---|---|---|
| `tee_quote_present` | Yes | Hardware quote fetched and non-empty |
| `tee_quote_structure` | Yes | Quote parses and signature verifies (TDX or SEV-SNP) |
| `tee_hardware_config` | Yes | Platform policy (TDX: attrs/XFAM/MR_SEAM/RTMR3; SEV-SNP: guest policy/TCB) |
| `tee_boot_config` | Yes | Boot measurements match expected (MRTD/RTMR0 or measurement) |
| `tee_tcb_current` | Yes | TCB SVN meets minimum threshold |
| `intel_pcs_collateral` | Yes (TDX only) | Intel collateral valid; N/A for SEV-SNP |
| `tls_key_binding` | Yes | TLS fingerprint matches REPORTDATA[0:32] |
| `e2ee_capable` | Yes | HPKE key extracted from REPORTDATA[32:64] and verified |
| `e2ee_usable` | Yes | EHBP request encrypted + response AEAD-authenticated |
| `sigstore_code_verified` | Yes | Code measurement verified via Sigstore DSSE |
| `cpu_id_registry` | Default `allow_fail` | Hardware platform matched against registry |
| `measured_model_weights` | Yes (transitive) | Model weights attested via dm-verity + Sigstore chain |
| `nonce_in_reportdata` | Advisory | V2: no client nonces; TLS key lifecycle freshness |
| `cpu_gpu_chain` | Skip | V2: GPU evidence not in attestation response |
| `nvidia_gpu_attestation` | Skip | V2: not available |

### `tinfoil_v3` Factors

| Factor | Enforced | Description |
|---|---|---|
| `tee_quote_present` | Yes | Hardware quote fetched and non-empty |
| `tee_quote_structure` | Yes | Quote parses and signature verifies (TDX or SEV-SNP) |
| `tee_hardware_config` | Yes | Platform policy (TDX: attrs/XFAM/MR_SEAM/RTMR3; SEV-SNP: guest policy/TCB) |
| `tee_boot_config` | Yes | Boot measurements match expected (MRTD/RTMR0 or measurement) |
| `tee_tcb_current` | Yes | TCB SVN meets minimum threshold |
| `intel_pcs_collateral` | Yes (TDX only) | Intel collateral valid; N/A for SEV-SNP |
| `tls_key_binding` | Yes | TLS fingerprint matches REPORTDATA[0:32] hash component |
| `e2ee_capable` | Yes | HPKE key from `report_data.hpke_key`, authenticated via REPORTDATA hash |
| `e2ee_usable` | Yes | EHBP request encrypted + response AEAD-authenticated |
| `sigstore_code_verified` | Yes | Code measurement verified via Sigstore DSSE |
| `cpu_id_registry` | Default `allow_fail` | Hardware platform matched against registry |
| `measured_model_weights` | Yes (transitive) | Model weights attested via dm-verity + Sigstore chain |
| `nonce_in_reportdata` | Yes | V3: client nonce in REPORTDATA hash |
| `cpu_gpu_chain` | Yes | V3: GPU evidence hash verified in REPORTDATA |
| `nvidia_gpu_attestation` | Yes | V3: SPDM evidence verified per GPU |

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
   (approximately lines 1312, 1372, 1617) are safe if the function is
   updated, but verify no other string literals reference old names.
5. **`validateAllowFail()`** in `internal/config/config.go` — validates
   against `KnownFactors`. After the rename, existing user `teep.toml`
   files with `allow_fail = ["tdx_hardware_config"]` will fail validation
   at startup because the factor name is no longer recognized. **This is
   correct fail-closed behavior** — unrecognized config entries must produce
   an error (per AGENTS.md: "Unknown or misspelled config values MUST be
   rejected at startup"). Users must update their config to use the new
   `tee_*` names.
6. **Default allow-fail lists** in `internal/defaults/defaults.go` — update
   all `tdx_*` entries in per-provider defaults.
7. **Documentation** — update `docs/measurement_allowlists.md`,
   `docs/api_support.md`, and any other docs referencing `tdx_*` factors.
8. **Test assertions** — update all test files that assert on `tdx_*` factor
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
   verification code. Phase 3 adds this. Shared provider plumbing can be
   implemented before Phase 3, but `tinfoil_v2` cannot be validated or used
   against the current deployment until SEV-SNP verification lands, because
   the deployed router currently serves SEV-SNP attestation (as observed
   from the live API). TDX-only support is insufficient for the deployed
   `tinfoil_v2` environment.

2. **EHBP is a new E2EE protocol**: Unlike existing field-level or ML-KEM
   protocols, EHBP uses HPKE (RFC 9180). The protocol is well-specified with
   reference implementations in Go, JS, and Swift.

3. **`tinfoil_v2` has no client nonces**: V2 attestation does not use
   client-supplied nonces. Freshness comes from the enclave's ephemeral TLS
   key (rotated on reboot). The proxy must re-attest on TLS certificate
   rotation (SPKI cache miss). The `nonce_in_reportdata` factor is advisory
   for `tinfoil_v2` and enforced for `tinfoil_v3`.

4. **Supply chain model differs**: Tinfoil uses Sigstore/GitHub Actions
   attestations rather than compose-hash/IMA. This is a stronger model (code
   measurement signed by transparent CI) but requires new verification code.

5. **Router architecture**: Tinfoil uses a confidential model router that
   handles multiple models. The attestation covers the router, not individual
   models. This is similar to nearcloud's gateway model. The router performs
   second-hop verification of each model enclave internally — teep trusts
   this because the router code is Sigstore-attested (see Authentication
   Chain 3 above).

6. **Model weight authentication is fully solved**: Unlike all existing teep
   providers, Tinfoil's model weights are cryptographically bound into the
   attestation chain via dm-verity + tinfoil-config.yml + Sigstore. The
   `measured_model_weights` factor can be set to `Pass` when the Sigstore
   supply chain verification succeeds (see Authentication Chain 4 above).
   This is a significant advantage over dstack providers where
   `measured_model_weights` always returns `Fail`.

7. **TEE.fail is unmitigated**: Tinfoil has no Proof of Cloud participation,
   no vTPM, and no DCEA. DDR5 memory bus key extraction attacks can forge
   TDX/SEV-SNP quotes with arbitrary measurements and REPORTDATA, defeating
   all software-layer security guarantees including Sigstore measurement
   matching and E2EE key binding. This is the same vulnerability affecting
   all TEE providers. The `cpu_id_registry` factor should be listed as a
   default `allow_fail` for both `tinfoil_v2` and `tinfoil_v3` until Tinfoil
   supports the hardware platform registry. When registry data becomes
   available, remove from `allow_fail` defaults to enforce it.
   See "Authentication Chain 5" for full analysis and the
   gpu_cpu_binding.md staged mitigation trajectory.

8. **GPU-CPU binding differs between providers**: `tinfoil_v3` binds GPU
   evidence into REPORTDATA (Option 2 from gpu_cpu_binding.md), preventing
   GPU splicing attacks in the absence of TEE.fail. `tinfoil_v2` has no GPU
   binding (`cpu_gpu_chain` = Skip). This is a key reason to migrate to
   `tinfoil_v3` when available.

9. **V3 attestation is not yet deployed or verified by any client**: The V3
   format exists in Tinfoil's CVM source code but has not been released. The
   tinfoil-go library only verifies V2. When V3 deploys, teep will be the
   first independent client to verify it, including GPU evidence binding and
   REPORTDATA hash verification. The `tinfoil_v3` provider is implemented
   now but cannot be tested against live endpoints until V3 deploys. Fixture-
   based offline tests cover the verification logic. Extra care is needed.

10. **V3 format may evolve before deployment**: Since V3 is unreleased, the
    format may change before it is deployed. The `tinfoil_v3` attester and
    verifier should be treated as provisional. If the format changes, update
    the V3 code without affecting `tinfoil_v2` (this is a key benefit of the
    two-provider model).

11. **Two-provider maintenance burden**: Having two provider variants adds
    code to maintain. This is mitigated by sharing ~90% of the logic in
    common files (EHBP, Sigstore, TLS transport, policy, TDX/SEV-SNP
    parsing). The V2-specific code (`attester_v2.go`, `reportdata_v2.go`) is
    small and self-contained. When V3 is fully deployed and tested, removing
    V2 requires deleting two files and one `case` block.
