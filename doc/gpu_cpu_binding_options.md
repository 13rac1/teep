# CPU–GPU Attestation Binding Options

**Factor:** `cpu_gpu_chain` — hardcoded `Fail` at [`report.go:453`](../internal/attestation/report.go:453)

---

## 1  Problem Statement

In the current NVIDIA Hopper + Intel TDX Confidential Computing stack, CPU
attestation (TDX quote) and GPU attestation (NVIDIA EAT / SPDM evidence) are
**two independent evidence chains** that share only a common nonce.  A remote
verifier cannot prove that the TDX quote and the GPU evidence originated from
the same physical machine.

### The attack — cross-machine evidence splicing

An attacker controlling two legitimate TEE machines can:

1. Obtain a valid TDX quote from Machine A (CPU TEE) using the client's nonce.
2. Obtain valid NVIDIA EAT evidence from Machine B (GPU TEE) with the same
   nonce.
3. Present both as a single attestation response.

Both pass all individual cryptographic checks.  The shared nonce proves only
that both were generated at roughly the same time in response to the same
challenge — not that they describe the same hardware.

### Why binding does not exist today

| Component | What it proves | What it does **not** prove |
|-----------|---------------|---------------------------|
| TDX Quote | CPU TEE identity, measurements, REPORTDATA binding | Which GPUs are attached |
| NVIDIA EAT | GPU firmware integrity, device identity (fused key) | Which CPU TEE it communicates with |
| Shared nonce | Temporal freshness | Physical co-location |

The SPDM session between the NVIDIA driver (inside the CVM) and the GPU
firmware establishes encrypted communication between CPU and GPU, but this
session is **local and not remotely attestable** — a remote verifier cannot
observe that the SPDM channel was established between a specific CPU TEE and a
specific GPU.

---

## 2  Option A — GPU Evidence Hash in TDX REPORTDATA (Software-Only)

### Overview

Embed a hash of the GPU attestation evidence inside the TDX REPORTDATA field
so the TDX quote cryptographically commits to the GPU evidence.  A remote
verifier can then confirm that the TDX-attested application saw exactly the GPU
evidence being presented.

### Binding strength

**Medium — application-layer binding.**  This does not prove hardware
co-location at the silicon level, but it proves that the CVM application
observed and committed to a specific GPU evidence blob before requesting its
TDX quote.  Since the CVM is the trust boundary (a compromised CVM is outside
the threat model), this is sufficient to prevent an external attacker from
splicing evidence from two separate machines.

### What infrastructure providers must implement

#### CVM-side changes (Near AI / dstack)

1. **Collect GPU EAT evidence first.**  The attestation flow must collect
   NVIDIA GPU evidence (the full EAT JSON payload) before generating the TDX
   quote.

2. **Compute a canonical hash of the GPU evidence.**  Use SHA-256 over the raw
   GPU EAT JSON bytes:
   ```
   gpu_evidence_hash = SHA256(nvidia_eat_json_bytes)
   ```

3. **Include the GPU hash in TDX REPORTDATA derivation.**  The current Near AI
   REPORTDATA layout (64 bytes) is:
   ```
   [0:32]  SHA256(signing_address_bytes || tls_fingerprint_bytes)
   [32:64] raw client nonce (32 bytes)
   ```
   This must be extended to cover the GPU evidence.  Options:

   - **Option A1 — Extend the first half:**
     ```
     [0:32]  SHA256(signing_address || tls_fingerprint || gpu_evidence_hash)
     [32:64] raw client nonce
     ```

   - **Option A2 — Three-part scheme (requires restructuring):**
     ```
     [0:16]  SHA256(signing_address || tls_fingerprint)[0:16]
     [16:32] gpu_evidence_hash[0:16]
     [32:64] raw client nonce
     ```
     Truncation weakens collision resistance; Option A1 is preferred.

   - **Option A3 — Hash-of-hashes:**
     ```
     [0:32]  SHA256(SHA256(signing_address || tls_fingerprint) || gpu_evidence_hash)
     [32:64] raw client nonce
     ```
     This is cleanest — the first 32 bytes bind both the TLS identity and GPU
     evidence chain, and the second 32 bytes remain the nonce.

4. **Include gpu_evidence_hash in the attestation response.**  The attestation
   JSON returned to clients must include the GPU evidence hash (or the raw GPU
   EAT payload from which it can be recomputed) so verifiers can reconstruct
   the REPORTDATA.

#### Client-side / verifier changes (teep)

1. **Recompute gpu_evidence_hash** from the presented NVIDIA EAT payload.
2. **Reconstruct the expected REPORTDATA** using the same derivation formula.
3. **Compare** the reconstructed REPORTDATA against the TDX quote's REPORTDATA
   field using constant-time comparison.
4. **Promote `cpu_gpu_chain`** from hardcoded `Fail` to a computed factor:
   - `Pass` if the REPORTDATA includes and matches the GPU evidence hash.
   - `Fail` if the GPU evidence hash does not match.
   - `Skip` if the provider does not implement this scheme.

#### Deployment considerations

- **Backwards compatibility:**  Providers that have not adopted the new
  REPORTDATA scheme will continue to produce attestations where `cpu_gpu_chain`
  is `Skip` or `Fail`.  The factor should remain outside `DefaultEnforced`
  initially and be promoted once providers adopt the scheme.

- **Ordering constraint:**  GPU evidence must be collected before the TDX
  report is generated.  This is already the natural order in most attestation
  flows: the GPU driver collects SPDM measurements first, then the TDX report
  is requested.

- **Canonical serialization:**  The GPU EAT JSON must be hashed byte-for-byte
  as received from the GPU driver.  Any re-serialization (pretty-printing,
  field reordering) will break the hash.  The raw bytes should be preserved.

- **No hardware changes required.**  This can be implemented entirely in the
  CVM application layer and the client verifier.

---

## 3  Option B — TDX Connect + TDISP (Hardware Binding)

### Overview

Intel TDX Connect and PCI-SIG TDISP (TEE Device Interface Security Protocol)
provide a hardware-enforced mechanism for extending the CPU TEE boundary to
include PCIe devices.  This eliminates bounce buffers and provides the missing
cryptographic binding between CPU and GPU attestation at the silicon level.

### Binding strength

**Strong — hardware-enforced.**  The CPU's TDX Connect report includes the
device's SPDM identity as part of the trust domain measurement.  PCIe link
encryption (IDE) ensures data integrity and confidentiality between CPU and GPU
without software intermediation.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CVM (Trust Domain)                   │
│                                                             │
│  ┌─────────────┐    TDISP/IDE     ┌──────────────────────┐  │
│  │  CPU TEE    │◄════════════════►│  GPU TEE (Blackwell) │  │
│  │  (TDX)      │   encrypted PCIe │  TDISP DSM           │  │
│  │             │   link           │                      │  │
│  │  TSM manages│                  │  SPDM Responder      │  │
│  │  device     │                  │  Device Identity     │  │
│  │  binding    │                  │  fused in silicon     │  │
│  └──────┬──────┘                  └──────────────────────┘  │
│         │                                                   │
│         ▼                                                   │
│  TDX Connect Report                                         │
│  - TD measurements                                          │
│  - Device SPDM identity ◄── hardware-attested binding       │
│  - IDE channel proof                                        │
└─────────────────────────────────────────────────────────────┘
```

### Protocol stack

| Layer | Protocol | Function |
|-------|----------|----------|
| Link encryption | **IDE** (Integrity and Data Encryption) | Encrypts all PCIe TLP traffic between CPU and GPU |
| Device interface | **TDISP** (TEE Device Interface Security Protocol) | Manages the device interface lifecycle, establishes trusted device interfaces (TDIs) |
| Device authentication | **SPDM** (Security Protocol and Data Model) | GPU authenticates to CPU using hardware-fused identity key; mutual attestation |
| Key management | **IDE_KM** | Manages encryption keys for the IDE stream |
| CPU-side coordination | **TSM** (TEE Security Manager) | Defines and enforces security policies for device integration |
| GPU-side coordination | **DSM** (Device Security Manager) | Works with TSM to establish secure channels |

### What infrastructure providers must implement

#### Hardware requirements

1. **CPU:**  Intel Xeon 6 processors (code name "Granite Rapids") or later with
   TDX Connect support.  Emerald Rapids / Sapphire Rapids CPUs (currently used
   by NearAI) **do not** support TDX Connect.

2. **GPU:**  NVIDIA Blackwell architecture (B200, B300, or later).  Hopper
   architecture (H100, H200) **does not** support TDISP.  Per the NVIDIA
   SecureAI whitepaper: *"To enable TDISP/IDE end-to-end, both the GPU and CPU
   should support it."*

3. **PCIe infrastructure:**  Any PCIe switch between CPU and GPU must support
   IDE flow-through.  Direct CPU-to-GPU PCIe connections do not require switch
   support.

4. **Firmware:**  Updated NVIDIA GPU VBIOS and driver with TDISP support.

#### Software / OS requirements

1. **Host OS:**  Linux kernel with TDX Connect and TDISP guest support.
   Ubuntu 25.10+ or equivalent with the required kernel patches.

2. **Guest OS:**  CVM kernel with TDISP device driver support for establishing
   secure device interfaces.

3. **NVIDIA driver:**  Updated kernel-mode and user-mode drivers that
   participate in the TDISP handshake and IDE key exchange instead of (or in
   addition to) the current bounce-buffer + SPDM-only approach.

4. **Attestation flow:**  The CVM's attestation agent must request a TDX
   Connect report (rather than a standard TDX report).  This report includes
   the SPDM device identity of attached GPUs as part of the trust domain
   measurement.

#### Verifier changes (teep)

1. **Parse TDX Connect reports.**  These extend the standard TDX quote format
   to include device identity claims.

2. **Validate device identity against NVIDIA's certificate chain.**  The SPDM
   device identity embedded in the TDX Connect report must chain to NVIDIA's
   Device Identity Root CA.

3. **Cross-reference.**  Confirm that the device identity in the TDX Connect
   report matches the device identity in the NVIDIA EAT evidence.

4. **Promote `cpu_gpu_chain` to `Pass`** when all cross-references succeed.

#### Deployment timeline

As of March 2026, the NVIDIA SecureAI whitepaper and Intel's announcements
indicate that:

- Granite Rapids processors with TDX Connect are **available** (5th and 6th
  Gen Xeon).
- Blackwell GPUs with TDISP support are **shipping** but TDISP software stack
  maturity is evolving.
- Intel and NVIDIA have demonstrated **bounce-buffer** composite attestation
  (NearAI's current approach) and are working toward TDISP-based direct
  integration.
- Full production readiness of the TDISP stack is expected in late 2026 / 2027.

---

## 4  Comparison

| Property | Option A: GPU hash in REPORTDATA | Option B: TDX Connect + TDISP |
|----------|--------------------------------|-------------------------------|
| **Binding level** | Application-layer | Hardware / silicon |
| **Threat model** | Prevents external attacker splicing; trusts CVM | Prevents even a compromised CVM from faking binding |
| **Hardware required** | Existing Hopper + any TDX CPU | Blackwell GPU + Granite Rapids CPU |
| **Software changes** | CVM attestation app + verifier | CVM kernel + NVIDIA driver + verifier |
| **Available today** | ✅ Yes (requires CVM app change by NearAI) | ⚠️ Hardware available; software stack maturing |
| **Implementation effort** | Low–medium | High (full stack change) |
| **Bounce buffer overhead** | Yes (unchanged) | No (TDISP/IDE eliminates bounce buffers) |
| **Standards-based** | No (proprietary REPORTDATA scheme) | Yes (PCI-SIG TDISP, DMTF SPDM, Intel TDX Connect) |

### Recommendation

1. **Immediate (2026):**  Implement Option A.  Request NearAI include the GPU
   evidence hash in their REPORTDATA derivation.  Update teep's
   `cpu_gpu_chain` factor to verify this binding.

2. **Medium-term (2026–2027):**  Track TDX Connect + TDISP readiness.  When
   NearAI upgrades to Blackwell + Granite Rapids, implement Option B as the
   primary binding mechanism.  Option A can remain as a fallback for
   Hopper-era deployments.

---

## 5  References

### Intel TDX Connect

- **Intel TDX Connect Architecture Specification**
  https://cdrdv2.intel.com/v1/dl/getContent/773614

- **Intel TDX Connect TEE-IO Device Guide (v0.6.5)**
  https://cdrdv2-public.intel.com/772642/whitepaper-tee-io-device-guide-v0-6-5.pdf

- **Confidential AI with GPU Acceleration: Bounce Buffers Offer a Solution Today** (Intel blog, March 2026)
  https://community.intel.com/t5/Blogs/Tech-Innovation/Artificial-Intelligence-AI/Confidential-AI-with-GPU-Acceleration-Bounce-Buffers-Offer-a/post/1740417

### NVIDIA Confidential Computing

- **NVIDIA Secure AI with Blackwell and Hopper GPUs** (whitepaper, WP-12554-001_v1.3)
  https://docs.nvidia.com/nvidia-secure-ai-with-blackwell-and-hopper-gpus-whitepaper.pdf

- **NVIDIA CC Deployment Guide for TDX** (SecureAI)
  https://docs.nvidia.com/cc-deployment-guide-tdx.pdf

- **Hopper Single GPU Attestation Example — Quick Start Guide** (NVIDIA)
  https://docs.nvidia.com/attestation/quick-start-guide/latest/attestation-examples/hopper_single_gpu.html

- **nvTrust: Ancillary Software for NVIDIA Trusted Computing Solutions**
  https://github.com/NVIDIA/nvtrust

### Composite Attestation

- **Seamless Attestation of Intel TDX and NVIDIA H100 TEEs with Intel Trust Authority** (Intel blog, December 2024)
  https://community.intel.com/t5/Blogs/Products-and-Solutions/Security/Seamless-Attestation-of-Intel-TDX-and-NVIDIA-H100-TEEs-with/post/1525587

- **GPU Remote Attestation with Intel Trust Authority** (documentation)
  https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-gpu-attestation.html

### Academic / Research

- **NVIDIA GPU Confidential Computing Demystified** (Gu et al., IBM Research + Ohio State, 2025)
  https://arxiv.org/html/2507.02770v1
  — In-depth security analysis of GPU-CC architecture, including attestation flow, SPDM session, and data protection mechanisms.

- **Securing AI Workloads with Intel TDX, NVIDIA Confidential Computing and Supermicro Servers** (Supermicro whitepaper)
  https://www.supermicro.com/white_paper/white_paper_Intel_TDX.pdf

### Standards

- **PCI-SIG TDISP 1.0** — TEE Device Interface Security Protocol
  https://pcisig.com/specifications/tee-device-interface-security-protocol-tdisp

- **DMTF SPDM** — Security Protocol and Data Model
  https://www.dmtf.org/standards/spdm

- **PCIe IDE** — Integrity and Data Encryption (part of PCIe 6.0+)
  https://pcisig.com/

- **IETF RATS** — Remote ATtestation procedureS Architecture (RFC 9334)
  https://www.rfc-editor.org/rfc/rfc9334

### Industry Context

- **Secure, Privacy & Verifiable LLMs with GPU TEEs** (Phala Network blog, April 2025)
  https://phala.com/posts/GPU-TEEs-is-Alive-on-OpenRouter
  — Covers NearAI, RedPill, and Phala implementations of GPU TEE for LLM inference.
