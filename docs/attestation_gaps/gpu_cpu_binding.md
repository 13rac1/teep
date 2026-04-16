# Hardware Attestation Binding Issues and Mitigations

**Date:** 2026-03-01
**Status:** Open

Two independent hardware security gaps in the Intel TDX + NVIDIA Hopper Confidential Computing stack — TDX attestation key extraction and missing CPU-to-GPU attestation binding — allow an attacker with physical access to completely subvert all attestation guarantees.  No compensating controls exist in the current hardware or protocol stack.  Five complementary mitigation options are evaluated, with a staged deployment trajectory from immediate verifier-side changes to medium-term hardware upgrades.

## The Problem

Two independent problems in the current Intel TDX + NVIDIA Hopper Confidential Computing stack undermine the integrity of hardware attestation.  These problems are independent, but their mitigation solutions have such a large degree of overlap that they are best discussed in tandem.

**Problem 1 — TDX attestation key extraction.**

[TEE.fail](https://tee.fail/) attacks
extract the actual TDX attestation *signing keys* via DDR5 memory bus
interposition.  With these keys an attacker can forge quotes with **arbitrary
measurements, firmware claims, and REPORTDATA** — fabricating what code is
running.  A forged quote is cryptographically indistinguishable from a legitimate one.

**Problem 2 — No CPU-to-GPU binding.**

CPU attestation (TDX quote) and GPU
attestation (NVIDIA EAT / SPDM evidence) are two independent evidence chains
sharing only a common nonce.  A remote verifier cannot prove both originated
from the same physical machine, which means it cannot prove that the authenticated GPU is actually being used at all.

## Impact

These problems compound: an attacker can forge or redirect CPU attestation
(Problem 1) and splice in GPU evidence from a different machine (Problem 2).
The combination means **all integrity and security guarantees of attestation
can be completely subverted** by an attacker with physical access to **any
Intel TDX and NVIDIA hardware**, not just your provider's hardware.

No compensating controls exist in the current hardware or protocol stack:

- **Security impact (Gap 1 — TEE.fail):** An attacker who extracts TDX attestation signing keys can forge quotes with arbitrary measurements, code claims, and REPORTDATA.  Forged quotes pass Intel's DCAP verification at the highest trust level.  The attacker can impersonate any CVM, bind their own signing keys in REPORTDATA, and intercept all E2EE traffic.

- **Security impact (Gap 2 — CPU-to-GPU splicing):** Without CPU-to-GPU binding, any attacker controlling two legitimate machines can splice GPU evidence from one into the attestation response of the other.  Gap 2 is independently exploitable *without* TEE.fail.

- **Compound security impact:** When combined, TEE.fail (Gap 1) defeats any application-layer GPU binding (Gap 2 mitigations) because forged REPORTDATA can contain fabricated GPU evidence hashes.  An attacker establishes E2EE with their own signing key and decrypts all inference traffic — complete confidentiality loss.

---

## Technical Background

Two complementary mitigation approach categories exist for these gaps:

1. **Trust-based platform identity (Proof of Cloud):**

   A [vendor-neutral alliance](https://proofofcloud.org/) maintains a public
   registry mapping hardware IDs (PPIDs, Chip IDs) to verified physical
   facilities.  Alliance members independently verify hardware locations
   through physical facility visits, automated zk-TLS / vTPM proofs, and/or
   continuous monitoring
   ([three levels are defined](https://proofofcloud.org/verification-methods)).

   Consumers trust the alliance's registry to confirm that a PPID belongs to
   a machine in a secured data center.  This raises the bar by requiring an
   attacker to compromise both the TEE *and* the physical verification process.
   However, it depends on:
   - **Trust in the alliance:**  proofofcloud.org must be trustworthy.
   - **No prior compromise:**  If a machine's TEE signing keys were extracted
     *before* enrollment in the registry (or if an enrolled machine is
     subsequently compromised), the attacker holds valid signing keys for a
     PPID that *is* in the registry.  Forged quotes carrying that registered
     PPID would pass the registry check.
   - **Registry freshness:**  Stale entries weaken assurance.

   Proof of Cloud is therefore a meaningful barrier but not a complete
   mitigation of TEE.fail attestation spoofing.

2. **Cryptographic dual attestation (DCEA / CCxTrust / CNCF):**

   Three similar proposed protocols can bind CVM attestation to a second
   hardware root of trust (typically a platform TPM or vTPM), generating
   self-contained cryptographic proofs:

   - [DCEA](https://arxiv.org/html/2510.12469v1) (Data Center Execution
   Assurance) cross-checks TDX RTMRs against vTPM PCR values with a sealed
   Attestation Key (AK), proving the CVM runs on a specific physical platform.
   - [CCxTrust](https://arxiv.org/html/2412.03842v2) extends this to a
   vendor-neutral composite attestation framework using collaborative TEE +
   TPM roots of trust, with an owner-controlled Certificate Authority.
   - [CNCF hybrid attestation](https://www.cncf.io/blog/2025/10/08/a-tpm-based-combined-remote-attestation-method-for-confidential-computing/)
   aggregates TEE and TPM evidence into a combined report.  These
   proofs can be verified by **any remote verifier directly** (including API
   consumers at request time) without trusting a third-party registry.

   Live TPM authentication is **strictly stronger** than registry-based
   defenses: even if an attacker extracts TDX signing keys via TEE.fail, they
   cannot reproduce the TPM quote (signed by a sealed AK bound to the
   platform's measured boot state).  The TPM AK is not extractable via the
   same memory bus attack, and it produces fresh proofs at attestation time
   that are bound to the specific platform.

   Unlike Proof of Cloud, this
   defense is **not vulnerable to pre-enrollment compromise**: a machine whose
   TEE keys were previously extracted cannot produce valid TPM-backed
   attestation using those extracted keys.

   Proof of Cloud's Level 2 vTPM method references DCEA, but the alliance's
   current verification levels do not require providers to expose live DCEA
   proofs to end-user API consumers.  Even Level 3 (continuous monitoring)
   verifies proofs on behalf of consumers rather than making them available
   inline.  For teep's threat model (where the proxy must independently verify
   attestation at request time), **direct proof availability from
   providers is the stronger goal**, with Proof of Cloud registry lookups
   serving as a complementary defense-in-depth layer.

---

## Detailed Gap Analysis

### Gap 1 — TDX attestation key extraction (TEE.fail)

[TEE.fail](https://tee.fail/) (Georgia Tech / Purdue / Synkhronix, 2025)
demonstrates practical DDR5 memory bus interposition that recovers ECDSA
attestation *signing keys* from Intel's PCE for under $1,000 in portable
equipment.  This breaks SGX and TDX attestation on fully patched systems.

With these keys, an attacker can forge TDX quotes with:
- Arbitrary measurements (MRTD, RTMRs) — fabricating what code is running
- Arbitrary firmware claims — impersonating any CVM configuration
- Arbitrary REPORTDATA — binding attacker-controlled signing keys

A forged quote is cryptographically indistinguishable from a legitimate one
and passes Intel's DCAP verification at the highest trust level.  Intel has
[acknowledged the vulnerability](https://www.intel.com/content/www/us/en/security-center/announcement/intel-security-announcement-2025-10-28-001.html)
but no hardware fix is available for current-generation processors.

### Gap 2 — No CPU-to-GPU binding

CPU attestation (TDX quote) and GPU attestation (NVIDIA EAT / SPDM evidence)
are two entirely independent evidence chains.  They share only a common nonce
provided by the client.  The TDX quote proves "this CVM has these
measurements."  The GPU EAT evidence proves "this GPU has these measurements
and signed with this nonce."  Neither evidence chain references or commits to
the other.

A remote verifier receiving both evidence blobs **cannot prove they originated
from the same physical machine**.  The nonce prevents replay (old evidence
cannot be reused with a new nonce), but it does not prevent splicing — an
attacker who controls two machines can collect fresh GPU evidence from Machine A
(with the client's nonce) and a fresh TDX quote from Machine B (with the same
nonce), then present them together.

NVIDIA GPU attestation keys are immune to TEE.fail — the GPU's Identity Key
(IK) is burned into on-die fuses and the Attestation Key (AK) lives in
GPU-local memory (HBM, on-package), neither of which is accessible via DDR5
memory bus interposition.  However, this does not help with the binding
problem: authentic GPU evidence from a real GPU can be freely combined with a
TDX quote from any machine.

### Compound exploitation

When both gaps are combined, an attacker can:

1. Extract TDX attestation signing keys from any Intel TDX machine (Gap 1)
2. Forge a TDX quote with attacker-controlled REPORTDATA (binding attacker's
   signing key) and legitimate-looking measurements
3. Obtain authentic GPU evidence from any real GPU by requesting attestation
   with the client's nonce (Gap 2 — GPU evidence is not bound to TDX quote)
4. Present the forged TDX quote alongside the authentic GPU evidence

The result: all verification checks pass.  The client establishes E2EE with
the attacker's signing key.  The attacker decrypts all inference traffic.

This compound attack does **not** require the attacker to compromise the
provider's actual hardware — any Intel TDX + NVIDIA hardware suffices for key
extraction, and GPU evidence can be obtained from any running CVM via a
standard attestation API request.

---

## Remediation

Five mitigation mechanisms are evaluated with respect to their ability to
address CPU identity binding (Gap 1), CPU-to-GPU binding (Gap 2), or both:

1. **[Option 1 — Proof of Cloud Hardware Registry](#option-1--proof-of-cloud-hardware-registry-cpu-identity-only):**
   Trust-based CPU identity binding.  The
   [Proof of Cloud](https://proofofcloud.org/) alliance maintains a public
   registry mapping hardware IDs (PPIDs) to verified data center facilities.
   Conditionally mitigates Gap 1 (TEE.fail) — effectiveness depends on the
   trustworthiness of the alliance and on enrolled machines not having been
   previously compromised.  Deployed today for teep's `cpu_id_registry` and
   `gateway_cpu_id_registry` factors.  Does not address GPU binding (Gap 2).

2. **[Option 2 — GPU Evidence Hash in TDX REPORTDATA](#option-2--gpu-evidence-hash-in-tdx-reportdata-software-only):**
   Application-layer CPU-to-GPU binding.  The CVM hashes GPU EAT evidence
   into the TDX REPORTDATA field.  Deployable today on existing hardware with
   a CVM app change.  Addresses Gap 2 only.  Does not defend against
   [TEE.fail](https://tee.fail/)-class key extraction (Gap 1) by itself.

3. **[Option 3 — vTPM / DCEA Platform-Mediated Binding](#option-3--vtpm--dcea-platform-mediated-binding-cpu-identity--gpu):**
   Platform-level binding via measured boot.  Extends the
   [DCEA](https://arxiv.org/html/2510.12469v1) protocol to bind both **CPU
   identity** (via platform TPM EKC chain) and **GPU SPDM identity** (via
   vTPM PCR extension) to TDX RTMRs.  Addresses both gaps.  Partially
   deployable today (GCP vTPM exists; GPU PCR extension needed).  Ideally
   these proofs would be exposed directly to API consumers (not only to a
   registry like [Proof of Cloud](https://proofofcloud.org/)).

4. **[Option 4 — Composite Attestation via TPM + TEE Collaborative Trust](#option-4--composite-attestation-via-tpm--tee-collaborative-trust):**
   Vendor-neutral composite evidence.  Bundles TEE and TPM attestation under
   a joint report with an owner-controlled CA.  Works across TDX, SEV-SNP,
   and ARM CCA.  Addresses both gaps.  Prototype stage.

5. **[Option 5 — TDX Connect + TDISP](#option-5--tdx-connect--tdisp-hardware-binding):**
   Hardware / silicon binding.  Intel TDX Connect incorporates GPU SPDM
   identity into the trust domain report via PCIe IDE link encryption.
   Addresses Gap 2 at the hardware level; combined with platform TPM addresses
   both gaps. This option **requires Blackwell GPUs + Granite Rapids CPUs**;
   software stack maturing.

### Implementation Options

#### Option 1 — Proof of Cloud Hardware Registry (CPU Identity Only)

##### Overview

The [Proof of Cloud](https://proofofcloud.org/) alliance maintains a public,
append-only, signed registry mapping hardware IDs (Intel DCAP PPIDs, AMD
SEV-SNP Chip IDs) to verified physical data center facilities.  Alliance
members independently verify hardware locations through physical facility
visits, zk-TLS proofs, vTPM claims, and continuous monitoring.  A remote
verifier queries the registry to confirm that a given PPID corresponds to a
machine in a known, secured facility.

##### Addresses

**Gap 1 partial mitigation (TEE.fail / CPU identity).**  If an attacker
extracts TDX attestation keys via [TEE.fail](https://tee.fail/) and generates
forged quotes on unauthorized hardware, the forged quote will carry a PPID
that is either not in the registry or is mapped to a different facility.  The
verifier rejects the quote based on the PPID mismatch.

However, this only fully mitigates TEE.fail under two critical assumptions:

1. **proofofcloud.org is trustworthy** — the registry operator and alliance
   members must be honest and competent.
2. **Enrolled machines have not been previously compromised** — if an
   attacker extracted signing keys from a machine *before* its enrollment in
   the registry, or compromises an enrolled machine at any point, the
   attacker holds valid signing keys for a PPID that *is* in the registry.
   Since TEE.fail enables complete attestation forgery (arbitrary
   measurements, code claims, REPORTDATA), a forged quote carrying a
   legitimate registered PPID would pass the registry check.

Does **not** address Gap 2 (CPU-to-GPU binding).  The registry contains no
information about GPU device identity.

##### Binding strength

**Low-medium — trust-based, conditional on no prior compromise.**  Security
depends on the integrity of the alliance's verification process, the freshness
of registry entries, and the assumption that enrolled machines were not
compromised before or during enrollment.  An attacker would need to compromise
both the TEE *and* the alliance's multi-party verification, which is a
significant barrier — but if the attacker already holds signing keys for an
enrolled PPID (from a prior TEE.fail attack on that machine), the registry
  provides no defense.  Unlike cryptographic dual attestation (Options 3–5),
this is not a self-contained proof — it requires trusting the registry
operator and assuming a clean enrollment history.

##### What teep implements today

The `cpu_id_registry` and `gateway_cpu_id_registry` factors query the Proof
of Cloud registry via a multi-peer quorum protocol:

1. **Stage 1:** Teep sends the full hex-encoded TDX quote to multiple
   registry peers concurrently (the trust servers extract the PPID on their
   side).  Requires quorum (currently 3 peers).
2. **Stage 2:** Chains opaque partial signatures through peers sequentially
   to produce a signed JWT confirming registration status.
3. **Verification:** Validates the JWT (EdDSA signature + claims when a
   signing key is configured; claims-only otherwise) and reports `Pass` if
   the PPID is found in the registry, `Fail` if explicitly not found, `Skip`
   if the registry query was attempted but failed (or in equivalent
   skip-classified cases such as offline mode with a PPID / a device ID with
   no registry), and `Fail` when no PoC result and no PPID/device ID exist,
   i.e. no CPU ID registry check is available/configured.

##### Limitations

- **Registry freshness:**  Point-in-time verification.  Hardware could be
  physically moved after the last verification.  Level 3 (continuous
  monitoring) mitigates this but is not universally deployed.
- **Trust in alliance:**  Consumers must trust the alliance members performed
  verification correctly.  Cross-verification by multiple independent members
  reduces this risk.
- **Pre-enrollment or post-enrollment compromise:**  If TEE signing keys were
  extracted from a machine *before* it was enrolled in the registry, or from
  an enrolled machine at any time, the attacker can forge quotes carrying
  that machine's legitimate PPID.  These forged quotes pass the registry
  check because the PPID is valid.  The registry cannot detect this unless
  continuous monitoring (Level 3) independently detects the compromise.
  Mechanisms that provide live TPM authentication of TEE attestation (Options
  3–5) are strictly stronger because previously extracted TEE keys cannot
  produce valid TPM-backed attestation.
- **No GPU coverage:**  The registry maps CPU PPIDs only.  GPU device identity
  (NVIDIA SPDM certificates) is not tracked.
- **No self-contained proof:**  Unlike DCEA, the verifier cannot independently
  check platform binding — it relies on the registry as an oracle.

##### Deployment status

Deployed in teep today.  `cpu_id_registry` is evaluated for inference CVM
attestation; `gateway_cpu_id_registry` for gateway CVM attestation.

#### Option 2 — GPU Evidence Hash in TDX REPORTDATA (Software-Only)

##### Overview

Embed a hash of the GPU attestation evidence inside the TDX REPORTDATA field
so the TDX quote cryptographically commits to the GPU evidence.  A remote
verifier can then confirm that the TDX-attested application saw exactly the GPU
evidence being presented.

##### Binding strength

**Medium — application-layer binding.  Addresses Gap 2 only.**  This does not
prove hardware co-location at the silicon level, but it proves that the CVM
application observed and committed to a specific GPU evidence blob before
requesting its TDX quote.  Since the CVM is the trust boundary (a compromised
CVM is outside the threat model), this is sufficient to prevent an external
attacker from splicing evidence from two separate machines.

**Does not address Gap 1 (TEE.fail).**  If an attacker extracts TDX
attestation *signing keys*, they can forge a TDX quote with arbitrary
measurements and REPORTDATA — including a fabricated GPU hash claiming to bind
to any GPU evidence.  Option 2 is only effective when combined
with a Gap 1 mitigation (Option 1, 3, 4, or 5).

##### What infrastructure providers must implement

###### CVM-side changes (Near AI / dstack)

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

   This must be extended to cover the GPU evidence. For example:
   ```
   [0:32]  SHA256(signing_address || tls_fingerprint || gpu_evidence_hash)
   [32:64] raw client nonce
   ```

4. **Include gpu_evidence_hash in the attestation response.**  The attestation
   JSON returned to clients must include the GPU evidence hash (or the raw GPU
   EAT payload from which it can be recomputed) so verifiers can reconstruct
   the REPORTDATA.

###### Client-side / verifier changes (teep)

1. **Recompute gpu_evidence_hash** from the presented NVIDIA EAT payload.
2. **Reconstruct the expected REPORTDATA** using the same derivation formula.
3. **Compare** the reconstructed REPORTDATA against the TDX quote's REPORTDATA
   field using constant-time comparison.
4. **Promote `cpu_gpu_chain`** from hardcoded `Fail` to a computed factor:
   - `Pass` if the REPORTDATA includes and matches the GPU evidence hash.
   - `Fail` if the GPU evidence hash does not match.
   - `Skip` if the provider does not implement this scheme.

###### Deployment considerations

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

##### Tinfoil V3: Existing implementation of Option 2

Tinfoil's V3 attestation format is the first concrete implementation of Option 2. V3 extends the basic approach to include both GPU and NVSwitch evidence hashes in REPORTDATA:

```
REPORTDATA[0:32] = SHA-256(tls_key_fp || hpke_key || nonce || gpu_evidence_hash || nvswitch_evidence_hash)
REPORTDATA[32:64] = zeros
```

Where `gpu_evidence_hash = SHA-256(raw_gpu_spdm_json)` and `nvswitch_evidence_hash = SHA-256(raw_nvswitch_spdm_json)`. The CPU hardware signs REPORTDATA as part of the TDX or SEV-SNP quote, so both hashes are hardware-authenticated.

The V3 attestation endpoint (`GET /.well-known/tinfoil-attestation?nonce=<64hex>`) collects fresh SPDM evidence from all GPUs and NVSwitches via NVML APIs with the client-supplied nonce passed through to the GPU hardware. Evidence is returned in the response as `gpu` and `nvswitch` JSON fields. For 8-GPU HGX systems, PCIe topology validation (8 GPUs + 4 NVSwitches mesh integrity) is enforced at boot time.

GPU attestation is boot-time fail-closed: if `nvattest` local verification fails, the CVM aborts boot. This is enforced by CVM code that is itself verified via Sigstore supply chain attestation.

Teep verifies the binding by extracting `gpu` and `nvswitch` as `json.RawMessage` (preserving raw bytes — re-serialization would break the hash), recomputing the evidence hashes, reconstructing expected REPORTDATA, and constant-time comparing against the verified CPU quote. When the binding verifies, `cpu_gpu_chain` is promoted to `Pass`.

Tinfoil V3's residual risks are the same as Option 2 in general: it does **not** address Gap 1 (TEE.fail). The GPU evidence relay attack described in [Stage 2 analysis](#gpu-evidence-relay-attack-stage-2-residual-risk) applies. Tinfoil does not currently implement Proof of Cloud (Option 1), DCEA (Option 3), or TDX Connect (Option 5).

#### Option 3 — vTPM / DCEA Platform-Mediated Binding (CPU Identity + GPU)

##### Overview

The [DCEA](https://arxiv.org/html/2510.12469v1) (Data Center Execution Assurance)
protocol binds CVM attestation to platform-level Trusted Platform Module (TPM)
evidence, generating a cryptographic proof that the CVM executes on specific
physical hardware.  DCEA was designed to address the physical-access gap
exposed by the [TEE.fail](https://tee.fail/) attacks — DDR5 memory bus
interposition that can extract TDX/SGX attestation keys from machines outside
physically secured data centers.

DCEA addresses **both binding gaps simultaneously**:

- **Gap 1 (CPU identity / TEE.fail):**  The vTPM's Attestation Key (AK) is
  sealed to the platform's measured boot state (PCR values).  The AK's
  Endorsement Key Certificate (EKC) is issued by the cloud provider, chaining
  to the provider's root CA.  Even if an attacker extracts TDX attestation
  keys via TEE.fail, the TPM quote — signed by a sealed AK bound to the
  platform — cannot be reproduced on different hardware.  This binds the
  attestation to a specific physical machine.

- **Gap 2 (CPU-to-GPU):**  The core RTMR ↔ PCR cross-checking mechanism can
  be **extended to transitively bind GPU attestation** to the CVM and its
  physical platform.  If the GPU driver's SPDM device identity is extended
  into the vTPM's PCR chain, and the AK is sealed to those PCR values, a
  remote verifier can confirm that the CPU TEE, GPU, and platform TPM all
  describe the same physical machine.

The [Proof of Cloud](https://proofofcloud.org/) alliance references DCEA as
one of its Level 2 automated verification methods ("vTPM Cryptographic
Claims"), but the alliance's model is a **registry**: verification happens
between providers and alliance members, and consumers trust the registry
rather than verifying DCEA proofs directly.  For teep's purposes, the stronger
goal is for providers to **expose DCEA proofs in-band in their attestation API
responses**, enabling direct client-side verification without trusting a
third-party registry.

The key insight is that Intel TDX Runtime Measurement Registers (RTMRs) share
a well-defined mapping with vTPM Platform Configuration Registers (PCRs).  If
the GPU driver's SPDM device identity and measurements are extended into the
vTPM's PCR chain, and the vTPM's AK is sealed to those PCR values, a remote
verifier can confirm that the CPU TEE, GPU, and platform TPM all describe the
same physical machine.

##### Background: TEE.fail and the physical-access threat

See the [problem description](#the-problem) above for full details on
[TEE.fail](https://tee.fail/).  In brief: DDR5 memory bus interposition
(under $1,000 portable device) recovers ECDSA attestation *signing keys* from
Intel's PCE, enabling complete forgery of TDX quotes — arbitrary measurements,
code claims, and REPORTDATA — that pass Intel's DCAP verification at the
highest trust level.

The [DCEA](https://arxiv.org/html/2510.12469v1) protocol addresses this by
binding CVM attestation to a second root of trust (the platform TPM / vTPM),
whose Endorsement Key Certificate (EKC) is issued by the cloud provider.  Even
if an attacker extracts TDX attestation keys, the attestation cannot be
replayed on hardware outside the provider's data center because the TPM
quote — signed by a sealed AK bound to the platform's measured boot state —
cannot be reproduced off-platform.  These proofs are cryptographic
and self-contained: **any verifier** can validate them if the provider includes
them in the attestation response.

##### How DCEA addresses both binding gaps

The [DCEA protocol](https://arxiv.org/html/2510.12469v1) was originally designed
for CVM-to-platform binding (proving the CVM runs on specific cloud hardware),
which directly addresses Gap 1 (CPU identity / TEE.fail).
To additionally address Gap 2 (CPU-to-GPU binding), the GPU's SPDM device
identity is extended into the vTPM's PCR chain, adding a third leg to the
trust chain:

```
┌──────────────────────────────────────────────────────────────────┐
│                     Physical Platform (Cloud)                    │
│                                                                  │
│  ┌──────────┐     vTPM PCRs      ┌──────────────────────────┐   │
│  │ Platform │  PCR 0-7: boot     │         CVM (TD)         │   │
│  │ TPM/vTPM │  PCR 8-15: OS      │                          │   │
│  │          │  PCR N: GPU SPDM   │  RTMR[0-2] ↔ PCR map   │   │
│  │  AK sealed   identity hash   │  report_data = H(AK_pub) │   │
│  │  to PCRs │                    │                          │   │
│  └────┬─────┘                    │   ┌──────────────────┐   │   │
│       │                          │   │  NVIDIA GPU      │   │   │
│       │    EKC chain → provider  │   │  SPDM session    │   │   │
│       │                          │   │  EAT evidence    │   │   │
│       │                          │   └──────────────────┘   │   │
│       │                          └──────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘

Verifier checks:
  1. TD RTMRs ↔ vTPM PCRs match  (CVM bound to platform — Gap 1)
  2. GPU SPDM identity in PCRs   (GPU bound to platform — Gap 2)
  3. NVIDIA EAT matches PCR GPU  (GPU evidence consistent — Gap 2)
  4. AK sealed to PCRs           (no cross-machine replay — Gap 1 + 2)
  5. EKC chains to provider      (platform is in data center — Gap 1)
```

##### Binding strength

**Medium-high — platform-mediated binding via measured boot.**  This is
stronger than Option 2 (application-layer) because the binding is rooted in
the platform's measured boot chain rather than a single application-layer hash.
The vTPM's AK is sealed to the PCR values by TPM hardware policy, so it cannot
be used on a different machine.  However, it is weaker than Option 5 (hardware
silicon binding) because it still depends on the host software stack correctly
measuring the GPU into the PCRs.

##### TDX RTMR ↔ vTPM PCR mapping

Per the [DCEA protocol](https://arxiv.org/html/2510.12469v1) and Intel TDX documentation, measurements overlap as
follows:

| TDX Register | vTPM PCRs | Covered Components |
|---|---|---|
| MRTD | PCR 0 | Virtual firmware (immutable image) |
| RTMR[0] | PCR 1, 7 | Virtual firmware data & configuration |
| RTMR[1] | PCR 2–5 | OS kernel, initrd, boot parameters |
| RTMR[2] | PCR 8–15 | OS applications / user-space integrity |
| RTMR[3] | — | Reserved (runtime extensions) |

GPU SPDM device identity and measurements would be extended into PCRs in the
RTMR[2] range (PCR 8–15), covering OS-level device enumeration and driver
initialization.

##### What infrastructure providers must implement

###### CVM-side changes (Near AI / dstack)

1. **Expose a vTPM to the CVM.**  The cloud provider must provision a vTPM
   instance for the TD.  On Google Cloud, vTPM is already available for TDX
   CVMs.  NearAI's dstack would need to expose vTPM to their TD guests.

2. **Extend GPU SPDM identity into vTPM PCRs.**  During CVM boot, after the
   NVIDIA driver establishes the SPDM session with the GPU:
   - Compute `gpu_spdm_hash = SHA256(gpu_device_certificate_bytes)`.
   - Extend this hash into a designated vTPM PCR (e.g., PCR 14 or PCR 15)
     using `TPM2_PCR_Extend`.
   - This captures the GPU's hardware-fused device identity in the platform
     measurement chain.

3. **Include AK public key hash in TD report_data.**  The CVM embeds
   `SHA256(AK_public_key)` in the TDX report's `report_data` field (or
   `MRCONFIGID`), binding the TD attestation to the specific vTPM instance.

4. **Seal the vTPM AK to PCR policy.**  The AK private key is sealed under a
   TPM policy bound to PCRs 0–7 (boot chain) and the GPU-extended PCR.  The
   AK can only sign quotes when the platform matches the expected measured
   state including the expected GPU.

5. **Return composite evidence.**  The attestation response includes:
   - The TDX quote (with AK hash in report_data).
   - The vTPM quote (PCR values signed by the sealed AK).
   - The vTPM's EKC chain (proving platform provenance).
   - The NVIDIA EAT evidence (GPU attestation).

###### Verifier changes (teep)

1. **Verify TDX quote** — standard TDX verification via Intel QE signature.
2. **Verify vTPM quote** — check AK signature, verify EKC chains to known
   cloud provider root.
3. **Cross-check AK binding** — confirm `SHA256(AK_public_key)` matches the
   TDX report's `report_data` field.
4. **Cross-check RTMR ↔ PCR consistency** — reconstruct expected PCR values
   from the TDX RTMRs and compare.
5. **Verify GPU in PCRs** — recompute `SHA256(gpu_device_certificate)` from
   the NVIDIA EAT evidence and confirm it matches the GPU-extended PCR value.
6. **Promote `cpu_gpu_chain`** to a computed factor:
   - `Pass` if all cross-checks succeed.
   - `Fail` if any mismatch is detected.
   - `Skip` if the provider does not expose a vTPM or does not extend GPU
     measurements.

##### Security analysis

The [DCEA protocol](https://arxiv.org/html/2510.12469v1) identifies six attack classes (A1–A6) and demonstrates mitigations for
each.  Applied to both CPU identity (Gap 1) and GPU binding (Gap 2):

| Attack | Gap | Mitigation |
|--------|-----|------------|
| **[TEE.fail](https://tee.fail/) key extraction** (attestation forgery) | Gap 1 | Even with extracted TDX keys, the attacker cannot reproduce the TPM quote signed by the platform-sealed AK; EKC chains to the provider's data center |
| **Cross-machine CPU splicing** (quote from wrong machine) | Gap 1 | AK is sealed to PCRs of the specific platform; RTMR ↔ PCR cross-check detects mismatch; EKC chain pinpoints platform identity |
| **Cross-machine GPU splicing** (GPU evidence from different machine) | Gap 2 | GPU SPDM identity is in the PCRs; AK is sealed to those PCRs; a quote from Machine B's vTPM will not contain Machine A's GPU identity |
| **vTPM quote forgery** | Gap 1 + 2 | AK sealed to PCR state; forged quotes fail signature or PCR policy |
| **Relay / proxy** | Gap 1 + 2 | AK hash embedded in TD report_data; nonce freshness; concurrent challenges with timing bounds |
| **GPU evidence replay** | Gap 2 | GPU SPDM hash in PCRs binds to platform; replayed GPU evidence mismatches the vTPM quote |

##### Deployment considerations

- **vTPM availability:**  Google Cloud already exposes vTPM for TDX CVMs and
  is the only platform with a DCEA reference implementation (both CVM and
  bare-metal scenarios).  Azure provides vTPM for TDX confidential VMs, making
  DCEA Scenario 1 feasible in principle, though Azure's paravisor architecture
  introduces PCR measurement overlap challenges that are not yet validated for
  DCEA.  AWS does not support Intel TDX.  See
  [DCEA cloud provider coverage](#dcea-cloud-provider-coverage) for the full
  provider matrix from the DCEA paper.  NearAI / dstack would need to add vTPM
  support to their attestation flow regardless of cloud platform.

- **GPU PCR extension:**  The NVIDIA GPU driver currently does not extend SPDM
  measurements into vTPM PCRs.  This requires a change to the CVM's
  attestation agent or GPU driver initialization scripts.

- **Bare-metal variant:**  On bare-metal deployments ([DCEA](https://arxiv.org/html/2510.12469v1) Scenario II), a
  discrete hardware TPM replaces the vTPM.  Intel TXT extends measurements
  into PCR 17–18, providing even stronger binding.  The GPU SPDM identity
  would be extended into a TXT-measured PCR.

- **Privacy:**  The vTPM EKC encodes deployment metadata (cloud region,
  availability zone).  If privacy is required, the [DCEA protocol](https://arxiv.org/html/2510.12469v1) proposes
  performing the cross-check inside the TD and releasing only a boolean
  result, or using zero-knowledge proofs for set membership.

- **Direct vs. registry verification:**  The [Proof of Cloud](https://proofofcloud.org/)
  alliance can perform DCEA verification on behalf of consumers (via its
  Level 2/3 vTPM method) and publish results to a trusted registry.  This is
  useful as a fallback and for providers who cannot yet expose DCEA proofs in
  their API.  However, for teep's fail-closed model, **direct DCEA proof
  verification at request time is strongly preferred** — it eliminates trust
  in the registry operator and provides real-time assurance rather than
  point-in-time registry entries.  Providers should be encouraged to include
  vTPM quotes and EKC chains in their attestation API responses.

- **Compatible with Option 2:**  Option 3 is orthogonal to Option 2.  Both
  can be implemented simultaneously for defense in depth — Option 2 provides
  application-layer binding via REPORTDATA, while Option 3 provides
  platform-level binding via vTPM PCRs.

#### Option 4 — Composite Attestation via TPM + TEE Collaborative Trust

##### Overview

The [CCxTrust](https://arxiv.org/html/2412.03842v2) architecture and the [CNCF](https://www.cncf.io/blog/2025/10/08/a-tpm-based-combined-remote-attestation-method-for-confidential-computing/) hybrid
attestation proposal describe composite attestation protocols
that integrate TEE-native reports with TPM-based quotes into a unified
evidence bundle.  Unlike Option 3 (which focuses on [DCEA](https://arxiv.org/html/2510.12469v1)'s RTMR-PCR
cross-checking), this option uses a **joint attestation report** that combines
TEE and TPM evidence under a single signed envelope, with the TPM providing an
independent measurement root that covers GPU device identity.

##### Architecture

[CCxTrust](https://arxiv.org/html/2412.03842v2) defines three collaborative roots of trust:

- **Root of Trust for Measurement (RTM):**  TEE and TPM independently measure
  the system.  The TEE measures the CVM (MRTD, RTMRs), while the TPM measures
  the platform boot chain and attached devices (PCRs).

- **Root of Trust for Report (RTR):**  TEE and TPM collaboratively generate a
  composite attestation report.  Both reports are signed and bundled, with
  cross-references preventing splicing.

- **Root of Trust for Storage (RTS):**  TPM provides sealed storage for keys,
  enabling persistence across reboots and migration.

For GPU binding, the TPM's independent measurement chain captures:
1. Platform boot (BIOS, firmware) → PCR 0–7.
2. OS and hypervisor (via TXT if bare-metal) → PCR 17–18.
3. GPU driver initialization and SPDM device discovery → extended PCR.
4. The composite report bundles the TEE quote, TPM quote, and GPU EAT evidence
   with cross-referencing nonces and measurement hashes.

##### Binding strength

**Medium — composite evidence with independent roots.**  The strength comes
from requiring two independent roots of trust (TEE hardware + TPM hardware) to
agree on the platform state.  An attacker must compromise both roots
simultaneously to splice evidence.  Weaker than Option 5 (no silicon-level
device binding) but provides a vendor-neutral framework that works across Intel
TDX, AMD SEV-SNP, and heterogeneous accelerators.

##### What infrastructure providers must implement

###### CVM-side changes

1. **Deploy a Confidential TPM (CTPM)** inside the CVM or at the highest
   privilege level (VMPL 0 for AMD, VTL for Intel).  The CTPM runs as a
   trusted service providing TPM functionality to the CVM, isolated from the
   host.

2. **Implement GPU measurement extension.**  The CVM's attestation agent
   collects GPU SPDM evidence and extends it into the CTPM's PCRs before
   generating the composite report.

3. **Generate a composite attestation report.**  The attestation agent:
   - Requests a TEE quote (TDX or SEV-SNP).
   - Requests a TPM quote from the CTPM over the relevant PCRs.
   - Bundles both with the NVIDIA EAT evidence.
   - Signs the bundle or includes cross-referencing hashes (e.g., the TPM
     quote hash in the TEE report_data).

4. **Owner CA registration.**  In the [CCxTrust](https://arxiv.org/html/2412.03842v2) model, the platform registers
   with an Owner Certificate Authority (OCA) that functions as both the TEE's
   OCA and the TPM's Privacy CA.  This decouples trust from the CPU vendor
   (Intel/AMD) and the GPU vendor (NVIDIA).

###### Verifier changes (teep)

1. **Parse the composite report** — extract TEE quote, TPM quote, and GPU
   EAT evidence.
2. **Verify each component independently** — TEE quote via vendor (Intel QE),
   TPM quote via EKC/AK chain, GPU EAT via NVIDIA certificate chain.
3. **Cross-check consistency** — confirm shared nonces, matching measurement
   hashes, and GPU device identity present in both the TPM PCRs and the NVIDIA
   EAT.
4. **Verify OCA chain** if using [CCxTrust](https://arxiv.org/html/2412.03842v2)'s owner-controlled trust model.
5. **Promote `cpu_gpu_chain`** — `Pass` if composite verification succeeds.

##### Differences from Option 3

| Aspect | Option 3 ([DCEA](https://arxiv.org/html/2510.12469v1) protocol) | Option 4 (Composite) |
|--------|----------------|---------------------|
| **Primary mechanism** | RTMR ↔ PCR cross-check | Joint attestation report |
| **TPM role** | Platform identity and measurement anchor | Independent measurement root + sealed storage |
| **GPU binding** | GPU SPDM hash extended into PCR | GPU SPDM hash in composite report + PCR |
| **Trust model** | Cloud provider issues EKC; proofs verifiable by any client | Owner CA (can be third-party or self-managed) |
| **Vendor lock-in** | Requires Intel TDX (RTMR mapping) | Works across TDX, SEV-SNP, ARM CCA |
| **tee.fail defense** | Strong (TPM as second root prevents replay of [tee.fail](https://tee.fail/) artifacts) | Strong (same TPM defense) |
| **Client-verifiable** | Yes, if provider exposes proofs in API ([Proof of Cloud](https://proofofcloud.org/) registry is fallback) | Yes, composite report is self-contained |
| **Maturity** | Reference implementation on GCP | Prototype on AMD SEV-SNP; [CNCF](https://www.cncf.io/blog/2025/10/08/a-tpm-based-combined-remote-attestation-method-for-confidential-computing/) spec in progress |

#### Option 5 — TDX Connect + TDISP (Hardware Binding)

##### Overview

Intel TDX Connect and PCI-SIG TDISP (TEE Device Interface Security Protocol)
provide a hardware-enforced mechanism for extending the CPU TEE boundary to
include PCIe devices.  This eliminates bounce buffers and provides the missing
cryptographic binding between CPU and GPU attestation at the silicon level.

##### Binding strength

**Strong — hardware-enforced.**  The CPU's TDX Connect report includes the
device's SPDM identity as part of the trust domain measurement.  PCIe link
encryption (IDE) ensures data integrity and confidentiality between CPU and GPU
without software intermediation.

##### Architecture

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

##### Protocol stack

| Layer | Protocol | Function |
|-------|----------|----------|
| Link encryption | **IDE** (Integrity and Data Encryption) | Encrypts all PCIe TLP traffic between CPU and GPU |
| Device interface | **TDISP** (TEE Device Interface Security Protocol) | Manages the device interface lifecycle, establishes trusted device interfaces (TDIs) |
| Device authentication | **SPDM** (Security Protocol and Data Model) | GPU authenticates to CPU using hardware-fused identity key; mutual attestation |
| Key management | **IDE_KM** | Manages encryption keys for the IDE stream |
| CPU-side coordination | **TSM** (TEE Security Manager) | Defines and enforces security policies for device integration |
| GPU-side coordination | **DSM** (Device Security Manager) | Works with TSM to establish secure channels |

##### What infrastructure providers must implement

###### Hardware requirements

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

###### Software / OS requirements

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

###### Verifier changes (teep)

1. **Parse TDX Connect reports.**  These extend the standard TDX quote format
   to include device identity claims.

2. **Validate device identity against NVIDIA's certificate chain.**  The SPDM
   device identity embedded in the TDX Connect report must chain to NVIDIA's
   Device Identity Root CA.

3. **Cross-reference.**  Confirm that the device identity in the TDX Connect
   report matches the device identity in the NVIDIA EAT evidence.

4. **Promote `cpu_gpu_chain` to `Pass`** when all cross-references succeed.

###### Deployment timeline

As of March 2026, the NVIDIA SecureAI whitepaper and Intel's announcements
indicate that:

- Granite Rapids processors with TDX Connect are **available** (Xeon 6).
- Blackwell GPUs with TDISP support are **shipping** but TDISP software stack
  maturity is evolving.
- Intel and NVIDIA have demonstrated **bounce-buffer** composite attestation
  (NearAI's current approach) and are working toward TDISP-based direct
  integration.
- Full production readiness of the TDISP stack is expected in late 2026 / 2027.

### Deployment Priority

The five options are **complementary, not mutually exclusive**.  Each layer
addresses a different gap or strengthens an existing mitigation, and no later
stage requires removing an earlier one.  The recommended path is ordered by
implementation ease — each stage is the lowest-effort next step that
meaningfully improves the security posture.

#### How the options combine

To understand the trajectory, it helps to see what each option does and does
not defend against, and how combinations eliminate residual gaps:

- **Option 1 (Proof of Cloud)** provides a conditional Gap 1 defense:
  it detects forged quotes *unless* the attacker holds signing keys for an
  enrolled PPID (potentially from before enrollment). It does nothing for Gap 2.
- **Option 2 (GPU hash in REPORTDATA)** provides an application-layer Gap 2
  defense: it binds GPU evidence to the TDX quote.  It does nothing for
  Gap 1.  Crucially, if an attacker has TEE.fail capability on an enrolled
  machine, they can forge a quote with fabricated REPORTDATA — defeating
  Option 2 and Option 1 simultaneously.  Options 1 + 2 together therefore
  cover *independent* exploitation of either gap, but not an attacker who
  combines TEE.fail with GPU splicing.
- **Option 3 (DCEA/vTPM)** provides a full Gap 1 defense (TPM-backed,
  immune to TEE.fail) and, with GPU SPDM extended into PCRs, a full Gap 2
  defense.  When DCEA is deployed, it becomes the primary defense for both
  gaps.  Options 1 and 2 remain useful as defense-in-depth layers — redundant
  checks that would catch regressions in the DCEA implementation or
  measurement chain.
- **Option 4 (CCxTrust/CNCF)** is an alternative to Option 3 for
  vendor-neutral deployments (AMD SEV-SNP, ARM CCA).  It addresses the same
  gaps using a different composite report format.  Track it for heterogeneous
  provider support.
- **Option 5 (TDX Connect + TDISP)** provides silicon-level Gap 2 defense.
  Combined with the TPM-backed attestation from Option 3, this is the
  strongest achievable posture.  All earlier options become additional
  defense-in-depth layers.

The following table shows the cumulative security posture at each stage:

| Stage | Options active | Gap 1 (TEE.fail) | Gap 2 (CPU-GPU) | Residual risk |
|-------|---------------|-------------------|-----------------|---------------|
| **1** | 1 | ⚠️ Conditional | ❌ Open | TEE.fail on enrolled machines; all GPU splicing |
| **2** | 1 + 2 | ⚠️ Conditional | ✅ App-layer | TEE.fail defeats both simultaneously via GPU evidence relay (see [Stage 2 analysis](#gpu-evidence-relay-attack-stage-2-residual-risk)) |
| **3** | 1 + 2 + 3 | ✅ TPM-backed | ✅ Platform + app | Host measurement chain error (mitigated by measured boot); 1 + 2 provide redundancy; DCEA [cloud provider coverage is limited](#dcea-cloud-provider-coverage) |
| **4** | 1 + 2 + 3 + 5 | ✅ TPM-backed | ✅ Silicon + platform + app | Silicon bugs; deepest defense-in-depth at all layers |

#### Stage 1.  Strengthen Proof of Cloud registry (deployed)

**Options:** 1 &nbsp; **Effort:** Verifier-side only &nbsp; **Gap 1:** Conditional ⚠️ &nbsp; **Gap 2:** Open ❌

The [Proof of Cloud](https://proofofcloud.org/) registry (Option 1) is
already deployed for teep's `cpu_id_registry` and `gateway_cpu_id_registry`
factors.  Strengthen the existing deployment:
- Encourage providers to achieve Level 2+ (automated) verification.
- Monitor registry freshness; stale entries weaken assurance.
- Treat `cpu_id_registry` as enforced for providers where the registry has
  coverage.

**Security posture after Stage 1:**  Gap 1 is conditionally mitigated —
forged quotes from non-enrolled hardware are detected, but an attacker who
extracted keys from an enrolled machine (pre- or post-enrollment) can still
forge quotes carrying a valid PPID.  Gap 2 is entirely unmitigated — GPU
evidence can be spliced from any machine.

#### Stage 2.  GPU evidence hash in REPORTDATA (immediate — request from providers)

**Options:** 1 + 2 &nbsp; **Effort:** CVM app change + verifier &nbsp; **Gap 1:** Conditional ⚠️ &nbsp; **Gap 2:** App-layer ✅

Request NearAI / dstack implement Option 2: include a SHA-256 hash of the GPU
EAT evidence in the TDX REPORTDATA derivation.  Update teep's `cpu_gpu_chain`
factor to verify this binding.  This is the **lowest-cost mitigation for
CPU-to-GPU splicing** (Gap 2), deployable on existing Hopper hardware with no
infrastructure changes.

Gap 2 is independently exploitable *without* TEE.fail — any attacker
controlling two legitimate machines can splice GPU evidence from one into the
attestation response of the other.  Option 1 closes this gap at the
application layer, which has standalone value.

**Security posture after Stage 2:**  Gaps 1 and 2 are each mitigated by
independent mechanisms (Option 1 for Gap 1, Option 2 for Gap 2).  An attacker
exploiting *only* Gap 2 (GPU splicing without TEE.fail) is now blocked.
However, an attacker with TEE.fail capability on an enrolled machine defeats
both defenses simultaneously: a forged TDX quote can carry fabricated
REPORTDATA (defeating Option 2) *and* a legitimate PPID (defeating Option 1).
This is the critical residual risk that Stage 3 eliminates.

##### GPU evidence relay attack (Stage 2 residual risk)

The residual risk at Stage 2 is worse than it might initially appear.  One
might assume that adding GPU device identity tracking to the Proof of Cloud
registry (mapping CPU PPID → GPU device certificate fingerprint) would
strengthen the defense, since NVIDIA GPU attestation keys are immune to
TEE.fail — the GPU's Identity Key (IK) is burned into on-die fuses and the
Attestation Key (AK) lives in GPU-local memory (HBM, on-package), neither of
which is accessible via DDR5 memory bus interposition.  An attacker who
extracts TDX signing keys cannot also extract GPU signing keys using the same
attack.

However, a **GPU evidence relay attack** defeats this combination without
requiring continued physical access or CVM compromise:

```
Precondition: Attacker previously extracted TDX signing keys from
Machine-A (enrolled in PoC with PPID-A, GPU-A installed).
Machine-A continues running normally.  Attacker has left the facility.

1. Client sends attestation request (nonce=N) to attacker's service.
2. Attacker relays nonce N to Machine-A's attestation API.
   (This is a standard API request — indistinguishable from a
   legitimate client.)
3. Machine-A's CVM collects GPU evidence from GPU-A with nonce N
   and returns {real TDX quote, real GPU EAT evidence}.
4. Attacker DISCARDS Machine-A's real TDX quote.
5. Attacker FORGES a TDX quote using extracted keys:
   - PPID = PPID-A (passes Proof of Cloud)
   - REPORTDATA = binding(ATTACKER_signing_key, gpu_evidence_hash)
   - MRTD / RTMRs = expected legitimate values
6. Attacker returns {forged TDX quote, relayed GPU evidence} to client.

Result: all verification factors pass.

Client establishes E2EE with attacker's signing key.
Attacker decrypts all inference traffic.
```

This attack works because:

- **GPU evidence is bound to the nonce, not to the TDX quote or CVM identity.**  The SPDM evidence proves "GPU-A signed these measurements with
  nonce N" — it says nothing about which TDX quote will accompany it.

- **The CVM's attestation API is network-accessible.**  Any client can request
  attestation with an arbitrary nonce.  The attacker's relay request is
  indistinguishable from a legitimate attestation request.

- **REPORTDATA is entirely fabricated.**  TEE.fail gives the attacker full
  control over the forged quote's contents.  The attacker constructs
  REPORTDATA binding *their own* signing key and the relayed GPU evidence hash.

- **No physical access or CVM compromise required at attack time.**  The
  attacker only needs: (a) TDX signing keys extracted at any prior point, and
  (b) network access to Machine-A's running CVM.

Even if the Proof of Cloud registry were extended to track GPU device
identities alongside CPU PPIDs — so the verifier confirms the GPU's SPDM
certificate fingerprint matches the registered device for that PPID — the
relay attack succeeds because the attacker obtains **real, fresh GPU
attestation** from the enrolled machine's actual GPU via a normal API call.
The GPU device identity is genuine and matches the registry.

#### Stage 3.  DCEA / vTPM dual attestation (near-term — provider infrastructure)

**Options:** 1 + 2 + 3 &nbsp; **Effort:** vTPM + CVM agent + verifier &nbsp; **Gap 1:** Full ✅ &nbsp; **Gap 2:** Full ✅

Prioritize Option 3 ([DCEA](https://arxiv.org/html/2510.12469v1) protocol).
NearAI / dstack / tinfoil should:
- Expose a vTPM to TD guests.
- Extend GPU SPDM device identity into vTPM PCRs.
- Include the AK public key hash in TDX report_data.
- Seal the AK to PCR policy (boot chain + GPU PCR).
- **Expose DCEA proofs directly in their attestation API responses** so that
  clients like teep can verify them at request time.

This is the **critical transition**: DCEA provides the first complete
defense against TEE.fail attestation spoofing (Gap 1).

The vTPM's Attestation Key is sealed to the platform's measured boot state —
even if an attacker extracts TDX signing keys, the TPM quote cannot be
reproduced on different hardware.  Unlike Proof of Cloud, DCEA is not vulnerable
to pre-enrollment compromise: previously extracted TEE keys cannot produce valid
TPM-backed attestation.

With GPU SPDM identity extended into the vTPM PCR chain, DCEA also provides
platform-level Gap 2 binding — stronger than Option 2's application-layer
binding because the GPU identity is rooted in the measured boot chain rather
than a single application-layer hash.

**Why Options 1 and 2 remain valuable:**  After DCEA is deployed, Proof of
Cloud (Option 1) provides a redundant Gap 1 check via a completely
independent mechanism (registry lookup vs. TPM proof).  GPU hash in
REPORTDATA (Option 2) provides a redundant Gap 2 check at the application
layer, independent of the vTPM measurement chain.  These redundant layers
catch implementation bugs or regressions in the DCEA stack — defense in depth.

**Security posture after Stage 3:**  Both gaps are fully mitigated by
TPM-backed cryptographic proofs, with Options 1 and 2 as redundant layers.
The primary residual risk is errors in the host measurement chain (e.g., the
GPU driver fails to extend SPDM identity into vTPM PCRs correctly), which
measured boot mitigates.

##### DCEA cloud provider coverage

DCEA's primary implementation caveat is limited cloud provider support.  The
DCEA protocol relies on the Intel TDX RTMR ↔ vTPM PCR mapping, which is
**Intel TDX-specific** — AMD SEV-SNP does not provide RTMRs or comparable
measurement registers required for the cross-check.  The [DCEA
paper](https://arxiv.org/html/2510.12469v1) surveyed cloud provider support
(Table 4 in the paper):

| Platform | TDX CVM | vTPM | Bare metal TDX | HW TPM | DCEA feasibility |
|----------|---------|------|----------------|--------|------------------|
| **GCP** | ✅ | ✅ | ✅ | ✅ | ✅ Full (reference implementation exists) |
| **Azure** | ✅ | ✅ | ❌ | ❌ | ⚠️ S1 only; paravisor approach has measurement overlap caveats |
| **AWS** | ❌ | ✅ | ❌ | ❌ | ❌ No Intel TDX support |
| **IBM Cloud** | ✅ | ⚠️ | ❌ | ❌ | ⚠️ Limited vTPM support |
| **OVH** | ✅ | ❌ | ✅ | ⚠️ | ❌ No vTPM for S1 |

The only existing reference implementation is on Google Cloud.  Azure
supports TDX CVMs with vTPMs (DCEA Scenario 1 is feasible), but Azure uses a
paravisor architecture and the DCEA paper notes that paravisor PCR
measurements "do not overlap with the runtime and platform configuration
of the guest OS, which is crucial for ensuring the binding." Intel Trust
Authority already supports
[Azure vTPM + TDX](https://docs.trustauthority.intel.com/main/articles/tutorial-azure-vtpm.html)
attestation, so Azure support is plausible but unvalidated for DCEA.

For teep's current providers (NearAI, dstack), neither runs on a major cloud
provider's managed vTPM infrastructure — they would need to provision vTPM
support themselves regardless of cloud platform.  This is the primary
deployment cost of Stage 3.

Option 4 ([CCxTrust](https://arxiv.org/html/2412.03842v2) / CNCF) provides
equivalent security properties using a vendor-neutral composite report format
that works across Intel TDX, AMD SEV-SNP, and ARM CCA.  If teep needs to
verify non-Intel providers, or if DCEA's cloud provider limitations prove
blocking, Option 4 becomes the primary path rather than a parallel track.

#### Stage 4.  TDX Connect + TDISP (medium-term — hardware upgrade)

**Options:** 1 + 2 + 3 + 5 &nbsp; **Effort:** New hardware + full stack &nbsp; **Gap 1:** Full ✅ &nbsp; **Gap 2:** Silicon ✅

When NearAI or other providers upgrade to Blackwell GPUs + Granite Rapids
CPUs, implement Option 5.  TDX Connect incorporates GPU SPDM identity
directly into the trust domain report at the silicon level via PCIe IDE link
encryption, eliminating reliance on the host software stack for GPU binding.

This is the **strongest achievable Gap 2 binding**: hardware-enforced at the
PCIe layer, not dependent on measured boot correctly extending GPU identity
into PCRs.  Combined with DCEA's TPM-backed Gap 1 defense (Stage 3), this
provides complete attestation assurance at the hardware level.

**All prior layers remain active** as defense-in-depth: Proof of Cloud
(registry), GPU hash in REPORTDATA (application), and DCEA (platform).

#### Parallel track: Composite attestation standards (monitor)

Track [CCxTrust](https://arxiv.org/html/2412.03842v2) (Option 4) and
[CNCF hybrid attestation](https://www.cncf.io/blog/2025/10/08/a-tpm-based-combined-remote-attestation-method-for-confidential-computing/)
as the **vendor-neutral alternative** to Option 3 for providers using AMD
SEV-SNP or heterogeneous accelerators.  CCxTrust provides the same dual-root
security properties (TEE + TPM) via a composite report format with an
owner-controlled CA, and works across Intel TDX, AMD SEV-SNP, and ARM CCA.

When composite attestation standards mature, implement composite report
parsing in teep.  This does not change the Intel TDX deployment trajectory
above — it extends teep's coverage to non-Intel providers.

#### Summary

| Stage | Add option | Action | Who | Gap 1 after | Gap 2 after |
|-------|-----------|--------|-----|-------------|-------------|
| **1** | 1 (deployed) | Strengthen Proof of Cloud enforcement | teep (verifier) | ⚠️ Conditional | ❌ Open |
| **2** | + 2 | Request GPU hash in REPORTDATA | Provider (CVM app) + teep | ⚠️ Conditional | ✅ App-layer |
| **3** | + 3 | Deploy DCEA / vTPM with GPU PCR extension | Provider (infrastructure) + teep | ✅ Full (TPM) | ✅ Full (platform) |
| *(parallel)* | 4 | Track CCxTrust / CNCF composite standards | Standards bodies + teep | ✅ Full (TPM) | ✅ Full (composite) |
| **4** | + 5 | Upgrade to TDX Connect + TDISP hardware | Provider (hardware) + teep | ✅ Full (TPM) | ✅ Full (silicon) |

Each stage is additive — no earlier option is removed when a later one is
deployed.  The trajectory moves from the easiest, lowest-cost improvements
(verifier-only changes, then CVM app changes) toward deeper infrastructure
changes (vTPM provisioning, then hardware upgrades), with each step
meaningfully reducing residual risk.

---

## References

### Intel TDX Connect

- **Intel TDX Connect Architecture Specification**
  https://cdrdv2.intel.com/v1/dl/getContent/773614

- **Intel TDX Connect TEE-IO Device Guide (v0.6.5)**
  https://cdrdv2-public.intel.com/772642/whitepaper-tee-io-device-guide-v0-6-5.pdf

- **Confidential AI with GPU Acceleration: Bounce Buffers Offer a Solution Today** (Intel blog, March 2026)
  https://community.intel.com/t5/Blogs/Tech-Innovation/Artificial-Intelligence-AI/Confidential-AI-with-GPU-Acceleration-Bounce-Buffers-Offer-a/post/1740417

### NVIDIA Confidential Computing

- **Confidential Compute on NVIDIA Hopper H100** (whitepaper, WP-11459-001_v1.0)
  https://images.nvidia.com/aem-dam/en-zz/Solutions/data-center/HCC-Whitepaper-v1.0.pdf
  — GPU device-unique Identity Key (IK) is burned into fuses; Attestation Key (AK) is regenerated deterministically at each chip reset and signed by IK.  Private IK keys are destroyed during manufacturing.  GPU keys reside in on-die fuses and GPU-local HBM memory, not in host DDR5 DRAM — thus not extractable via TEE.fail's DDR5 bus interposition.

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

### DCEA (Data Center Execution Assurance)

- **[Proof of Cloud: Data Center Execution Assurance for Confidential VMs](https://arxiv.org/html/2510.12469v1)** (Rezabek et al., Flashbots / TU Munich, 2025)
  https://arxiv.org/html/2510.12469v1
  — Defines the DCEA cryptographic protocol binding CVM attestation to platform TPM/vTPM via RTMR-PCR cross-checks; demonstrates mitigations for relay, proxy, and Frankenstein attacks; reference implementation on Google Cloud with Intel TDX and Intel TXT.  DCEA proofs are self-contained and verifiable by any remote party.

### Proof of Cloud Alliance

- **[Proof of Cloud — Verifiable Cloud Hardware Registry](https://proofofcloud.org/)** (Proof of Cloud Alliance, 2025)
  https://proofofcloud.org/
  — Vendor-neutral alliance maintaining a public registry mapping TEE hardware IDs (PPIDs, Chip IDs) to verified physical facilities.  Three verification levels: Level 1 (human-witnessed), Level 2 (automated via zk-TLS, vTPM/DCEA, RFID), Level 3 (continuous monitoring).  Level 2 references DCEA as one method but the registry model means proofs are verified by the alliance on behalf of consumers, not exposed directly to API users.

- **[Proof of Cloud — Verification Methods](https://proofofcloud.org/verification-methods)**
  https://proofofcloud.org/verification-methods
  — Detailed methodologies for each verification level.

- **[tee.fail: Breaking Trusted Execution Environments via DDR5 Memory Bus Interposition](https://tee.fail/)** (Georgia Tech / Purdue / Synkhronix, 2025)
  https://tee.fail/
  — Demonstrates practical DDR5 memory bus interposition recovering ECDSA attestation keys from Intel's PCE; breaks SGX and TDX attestation on fully patched systems for under $1,000.

- **Intel Security Announcement: TEE.fail** (Intel, October 2025)
  https://www.intel.com/content/www/us/en/security-center/announcement/intel-security-announcement-2025-10-28-001.html

### TPM + TEE Composite Attestation

- **[CCxTrust: Confidential Computing Platform Based on TEE and TPM Collaborative Trust](https://arxiv.org/html/2412.03842v2)** (Shang et al., Chinese Academy of Sciences, 2024)
  https://arxiv.org/html/2412.03842v2
  — Proposes collaborative roots of trust (RTM, RTR, RTS) combining TEE and TPM; implements Confidential TPM (CTPM) for CVMs; composite attestation protocol with 24% efficiency improvement; prototype on AMD SEV-SNP.

- **[A TPM-based Combined Remote Attestation Method for Confidential Computing](https://www.cncf.io/blog/2025/10/08/a-tpm-based-combined-remote-attestation-method-for-confidential-computing/)** (CNCF / JD.COM, 2025)
  — Hybrid attestation combining TEE-native reports with TPM quotes; vTPM running inside SVSM at VMPL 0 (AMD) or TD partitions (Intel); Privacy CA issuing vAIK certificates; deployed in production on Hygon CSV with AMD SNP and Intel TDX support in development.

- **Remote Attestation of Confidential VMs Using Ephemeral vTPMs** (ACM CCS, 2023)
  https://dl.acm.org/doi/fullHtml/10.1145/3627106.3627112
  — Implements confidential vTPM emulated inside a TEE, linked to enclave root of trust; provides TPM properties (measured boot, sealing) isolated from both host and guest.

- **The Trust Model of vTPM in Confidential VMs** (Gauthier Jolly, 2025)
  https://gjolly.fr/blog/ek-cvm-binding/
  — Discusses EK-to-CVM binding and the convergence toward vTPM as the attestation abstraction for confidential VMs.

- **Intel vtpm-td: Trust Domain-based Virtual TPM** (Intel, 2025)
  https://github.com/intel/vtpm-td
  — Intel's implementation of a vTPM running as a dedicated TD, providing TPM functionality isolated from the host; mitigates malicious hypervisor proxying attacks.

---

## Teep Status

### Affected validation factors

CPU identity binding:

- **`cpu_id_registry`** — [Proof of Cloud](https://proofofcloud.org/) registry
  mitigation of [TEE.fail](https://tee.fail/) at inference CVM
- **`gateway_cpu_id_registry`** — [Proof of Cloud](https://proofofcloud.org/)
  registry mitigation of [TEE.fail](https://tee.fail/) at gateway CVM

CPU-to-GPU binding:

- **`cpu_gpu_chain`** — hardcoded `Fail` in
  [`report.go` `evalCPUGPUChain`](../../internal/attestation/report.go#L1024-L1032)

GPU nonce binding:

- **`nvidia_nonce_client_bound`** — spurious failures on nearcloud

### Current behavior

`cpu_id_registry` and `gateway_cpu_id_registry` are evaluated via the Proof of
Cloud multi-peer quorum protocol (Option 1, deployed).  `cpu_gpu_chain` is
hardcoded to `Fail` because no provider currently implements CPU-to-GPU
binding (Options 2–5).

Once providers adopt Option 2 (GPU evidence hash in REPORTDATA), teep will
promote `cpu_gpu_chain` from hardcoded `Fail` to a computed factor.  The
factor should remain outside `DefaultEnforced` initially and be promoted to
enforced once providers deploy the scheme.
